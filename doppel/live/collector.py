"""The Live Hunt collector (P12): a background service that judges every new certificate's names as they appear.

    source  (live)    wss://api.certstream.dev/  -> parse (both formats) -> recorder (hourly .jsonl.gz)
            (replay)  a recording, re-fed at 1x with its real timestamps
      |  bounded queue (drops are counted, never silent)
    pipeline  dedupe -> keyword baseline || Brain.investigate(name, "ct_feed") -> counters, ticker,
              catch store, arming (a watched NRD look-alike appears) -> CT enricher (flagged names only)
    jobs      state.json every second, per-minute counters, session heartbeat, watchdog (silence / slow /
              format alarms + reconnect), Phishing.Database polls (live), daily NRD ingest (live), retention

Doppel never contacts a suspect: names come from CT logs (via certstream), facts from CT search, lists from
GitHub. ``ct_feed`` is a batch source, so the brain stops after Quick unless there is a brand signal, never runs
Deep, and never looks CT up by itself (the enricher does, under a daily cap).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import gzip
import json
import logging
import logging.handlers
import os
import queue
import threading
import time
from collections import Counter, deque
from pathlib import Path

from doppel.live import mode_dir
from doppel.live.dedupe import RecentNames
from doppel.live.messages import Entry, parse
from doppel.live.store import FLAGGED, Store

STREAM_URL = "wss://api.certstream.dev/"
SILENCE_S = 30            # no message at all for this long: alarm + reconnect
RATE_FLOOR = 50           # names/s averaged over a minute; below it (while connected): "slow" alarm
FORMAT_WINDOW_S = 60      # messages but zero names, with unknown types, for this long: "format" alarm
WATCHDOG_EVERY_S = 5
RECONNECT_MAX_S = 60.0
QUEUE_MAX = 200_000
TICKER = 60
KEEP_HOURS = 96           # recordings kept for replay (~15-25 MB/h gzipped)
STATE_EVERY_S = 1.0
log = logging.getLogger("doppel.live")


def tricks_of(v: dict) -> list[str]:
    out = []
    for e in v.get("evidence", []):
        if e["tool"] in ("trick_detector", "family_verifier") and e["points_to"] == "phishing":
            out.append(e["finding"])
    return list(dict.fromkeys(out))


def platform_of(v: dict) -> str | None:
    for e in v.get("evidence", []):
        if e["tool"] == "address_reader" and e["finding"] == "free_hosting_owner":
            return (e.get("details") or {}).get("platform")
    return None


def proof_of(v: dict) -> str | None:
    for e in v.get("evidence", []):
        if e["points_to"] == "genuine" and e["strength"] == "strong":
            return e["finding"]
    return None


class Recorder:
    """Every parsed message, one JSON line, hourly gzip files: ``[t, kind, names, issuer, not_before]``."""

    def __init__(self, folder: Path, keep_hours: int = KEEP_HOURS) -> None:
        self.folder = folder
        self.keep_hours = keep_hours
        self.folder.mkdir(parents=True, exist_ok=True)
        self._hour, self._fh, self._last_flush = None, None, 0.0
        self.lock = threading.Lock()

    def write(self, t: float, e: Entry) -> None:
        hour = dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y%m%d-%H")
        line = json.dumps([round(t, 3), e.kind[0], e.names, e.issuer, e.not_before], separators=(",", ":"))
        with self.lock:
            if hour != self._hour:
                self._close()
                self._hour = hour
                self._fh = gzip.open(self.folder / f"stream-{hour}.jsonl.gz", "at", encoding="utf-8")
            self._fh.write(line + "\n")
            if t - self._last_flush > 5:
                self._fh.flush()
                self._last_flush = t

    def _close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def close(self) -> None:
        with self.lock:
            self._close()

    def prune(self, now: float | None = None) -> int:
        cutoff = (now or time.time()) - self.keep_hours * 3600
        n = 0
        for p in self.folder.glob("stream-*.jsonl.gz"):
            if p.stat().st_mtime < cutoff:
                p.unlink(missing_ok=True)
                n += 1
        return n


def read_recording(paths: list[Path]):
    """Yield ``(t, Entry)`` from recordings, oldest first (a truncated last line is skipped)."""
    kinds = {"c": "certificate_update", "d": "dns_entries", "h": "heartbeat", "u": "unknown"}
    for p in sorted(paths):
        try:
            with gzip.open(p, "rt", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        t, k, names, issuer, nb = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    yield t, Entry(kinds.get(k, "unknown"), names, None, nb, issuer, kinds.get(k))
        except (EOFError, OSError) as exc:                  # a recording cut off mid-write
            log.warning("recording %s ends early: %s", p.name, exc)


class Pipeline:
    """Judge names, count them, store the catches. Source-agnostic; runs in one worker thread."""

    def __init__(self, store: Store, brain, naive, mode: str, on_flag=None, brain_lock: threading.Lock | None = None,
                 list_watch=None) -> None:
        self.store, self.brain, self.naive, self.mode = store, brain, naive, mode
        self.on_flag = on_flag
        self.brain_lock = brain_lock or threading.Lock()
        self.list_watch = list_watch
        self.recent = RecentNames()
        self.minute: int | None = None
        self.mcounts: Counter = Counter()
        self.totals: Counter = Counter()
        self.ticker: deque = deque(maxlen=TICKER)
        self.latest_flags: deque = deque(maxlen=12)
        self.watch = store.watched_owners()
        self.reload_watch = False
        self.stream_now: float | None = None
        self.lock = threading.Lock()

    def _tick_minute(self, t: float) -> None:
        m = int(t // 60)
        if self.minute is None:
            self.minute = m
        elif m != self.minute:
            self.flush()
            self.minute = m

    def flush(self) -> None:
        if self.minute is not None and self.mcounts:
            self.store.add_minute(self.minute, dict(self.mcounts))
        self.mcounts = Counter()

    def count(self, key: str, n: int = 1) -> None:
        self.mcounts[key] += n
        self.totals[key] += n

    def feed(self, t: float, e: Entry) -> None:
        if self.reload_watch:
            self.watch = self.store.watched_owners()
            self.reload_watch = False
        self.stream_now = t
        self._tick_minute(t)
        if e.kind in ("heartbeat", "unknown"):
            return
        self.count("certs")
        self.count("names", len(e.names))
        for name in e.names:
            if self.recent.seen_or_add(name):
                continue
            self.count("uniq")
            self.judge(name, t, e)

    def judge(self, name: str, t: float, e: Entry) -> dict | None:
        kw = self.naive.hit(name)
        try:
            with self.brain_lock:
                v = self.brain.investigate(name, "ct_feed")
        except Exception as exc:                          # noqa: BLE001 - one odd name must not stop the hunt
            self.count("errors")
            log.debug("cannot judge %r: %s", name, exc)
            return None
        label = v["label"]
        flagged = label in FLAGGED
        brand = (v.get("target_brand") or {}).get("id")
        if kw:
            self.count("naive")
        if flagged:
            self.count("flags")
        if kw and flagged:
            self.count("both_hit")
        elif kw:
            self.count("naive_only")
        elif flagged:
            self.count("doppel_only")
        if label == "genuine":
            self.count("genuine")
            self.store.add_genuine(name, brand, proof_of(v), t)
        if flagged or label == "genuine" or kw or len(self.ticker) < 5 or self.totals["uniq"] % 7 == 0:
            with self.lock:     # the ticker: every flag, genuine and keyword hit, plus a sample of the rest
                self.ticker.append({"name": name, "t": round(t, 3), "label": label, "brand": brand,
                                    "naive": kw, "risk": v["risk_score"]})
        owner = v.get("owner") or name
        armed = None
        if owner in self.watch:
            armed = self.store.arm(owner, name, t, label, v["risk_score"])
            self.watch.discard(owner)
            if armed:
                log.warning("ARMED: watched %s (added %s) appeared in the stream as %s", owner,
                            dt.datetime.fromtimestamp(armed["added"]).isoformat(timespec="seconds"), name)
        if flagged:
            row = {"name": name, "owner": owner, "brand": brand, "label": label, "risk": v["risk_score"],
                   "tricks": ",".join(tricks_of(v)), "reason": v["reason"], "first_seen": t, "last_seen": t,
                   "stream_issuer": e.issuer, "stream_not_before": e.not_before, "naive": kw,
                   "platform": platform_of(v)}
            if self.list_watch is not None:
                row.update(self.list_watch.status_at_flag(name, owner, row["platform"]))
            new = self.store.upsert_catch(row, v)
            if new:
                with self.lock:
                    self.latest_flags.appendleft({k: row[k] for k in ("name", "brand", "label", "risk", "first_seen")})
                if self.on_flag:
                    self.on_flag(row, armed is not None)
        return v


class Collector:
    def __init__(self, mode: str = "live", root: Path | None = None, url: str = STREAM_URL,
                 recording: list[Path] | None = None, speed: float = 1.0, ct_daily_cap: int = 20,
                 pdb_every_h: float = 1.0, nrd_every_h: float = 24.0, keep_hours: int = KEEP_HOURS,
                 brain=None, record: bool | None = None, jobs: bool | None = None) -> None:
        from doppel.family import load_registry
        from doppel.live.naive import KeywordBaseline

        self.mode = mode
        self.dir = mode_dir(mode, root)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.url, self.recording, self.speed = url, recording or [], speed
        self.stop = threading.Event()
        self.q: queue.Queue = queue.Queue(QUEUE_MAX)
        self.store = Store(self.dir / "catches.db")
        if brain is None:
            from doppel.brain.brain import Brain
            brain = Brain(deep=False)
        self.brain = brain
        self.brain_lock = threading.Lock()
        live = mode == "live"
        self.jobs_on = live if jobs is None else jobs
        self.list_watch = None
        if self.jobs_on:
            from doppel.live.leadtime import ListWatch
            self.list_watch = ListWatch(self.dir, Store(self.dir / "catches.db"), every_h=pdb_every_h)
        self.enricher = None
        if live and ct_daily_cap > 0:
            from doppel.live.enrich import Enricher
            self.enricher = Enricher(self.dir / "catches.db", self._rejudge, daily_cap=ct_daily_cap)
        self.pipeline = Pipeline(self.store, brain, KeywordBaseline(brain.reg), mode,
                                 on_flag=self.enricher.offer if self.enricher else None,
                                 brain_lock=self.brain_lock, list_watch=self.list_watch)
        self.recorder = Recorder(self.dir.parent / "recordings", keep_hours) if (live if record is None else record) else None
        self.nrd_every_h, self.ct_daily_cap = nrd_every_h, ct_daily_cap
        self.connected = False
        self.last_msg_wall: float | None = None
        self.connected_since: float | None = None
        self.unknown_types: Counter = Counter()
        self.last_names_wall: float | None = None
        self.rate_window: deque = deque()          # (wall second, names) for the last 60 s
        self.reconnects = 0
        self.forced = 0
        self.dropped = 0
        self.started = time.time()
        self.sid = self.store.open_session(mode, url if live else ",".join(p.name for p in self.recording))
        self.replay_info: dict = {}
        self._ws = None
        self._loop = None

    # ------------------------------------------------------------------ sources ---

    def _enqueue(self, t: float, e: Entry) -> None:
        if self.recorder is not None and e.kind != "heartbeat":
            self.recorder.write(t, e)
        now = time.time()
        self.last_msg_wall = now
        if e.kind == "unknown":
            self.unknown_types[e.raw_type] += 1
        if e.names:
            self.last_names_wall = now
            sec = int(now)
            if self.rate_window and self.rate_window[-1][0] == sec:
                self.rate_window[-1][1] += len(e.names)
            else:
                self.rate_window.append([sec, len(e.names)])
            while self.rate_window and self.rate_window[0][0] < sec - 60:
                self.rate_window.popleft()
        try:
            self.q.put_nowait((t, e))
        except queue.Full:
            self.dropped += len(e.names)
            self.pipeline.count("dropped", len(e.names))

    async def _ws_main(self) -> None:
        import websockets

        backoff = 1.0
        watchdog = asyncio.create_task(self._watchdog())
        while not self.stop.is_set():
            try:
                async with websockets.connect(self.url, max_size=2 ** 24, open_timeout=20, ping_interval=20,
                                              ping_timeout=30, close_timeout=5) as ws:
                    self._ws = ws
                    self.connected, self.connected_since = True, time.time()
                    self.last_msg_wall = time.time()
                    backoff = 1.0
                    self.store.resolve("disconnected")
                    log.info("connected to %s", self.url)
                    async for raw in ws:
                        if self.stop.is_set():
                            break
                        try:
                            msg = json.loads(raw)
                        except ValueError:
                            self._enqueue(time.time(), Entry("unknown", raw_type="not-json"))
                            continue
                        self._enqueue(time.time(), parse(msg))
            except asyncio.CancelledError:
                raise
            except Exception as exc:                       # noqa: BLE001 - reconnect on anything
                log.warning("stream error: %s: %s", type(exc).__name__, str(exc)[:200])
            self._ws = None
            if self.connected:
                self.reconnects += 1
            self.connected = False
            if self.stop.is_set():
                break
            down_since = self.last_msg_wall or self.started
            if time.time() - down_since > 60:
                self.store.alarm("disconnected", f"Can't reach {self.url} for {time.time() - down_since:.0f} s; "
                                                 "retrying with backoff.")
            await asyncio.sleep(min(backoff, RECONNECT_MAX_S))
            backoff = min(backoff * 2, RECONNECT_MAX_S)
        watchdog.cancel()

    async def _watchdog(self) -> None:
        """Silence, slowness and unknown formats raise alarms (and silence forces a reconnect)."""
        while not self.stop.is_set():
            await asyncio.sleep(WATCHDOG_EVERY_S)
            now = time.time()
            if not self.connected:
                continue
            if (self.dir / "RECONNECT").exists():          # `doppel live reconnect`: prove the reconnect path live
                (self.dir / "RECONNECT").unlink(missing_ok=True)
                self.forced += 1
                log.warning("forced reconnect requested: closing the stream")
                if self._ws is not None:
                    await self._ws.close()
                continue
            quiet = now - (self.last_msg_wall or now)
            if quiet > SILENCE_S:
                self.store.alarm("silent", f"The stream went silent: no message for {quiet:.0f} s. Reconnecting.")
                log.warning("silent for %.0f s: reconnecting", quiet)
                if self._ws is not None:
                    await self._ws.close()
                continue
            self.store.resolve("silent")
            no_names = now - (self.last_names_wall or self.connected_since or now)
            if no_names > FORMAT_WINDOW_S and self.unknown_types:
                kinds = ", ".join(f"{k} x{n}" for k, n in self.unknown_types.most_common(3))
                self.store.alarm("format", f"Messages arrive but carry no names for {no_names:.0f} s: unknown "
                                           f"message types ({kinds}). The feed format may have changed.")
            elif no_names <= FORMAT_WINDOW_S:
                self.store.resolve("format")
                self.unknown_types.clear()
            if now - (self.connected_since or now) > 90:
                rate = self.rate()
                if rate < RATE_FLOOR:
                    self.store.alarm("slow", f"Stream rate {rate:.0f} names/s, below the floor of {RATE_FLOOR}/s.")
                elif rate >= RATE_FLOOR * 1.2:
                    self.store.resolve("slow")

    def rate(self) -> float:
        now = int(time.time())
        n = sum(c for s, c in self.rate_window if s >= now - 60)
        span = min(60, max(1, now - int(self.started)))    # the window spans reconnects: divide by its own length
        return n / span

    def _replay_main(self) -> None:
        base_rec = base_wall = None
        total = 0
        self.connected, self.connected_since = True, time.time()
        for t, e in read_recording(self.recording):
            if self.stop.is_set():
                break
            if base_rec is None:
                base_rec, base_wall = t, time.time()
                self.replay_info.update(first=t)
            target = base_wall + (t - base_rec) / self.speed
            while not self.stop.is_set():
                d = target - time.time()
                if d <= 0:
                    break
                time.sleep(min(d, 0.25))
            self._enqueue(t, e)
            total += 1
            self.replay_info.update(position=t, messages=total)
        self.replay_info["finished"] = True
        self.connected = False
        log.info("replay finished: %d messages", total)

    # ------------------------------------------------------------------ worker + jobs ---

    def _worker(self) -> None:
        while not self.stop.is_set() or not self.q.empty():
            try:
                t, e = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.pipeline.feed(t, e)
            except Exception:                              # noqa: BLE001
                log.exception("pipeline error")
        self.pipeline.flush()

    def _rejudge(self, name: str) -> dict | None:
        with self.brain_lock:
            try:
                return self.brain.investigate(name, "ct_feed")
            except Exception:                              # noqa: BLE001
                return None

    def _jobs(self) -> None:
        last_beat = last_prune = 0.0
        last_watch = time.time()
        next_nrd = self._next_nrd()
        while not self.stop.is_set():
            now = time.time()
            try:
                self.write_state()
                if now - last_beat >= 60:
                    self.store.beat(self.sid)
                    last_beat = now
                if now - last_watch > 600:                 # pick up ingests run outside this process
                    self.pipeline.reload_watch = True
                    last_watch = now
                if self.recorder is not None and now - last_prune > 3600:
                    self.recorder.prune()
                    last_prune = now
                if self.list_watch is not None:
                    self.list_watch.maybe_poll()
                if self.jobs_on and next_nrd is not None and now >= next_nrd:
                    ok = self._run_nrd()
                    next_nrd = now + (self.nrd_every_h * 3600 if ok else 3600)    # a failed ingest retries in 1 h
                if (self.dir / "STOP").exists():
                    log.info("STOP file found: shutting down")
                    (self.dir / "STOP").unlink(missing_ok=True)
                    self.stop.set()
            except Exception:                              # noqa: BLE001 - a failed job must not stop the hunt
                log.exception("job error")
            self.stop.wait(STATE_EVERY_S)

    def _next_nrd(self) -> float | None:
        if not self.jobs_on or self.nrd_every_h <= 0:
            return None
        polls = self.store.polls("nrd")
        return (polls[-1]["t"] + self.nrd_every_h * 3600) if polls else time.time() + 30

    def _run_nrd(self) -> bool:
        """The daily NRD ingest runs as its own process (a 2M-name scan uses several cores for minutes)."""
        import subprocess
        import sys

        log.info("NRD ingest starting")
        workers = max(1, min(8, (os.cpu_count() or 4) // 2))
        try:
            p = subprocess.run([sys.executable, "-m", "doppel.cli", "live", "ingest-nrd", "--workers", str(workers)],
                               capture_output=True, text=True, timeout=3 * 3600)
            log.info("NRD ingest exit %s: %s", p.returncode, (p.stderr or p.stdout)[-400:])
            ok = p.returncode == 0
            if not ok:
                self.store.alarm("nrd", f"Daily NRD ingest failed (exit {p.returncode}); retrying in 1 h.")
            else:
                self.store.resolve("nrd")
        except subprocess.TimeoutExpired:
            ok = False
            self.store.alarm("nrd", "Daily NRD ingest took over 3 h and was stopped; retrying in 1 h.")
        self.pipeline.reload_watch = True
        return ok

    # ------------------------------------------------------------------ state ---

    def state(self) -> dict:
        p = self.pipeline
        with p.lock:
            ticker = list(p.ticker)[-40:]
            latest = list(p.latest_flags)
        en = self.enricher.status() if self.enricher else {"enabled": False}
        return {
            "mode": self.mode, "session": self.sid, "pid": os.getpid(), "started": self.started, "written": time.time(),
            "stream_now": p.stream_now, "connected": self.connected, "source": self.url if self.mode == "live" else
            [x.name for x in self.recording], "rate_names_s": round(self.rate(), 1),
            "queue": self.q.qsize(), "reconnects": self.reconnects, "forced_reconnects": self.forced,
            "dropped": self.dropped, "connected_since": self.connected_since,
            "last_message_age_s": None if self.last_msg_wall is None else round(time.time() - self.last_msg_wall, 1),
            "session_totals": dict(p.totals), "ticker": ticker, "latest_flags": latest,
            "dedupe": {"memory_mb": p.recent.memory_mb, "rotations": p.recent.rotations, "fp": p.recent.fp},
            "ct": en, "watch_size": len(p.watch),
            "replay": {**self.replay_info, "speed": self.speed} if self.mode == "replay" else None,
            "pdb": self.list_watch.status() if self.list_watch else None,
        }

    def write_state(self, stopped: bool = False) -> None:
        tmp = self.dir / "state.json.tmp"
        tmp.write_text(json.dumps({**self.state(), "stopped": stopped}, separators=(",", ":")), encoding="utf-8")
        tmp.replace(self.dir / "state.json")

    # ------------------------------------------------------------------ run ---

    def run(self, duration_s: float | None = None) -> None:
        threads = [threading.Thread(target=self._worker, name="live-worker", daemon=True),
                   threading.Thread(target=self._jobs, name="live-jobs", daemon=True)]
        if self.enricher is not None:
            threads.append(threading.Thread(target=self.enricher.run, args=(self.stop,), name="live-ct", daemon=True))
        for th in threads:
            th.start()
        if duration_s:
            threading.Timer(duration_s, self.stop.set).start()
        try:
            if self.mode == "live":
                asyncio.run(self._run_async())
            else:
                self._replay_main()
                if not self.stop.is_set():          # let the worker drain, then stop
                    while not self.q.empty():
                        time.sleep(0.2)
                    self.stop.set()
        except KeyboardInterrupt:
            log.info("interrupted")
        finally:
            self.stop.set()
            for th in threads:
                th.join(timeout=30)
            self.write_state(stopped=True)
            self.store.beat(self.sid, ended=True)
            if self.recorder is not None:
                self.recorder.close()

    async def _run_async(self) -> None:
        main = asyncio.create_task(self._ws_main())
        while not self.stop.is_set() and not main.done():
            await asyncio.sleep(0.5)
        if self._ws is not None:
            await self._ws.close()
        main.cancel()
        try:
            await main
        except (asyncio.CancelledError, Exception):     # noqa: BLE001
            pass


def setup_logging(folder: Path, verbose: bool = False, quiet: bool = False) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    h = logging.handlers.RotatingFileHandler(folder / "collector.log", maxBytes=5_000_000, backupCount=5,
                                             encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(message)s"))
    root = logging.getLogger("doppel.live")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.addHandler(h)
    if not quiet:                       # a background service logs to the rotating file only
        s = logging.StreamHandler()
        s.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        root.addHandler(s)


def running(mode: str, root: Path | None = None, within_s: float = 15) -> dict | None:
    """The state of a collector that wrote its state file in the last ``within_s`` seconds, else None."""
    p = mode_dir(mode, root) / "state.json"
    try:
        st = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return st if time.time() - st.get("written", 0) <= within_s and not st.get("stopped") else None
