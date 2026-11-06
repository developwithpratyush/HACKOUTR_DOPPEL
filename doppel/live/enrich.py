"""CT facts for flagged names only, under a daily cap (the SSLMate key has strict limits, O46).

When Doppel flags a name in the stream, its registrable owner goes into a pending pool. One lookup every
``86400 / daily_cap`` seconds (so the cap lasts all day) takes the **highest-priority** pending owner flagged in the
last 12 hours:

    priority = risk + 0.3 (an Indian brand, not Google) + 0.5 (it armed a watched sleeper) + 0.2 (phishing)
               + 0.2 (a clear imitation shape: combosquat, level-squat, hidden letters, trust-signal mimicry)
               - 0.4 (only a typo of a name of 5 letters or fewer: the noisiest class, O14, e.g. ``ubi.dev``)

The first lookup of a run waits one full gap, so it picks the best of a full pool (and a restart never bursts).

``doppel.certs.ct.search`` answers from the cache when it can (no quota), else SSLMate (the key in ``.env``),
else crt.sh. After the lookup the name is judged again (``ct_feed``): ``ct_history`` now reads the cached record,
so the verdict gains C16 (validated organisation) and C17 (``armed`` / ``established_certificates``). The catch
gets the facts the Live Hunt card shows: how many certificates, the first one, and the not-before of the
certificate that names it (so "issued N seconds before it reached the stream").

Hosting-platform tenants (``x.pages.dev``) are never looked up: their certificate is the platform's wildcard.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import threading
import time
from pathlib import Path

from doppel.certs import ct
from doppel.certs.facts import san_covers
from doppel.live.store import Store

log = logging.getLogger("doppel.live")
FRESH_S = 12 * 3600
MIN_GAP_S = 60
CLEAR_SHAPES = {"combosquat", "level_squat", "homoglyph", "trust_signal_mimicry", "twin_letters"}
RESERVE = 10                       # stop for the day when SSLMate says fewer lookups than this remain


def _ts(s: str | None) -> float | None:
    if not s:
        return None
    try:
        return dt.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        return None


def facts(rec: dict, name: str, seen: float | None) -> dict:
    """What the card shows, from a CT record: count, first certificate, issuers, the cert naming this name."""
    certs = rec.get("issuances", [])
    nbs = [c["not_before"] for c in certs if c.get("not_before")]
    covering = [c for c in certs if any(san_covers(s, name) for s in c.get("sans", [])) and c.get("not_before")]
    if seen is not None:            # the certificate that put this name in the stream: issued at or before it
        before = [c for c in covering if (_ts(c["not_before"]) or 0) <= seen + 300]
        covering = before or covering
    pick = max(covering, key=lambda c: c["not_before"]) if covering else None
    issuers: dict[str, int] = {}
    for c in certs:
        o = (c.get("issuer") or {}).get("o") or "?"
        issuers[o] = issuers.get(o, 0) + 1
    orgs = sorted({(c.get("subject") or {}).get("o") for c in certs if (c.get("subject") or {}).get("o")})
    return {"ct_count": len(certs), "ct_first": min(nbs) if nbs else None,
            "ct_cert_not_before": pick["not_before"] if pick else None,
            "ct_issuers": json.dumps(issuers), "ct_org": "; ".join(orgs) or None,
            "ct_source": rec.get("source"), "ct_checked": _ts(rec.get("fetched_at")) or time.time()}


class Enricher:
    def __init__(self, db_path: Path, rejudge, daily_cap: int = 20, network: bool = True, search=None,
                 clock=time.time) -> None:
        self.db_path, self.rejudge = db_path, rejudge
        self.cap = max(0, daily_cap)
        self.gap = max(MIN_GAP_S, 86400 / self.cap) if self.cap else float("inf")
        self.network = network
        self.search = search or ct.search
        self.clock = clock
        self.pending: dict[str, tuple[float, float, str]] = {}      # owner -> (priority, flagged at, name)
        self.ready: list[str] = []                                  # cached already: re-judge, no quota
        self.lock = threading.Lock()
        self.last_lookup = clock()            # the first lookup waits one gap: a full pool to choose from
        self.paused_until = 0.0
        self.done = 0
        self.last: dict | None = None
        self.store: Store | None = None

    @staticmethod
    def priority(row: dict, armed: bool) -> float:
        p = float(row.get("risk") or 0)
        if row.get("brand") and row["brand"] != "google":
            p += 0.3
        if armed:
            p += 0.5
        if row.get("label") == "phishing":
            p += 0.2
        tricks = set(filter(None, (row.get("tricks") or "").split(",")))
        if tricks & CLEAR_SHAPES:
            p += 0.2
        core = (row.get("owner") or "").split(".")[0]
        if tricks and tricks <= {"typo", "brand_closeness", "not_in_family"} and len(core) <= 5:
            p -= 0.4
        return p

    def offer(self, row: dict, armed: bool = False) -> None:
        """Called by the pipeline for every new catch (worker thread): cheap, never blocks on the network."""
        owner = row["owner"]
        if row.get("platform"):
            self._mark(row["name"], ct_status="skipped_platform")
            return
        with self.lock:
            if ct.search(owner, include_subdomains=True, network=False) is not None:
                self.ready.append(row["name"])
                return
            pr = self.priority(row, armed)
            old = self.pending.get(owner)
            if old is None or pr > old[0]:
                self.pending[owner] = (pr, row["first_seen"], row["name"])
        self._mark(row["name"], ct_status="queued")

    def _mark(self, name: str, **fields) -> None:
        if self.store is None:
            self.store = Store(self.db_path)
        self.store.update_catch(name, **fields)

    def _day(self) -> str:
        return dt.datetime.fromtimestamp(self.clock(), dt.timezone.utc).strftime("%Y-%m-%d")

    def status(self) -> dict:
        used = self.store.ct_used(self._day()) if self.store else 0
        return {"enabled": self.cap > 0, "daily_cap": self.cap, "used_today": used, "pending": len(self.pending),
                "every_s": None if self.cap == 0 else round(self.gap), "paused_until": self.paused_until or None,
                "done": self.done, "last": self.last}

    def _apply(self, name: str, seen: float | None, rec: dict | None, status: str) -> None:
        fields = {"ct_status": status}
        if rec is not None:
            fields.update(facts(rec, name, seen))
        v = self.rejudge(name)
        if v is not None:
            fields["ct_armed"] = int(any(e["finding"] == "armed" for e in v.get("evidence", [])))
        self.store.update_catch(name, verdict=v, **fields)
        self.done += 1
        self.last = {"name": name, "status": status, "t": self.clock(), "count": fields.get("ct_count")}

    def step(self) -> str | None:
        """One unit of work. Returns what happened (for tests and the log)."""
        if self.store is None:
            self.store = Store(self.db_path)
        with self.lock:
            name = self.ready.pop(0) if self.ready else None
        if name is not None:
            c = self.store.catch(name)
            owner = c["owner"] if c else name
            self._apply(name, c["first_seen"] if c else None, ct.search(owner, network=False), "cached")
            return "cached"
        now = self.clock()
        if not self.network or self.cap == 0 or now < self.paused_until or now - self.last_lookup < self.gap:
            return None
        day = self._day()
        if self.store.ct_used(day) >= self.cap:
            return None
        with self.lock:
            fresh = {o: v for o, v in self.pending.items() if now - v[1] <= FRESH_S}
            self.pending = fresh
            if not fresh:
                return None
            owner = max(fresh, key=lambda o: fresh[o][0])
            _, seen, name = self.pending.pop(owner)
        self.last_lookup = now
        try:
            rec = self.search(owner, include_subdomains=True, network=True)
            looked_up = rec is not None and rec.get("fetched_at") and _ts(rec["fetched_at"]) >= now - 120
            if looked_up:
                self.store.ct_spend(day)
            rem = (rec or {}).get("rate_limit_remaining")
            if rem is not None and str(rem).isdigit() and int(rem) < RESERVE:
                self.paused_until = now + 3600
                log.warning("SSLMate says %s lookups remain: pausing CT lookups for an hour", rem)
            self._apply(name, seen, rec, "looked_up" if looked_up else "cached")
            log.info("CT %s: %s (%s certificates)", owner, rec.get("source") if rec else "-",
                     len((rec or {}).get("issuances", [])))
            return "looked_up"
        except ct.RateLimited as exc:
            self.paused_until = now + 3600
            self.store.alarm("ct_quota", f"CT search rate-limited ({exc}); lookups paused for an hour.")
            self._mark(name, ct_status="rate_limited")
            return "rate_limited"
        except Exception as exc:                              # noqa: BLE001
            log.warning("CT lookup for %s failed: %s", owner, exc)
            self._mark(name, ct_status="error")
            return "error"

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                did = self.step()
            except Exception:                                 # noqa: BLE001
                log.exception("enricher error")
                did = None
            if did is None:
                stop.wait(2.0)
