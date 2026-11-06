"""Lead time against a public blocklist: did Doppel flag the name before Phishing.Database ACTIVE listed it?

The list is polled (hourly by default; ``If-None-Match`` makes an unchanged list a 304). Each poll has a time,
so for a name Doppel flagged at F:

- **listed_before**: on the latest list Doppel had at F (listed at or before that poll, so before the flag).
- **listed_after**: first on a poll Pk, absent from the previous poll P(k-1), and P(k-1) >= F. It was listed
  between P(k-1) and Pk, so Doppel was ahead by between (P(k-1) - F) and (Pk - F). Both bounds are stored.
- **listed_same_window**: first on Pk with P(k-1) < F: listed between P(k-1) and Pk, which could be before or
  after F. Counted separately, never as a lead.
- **not_listed**: not on any poll so far.

Matching: the exact name, or its registrable owner (the list holds host names; ``login.x.top`` listed means
``x.top`` is listed too). Owners on hosting platforms match exactly only (``x.pages.dev`` is not ``pages.dev``).

The snapshot lives in ``runs/live/<mode>/pdb/``, never in ``data/raw/``: the gate's frozen India slice and its
noise metric read ``data/raw/phishing_database/`` and must not move under it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path

PDB_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
USER_AGENT = "doppel-live/0.1 (research; blocklist lead-time)"
log = logging.getLogger("doppel.live")


def parse_list(text: str) -> set[str]:
    out = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            out.add(line.rstrip("."))
    return out


def parents(names: set[str]) -> set[str]:
    """Every parent of every listed name (2+ labels): ``a.b.x.top`` -> ``b.x.top``, ``x.top``."""
    out = set()
    for n in names:
        parts = n.split(".")
        for i in range(1, len(parts) - 1):
            out.add(".".join(parts[i:]))
    return out


class ListWatch:
    def __init__(self, folder: Path, store, every_h: float = 1.0, url: str = PDB_URL, fetch=None) -> None:
        self.dir = Path(folder) / "pdb"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.store, self.url, self.every_s = store, url, every_h * 3600
        self.fetch = fetch or self._http
        self.names: set[str] = set()
        self.par: set[str] = set()
        self.poll_t: float | None = None
        self.etag: str | None = None
        self.last_try = 0.0
        self._load()

    # ------------------------------------------------------------------ snapshot ---

    def _load(self) -> None:
        snap, info = self.dir / "ACTIVE-latest.txt", self.dir / "latest.json"
        if snap.is_file() and info.is_file():
            try:
                meta = json.loads(info.read_text(encoding="utf-8"))
                self._set(parse_list(snap.read_text(encoding="utf-8", errors="replace")), meta["t"])
                self.etag = meta.get("etag")
            except (OSError, ValueError, KeyError):
                pass

    def _set(self, names: set[str], t: float) -> None:
        self.names, self.par, self.poll_t = names, parents(names), t

    def _http(self, etag: str | None) -> tuple[int, str | None, bytes]:
        req = urllib.request.Request(self.url, headers={"User-Agent": USER_AGENT, **({"If-None-Match": etag} if etag else {})})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:      # noqa: S310 - a fixed public GitHub file
                return r.status, r.headers.get("ETag"), r.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return 304, etag, b""
            raise

    # ------------------------------------------------------------------ polling ---

    def maybe_poll(self, now: float | None = None) -> bool:
        now = now or time.time()
        if self.poll_t is not None and now - self.poll_t < self.every_s:
            return False
        if now - self.last_try < min(600, self.every_s):    # after a failure, retry in 10 min
            return False
        self.last_try = now
        return self.poll(now)

    def poll(self, now: float | None = None) -> bool:
        now = now or time.time()
        try:
            status, etag, body = self.fetch(self.etag)
        except Exception as exc:                            # noqa: BLE001
            log.warning("Phishing.Database poll failed: %s", exc)
            self.store.add_poll("pdb", now, 0, None, False, f"{type(exc).__name__}: {str(exc)[:120]}")
            return False
        if status == 304:                                   # unchanged: this poll still dates the list
            names = self.names
            sha = None
            note = "304 not modified"
        else:
            names = parse_list(body.decode("utf-8", errors="replace"))
            sha = hashlib.sha256(body).hexdigest()
            note = ""
            if len(names) < 1000:                           # a broken download must not "unlist" everything
                self.store.add_poll("pdb", now, len(names), sha, False, "too small; ignored")
                return False
            tmp = self.dir / "ACTIVE-latest.txt.tmp"
            tmp.write_bytes(body)
            tmp.replace(self.dir / "ACTIVE-latest.txt")
        prev_t = self.poll_t
        self._set(names, now)
        self.etag = etag
        (self.dir / "latest.json").write_text(json.dumps({"t": now, "etag": etag, "size": len(names), "sha256": sha}),
                                             encoding="utf-8")
        self.store.add_poll("pdb", now, len(names), sha, True, note)
        n = self.diff(prev_t, now)
        log.info("Phishing.Database poll: %d names (%s); %d catches newly listed", len(names), note or "new", n)
        return True

    def listed(self, name: str, owner: str | None, platform: str | None) -> str | None:
        if name in self.names:
            return "exact"
        if owner and owner != name and not platform and (owner in self.names or owner in self.par):
            return "owner"
        if owner and not platform and name == owner and name in self.par:
            return "owner"
        return None

    def status_at_flag(self, name: str, owner: str | None, platform: str | None) -> dict:
        """Called the moment Doppel flags a name: is it already on the list Doppel has?"""
        if self.poll_t is None:
            return {}
        m = self.listed(name, owner, platform)
        if m:
            return {"pdb_status": "listed_before", "pdb_listed_poll": self.poll_t, "pdb_match": m}
        return {"pdb_status": "not_listed", "pdb_prev_poll": self.poll_t}

    def diff(self, prev_t: float | None, t: float) -> int:
        """After a poll at ``t``: every catch (and watch-list entry) not yet listed, now on the list."""
        n = 0
        for table, key, seen in (("catches", "name", "first_seen"), ("watchlist", "owner", "added")):
            rows = self.store.db.execute(
                f"SELECT {key} AS k, {'owner' if table == 'catches' else 'owner'} AS owner, "
                f"{'platform' if table == 'catches' else 'NULL'} AS platform, {seen} AS f, pdb_status "
                f"FROM {table} WHERE pdb_status IS NULL OR pdb_status='not_listed'").fetchall()
            updates = []
            for r in rows:
                m = self.listed(r["k"], r["owner"], r["platform"])
                if not m:
                    if r["pdb_status"] is None:
                        updates.append(("not_listed", None, prev_t, None, r["k"]))
                    continue
                if prev_t is None:          # the very first poll: no "before" list to compare with
                    st = "listed_before" if r["f"] >= t else "listed_same_window"
                else:
                    st = "listed_after" if prev_t >= r["f"] else "listed_same_window"
                updates.append((st, t, prev_t, m, r["k"]))
                n += 1
            with self.store.lock:
                self.store.db.executemany(
                    f"UPDATE {table} SET pdb_status=?, pdb_listed_poll=?, pdb_prev_poll=?, pdb_match=? WHERE {key}=?",
                    updates)
                self.store.db.commit()
        return n

    def status(self) -> dict:
        return {"poll_t": self.poll_t, "size": len(self.names), "every_h": self.every_s / 3600}
