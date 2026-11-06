"""The catch store: one SQLite file per mode (``runs/live/live/catches.db``, ``runs/live/replay/catches.db``).

    sessions   one row per collector run: started, last heartbeat, ended (hours watched = sum of the spans)
    minutes    per-minute counters: certificates, names, unique names, Doppel flags, naive alerts, overlap, drops
    catches    every name Doppel flagged: first seen (stream time), verdict (zlib JSON, for the Decision Trace),
               the keyword baseline's view, CT facts (flagged names only), and its Phishing.Database status
    genuine    names proven genuine live (e.g. Google's own ``*.vertexai.goog``): the other side of the queue
    watchlist  sleepers: NRD look-alikes Doppel flags, waiting for their first certificate
    armings    a watched name showed up in the stream: the ARMED card
    alarms     the stream went silent, slowed below the floor, or changed format
    polls      Phishing.Database (and NRD) fetches, with their time: the lead-time clock
    ct_budget  CT lookups spent per UTC day (the SSLMate key has strict limits)

WAL mode: the collector writes while the API reads. Every thread opens its own ``Store``.
"""

from __future__ import annotations

import json
import functools
import sqlite3
import threading
import time
import zlib
from pathlib import Path

FLAGGED = ("needs_review", "phishing", "sleeper")

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, mode TEXT, source TEXT, started REAL, last_beat REAL,
    ended REAL, note TEXT);
CREATE TABLE IF NOT EXISTS minutes(t INTEGER PRIMARY KEY, certs INT DEFAULT 0, names INT DEFAULT 0,
    uniq INT DEFAULT 0, flags INT DEFAULT 0, naive INT DEFAULT 0, genuine INT DEFAULT 0, both_hit INT DEFAULT 0,
    naive_only INT DEFAULT 0, doppel_only INT DEFAULT 0, dropped INT DEFAULT 0, errors INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS catches(name TEXT PRIMARY KEY, owner TEXT, brand TEXT, label TEXT, risk REAL,
    tricks TEXT, reason TEXT, first_seen REAL, last_seen REAL, times_seen INT DEFAULT 1, stream_issuer TEXT,
    stream_not_before REAL, naive TEXT, platform TEXT, verdict BLOB, judged_at REAL,
    ct_status TEXT, ct_checked REAL, ct_source TEXT, ct_count INT, ct_first TEXT, ct_cert_not_before TEXT,
    ct_issuers TEXT, ct_armed INT, ct_org TEXT,
    pdb_status TEXT, pdb_prev_poll REAL, pdb_listed_poll REAL, pdb_match TEXT);
CREATE INDEX IF NOT EXISTS catches_first ON catches(first_seen);
CREATE INDEX IF NOT EXISTS catches_owner ON catches(owner);
CREATE TABLE IF NOT EXISTS genuine(name TEXT PRIMARY KEY, brand TEXT, proof TEXT, first_seen REAL);
CREATE TABLE IF NOT EXISTS watchlist(owner TEXT PRIMARY KEY, brand TEXT, label TEXT, risk REAL, tricks TEXT,
    reason TEXT, added REAL, source TEXT, cert_known INT, armed_at REAL, armed_name TEXT,
    pdb_status TEXT, pdb_prev_poll REAL, pdb_listed_poll REAL, pdb_match TEXT);
CREATE TABLE IF NOT EXISTS armings(id INTEGER PRIMARY KEY, owner TEXT, name TEXT, t REAL, watch_added REAL,
    brand TEXT, risk REAL, label TEXT);
CREATE TABLE IF NOT EXISTS alarms(id INTEGER PRIMARY KEY, kind TEXT, t REAL, message TEXT, resolved REAL);
CREATE TABLE IF NOT EXISTS polls(id INTEGER PRIMARY KEY, list TEXT, t REAL, size INT, sha256 TEXT, ok INT,
    note TEXT);
CREATE TABLE IF NOT EXISTS ct_budget(day TEXT PRIMARY KEY, used INT DEFAULT 0);
"""

MINUTE_COLS = ("certs", "names", "uniq", "flags", "naive", "genuine", "both_hit", "naive_only", "doppel_only",
               "dropped", "errors")


def _locked(fn):
    """One connection, several threads (worker, jobs, watchdog): one statement group at a time."""
    @functools.wraps(fn)
    def wrap(self, *a, **kw):
        with self.lock:
            return fn(self, *a, **kw)
    return wrap


def pack(verdict: dict) -> bytes:
    return zlib.compress(json.dumps(verdict, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), 6)


def unpack(blob: bytes | None) -> dict | None:
    return json.loads(zlib.decompress(blob).decode("utf-8")) if blob else None


class Store:
    def __init__(self, path: Path, readonly: bool = False) -> None:
        self.path = Path(path)
        self.lock = threading.RLock()
        if readonly:
            self.db = sqlite3.connect(f"file:{self.path.as_posix()}?mode=ro", uri=True, timeout=10,
                                      check_same_thread=False)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.db = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.executescript(SCHEMA)
            self.db.commit()
        self.db.row_factory = sqlite3.Row

    @_locked
    def close(self) -> None:
        self.db.close()

    # ------------------------------------------------------------------ meta / sessions ---

    @_locked
    def set_meta(self, key: str, value) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, json.dumps(value)))
        self.db.commit()

    @_locked
    def meta(self, key: str, default=None):
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(r[0]) if r else default

    @_locked
    def open_session(self, mode: str, source: str, note: str = "", t: float | None = None) -> int:
        t = t or time.time()
        cur = self.db.execute("INSERT INTO sessions(mode,source,started,last_beat,note) VALUES(?,?,?,?,?)",
                              (mode, source, t, t, note))
        self.db.commit()
        return cur.lastrowid

    @_locked
    def beat(self, sid: int, t: float | None = None, ended: bool = False) -> None:
        t = t or time.time()
        self.db.execute("UPDATE sessions SET last_beat=?" + (", ended=?" if ended else "") + " WHERE id=?",
                        (t, t, sid) if ended else (t, sid))
        self.db.commit()

    # ------------------------------------------------------------------ counters ---

    @_locked
    def add_minute(self, t_min: int, counts: dict) -> None:
        cols = [c for c in MINUTE_COLS if counts.get(c)]
        if not cols:
            self.db.execute("INSERT OR IGNORE INTO minutes(t) VALUES(?)", (t_min,))
        else:
            self.db.execute(f"INSERT INTO minutes(t,{','.join(cols)}) VALUES(?{',?' * len(cols)}) "
                            f"ON CONFLICT(t) DO UPDATE SET " + ",".join(f"{c}={c}+excluded.{c}" for c in cols),
                            (t_min, *[counts[c] for c in cols]))
        self.db.commit()

    @_locked
    def totals(self) -> dict:
        r = self.db.execute(f"SELECT COUNT(*) AS minutes, {','.join(f'COALESCE(SUM({c}),0) AS {c}' for c in MINUTE_COLS)} "
                            "FROM minutes").fetchone()
        return dict(r)

    @_locked
    def minutes(self, since: float | None = None) -> list[dict]:
        q = "SELECT * FROM minutes" + (" WHERE t>=?" if since else "") + " ORDER BY t"
        return [dict(r) for r in self.db.execute(q, (int(since // 60),) if since else ())]

    @_locked
    def hours_watched(self) -> float:
        r = self.db.execute("SELECT COALESCE(SUM(last_beat-started),0) FROM sessions").fetchone()
        return round(r[0] / 3600, 3)

    # ------------------------------------------------------------------ catches ---

    @_locked
    def upsert_catch(self, row: dict, verdict: dict | None) -> bool:
        """Insert a new catch (True) or update the last-seen/verdict of a known one (False)."""
        old = self.db.execute("SELECT first_seen FROM catches WHERE name=?", (row["name"],)).fetchone()
        if old is None:
            cols = list(row) + ["verdict", "judged_at"]
            self.db.execute(f"INSERT INTO catches({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                            (*row.values(), pack(verdict) if verdict else None, time.time()))
            self.db.commit()
            return True
        self.db.execute("UPDATE catches SET last_seen=?, times_seen=times_seen+1 WHERE name=?",
                        (row["last_seen"], row["name"]))
        self.db.commit()
        return False

    @_locked
    def update_catch(self, name: str, verdict: dict | None = None, **fields) -> None:
        if verdict is not None:
            fields.update(verdict=pack(verdict), judged_at=time.time(), label=verdict["label"],
                          risk=verdict["risk_score"], reason=verdict["reason"])
        if not fields:
            return
        self.db.execute(f"UPDATE catches SET {','.join(f'{k}=?' for k in fields)} WHERE name=?",
                        (*fields.values(), name))
        self.db.commit()

    @_locked
    def catch(self, name: str) -> dict | None:
        r = self.db.execute("SELECT * FROM catches WHERE name=?", (name,)).fetchone()
        if r is None:
            return None
        d = dict(r)
        d["verdict"] = unpack(d["verdict"])
        return d

    @_locked
    def recent_catches(self, limit: int = 40, offset: int = 0, brand: str | None = None,
                       label: str | None = None) -> list[dict]:
        where, args = [], []
        if brand:
            where.append("brand=?")
            args.append(brand)
        if label:
            where.append("label=?")
            args.append(label)
        q = ("SELECT * FROM catches" + (" WHERE " + " AND ".join(where) if where else "") +
             " ORDER BY first_seen DESC LIMIT ? OFFSET ?")
        out = []
        for r in self.db.execute(q, (*args, limit, offset)):
            d = dict(r)
            d.pop("verdict", None)
            out.append(d)
        return out

    @_locked
    def count_catches(self) -> dict:
        rows = self.db.execute("SELECT label, COUNT(*) FROM catches GROUP BY label").fetchall()
        return {r[0]: r[1] for r in rows}

    @_locked
    def add_genuine(self, name: str, brand: str | None, proof: str | None, t: float) -> None:
        self.db.execute("INSERT OR IGNORE INTO genuine VALUES(?,?,?,?)", (name, brand, proof, t))
        self.db.commit()

    # ------------------------------------------------------------------ watch list / arming ---

    @_locked
    def watch_add(self, rows: list[dict]) -> int:
        n = 0
        for row in rows:
            cur = self.db.execute(f"INSERT OR IGNORE INTO watchlist({','.join(row)}) VALUES({','.join('?' * len(row))})",
                                  tuple(row.values()))
            n += cur.rowcount
        self.db.commit()
        return n

    @_locked
    def watched_owners(self) -> set[str]:
        return {r[0] for r in self.db.execute("SELECT owner FROM watchlist WHERE armed_at IS NULL")}

    @_locked
    def arm(self, owner: str, name: str, t: float, label: str | None, risk: float | None) -> dict | None:
        w = self.db.execute("SELECT * FROM watchlist WHERE owner=? AND armed_at IS NULL", (owner,)).fetchone()
        if w is None:
            return None
        self.db.execute("UPDATE watchlist SET armed_at=?, armed_name=? WHERE owner=?", (t, name, owner))
        self.db.execute("INSERT INTO armings(owner,name,t,watch_added,brand,risk,label) VALUES(?,?,?,?,?,?,?)",
                        (owner, name, t, w["added"], w["brand"], risk if risk is not None else w["risk"], label))
        self.db.commit()
        return dict(w)

    @_locked
    def armings(self, limit: int = 20) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM armings ORDER BY t DESC LIMIT ?", (limit,))]

    @_locked
    def watch_stats(self) -> dict:
        r = self.db.execute("SELECT COUNT(*), SUM(armed_at IS NOT NULL), SUM(cert_known=1) FROM watchlist").fetchone()
        return {"watched": r[0] or 0, "armed": r[1] or 0, "cert_known_at_add": r[2] or 0}

    # ------------------------------------------------------------------ alarms ---

    @_locked
    def alarm(self, kind: str, message: str, t: float | None = None) -> int | None:
        """Open an alarm of this kind unless one is already open. Returns its id when new."""
        if self.db.execute("SELECT 1 FROM alarms WHERE kind=? AND resolved IS NULL", (kind,)).fetchone():
            return None
        cur = self.db.execute("INSERT INTO alarms(kind,t,message) VALUES(?,?,?)", (kind, t or time.time(), message))
        self.db.commit()
        return cur.lastrowid

    @_locked
    def resolve(self, kind: str, t: float | None = None) -> int:
        cur = self.db.execute("UPDATE alarms SET resolved=? WHERE kind=? AND resolved IS NULL", (t or time.time(), kind))
        self.db.commit()
        return cur.rowcount

    @_locked
    def alarms(self, open_only: bool = False, limit: int = 50) -> list[dict]:
        q = "SELECT * FROM alarms" + (" WHERE resolved IS NULL" if open_only else "") + " ORDER BY t DESC LIMIT ?"
        return [dict(r) for r in self.db.execute(q, (limit,))]

    # ------------------------------------------------------------------ polls / CT budget ---

    @_locked
    def add_poll(self, lst: str, t: float, size: int, sha: str | None, ok: bool, note: str = "") -> None:
        self.db.execute("INSERT INTO polls(list,t,size,sha256,ok,note) VALUES(?,?,?,?,?,?)",
                        (lst, t, size, sha, int(ok), note))
        self.db.commit()

    @_locked
    def polls(self, lst: str, ok_only: bool = True) -> list[dict]:
        q = "SELECT * FROM polls WHERE list=?" + (" AND ok=1" if ok_only else "") + " ORDER BY t"
        return [dict(r) for r in self.db.execute(q, (lst,))]

    @_locked
    def ct_used(self, day: str) -> int:
        r = self.db.execute("SELECT used FROM ct_budget WHERE day=?", (day,)).fetchone()
        return r[0] if r else 0

    @_locked
    def ct_spend(self, day: str) -> None:
        self.db.execute("INSERT INTO ct_budget(day,used) VALUES(?,1) ON CONFLICT(day) DO UPDATE SET used=used+1", (day,))
        self.db.commit()
