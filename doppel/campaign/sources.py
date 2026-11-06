"""Where Campaign Radar's flagged domains come from.

- ``from_raw(path, tag)``: any list of names (the NRD snapshot, Phishing.Database ACTIVE, a pasted list), judged
  by the real brain (batch source, process pool); only flagged verdicts become items. This is "from raw input":
  nothing is pre-selected by hand.
- ``from_live(db)``: the P12 catch store (live flags) and its sleeper watch list (NRD flags), already judged.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

FLAGGED = ("needs_review", "phishing", "sleeper")


def _tricks(v: dict) -> str:
    return ",".join(dict.fromkeys(e["finding"] for e in v.get("evidence", [])
                                  if e["tool"] == "trick_detector" and e["points_to"] == "phishing"))


def from_raw(path: Path, tag: str, workers: int | None = None, limit: int | None = None) -> tuple[list[dict], dict]:
    from doppel.brain.scan import _from_file, scan

    names = _from_file(Path(path))
    if limit:
        names = names[:limit]
    verdicts, stats = scan(names, "nrd_snapshot", workers=workers if len(names) > 2000 else 1, keep_labels=FLAGGED,
                           chunksize=512)
    items = [{"name": v["domain"], "owner": v.get("owner") or v["domain"], "brand": (v.get("target_brand") or {}).get("id"),
              "label": v["label"], "risk": v["risk_score"], "tricks": _tricks(v), "source": tag, "first_seen": None}
             for v in verdicts if v["label"] in FLAGGED]
    return items, {"source": tag, "file": str(path), "names": len(names), "flagged": len(items),
                   "elapsed_s": round(stats["elapsed_ms"] / 1000, 1)}


def from_live(db: Path) -> tuple[list[dict], dict]:
    if not Path(db).is_file():
        return [], {"source": "live", "flagged": 0}
    con = sqlite3.connect(f"file:{Path(db).as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    items = [{"name": r["name"], "owner": r["owner"], "brand": r["brand"], "label": r["label"], "risk": r["risk"],
              "tricks": r["tricks"], "source": "live", "first_seen": r["first_seen"]}
             for r in con.execute("SELECT name, owner, brand, label, risk, tricks, first_seen FROM catches")]
    watch = [{"name": r["owner"], "owner": r["owner"], "brand": r["brand"], "label": r["label"], "risk": r["risk"],
              "tricks": r["tricks"], "source": "nrd", "first_seen": r["added"]}
             for r in con.execute("SELECT owner, brand, label, risk, tricks, added FROM watchlist")]
    con.close()
    return items + watch, {"source": "live", "flagged": len(items), "watchlist": len(watch)}
