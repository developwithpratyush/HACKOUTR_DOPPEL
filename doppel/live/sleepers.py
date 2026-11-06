"""The sleeper watch list: newly registered look-alikes, waiting for their first certificate.

Daily: fetch hagezi's 7-day NRD list, keep only names not ingested before, judge them with the real brain (batch
source ``nrd_snapshot``, process pool), and put every flagged one on the watch list with its verdict summary.
The collector then watches the stream: the first time a watched owner (or any name under it) appears in a new
certificate, that's the **ARMED** card: the look-alike is getting ready to go live, usually before the first SMS.

``cert_known``: whether the CT cache already holds a certificate for it when it joins the list (no lookup is
made here: watch-list names are never looked up in bulk). Honest wording on screen: "first certificate *seen by
Doppel* since it joined the watch list".
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import logging
import time
import urllib.request
from pathlib import Path

from doppel.certs import ct
from doppel.live.collector import tricks_of
from doppel.live.store import FLAGGED, Store

NRD_URL = "https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt"
log = logging.getLogger("doppel.live")


def _names(text: str) -> list[str]:
    return [l.strip().lower() for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]


def ingest(folder: Path, url: str = NRD_URL, local: Path | None = None, workers: int | None = None,
           limit: int | None = None) -> dict:
    """Fetch (or read ``local``), diff against everything ingested before, judge the new names, watch the flags."""
    folder = Path(folder)
    nrd_dir = folder / "nrd"
    nrd_dir.mkdir(parents=True, exist_ok=True)
    store = Store(folder / "catches.db")
    t = time.time()
    if local is not None:
        body = Path(local).read_bytes()
        src = f"file:{Path(local).name}"
    else:
        req = urllib.request.Request(url, headers={"User-Agent": "doppel-live/0.1 (research)"})
        with urllib.request.urlopen(req, timeout=300) as r:         # noqa: S310 - a fixed public GitHub file
            body = r.read()
        src = url
    names = _names(body.decode("utf-8", errors="replace"))
    sha = hashlib.sha256(body).hexdigest()
    seen_file = nrd_dir / "ingested.txt.gz"
    seen: set[str] = set()
    if seen_file.is_file():
        with gzip.open(seen_file, "rt", encoding="utf-8") as fh:
            seen = {l.strip() for l in fh if l.strip()}
    new = [n for n in dict.fromkeys(names) if n not in seen]
    if limit:
        new = new[:limit]
    log.info("NRD ingest: %d names in the list, %d new", len(names), len(new))
    from doppel.brain.scan import scan

    verdicts, stats = scan(new, "nrd_snapshot", workers=workers if len(new) > 2000 else 1, keep_labels=FLAGGED,
                           chunksize=512)
    day = dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d")
    rows = []
    for v in verdicts:
        if v["label"] not in FLAGGED:
            continue
        owner = v.get("owner") or v["domain"]
        rec = ct.search(owner, include_subdomains=True, network=False)
        rows.append({"owner": owner, "brand": (v.get("target_brand") or {}).get("id"), "label": v["label"],
                     "risk": v["risk_score"], "tricks": ",".join(tricks_of(v)), "reason": v["reason"], "added": t,
                     "source": f"hagezi nrd7 {day}", "cert_known": int(bool(rec and rec.get("issuances")))})
    added = store.watch_add(rows)
    with gzip.open(seen_file, "at", encoding="utf-8") as fh:
        fh.write("".join(n + "\n" for n in new))
    note = f"{len(names)} listed, {len(new)} new, {len(rows)} flagged, {added} added to the watch list"
    store.add_poll("nrd", t, len(names), sha, True, note + f" ({src})")
    log.info("NRD ingest: %s in %.0f s", note, time.time() - t)
    return {"listed": len(names), "new": len(new), "flagged": len(rows), "added": added,
            "elapsed_s": round(time.time() - t, 1), "by_label": stats["by_label"], "sha256": sha}
