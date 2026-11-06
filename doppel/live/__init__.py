"""Live Hunt (P12, SIG): the world's new certificates, judged as they appear.

    certstream (CT logs, a third party) -> dedupe -> naive keyword baseline || Doppel (Quick -> Standard)
        -> catch store (SQLite) -> CT facts for flagged names only (capped) -> lead time vs Phishing.Database
    hagezi NRD (daily) -> sleeper watch list -> ARMED when a watched name shows up in the stream

Doppel never contacts a suspect here either: names come from CT logs, certificate facts from CT search,
the reference list from a public GitHub file. Modules:

- ``messages``  parse both stream formats (``certificate_update``, ``dns_entries``)
- ``dedupe``    a rotating Bloom filter (unique names over the last few hours, in ~60 MB)
- ``naive``     the keyword baseline (brand substrings), run on the same names
- ``store``     the catch store: catches, per-minute counters, watch list, alarms, list polls
- ``collector`` the service: source (websocket or a recording) -> pipeline -> store, recorder, watchdog
- ``enrich``    CT lookups for flagged names, highest priority first, under a daily cap
- ``leadtime``  Phishing.Database ACTIVE polls: was it listed before we flagged it, or after (and how long)?
- ``sleepers``  daily NRD ingest: flagged look-alikes go on the watch list
- ``report``    ``docs/eval/p12-live.md``, regenerated from the store
"""

from pathlib import Path

from doppel.contract import REPO_ROOT

LIVE_DIR = REPO_ROOT / "runs" / "live"
MODES = ("live", "replay")


def mode_dir(mode: str, root: Path | None = None) -> Path:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    return (root or LIVE_DIR) / mode
