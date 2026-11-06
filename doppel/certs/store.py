"""The certificate cache: every certificate read is saved as JSON with its fetch time, so the demo replays offline.

    data/certs/tls/<host>.json   a live TLS read of a proven-genuine name   {host, fetched_at, source, cert}
    data/certs/ct/<domain>.json  a CT-log search for a domain               {domain, fetched_at, source, issuances, ...}

The cache is committed: certificates are public documents (CT logs publish them), and a fresh clone must replay
the certificate examples with no network. ``DOPPEL_OFFLINE=1`` means "cache only, never the network".
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from pathlib import Path

from doppel.contract import REPO_ROOT

CACHE = REPO_ROOT / "data" / "certs"
_SAFE = re.compile(r"[^a-z0-9.\-_]")


def offline() -> bool:
    """Cache only: ``DOPPEL_OFFLINE=1``, or the network failed in the last minute or two (``doppel.net``)."""
    from doppel import net

    return net.offline()


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _path(kind: str, name: str, root: Path | None = None) -> Path:
    return (root or CACHE) / kind / (_SAFE.sub("_", name.lower()) + ".json")


def load(kind: str, name: str, root: Path | None = None) -> dict | None:
    p = _path(kind, name, root)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save(kind: str, name: str, record: dict, root: Path | None = None) -> Path:
    p = _path(kind, name, root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, indent=1, sort_keys=False), encoding="utf-8")
    tmp.replace(p)
    return p
