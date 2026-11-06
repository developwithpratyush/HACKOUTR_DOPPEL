"""Parse certstream messages. Both formats, because the public server switched between them in one night
(2026-11-06) and a collector that knew only the old one silently caught 0 names (finale-examples §3.5).

- ``certificate_update`` (the original certstream): ``data.leaf_cert.all_domains``, ``data.seen``,
  ``leaf_cert.not_before``, ``leaf_cert.issuer.O``. One message = one certificate log entry.
- ``dns_entries`` (``wss://api.certstream.dev/`` since 2026-11-06): ``data`` is the list of names. One message =
  one log entry, names only (no issuer, no dates): certificate facts come from CT search, flagged names only.
- ``heartbeat``: liveness only.

Anything else is ``unknown`` and counted, so the watchdog can say "the format changed" instead of going quiet.
"""

from __future__ import annotations

from dataclasses import dataclass, field

KNOWN = ("certificate_update", "dns_entries", "heartbeat")


@dataclass
class Entry:
    kind: str                         # certificate_update | dns_entries | heartbeat | unknown
    names: list[str] = field(default_factory=list)
    seen: float | None = None         # the server's own timestamp, when the format has one
    not_before: float | None = None
    issuer: str | None = None
    raw_type: str | None = None       # the message_type as received (for the unknown-format alarm)


def clean(name: str) -> str | None:
    """A lower-case host name, wildcard label removed; None for junk (IPs, empty, no dot)."""
    if not isinstance(name, str):
        return None
    n = name.strip().lower().rstrip(".")
    while n.startswith("*."):
        n = n[2:]
    if not n or "." not in n or " " in n or len(n) > 253:
        return None
    if n.replace(".", "").isdigit():            # an IPv4 SAN
        return None
    return n


def _names(items) -> list[str]:
    out, seen = [], set()
    for x in items or []:
        n = clean(x)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def parse(msg: dict) -> Entry:
    mt = msg.get("message_type") if isinstance(msg, dict) else None
    if mt == "heartbeat":
        return Entry("heartbeat", raw_type=mt)
    if mt == "dns_entries":
        data = msg.get("data")
        if isinstance(data, dict):                     # tolerate {"data": {"dns_entries": [...]}} too
            data = data.get("dns_entries") or data.get("all_domains")
        return Entry("dns_entries", _names(data if isinstance(data, list) else []), raw_type=mt)
    if mt == "certificate_update":
        data = msg.get("data") or {}
        leaf = data.get("leaf_cert") or {}
        issuer = leaf.get("issuer") or {}
        nb = leaf.get("not_before")
        return Entry("certificate_update", _names(leaf.get("all_domains")),
                     seen=_num(data.get("seen")), not_before=_num(nb),
                     issuer=issuer.get("O") or issuer.get("CN") if isinstance(issuer, dict) else None, raw_type=mt)
    return Entry("unknown", raw_type=str(mt)[:40] if mt is not None else None)


def _num(x) -> float | None:
    try:
        return float(x) if x is not None else None
    except (TypeError, ValueError):
        return None
