"""Certificate recipes, from cached CT records only (``data/certs/ct/``; no lookups here).

The recipe of a domain is the set of SAN shapes across its certificates, with names abstracted:
``A`` apex, ``W`` its wildcard, ``S3`` a 3-letter subdomain, ``WS3`` that subdomain's wildcard, ``www``.
The e-Challan kit issues ``{A+W, A+S3+WS3}`` for every domain (one random 3-letter host per domain).
Plus the CA set and the time of the first certificate.
"""

from __future__ import annotations

import datetime as dt

from doppel.certs import ct


def _shape(san: str, owner: str) -> str | None:
    san = san.lower()
    if san == owner:
        return "A"
    if san == "*." + owner:
        return "W"
    if not san.endswith("." + owner):
        return None
    sub = san[: -len(owner) - 1]
    wild = sub.startswith("*.")
    sub = sub[2:] if wild else sub
    if sub == "www":
        return "Wwww" if wild else "www"
    first = sub.split(".")[0]
    return ("WS" if wild else "S") + str(len(first)) + ("+" if "." in sub else "")


def _ts(s: str) -> float:
    return dt.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp()


def recipe(owner: str) -> dict | None:
    """The recipe of ``owner`` from the CT cache, or None when it was never looked up (or has no certificate)."""
    rec = ct.search(owner, include_subdomains=True, network=False)
    if not rec or not rec.get("issuances"):
        return None
    shapes, issuers, firsts, shas, sans = set(), set(), [], set(), set()
    for c in rec["issuances"]:
        s = tuple(sorted({x for x in (_shape(n, owner) for n in c.get("sans", [])) if x}))
        if s:
            shapes.add("+".join(s))
        issuers.add((c.get("issuer") or {}).get("o") or "?")
        if c.get("not_before"):
            firsts.append(_ts(c["not_before"]))
        if c.get("sha256"):
            shas.add(c["sha256"])
        sans.update(n.lower().lstrip("*.") for n in c.get("sans", []))
    subs = sorted({n[: -len(owner) - 1].split(".")[-1] for n in sans if n.endswith("." + owner)} - {"www"})
    return {"owner": owner, "shapes": sorted(shapes), "issuers": sorted(issuers), "first": min(firsts) if firsts else None,
            "count": len(rec["issuances"]), "shas": sorted(shas), "sans": sorted(sans), "subdomains": subs,
            "fetched_at": rec.get("fetched_at")}


def same_recipe(a: dict, b: dict, window_h: float = 96) -> float:
    """Edge weight for two recipes: 0 (different), 0.6 (same shape, CAs overlap, within the window), 0.9 (within 1 h)."""
    if not a["shapes"] or a["shapes"] != b["shapes"] or a["first"] is None or b["first"] is None:
        return 0.0
    ia, ib = set(a["issuers"]), set(b["issuers"])
    if len(ia & ib) / len(ia | ib) < 0.5:
        return 0.0
    gap = abs(a["first"] - b["first"]) / 3600
    if gap > window_h:
        return 0.0
    return 0.9 if gap <= 1 else 0.6
