"""Deep stage (P8 Page Inspector + Vision AI; P9 Credential Tracker).

Needs the ``deep`` extra (Playwright + Chromium, imagehash, scikit-image) and, for the Vision AI, the ``llm``
extra plus a Gemini key in ``.env``. Without them the brain skips the Deep stage and says why.
"""

from __future__ import annotations

from functools import lru_cache


@lru_cache(maxsize=4096)
def _family(reg_id: int, host: str):
    from doppel.address import read_address
    from doppel.family import check_family

    r = read_address(host)
    return r, check_family(r, _REG[reg_id])


_REG: dict = {}


def in_family_of(reg, brand_id: str, host: str, certs: bool = False) -> bool:
    """True if ``host`` is proven to belong to ``brand_id``'s genuine family: the Family Verifier's H1 facts, and with
    ``certs`` also the SAN links from family auto-discovery (P11; never a user-content host or a platform tenant)."""
    _REG[id(reg)] = reg
    try:
        r, fam = _family(id(reg), host.lower())
    except ValueError:
        return False
    if fam.genuine:
        return bool(fam.brand is not None and fam.brand.id == brand_id)
    if not certs or fam.status == "user_content" or (r.hosting_platform and r.host != r.hosting_platform):
        return False
    from doppel.certs.index import load_index

    hit = load_index().lookup(r.host)
    return bool(hit and hit["brand"] == brand_id)
