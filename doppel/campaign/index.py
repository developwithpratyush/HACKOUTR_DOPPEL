"""The brain's view of Campaign Radar: ``data/campaigns/index.json`` (owner -> campaign), and the C18 evidence.

Weak and bounded on purpose: at most +0.5 log-odds (``strength = weak``). A name in a campaign is still judged by
its own evidence; membership only moves it up the review queue. Rebuild the index with ``doppel campaigns``.
"""

from __future__ import annotations

import json
from pathlib import Path

from doppel.campaign import CAMPAIGN_DIR
from doppel.evidence import Ids, brand_ref, evidence

CERT_LINKS = {"shared_cert", "cert_recipe"}
WORDS = {"shared_cert": "a shared certificate", "cert_recipe": "the same certificate recipe",
         "naming_template": "the same naming template"}


def load_campaigns(path: Path | None = None) -> dict:
    p = path or CAMPAIGN_DIR / "index.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("members", {})
    except (OSError, ValueError):
        return {}


def campaign_radar(r, hit: dict, brand, ids: Ids | None = None) -> list[dict]:
    ids = ids or Ids()
    links = hit.get("links", [])
    by_cert = bool(CERT_LINKS & set(links))
    how = " and ".join(WORDS[k] for k in ("shared_cert", "cert_recipe", "naming_template") if k in links)
    peers = ", ".join(hit.get("peers", [])[:3])
    tpl = f" (template {hit['template']})" if hit.get("template") else ""
    return [evidence(ids, tool="campaign_radar", stage="standard", criterion="C18", finding="campaign_member",
                     points_to="phishing", strength="weak", score=1.0 if by_cert else 0.6, target_brand=brand_ref(brand),
                     summary=(f"Part of a campaign of {hit['size']} domains linked by {how}{tpl}: {peers}. "
                              "Higher review priority; a campaign never decides the label on its own."),
                     campaign_id=hit["campaign"], size=hit["size"], links=links, strength_of_link=hit.get("strength"),
                     template=hit.get("template"), peers=hit.get("peers", []), index="data/campaigns/index.json")]
