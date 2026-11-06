"""Ending type (C6): how often an ending (TLD) carries phishing in PhiUSIIL. A **weak** hint only.

    python -m doppel.tricks.tld_risk      # rebuilds doppel/tricks/tld_risk.json from data/raw/phiusiil

risk(tld) = (phishing rows + k * p0) / (all rows + k): the phishing share, smoothed towards the
dataset's base rate p0 with k = 20 pseudo-rows, so a TLD seen twice can't reach 1.0.

Honest limits, stated in the evidence: PhiUSIIL's base rate (42.8% phishing) is nothing like the real
world's, and its legitimate rows are popular `https://www.` homepages, so ordinary endings of small
sites look riskier than they are. ``.app``/``.dev`` are high because of free hosting (web.app,
pages.dev), which the Address Reader already explains. This can never decide a verdict alone.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from functools import lru_cache
from pathlib import Path

from doppel.contract import REPO_ROOT

OUT = Path(__file__).resolve().parent / "tld_risk.json"
SOURCE = REPO_ROOT / "data" / "raw" / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv"
K = 20
MIN_ROWS = 10          # TLDs seen fewer times aren't stored
ABUSED = 0.85          # risk at or above this, with at least ABUSED_MIN_ROWS rows, is reported
ABUSED_MIN_ROWS = 25


def build() -> dict:
    csv.field_size_limit(10_000_000)
    phish, legit = Counter(), Counter()
    with SOURCE.open(encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            (legit if row["label"] == "1" else phish)[row["TLD"].lower()] += 1  # label 1 = legitimate
    p, l = sum(phish.values()), sum(legit.values())
    p0 = p / (p + l)
    table = {}
    for tld in sorted(set(phish) | set(legit)):
        n = phish[tld] + legit[tld]
        if n >= MIN_ROWS:
            table[tld] = {"risk": round((phish[tld] + K * p0) / (n + K), 3), "phishing": phish[tld], "legitimate": legit[tld]}
    return {"source": "PhiUSIIL (UCI 967, CC BY 4.0), column TLD (last label only)", "base_rate": round(p0, 3),
            "smoothing_rows": K, "abused_threshold": ABUSED, "abused_min_rows": ABUSED_MIN_ROWS, "tlds": table}


@lru_cache(maxsize=None)
def table() -> dict:
    return json.loads(OUT.read_text(encoding="utf-8"))


def tld_risk(tld: str) -> dict | None:
    """{risk, phishing, legitimate, abused} for the last label of a host, or None if unseen."""
    t = table()
    row = t["tlds"].get(tld.lower().rsplit(".", 1)[-1])
    if row is None:
        return None
    n = row["phishing"] + row["legitimate"]
    return {**row, "abused": row["risk"] >= t["abused_threshold"] and n >= t["abused_min_rows"]}


if __name__ == "__main__":
    data = build()
    OUT.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    abused = sorted((t for t, r in data["tlds"].items() if r["risk"] >= ABUSED and r["phishing"] + r["legitimate"] >= ABUSED_MIN_ROWS))
    print(f"{len(data['tlds'])} TLDs, base rate {data['base_rate']}; abused: {', '.join(abused)}")
