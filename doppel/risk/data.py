"""PhiUSIIL loading for the Risk Model and the leakage audit (P7).

PhiUSIIL's label is **1 = legitimate, 0 = phishing**. Everything here uses ``y = 1`` for *phishing*.
"""

from __future__ import annotations

import csv

from doppel.address.reader import AddressError
from doppel.contract import REPO_ROOT
from doppel.risk.features import model_host, registrable

PHIUSIIL = REPO_ROOT / "data" / "raw" / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv"
PAIRS = REPO_ROOT / "data" / "pairs" / "pairs.csv"
NRD = REPO_ROOT / "data" / "raw" / "nrd" / "nrd7.txt"
TEXT_COLUMNS = {"FILENAME", "URL", "Domain", "TLD", "Title"}


def load_phiusiil():
    """The full table as a pandas DataFrame, with ``y`` (1 = phishing), ``host`` (model form) and ``group``."""
    import pandas as pd

    if not PHIUSIIL.exists():
        raise FileNotFoundError(f"{PHIUSIIL} is missing: run `python scripts/data/fetch.py` first")
    df = pd.read_csv(PHIUSIIL, encoding="utf-8-sig", low_memory=False)
    df["y"] = 1 - df["label"].astype(int)
    hosts = []
    for url in df["URL"].astype(str):
        try:
            hosts.append(model_host(url))
        except (AddressError, UnicodeError, ValueError):
            hosts.append("")
    df["host"] = hosts
    df = df[df["host"] != ""].copy()
    df["group"] = [registrable(h) for h in df["host"]]
    return df


def unique_hosts(df):
    """One row per host. Hosts that carry both labels (open redirects: ``google.com`` appears in phishing
    because the trick is in the path, O2) are dropped, since a host-only model can't tell them apart."""
    g = df.groupby("host")["y"].agg(["min", "max", "size"]).reset_index()
    conflicted = g[g["min"] != g["max"]]
    keep = g[g["min"] == g["max"]]
    out = keep[["host"]].copy()
    out["y"] = keep["min"].astype(int).values
    out["rows"] = keep["size"].values
    out["group"] = [registrable(h) for h in out["host"]]
    return out.reset_index(drop=True), conflicted["host"].tolist()


def pairs_rows() -> list[dict]:
    with PAIRS.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def pairs_hosts(rows: list[dict] | None = None) -> set[str]:
    """Model-form hosts of every pairs.csv row: kept out of training so P3 evaluation stays clean
    (``test_real`` is made of PhiUSIIL phishing rows, and hard negatives partly of PhiUSIIL legitimate rows)."""
    out = set()
    for r in rows or pairs_rows():
        try:
            out.add(model_host(r["candidate"]))
        except (AddressError, UnicodeError, ValueError):
            pass
    return out


def nrd_names(limit: int | None = None, every: int = 1):
    """Names from the hagezi NRD 7-day snapshot (one per line; comments skipped)."""
    seen = out = 0
    with NRD.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            name = line.strip()
            if not name or name.startswith("#"):
                continue
            seen += 1
            if (seen - 1) % every:
                continue
            yield name
            out += 1
            if limit is not None and out >= limit:
                return
