"""P13: the split-conformal NEEDS REVIEW threshold.

    python bench/p13_conformal.py            # -> docs/eval/p13-conformal.json (+ printed summary)

Split conformal, one-sided: calibrate on the P3 ``dev`` look-alikes (label 1), nonconformity = Doppel's risk score
(low risk = looks benign). With n calibration scores and alpha = 0.05, the threshold tau is the
floor(alpha * (n + 1))-th smallest score: for a new look-alike exchangeable with the calibration set,
P(risk < tau) <= alpha. That is the line "at most 5% of real phishing falls below it".

Measured, never assumed: what a "brand signal but risk < tau -> BENIGN" rule would cost on the gate's test splits,
P3's ``test_real`` (201 real phishing URLs), the Phishing.Database India slice, and what it would clear among the
live flags (the P12 catch store). Run the gate before shipping any change to the label policy.
"""

from __future__ import annotations

import csv
import json
import math
import os
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
os.environ["DOPPEL_OFFLINE"] = "1"
ALPHA = 0.05
FLAG = {"needs_review", "phishing", "sleeper"}


def tau_of(scores: list[float], alpha: float = ALPHA) -> tuple[float, int]:
    s = sorted(scores)
    k = math.floor(alpha * (len(s) + 1))
    return (s[k - 1] if k >= 1 else 0.0), k


def main() -> dict:
    from doppel.brain.brain import Brain

    b = Brain(deep=False)
    judge = lambda n: b.investigate(n, "file", counterfactual=False)   # noqa: E731
    rows = list(csv.DictReader(open(REPO / "data/pairs/pairs.csv", encoding="utf-8")))
    cal = [r for r in rows if r["split"] == "dev" and r["label"] == "1"]
    cal_v = [judge(r["candidate"]) for r in cal]
    scores = [v["risk_score"] for v in cal_v]
    tau, k = tau_of(scores)
    out = {"alpha": ALPHA, "calibration": {"split": "dev look-alikes", "n": len(scores), "k": k, "tau": tau,
                                           "below_tau": sum(x < tau for x in scores),
                                           "flagged": sum(v["label"] in FLAG for v in cal_v)}}

    def cost(name: str, names: list[str]) -> None:
        vs = [judge(n) for n in names]
        flagged = [v for v in vs if v["label"] in FLAG]
        lost = [v["domain"] for v in flagged if v["risk_score"] < tau]
        out[name] = {"n": len(vs), "flagged": len(flagged), "missed_now": len(vs) - len(flagged),
                     "would_drop": len(lost), "missed_with_tau": len(vs) - len(flagged) + len(lost),
                     "missed_rate_with_tau": round((len(vs) - len(flagged) + len(lost)) / max(1, len(vs)), 4),
                     "risk_below_tau": sum(v["risk_score"] < tau for v in vs), "examples_dropped": lost[:10]}

    cost("test_lookalikes", [r["candidate"] for r in rows if r["split"] in ("test_seen", "test_unseen") and r["label"] == "1"])
    cost("test_real", [r["candidate"] for r in rows if r["split"] == "test_real"])
    cost("pdb_india_slice", [l.split()[1] for l in open(REPO / "bench/data/pdb_india_slice.txt", encoding="utf-8") if len(l.split()) == 2 and not l.startswith("#")])
    db = REPO / "runs/live/live/catches.db"
    if db.is_file():
        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        live = con.execute("SELECT name, risk, brand FROM catches").fetchall()
        low = sorted([(n, r, br) for n, r, br in live if r < tau], key=lambda x: x[1])
        out["live_flags"] = {"n": len(live), "would_clear": len(low), "examples": [f"{n} ({br}, {r:.2f})" for n, r, br in low[:15]]}
    (REPO / "docs/eval/p13-conformal.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    return out


if __name__ == "__main__":
    print(json.dumps(main(), indent=1))
