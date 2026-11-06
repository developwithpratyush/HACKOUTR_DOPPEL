"""P11 eval: Certificate Forensics (C16/C17), family auto-discovery, fixes (a)-(d), the no-degradation gate.

    python bench/p11_cert_eval.py            # ~6-8 min (two full scans); writes docs/eval/p11-cert.{json,md}
    python bench/p11_cert_eval.py --quick    # skip the full NRD and Phishing.Database scans

Offline (``DOPPEL_OFFLINE=1``): every certificate comes from the committed cache (data/certs/) and discovery
result (data/brands/discovered.yaml), so the numbers reproduce on any machine.

1. The finale examples (docs/finale-examples.md §2), each with certificates OFF and ON (the ablation switch).
2. The P5 NRD flags (590, recorded in docs/eval/p5-nrd-run.json) re-judged: how many certificate proof clears,
   how many fix (c) clears, and every name proven genuine (hand-checkable: none may be a look-alike).
3. The full NRD snapshot and the full Phishing.Database ACTIVE list, certificates ON: new flags (fix a, the
   NPCI brand) and **every name proven genuine by a certificate** (must be zero look-alikes; zero phishing).
4. Family auto-discovery: accepted links, platform-only names (guard 3), the OV/EV coverage of the seeds.
5. Fixes (a)-(d) before/after, and the gate (bench/regress.py: docs/eval/baseline.json vs runs/regress/last.json).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
os.environ["DOPPEL_OFFLINE"] = "1"
for _var in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_var, "1")

import yaml  # noqa: E402

from doppel.brain.brain import Brain  # noqa: E402
from doppel.brain.scan import scan  # noqa: E402

OUT = REPO / "docs" / "eval"
NRD = REPO / "data" / "raw" / "nrd" / "nrd7.txt"
PDB = REPO / "data" / "raw" / "phishing_database" / "phishing-domains-ACTIVE.txt"
DISCOVERED = REPO / "data" / "brands" / "discovered.yaml"
KEEP = ("phishing", "sleeper", "needs_review", "genuine")
FLAG = {"phishing", "sleeper", "needs_review"}
CERT_PROOF = {"certificate_san_link", "certificate_organisation_match"}

EXAMPLES = [  # (name, docs/finale-examples.md section, what it shows)
    ("google.co.in", "2.1", "Google's India homepage: a tld_swap by every rule"),
    ("google-analytics.com", "2.1", "combosquat by every rule"),
    ("googlecommerce.com", "2.1", "combosquat by every rule"),
    ("googleapis.com", "2.1", "the platform's own name (bare)"),
    ("us-central1-aiplatform.rep.googleapis.com", "2.1", "a googleapis.com tenant: guard 3 keeps it unproven"),
    ("urchin.com", "2.2", "no 'google' in it"),
    ("gvt1.com", "2.2", "Chrome's update servers"),
    ("youtube-nocookie.com", "2.2", "no 'google' in it"),
    ("upichalega.com", "2.3", "UPI's own campaign site looks like a scam"),
    ("bhimupi.org.in", "2.3", "on NPCI's certificate"),
    ("hdfcbank.com", "2.4", "old and new address on one certificate (both already on the list)"),
    ("echallan.parivahan.gov.in", "2.5", "the real e-Challan site: DV, no Organisation"),
    ("in-echallan.online", "2.5/2.8", "the fake: DV too; armed"),
    ("hdfc-pan-up-date2.web.app", "2.6", "Google's padlock on an HDFC scam"),
    ("sbicard.com", "2.7", "a real company, but not the bank"),
    ("ln-echallan.bid", "2.8", "a campaign name, armed"),
    ("pop.gmail.com", "3.3", "a live-feed false alarm (fix d)"),
]


def names(path: Path) -> list[str]:
    with path.open(encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def proof_of(v: dict) -> str | None:
    return next((e["finding"] for e in v["evidence"] if e["finding"] in CERT_PROOF), None)


def examples(brain: Brain) -> list[dict]:
    rows = []
    for name, sec, what in EXAMPLES:
        off = brain.investigate(name, "paste", certs=False)
        on = brain.investigate(name, "paste", certs=True)
        new = [e for e in on["evidence"] if e["tool"] in ("cert_forensics", "ct_history")]
        rows.append({"name": name, "section": sec, "what": what, "off": off["label"], "on": on["label"],
                     "risk_off": off["risk_score"], "risk_on": on["risk_score"],
                     "cert_findings": [e["finding"] for e in new], "reason_on": on["reason"],
                     "sha256": next((e["details"].get("cert_sha256") for e in new if e["details"].get("cert_sha256")), None)})
    return rows


def p5_flags(brain: Brain) -> dict:
    p5 = json.loads((OUT / "p5-nrd-run.json").read_text(encoding="utf-8"))
    before = [r["domain"] for r in p5["flagged_ranked"]]
    out = {"p5_flagged": len(before), "still_flagged": 0, "cleared_by_certificate": [], "cleared_by_email_shape": [],
           "cleared_other": []}
    for d in before:
        v = brain.investigate(d, "nrd_snapshot", counterfactual=False)
        if v["label"] in FLAG:
            out["still_flagged"] += 1
        elif proof_of(v):
            out["cleared_by_certificate"].append({"domain": d, "label": v["label"], "reason": v["reason"]})
        elif any(e["finding"] == "email_shaped_name" for e in v["evidence"]):
            out["cleared_by_email_shape"].append(d)
        else:
            out["cleared_other"].append({"domain": d, "label": v["label"], "reason": v["reason"]})
    return out


def full_scan(path: Path, source: str, workers: int, certs: bool | None = None) -> dict:
    t = time.perf_counter()
    verdicts, stats = scan(names(path), source, workers=workers, keep_labels=KEEP, chunksize=512, certs=certs)
    by_proof = [{"domain": v["domain"], "brand": v["target_brand"]["id"], "proof": proof_of(v)}
                for v in verdicts if v["label"] == "genuine" and proof_of(v)]
    flagged = sorted(v["domain"] for v in verdicts if v["label"] in FLAG)
    return {"names": stats["total"], "by_label": stats["by_label"], "seconds": round(time.perf_counter() - t, 1),
            "flagged": flagged, "genuine_by_certificate": by_proof,
            "genuine_by_list": sorted(v["domain"] for v in verdicts if v["label"] == "genuine" and not proof_of(v))}


def discovery() -> dict:
    d = yaml.safe_load(DISCOVERED.read_text(encoding="utf-8"))
    return {"accepted": len(d["accepted"]), "accepted_by_brand": dict(Counter(e["brand"] for e in d["accepted"])),
            "platform_only": len(d["platform_only"]), "platform_only_sample": sorted({p["san"] for p in d["platform_only"]})[:8],
            "review": len(d["review"]), "seeds": d["seeds"], "legal_name_proposals": d["legal_name_proposals"],
            "seed_failures": len(d["seed_failures"]), "generated": d["generated"],
            "accepted_names": [f"{e['domain']}{' (+subdomains)' if e['include_subdomains'] else ''}" for e in d["accepted"]]}


def gate() -> dict:
    base = json.loads((OUT / "baseline-pre-p11.json").read_text(encoding="utf-8"))
    last = json.loads((REPO / "runs" / "regress" / "last.json").read_text(encoding="utf-8"))
    return {"before": base, "after": last}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    brain = Brain(deep=False)
    res = {"generated": time.strftime("%Y-%m-%d"), "examples": examples(brain), "p5_flags": p5_flags(brain),
           "discovery": discovery()}
    print("examples + P5 flags done", flush=True)
    if not a.quick:
        res["nrd"] = full_scan(NRD, "nrd_snapshot", a.workers)
        p5 = {r["domain"] for r in json.loads((OUT / "p5-nrd-run.json").read_text(encoding="utf-8"))["flagged_ranked"]}
        res["nrd"]["new_flags"] = sorted(set(res["nrd"]["flagged"]) - p5)
        res["nrd"]["flagged_count"] = len(res["nrd"]["flagged"])
        del res["nrd"]["flagged"]
        print(f"NRD: {res['nrd']['by_label']} in {res['nrd']['seconds']} s", flush=True)
        res["pdb"] = full_scan(PDB, "file", a.workers)
        res["pdb"]["flagged_count"] = len(res["pdb"]["flagged"])
        del res["pdb"]["flagged"]
        print(f"Phishing.Database: {res['pdb']['by_label']} in {res['pdb']['seconds']} s", flush=True)
    res["gate"] = gate()
    (OUT / "p11-cert.json").write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT / 'p11-cert.json'}")


if __name__ == "__main__":
    main()
