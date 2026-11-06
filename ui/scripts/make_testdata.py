"""Regenerate ui/src/lib/testdata/real-verdicts.json: real brain verdicts the UI's replay tests run on.

Run after the brain's output changes:  DOPPEL_OFFLINE=1 .venv/Scripts/python.exe ui/scripts/make_testdata.py
"""

import json
from pathlib import Path

from doppel.brain.brain import Brain

CASES = [("https://pаytm.com/login", "gallery"), ("paytrn.com", "gallery"), ("sbi-kyc-update.in", "nrd_snapshot"),
         ("https://echallan.parivahan.gov.in.pay-fine.icu/challan", "gallery"), ("kx72-secure.top", "gallery"),
         ("onlinesbi.sbi.bank.in", "gallery"), ("thanksbitcoin.com", "nrd_snapshot"), ("sbi.bank-in.com", "gallery"),
         ("chai-and-code.in", "file"), ("blog.google", "nrd_snapshot"), ("sbi-kyc.web.app", "paste"),
         ("hdfcbank.bank.in", "paste"), ("g00gle.com", "fool_it"), ("in-echallan.online", "nrd_snapshot"),
         # P11 Certificate Forensics (from the committed certificate cache; run with DOPPEL_OFFLINE=1)
         ("google.co.in", "paste"), ("hdfc-pan-up-date2.web.app", "paste"), ("sbicard.com", "paste")]
OUT = Path(__file__).resolve().parents[1] / "src" / "lib" / "testdata" / "real-verdicts.json"

brain = Brain()
verdicts = [brain.investigate(raw, source) for raw, source in CASES]
for v in verdicts:
    v["meta"]["generated_at"] = "2026-11-05T00:00:00+00:00"   # stable diffs
OUT.write_bytes(json.dumps(verdicts, ensure_ascii=False, indent=0).encode("utf-8"))
print(f"wrote {len(verdicts)} verdicts to {OUT}")
