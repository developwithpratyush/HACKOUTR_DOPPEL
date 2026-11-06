"""P14 smoke check: does every finale beat (docs/finale-examples.md §0) still give the verdict the docs promise?

    .venv/Scripts/python.exe demo/finale/smoke.py          # PASS/FAIL per case, exit 1 on any FAIL

The expected verdicts below are the pinned example pack: each row cites the section of finale-examples.md it
comes from. Runs with DOPPEL_OFFLINE=1, so certificates come from the CT cache only (no lookups, no key used),
and pages are the local fixture kits (demo/fixtures/sites.yaml). Nothing here ever contacts a suspect.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

os.environ["DOPPEL_OFFLINE"] = "1"
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from doppel.brain.brain import investigate  # noqa: E402

G, R, P, B = "genuine", "needs_review", "phishing", "benign"

# (beat, domain, source, certs, expected label, evidence id that must appear or None, finale-examples section)
CASES = [
    ("1 opener", "echallan.parivahan.gov.in.pay-fine.icu", "gallery", None, P, None, "§1 fake"),
    ("1 opener", "echallan.parivahan.gov.in", "paste", None, G, None, "§1 real"),
    ("3 cert", "google.co.in", "paste", False, R, None, "§2.1 cert off"),
    ("3 cert", "google.co.in", "paste", True, G, "certificate_san_link", "§2.1 cert on"),
    ("3 cert", "googleapis.com", "paste", True, G, None, "§2.1"),
    ("3 cert", "upichalega.com", "paste", True, G, None, "§2.3"),
    ("4 padlock", "hdfc-pan-up-date2.web.app", "paste", True, R, "certificate_platform_only", "§2.6"),
    ("4 padlock", "sbicard.com", "paste", True, R, "certificate_organisation_other", "§2.7"),
    ("5 campaign", "in-echallan.online", "paste", True, R, "campaign_member", "§4.1"),
    ("6 deep", "kx72-secure.top", "gallery", None, P, None, "§6.1"),
    ("6 deep", "xn--pytm-53d.com", "gallery", None, P, None, "§6.2"),
    ("7 fool", "sbi-secure-login.com", "paste", None, R, None, "§5"),
    ("7 fool", "paytm.com.verify-kyc.in", "paste", None, R, None, "§5"),
    ("7 fool", "onlinesbi.co", "paste", None, R, None, "§5"),
    ("7 fool", "goog1e.com", "paste", None, R, None, "§5"),
    ("7 fool", "icicibank.com.in", "paste", None, R, None, "§5"),
    ("7 fool", "hdfcbank-rewards.in", "paste", None, R, None, "§5"),
    ("7 fool", "google.one", "paste", None, R, None, "§5"),
    ("7 fool", "one.google", "paste", None, G, None, "§5"),
    ("7 fool", "sbi.bank.in", "paste", None, G, None, "§5"),
    ("7 fool", "yonobusiness.sbi", "paste", None, G, None, "§7"),
]


def check_campaign() -> tuple[bool, str]:
    """§4.1: the radar holds the 5-name e-Challan island with the certificate recipe."""
    radar = json.loads((ROOT / "data" / "campaigns" / "radar.json").read_text(encoding="utf-8"))
    want = {"in-echallan.online", "in-echallan.date", "in-echallan.party", "in-echallan.trade", "ln-echallan.bid"}
    for c in radar["campaigns"]:
        if want <= set(c["members_ids"]):
            return "recipe" in c["strength"], f"{c['size']} members, {c['strength']}, {len(c['armed'])} armed"
    return False, "e-Challan island missing (rerun `doppel campaigns`)"


def check_live() -> tuple[bool, str]:
    """§3: the saved catch store still loads (the stage replays from it)."""
    from doppel.live.report import summary

    s = summary(mode="live")
    flat = json.dumps(s, default=str)
    return bool(s) and '"flag' in flat, f"catch store loads ({len(flat):,} bytes of summary)"


def main() -> int:
    fails, t0 = 0, time.time()
    for beat, dom, src, certs, want, ev, ref in CASES:
        try:
            v = investigate(dom, src, certs=certs)
            got, risk = v["label"], v.get("risk", v.get("risk_score"))
            ok = got == want and (ev is None or ev in json.dumps(v))
            note = f"{got} ({risk})" + ("" if ev is None or ev in json.dumps(v) else f", missing {ev}")
        except Exception as exc:  # a crash is a FAIL, not a stop
            ok, note = False, f"error: {exc!r}"[:120]
        fails += not ok
        tag = "" if certs is None else (" [cert on]" if certs else " [cert off]")
        print(f"{'PASS' if ok else 'FAIL'}  {beat:<11} {dom + tag:<52} want {want:<12} got {note}  {ref}")
    for name, fn in (("5 campaign", check_campaign), ("2 live", check_live)):
        try:
            ok, note = fn()
        except Exception as exc:
            ok, note = False, f"error: {exc!r}"[:120]
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name:<11} {note}")
    total = len(CASES) + 2
    print(f"\n{total - fails}/{total} pass in {time.time() - t0:.1f} s")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
