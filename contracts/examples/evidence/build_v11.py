"""Mock evidence for the checks contract v1.1.0 adds (decision 004): C16, C17 (P11) and C18 (P13).

    python contracts/examples/evidence/build_v11.py     # writes v1.1-new-checks.json next to this file, validated

Hand-written, like the verdict mocks one folder up: the numbers are illustrative (taken from the 2026-11-06
measurements in docs/finale-examples.md, not re-measured here). C16/C17 are built in P11 (doppel/certs); C18 is
the shape P13's Campaign Radar should return. Kept in a sub-folder so the UI (which imports every
contracts/examples/*.json as a verdict) doesn't read these as verdicts.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))

from doppel.contract import validate_evidence_item  # noqa: E402

GOOGLE = {"id": "google", "name": "Google"}
SBI = {"id": "sbi", "name": "State Bank of India"}
HDFC = {"id": "hdfc", "name": "HDFC Bank"}
ECHALLAN = {"id": "parivahan", "name": "Parivahan / e-Challan"}

ITEMS = [
    {"evidence_id": "E1", "tool": "cert_forensics", "stage": "quick", "criterion": "C16",
     "finding": "certificate_san_link", "points_to": "genuine", "strength": "strong", "score": 0.97,
     "target_brand": GOOGLE,
     "summary": ("Proven Google: Google's own certificate (served at google.com, Google Trust Services, 65 names) lists "
                 "'*.google.co.in' next to 'google.com', a proven Google name."),
     "details": {"proof": "certificate_san", "matched_san": "*.google.co.in", "linked_to": ["google.com"],
                 "family_entry": "google.co.in", "seed_host": "google.com", "cert_sha256": "b0c47f…(mock)",
                 "issuer": "Google Trust Services", "validation": "DV", "organisation": None,
                 "sans": ["*.google.com", "*.google.co.in", "google-analytics.com", "urchin.com", "google.com"]}},
    {"evidence_id": "E2", "tool": "cert_forensics", "stage": "quick", "criterion": "C16",
     "finding": "certificate_platform_only", "points_to": "neutral", "strength": "strong", "score": 0,
     "target_brand": HDFC,
     "summary": ("hdfc-pan-up-date2.web.app is a tenant on web.app. Any certificate here is the platform's (a *.web.app "
                 "wildcard): it proves the platform, never the tenant."),
     "details": {"platform": "web.app", "platform_brand": None, "guard": "platform_never_tenant"}},
    {"evidence_id": "E3", "tool": "ct_history", "stage": "standard", "criterion": "C16",
     "finding": "certificate_organisation_other", "points_to": "neutral", "strength": "medium", "score": 0,
     "target_brand": SBI,
     "summary": ("Its OV certificate names a validated company: \"SBI CARDS AND PAYMENT SERVICES LIMITED\". That is not "
                 "State Bank of India's legal name (STATE BANK OF INDIA)."),
     "details": {"organisation": "SBI CARDS AND PAYMENT SERVICES LIMITED", "country": "IN", "validation": "OV",
                 "brand_legal_names": ["STATE BANK OF INDIA"], "ct_source": "sslmate"}},
    {"evidence_id": "E4", "tool": "ct_history", "stage": "standard", "criterion": "C17",
     "finding": "armed", "points_to": "phishing", "strength": "weak", "score": 1.0, "target_brand": ECHALLAN,
     "summary": ("Armed: first certificate 2026-10-26 (11 days before the lookup), 4 certificates in CT logs "
                 "(Google Trust Services x3, Let's Encrypt x1)."),
     "details": {"domain": "in-echallan.online", "count": 4, "first_seen": "2026-10-26T11:28:29Z", "age_days": 10.5,
                 "recipes": {"apex + 1 subdomain": 2, "apex + wildcard": 2}, "subdomain_labels": ["poy"],
                 "ct_source": "sslmate"}},
    {"evidence_id": "E5", "tool": "ct_history", "stage": "standard", "criterion": "C17",
     "finding": "no_certificate_yet", "points_to": "neutral", "strength": "weak", "score": 0, "target_brand": SBI,
     "summary": "No certificate for sbi-kyc-update.in in CT logs yet: not armed.",
     "details": {"domain": "sbi-kyc-update.in", "count": 0, "ct_source": "sslmate"}},
    {"evidence_id": "E6", "tool": "campaign_radar", "stage": "standard", "criterion": "C18",
     "finding": "campaign_member", "points_to": "phishing", "strength": "medium", "score": 0.85, "target_brand": ECHALLAN,
     "summary": ("One of 5 e-Challan look-alikes with the same naming template (in-echallan.<tld>), the same "
                 "certificate recipe (apex + wildcard + one 3-letter subdomain) and first certificates within 4 days."),
     "details": {"campaign_id": "echallan-2026-10", "members": ["in-echallan.online", "in-echallan.date",
                                                               "in-echallan.party", "in-echallan.trade", "ln-echallan.bid"],
                 "shared": ["naming_template", "certificate_recipe", "timing"], "phase": "P13 (shape only)"}},
]


def main() -> int:
    bad = 0
    for it in ITEMS:
        problems = validate_evidence_item(it)
        if problems:
            bad += 1
            print(f"FAIL {it['evidence_id']} {it['finding']}: {problems}")
    out = {"mock": True, "contract": "1.1.0",
           "note": "Hand-written evidence items for C16-C18 (decision 004). Illustrative numbers.", "items": ITEMS}
    (HERE / "v1.1-new-checks.json").write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{len(ITEMS) - bad}/{len(ITEMS)} items valid -> {HERE / 'v1.1-new-checks.json'}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
