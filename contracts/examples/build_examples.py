"""Build the mock verdicts in contracts/examples/ (one per Deception Gallery case).

These are hand-designed MOCKS (meta.mock = true): the numbers are illustrative,
not measured. The UI (P6) and the case-file writer (P10) build against them
before the real brain exists. Edit the cases here, then run:

    python contracts/examples/build_examples.py

The builder numbers evidence IDs and trace steps, derives the stage records and
timings from the tool calls, and validates every file against the contract.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from doppel.contract import validate_verdict  # noqa: E402

GENERATED_AT = "2026-11-05T10:00:00+05:30"
ENGINE = "0.0.1-mock"

SBI = {"id": "sbi", "name": "State Bank of India"}
PAYTM = {"id": "paytm", "name": "Paytm"}
PARIVAHAN = {"id": "parivahan", "name": "Parivahan / e-Challan"}

RULES = {
    "H1_genuine_family": ("genuine", "Ownership is proven by the Family Verifier, so the domain is genuine whatever the other signals say."),
    "H2_brand_claim_foreign_credentials": ("phishing", "The page claims a brand, the owner isn't in that brand's family, and the credentials leave to a domain outside it."),
    "H3_accepts_any_credentials": ("phishing", "The page accepted made-up credentials, which a genuine login never does."),
    "H4_direct_exfil_channel": ("phishing", "The page sends the submitted data straight to a messaging or form service (Telegram, Discord, Google Forms)."),
}


def ev(tool, criterion, finding, points_to, strength, score, brand, summary, **details):
    return {
        "tool": tool, "criterion": criterion, "finding": finding, "points_to": points_to,
        "strength": strength, "score": score, "target_brand": brand, "summary": summary,
        "details": details,
    }


class Case:
    def __init__(self, domain, raw, display, source, owner):
        self.v = {
            "schema_version": "1.0.0", "domain": domain,
            "input": {"raw": raw, "display": display, "source": source},
            "owner": owner,
        }
        self.evidence, self.trace, self.risk = [], [], 0.0
        self.stages = {s: {"stage": s, "status": "completed", "tools": [], "evidence_ids": [], "provisional": None}
                       for s in ("quick", "standard", "deep")}
        self.spans = {}

    def _step(self, **step):
        self.trace.append({"step": len(self.trace) + 1, **step})

    def open(self, message):
        self._step(t_ms=0, kind="case_opened", message=message)

    def policy(self, t, message):
        self._step(t_ms=t, kind="policy", message=message)

    def tool(self, stage, tool, args, t, dur, items, risk_after, message):
        ids = []
        for item in items:
            eid = f"E{len(self.evidence) + 1}"
            self.evidence.append({"evidence_id": eid, "tool": item["tool"], "stage": stage, **{
                k: item[k] for k in ("criterion", "finding", "points_to", "strength", "score",
                                     "target_brand", "summary", "details")}, "duration_ms": dur})
            assert item["tool"] == tool, (tool, item)
            ids.append(eid)
        rec = self.stages[stage]
        if tool not in rec["tools"]:
            rec["tools"].append(tool)
        rec["evidence_ids"] += ids
        lo, hi = self.spans.get(stage, (t, t + dur))
        self.spans[stage] = (min(lo, t), max(hi, t + dur))
        self._step(t_ms=t, kind="tool", stage=stage, tool=tool, args=args, duration_ms=dur,
                   evidence_ids=ids, risk_before=self.risk, risk_after=risk_after, message=message)
        self.risk = risk_after
        return ids

    def provisional(self, stage, t, label, reason):
        self.stages[stage]["provisional"] = {"label": label, "risk_score": self.risk, "reason": reason}
        self._step(t_ms=t, kind="provisional_verdict", stage=stage, label=label,
                   risk_after=self.risk, message=reason)

    def skip(self, stage, reason):
        self.stages[stage].update(status="skipped", skip_reason=reason)

    def hard_rule(self, t, rule_id, evidence_ids, also_fired=()):
        forces, description = RULES[rule_id]
        rule = {"id": rule_id, "forces": forces, "description": description, "evidence_ids": evidence_ids}
        if also_fired:
            rule["also_fired"] = list(also_fired)
        self.v["hard_rule"] = rule
        names = ", ".join([rule_id, *also_fired])
        self._step(t_ms=t, kind="hard_rule", evidence_ids=evidence_ids,
                   message=f"Hard rule fired: {names}. {description}")

    def final(self, t, label, risk, target, closeness, confidence, reason, counterfactual, notes=""):
        self.v.setdefault("hard_rule", None)
        for rec in self.stages.values():  # the last stage's provisional verdict is the final one
            if rec["status"] == "completed" and rec["provisional"] is None:
                rec["provisional"] = {"label": label, "risk_score": risk, "reason": reason}
        self._step(t_ms=t, kind="final_verdict", label=label, risk_before=self.risk,
                   risk_after=risk, message=f"{label.upper().replace('_', ' ')}: {reason}")
        timings = {}
        for s in ("quick", "standard", "deep"):
            if self.stages[s]["status"] == "skipped":
                timings[s] = None
            else:
                lo, hi = self.spans[s]
                timings[s] = round(hi - lo, 1)
        timings["total"] = t
        meta = {"generated_at": GENERATED_AT, "engine_version": ENGINE, "mock": True}
        if notes:
            meta["notes"] = notes
        out = {
            **self.v, "target_brand": target, "closeness": closeness, "risk_score": risk,
            "confidence": confidence, "label": label, "reason": reason,
            "evidence": self.evidence, "stages": list(self.stages.values()), "trace": self.trace,
            "hard_rule": self.v["hard_rule"], "counterfactual": counterfactual,
            "timings_ms": timings,
            "meta": meta,
        }
        order = ["schema_version", "domain", "input", "owner", "target_brand", "closeness",
                 "risk_score", "confidence", "label", "reason", "hard_rule", "counterfactual",
                 "timings_ms", "stages", "evidence", "trace", "meta"]
        return {k: out[k] for k in order}


def cf(change, undone, label, risk, summary, domain=None):
    out = {"change": change, "undone_evidence_ids": undone, "label": label, "risk_score": risk, "summary": summary}
    if domain:
        out["counterfactual_domain"] = domain
    return out


SINGLE = "Single investigation, so every stage runs and the verdict updates after each one."
BATCH = "Batch input, so the brain escalates only on evidence."


# ---------------------------------------------------------------------------
def case_invisible_letter():
    c = Case("xn--pytm-53d.com", "https://pаytm.com/login", "pаytm.com", "gallery", "xn--pytm-53d.com")
    c.open(f"New case: xn--pytm-53d.com (shown as pаytm.com in the SMS). {SINGLE}")
    c.tool("quick", "address_reader", {"domain": "xn--pytm-53d.com"}, 1, 3, [
        ev("address_reader", "C1", "owner_resolved", "neutral", "strong", 0, None,
           "Real owner is xn--pytm-53d.com (public suffix 'com').",
           owner="xn--pytm-53d.com", public_suffix="com", private_suffix=False),
        ev("address_reader", "C3", "mixed_script", "phishing", "strong", 0.95, None,
           "Mixes Latin and Cyrillic: the second letter is Cyrillic 'а' (U+0430), not Latin 'a'.",
           scripts=["Latin", "Cyrillic"], unicode="pаytm.com",
           edits=[{"op": "substitute", "candidate": "а", "genuine": "a", "candidate_span": [1, 2],
                   "genuine_span": [1, 2], "cost": 0.0, "kind": "homoglyph", "codepoints": ["U+0430"]}]),
    ], 0.55, "Address Reader: decoded the punycode and found a hidden Cyrillic letter.")
    c.tool("quick", "family_verifier", {"owner": "xn--pytm-53d.com"}, 4, 1, [
        ev("family_verifier", "C2", "not_in_family", "phishing", "medium", 0.5, PAYTM,
           "Not Paytm's: no brand-owned ending, no restricted registry, not on Paytm's official list.",
           proofs_checked=["brand_tld", "restricted_registry", "official_list"], proofs_matched=[]),
    ], 0.62, "Family Verifier: no ownership proof for any protected brand.")
    c.tool("quick", "trick_detector", {"domain": "xn--pytm-53d.com", "owner": "xn--pytm-53d.com"}, 5, 14, [
        ev("trick_detector", "C5", "homoglyph", "phishing", "medium", 0.95, PAYTM,
           "UTS-39 skeleton is 'paytm.com', identical to the genuine paytm.com.",
           skeleton="paytm.com", genuine="paytm.com"),
        ev("trick_detector", "C4", "brand_closeness", "phishing", "medium", 0.99, PAYTM,
           "Closeness to paytm.com is 0.99 (one zero-cost homoglyph swap).",
           closeness=0.99, genuine="paytm.com", per_brand={"paytm": 0.99, "sbi": 0.04}),
    ], 0.78, "Trick Detector: homoglyph of paytm.com.")
    c.provisional("quick", 19, "suspicious", "Suspicious: one hidden Cyrillic letter, imitating Paytm.")
    c.policy(19, "Brand signal found, so go to Stage 2 (Standard).")
    c.tool("standard", "human_eye_renderer", {"candidate": "pаytm.com", "genuine": "paytm.com", "view": "sms"}, 20, 310, [
        ev("human_eye_renderer", "C7", "sms_view_identical", "phishing", "medium", 0.98, PAYTM,
           "Rendered in the SMS view, it is pixel-identical to paytm.com (SSIM 1.00).",
           ssim=1.0, visual_edit_distance=0.0,
           artifacts=[{"kind": "render", "path": "renders/xn--pytm-53d.com_sms.png", "caption": "SMS view, candidate vs genuine"}]),
    ], 0.82, "Human-Eye Renderer: a reader can't see any difference.")
    c.tool("standard", "risk_model", {"domain": "xn--pytm-53d.com"}, 20, 40, [
        ev("risk_model", "C8", "ml_risk", "genuine", "weak", 0.78, None,
           "ML risk 0.22: the dataset model sees an ordinary short .com (supporting signal only).",
           probability=0.22),
    ], 0.81, "Risk Model: low ML risk. The name-only model is fooled, as expected.")
    c.tool("standard", "page_probe", {"domain": "xn--pytm-53d.com"}, 20, 790, [
        ev("page_probe", "C9", "live_login_form", "phishing", "medium", 0.7, None,
           "A live page with a login form (mobile number + password).",
           status="live", http_status=200, has_login_form=True),
    ], 0.86, "Page Probe: live page with a login form.")
    c.provisional("standard", 810, "suspicious", "Suspicious: invisible to a reader, and a live login page exists.")
    c.policy(810, "Live page, so go to Stage 3 (Deep).")
    c.tool("deep", "page_inspector", {"url": "https://xn--pytm-53d.com/login", "genuine_snapshot": "paytm_login"}, 811, 2100, [
        ev("page_inspector", "C10", "visual_match", "phishing", "medium", 0.94, PAYTM,
           "Screenshot matches the saved Paytm login page at 94%.",
           phash_distance=4, ssim=0.94,
           artifacts=[{"kind": "heatmap", "path": "deep/xn--pytm-53d.com_heatmap.png", "caption": "Differences vs genuine Paytm login"}]),
        ev("page_inspector", "C11", "form_target_changed", "phishing", "medium", 0.8, PAYTM,
           "Same layout as the genuine page, but the form now posts to /collect.php on the suspect domain.",
           genuine_action="https://paytm.com/api/login", suspect_action="https://xn--pytm-53d.com/collect.php"),
    ], 0.9, "Page Inspector: a near-exact copy with a changed form target.")
    c.tool("deep", "vision_ai", {"screenshot": "deep/xn--pytm-53d.com.png"}, 811, 2900, [
        ev("vision_ai", "C12", "claimed_brand_mismatch", "phishing", "strong", 0.95, PAYTM,
           "The page claims to be Paytm, but its owner isn't in Paytm's family.",
           claimed_brand="Paytm", model="gemini-flash", temperature=0),
        ev("vision_ai", "C13", "asks_sensitive", "phishing", "medium", 0.85, PAYTM,
           "Asks for mobile number, password and OTP.", asks_for=["mobile_number", "password", "otp"]),
    ], 0.94, "Vision AI: claims Paytm, asks for password and OTP.")
    c.tool("deep", "credential_tracker", {"url": "https://xn--pytm-53d.com/login"}, 811, 4800, [
        ev("credential_tracker", "C14", "credentials_to_foreign_domain", "phishing", "strong", 0.9, PAYTM,
           "Dummy credentials were POSTed to xn--pytm-53d.com/collect.php, outside Paytm's family.",
           first_hop="https://xn--pytm-53d.com/collect.php", dummy_credentials=True, requests_captured=7),
    ], 0.97, "Credential Tracker: the password leaves Paytm's family.")
    c.hard_rule(5611, "H2_brand_claim_foreign_credentials", ["E11", "E13"])
    return c.final(5612, "phishing", 0.97, PAYTM, 0.99, "high",
                   "Looks exactly like paytm.com because of one hidden Cyrillic letter, copies Paytm's login page, and sends the password to itself.",
                   cf("Cyrillic 'а' (U+0430) -> Latin 'a'", ["E2", "E4"], "genuine", 0.02,
                      "Would be GENUINE only if the 'а' were a Latin 'a': one hidden letter is all that separates it from paytm.com.",
                      domain="paytm.com"))


# ---------------------------------------------------------------------------
def case_twin_letters():
    c = Case("paytrn.com", "paytrn.com", "paytrn.com", "gallery", "paytrn.com")
    c.open(f"New case: paytrn.com. {SINGLE}")
    c.tool("quick", "address_reader", {"domain": "paytrn.com"}, 1, 2, [
        ev("address_reader", "C1", "owner_resolved", "neutral", "strong", 0, None,
           "Real owner is paytrn.com (public suffix 'com').", owner="paytrn.com", public_suffix="com", private_suffix=False),
        ev("address_reader", "C3", "single_script", "neutral", "strong", 0, None,
           "Plain ASCII, one script: no hidden letters.", scripts=["Latin"]),
    ], 0.1, "Address Reader: ordinary ASCII name.")
    c.tool("quick", "family_verifier", {"owner": "paytrn.com"}, 3, 1, [
        ev("family_verifier", "C2", "not_in_family", "phishing", "medium", 0.5, PAYTM,
           "Not Paytm's: no ownership proof matched.",
           proofs_checked=["brand_tld", "restricted_registry", "official_list"], proofs_matched=[]),
    ], 0.2, "Family Verifier: not in any brand's family.")
    c.tool("quick", "trick_detector", {"domain": "paytrn.com", "owner": "paytrn.com"}, 4, 11, [
        ev("trick_detector", "C5", "twin_letters", "phishing", "medium", 0.9, PAYTM,
           "'rn' stands in for 'm': paytrn reads as paytm.",
           edits=[{"op": "substitute", "candidate": "rn", "genuine": "m", "candidate_span": [4, 6],
                   "genuine_span": [4, 5], "cost": 0.05, "kind": "twin_letters"}],
           levenshtein=2),
        ev("trick_detector", "C4", "brand_closeness", "phishing", "medium", 0.96, PAYTM,
           "Closeness to paytm.com is 0.96 by visual edit distance (plain letter counting says only 0.67).",
           closeness=0.96, levenshtein_similarity=0.67, genuine="paytm.com"),
    ], 0.7, "Trick Detector: rn -> m twin letters, imitating Paytm.")
    c.provisional("quick", 15, "suspicious", "Suspicious: reads as 'paytm' to the eye.")
    c.policy(15, "Brand signal found, so go to Stage 2 (Standard).")
    c.tool("standard", "human_eye_renderer", {"candidate": "paytrn.com", "genuine": "paytm.com", "view": "sms"}, 16, 290, [
        ev("human_eye_renderer", "C7", "sms_view_near_identical", "phishing", "medium", 0.93, PAYTM,
           "In the SMS view, SSIM 0.97 against paytm.com: a reader would not notice.",
           ssim=0.97, visual_edit_distance=0.05,
           artifacts=[{"kind": "render", "path": "renders/paytrn.com_sms.png", "caption": "SMS view, candidate vs genuine"}]),
    ], 0.74, "Human-Eye Renderer: near-identical to the eye.")
    c.tool("standard", "risk_model", {"domain": "paytrn.com"}, 16, 35, [
        ev("risk_model", "C8", "ml_risk", "genuine", "weak", 0.59, None,
           "ML risk 0.41 (supporting signal only).", probability=0.41),
    ], 0.72, "Risk Model: middling ML risk.")
    c.tool("standard", "page_probe", {"domain": "paytrn.com"}, 16, 700, [
        ev("page_probe", "C9", "live_no_credentials", "genuine", "medium", 0.4, None,
           "A live page with ordinary content and no login or payment form.",
           status="live", http_status=200, has_login_form=False),
    ], 0.62, "Page Probe: live page, but it asks for nothing.")
    c.provisional("standard", 716, "suspicious", "Suspicious name, but the page asks for nothing.")
    c.policy(716, "Live page, so go to Stage 3 (Deep) to check whether it copies Paytm.")
    c.tool("deep", "page_inspector", {"url": "https://paytrn.com/", "genuine_snapshot": "paytm_home"}, 717, 1900, [
        ev("page_inspector", "C10", "visual_mismatch", "genuine", "medium", 0.6, PAYTM,
           "Screenshot matches Paytm's saved page at only 18%.", ssim=0.18, phash_distance=31),
    ], 0.58, "Page Inspector: doesn't look like Paytm.")
    c.tool("deep", "vision_ai", {"screenshot": "deep/paytrn.com.png"}, 717, 2600, [
        ev("vision_ai", "C12", "no_brand_claim", "genuine", "strong", 0.5, None,
           "The page doesn't claim to be any protected brand.", claimed_brand=None, model="gemini-flash", temperature=0),
        ev("vision_ai", "C13", "asks_nothing_sensitive", "genuine", "medium", 0.6, None,
           "Asks for nothing sensitive.", asks_for=[]),
    ], 0.55, "Vision AI: no brand claimed, nothing requested.")
    c.tool("deep", "credential_tracker", {"url": "https://paytrn.com/"}, 717, 900, [
        ev("credential_tracker", "C14", "no_credential_form", "neutral", "strong", 0, None,
           "No form to submit, so there is no credential destination to report.", forms_found=0),
    ], 0.55, "Credential Tracker: nothing to submit.")
    return c.final(3318, "needs_review", 0.55, PAYTM, 0.96, "low",
                   "Reads as paytm.com to the eye (rn -> m), but today the page copies nothing and asks for nothing. An analyst should decide.",
                   cf("rn -> m look-alike undone (treat 'paytrn' as an ordinary word)", ["E4", "E5", "E6"], "benign", 0.18,
                      "Would be BENIGN without the rn -> m look-alike: everything else about it is unremarkable."),
                   notes="Risk 0.55 falls inside the NEEDS REVIEW band (mock band 0.40-0.70; P11 sets it by split-conformal).")


# ---------------------------------------------------------------------------
def case_sleeper():
    c = Case("sbi-kyc-update.in", "sbi-kyc-update.in", "sbi-kyc-update.in", "nrd_snapshot", "sbi-kyc-update.in")
    c.open(f"New case: sbi-kyc-update.in from the newly-registered-domains snapshot. {BATCH}")
    c.tool("quick", "address_reader", {"domain": "sbi-kyc-update.in"}, 1, 2, [
        ev("address_reader", "C1", "owner_resolved", "neutral", "strong", 0, None,
           "Real owner is sbi-kyc-update.in (public suffix 'in').", owner="sbi-kyc-update.in", public_suffix="in", private_suffix=False),
        ev("address_reader", "C3", "single_script", "neutral", "strong", 0, None, "Plain ASCII: no hidden letters.", scripts=["Latin"]),
    ], 0.1, "Address Reader: ordinary ASCII name.")
    c.tool("quick", "family_verifier", {"owner": "sbi-kyc-update.in"}, 3, 1, [
        ev("family_verifier", "C2", "not_in_family", "phishing", "medium", 0.5, SBI,
           "Not SBI's: not under .sbi or .bank.in, and not on SBI's official list.",
           proofs_checked=["brand_tld", "restricted_registry", "official_list"], proofs_matched=[]),
    ], 0.25, "Family Verifier: not SBI's.")
    c.tool("quick", "trick_detector", {"domain": "sbi-kyc-update.in", "owner": "sbi-kyc-update.in"}, 4, 9, [
        ev("trick_detector", "C5", "combosquat", "phishing", "medium", 0.85, SBI,
           "Brand token 'sbi' plus lure words 'kyc' and 'update'.",
           tokens=["sbi", "kyc", "update"], brand_alias="sbi",
           lure_words=[{"word": "kyc", "category": "account"}, {"word": "update", "category": "account"}]),
        ev("trick_detector", "C4", "brand_closeness", "phishing", "medium", 0.62, SBI,
           "Closeness to SBI is 0.62: the brand token is exact, the rest is added words (letter counting calls it 'far').",
           closeness=0.62, genuine="sbi.bank.in", levenshtein_similarity=0.29),
    ], 0.72, "Trick Detector: brand + lure words, imitating SBI.")
    c.provisional("quick", 13, "suspicious", "Suspicious: SBI's name plus KYC and update lures.")
    c.policy(13, "Brand signal found, so go to Stage 2 (Standard).")
    c.tool("standard", "human_eye_renderer", {"candidate": "sbi-kyc-update.in", "genuine": "sbi.bank.in", "view": "sms"}, 14, 280, [
        ev("human_eye_renderer", "C7", "sms_view_brand_prominent", "phishing", "medium", 0.5, SBI,
           "In the SMS view, 'sbi' leads the link and reads as an official SBI KYC address.",
           visual_edit_distance=0.48),
    ], 0.74, "Human-Eye Renderer: the brand leads the link.")
    c.tool("standard", "risk_model", {"domain": "sbi-kyc-update.in"}, 14, 38, [
        ev("risk_model", "C8", "ml_risk", "phishing", "weak", 0.81, None,
           "ML risk 0.81 (supporting signal only).", probability=0.81),
    ], 0.77, "Risk Model: high ML risk.")
    c.tool("standard", "page_probe", {"domain": "sbi-kyc-update.in"}, 14, 650, [
        ev("page_probe", "C9", "parked", "phishing", "medium", 0.6, None,
           "Registrar parking page: no content, no form. Registered, not weaponised yet.",
           status="parked", http_status=200, has_login_form=False),
    ], 0.79, "Page Probe: parked.")
    c.provisional("standard", 664, "sleeper", "Sleeper: a high-risk SBI look-alike with no live page yet.")
    c.policy(664, "No live page, so skip Stage 3 (Deep) and watch it.")
    c.skip("deep", "No live page (parked): nothing to open. Re-check in 24 h.")
    return c.final(665, "sleeper", 0.79, SBI, 0.62, "medium",
                   "SBI's name plus 'kyc' and 'update', registered but parked: not live yet, re-check daily.",
                   cf("brand token 'sbi' removed", ["E4", "E5", "E6"], "benign", 0.21,
                      "Would be BENIGN without the 'sbi' token: the lure words alone aren't enough.",
                      domain="kyc-update.in"))


# ---------------------------------------------------------------------------
def case_disguise():
    d = "echallan.parivahan.gov.in.pay-fine.icu"
    c = Case(d, f"https://{d}/challan", d, "gallery", "pay-fine.icu")
    c.open(f"New case: {d}. {SINGLE}")
    c.tool("quick", "address_reader", {"domain": d}, 1, 3, [
        ev("address_reader", "C1", "owner_differs", "phishing", "strong", 0.85, None,
           "Real owner is pay-fine.icu. 'echallan.parivahan.gov.in' is only a sub-part the attacker chose.",
           owner="pay-fine.icu", public_suffix="icu", private_suffix=False,
           subdomain_labels=["echallan", "parivahan", "gov", "in"], embedded_suffix="gov.in"),
        ev("address_reader", "C3", "single_script", "neutral", "strong", 0, None, "Plain ASCII: no hidden letters.", scripts=["Latin"]),
    ], 0.55, "Address Reader: the real owner is pay-fine.icu.")
    c.tool("quick", "family_verifier", {"owner": "pay-fine.icu"}, 4, 1, [
        ev("family_verifier", "C2", "imitates_trust_signal", "phishing", "strong", 0.85, PARIVAHAN,
           "Borrows the gov.in trust signal without being under gov.in.",
           proofs_checked=["brand_tld", "restricted_registry", "official_list"], proofs_matched=[], imitated="gov.in"),
    ], 0.7, "Family Verifier: imitates a gov.in address it doesn't have.")
    c.tool("quick", "trick_detector", {"domain": d, "owner": "pay-fine.icu"}, 5, 12, [
        ev("trick_detector", "C5", "level_squat", "phishing", "medium", 0.95, PARIVAHAN,
           "The genuine 'echallan.parivahan.gov.in' is used as a prefix of a different owner.",
           genuine="echallan.parivahan.gov.in"),
        ev("trick_detector", "C6", "abused_tld", "phishing", "weak", 0.4, None,
           "'.icu' is a cheap ending that is common in phishing.", tld="icu"),
        ev("trick_detector", "C4", "brand_closeness", "phishing", "medium", 0.9, PARIVAHAN,
           "Closeness to echallan.parivahan.gov.in is 0.90 (the whole genuine name appears at the start).",
           closeness=0.9, genuine="echallan.parivahan.gov.in"),
    ], 0.86, "Trick Detector: level-squat on the e-Challan address.")
    c.provisional("quick", 17, "suspicious", "Suspicious: disguised as the e-Challan portal.")
    c.policy(17, "Brand signal found, so go to Stage 2 (Standard).")
    c.tool("standard", "human_eye_renderer", {"candidate": d, "genuine": "echallan.parivahan.gov.in", "view": "sms"}, 18, 320, [
        ev("human_eye_renderer", "C7", "sms_view_prefix_match", "phishing", "medium", 0.9, PARIVAHAN,
           "In the SMS text, the first 25 characters are the real e-Challan address; a reader who checks the start is fooled.",
           matching_prefix_chars=25,
           artifacts=[{"kind": "render", "path": "renders/pay-fine.icu_sms.png", "caption": "How the link reads in the SMS"}]),
    ], 0.88, "Human-Eye Renderer: reads as the genuine portal in the message.")
    c.tool("standard", "risk_model", {"domain": d}, 18, 42, [
        ev("risk_model", "C8", "ml_risk", "phishing", "weak", 0.88, None, "ML risk 0.88 (supporting signal only).", probability=0.88),
    ], 0.89, "Risk Model: high ML risk.")
    c.tool("standard", "page_probe", {"domain": d}, 18, 760, [
        ev("page_probe", "C9", "live_payment_form", "phishing", "medium", 0.75, None,
           "A live page with a payment form.", status="live", http_status=200, has_login_form=True),
    ], 0.91, "Page Probe: live payment page.")
    c.provisional("standard", 778, "suspicious", "Very suspicious: reads as the real portal, and a live payment page exists.")
    c.policy(778, "Live page, so go to Stage 3 (Deep).")
    c.tool("deep", "page_inspector", {"url": f"https://{d}/challan", "genuine_snapshot": "echallan_pay"}, 779, 2200, [
        ev("page_inspector", "C10", "visual_match", "phishing", "medium", 0.88, PARIVAHAN,
           "Screenshot matches the saved e-Challan payment page at 88%.", ssim=0.88, phash_distance=7,
           artifacts=[{"kind": "heatmap", "path": "deep/pay-fine.icu_heatmap.png", "caption": "Differences vs genuine e-Challan page"}]),
        ev("page_inspector", "C11", "fields_added", "phishing", "medium", 0.85, PARIVAHAN,
           "Same layout, but card number, CVV and OTP fields were added and the form posts to /pay.php.",
           added_inputs=["card_number", "cvv", "otp"], suspect_action=f"https://{d}/pay.php"),
    ], 0.93, "Page Inspector: a copy with added card fields.")
    c.tool("deep", "vision_ai", {"screenshot": "deep/pay-fine.icu.png"}, 779, 3000, [
        ev("vision_ai", "C12", "claimed_brand_mismatch", "phishing", "strong", 0.93, PARIVAHAN,
           "The page claims to be the Parivahan e-Challan portal, but its owner isn't under gov.in.",
           claimed_brand="Parivahan e-Challan", model="gemini-flash", temperature=0),
        ev("vision_ai", "C13", "asks_sensitive", "phishing", "medium", 0.9, PARIVAHAN,
           "Asks for vehicle number, card number, CVV and OTP.", asks_for=["vehicle_number", "card_number", "cvv", "otp"]),
    ], 0.95, "Vision AI: claims to be e-Challan, asks for card details.")
    c.tool("deep", "credential_tracker", {"url": f"https://{d}/challan"}, 779, 5100, [
        ev("credential_tracker", "C14", "credentials_to_foreign_domain", "phishing", "strong", 0.85, PARIVAHAN,
           "Dummy card details were POSTed to pay-fine.icu/pay.php (same-origin relay).",
           first_hop=f"https://{d}/pay.php", relay="same_origin", dummy_credentials=True, requests_captured=9),
        ev("credential_tracker", "C15", "accepts_any_credentials", "phishing", "strong", 0.95, PARIVAHAN,
           "The page accepted a made-up card and OTP and showed 'Payment successful'.",
           accepted=True, redirect_after=None),
    ], 0.98, "Credential Tracker: accepts fake card details.")
    c.hard_rule(5879, "H2_brand_claim_foreign_credentials", ["E12", "E14", "E15"], also_fired=["H3_accepts_any_credentials"])
    return c.final(5880, "phishing", 0.98, PARIVAHAN, 0.9, "high",
                   "Starts with the real e-Challan address but is owned by pay-fine.icu, copies the payment page and accepts any card.",
                   cf("page rejects fake details and posts to echallan.parivahan.gov.in", ["E11", "E14", "E15"], "needs_review", 0.66,
                      "Would only drop to NEEDS REVIEW if the page rejected fake details and sent data to the real portal: the name alone is already high risk."),
                   notes="The Credential Tracker sees only the first hop; server-side exfiltration (PHP mail) is invisible to it.")


# ---------------------------------------------------------------------------
def case_brandless_clone():
    d = "kx72-secure.top"
    c = Case(d, f"https://{d}/", d, "gallery", d)
    c.open(f"New case: {d}. {SINGLE}")
    c.tool("quick", "address_reader", {"domain": d}, 1, 2, [
        ev("address_reader", "C1", "owner_resolved", "neutral", "strong", 0, None,
           "Real owner is kx72-secure.top (public suffix 'top').", owner=d, public_suffix="top", private_suffix=False),
        ev("address_reader", "C3", "single_script", "neutral", "strong", 0, None, "Plain ASCII: no hidden letters.", scripts=["Latin"]),
    ], 0.05, "Address Reader: ordinary name.")
    c.tool("quick", "family_verifier", {"owner": d}, 3, 1, [
        ev("family_verifier", "C2", "no_brand_to_verify", "neutral", "strong", 0, None,
           "The name points to no protected brand, so there is no family to check.",
           proofs_checked=[], proofs_matched=[]),
    ], 0.05, "Family Verifier: nothing to verify.")
    c.tool("quick", "trick_detector", {"domain": d, "owner": d}, 4, 10, [
        ev("trick_detector", "C4", "far_from_all_brands", "genuine", "medium", 0.9, None,
           "Far from every protected brand (best: SBI at 0.08).", per_brand={"sbi": 0.08, "paytm": 0.05}),
        ev("trick_detector", "C6", "abused_tld", "phishing", "weak", 0.4, None,
           "'.top' is a cheap ending that is common in phishing.", tld="top"),
    ], 0.15, "Trick Detector: no naming trick.")
    c.provisional("quick", 14, "benign", "Benign by name: it resembles no brand. (Every name-only tool stops here.)")
    c.policy(14, f"{SINGLE.split(',')[0]}: continue to Stage 2 anyway.")
    c.tool("standard", "risk_model", {"domain": d}, 15, 37, [
        ev("risk_model", "C8", "ml_risk", "phishing", "weak", 0.63, None, "ML risk 0.63 (supporting signal only).", probability=0.63),
    ], 0.3, "Risk Model: moderate ML risk.")
    c.tool("standard", "page_probe", {"domain": d}, 15, 720, [
        ev("page_probe", "C9", "live_login_form", "phishing", "medium", 0.7, None,
           "A live page with a login form.", status="live", http_status=200, has_login_form=True),
    ], 0.52, "Page Probe: live login form.")
    c.provisional("standard", 735, "suspicious", "Suspicious: no brand in the name, but a live login form.")
    c.policy(735, "No brand signal, but a login page exists: go to Stage 3 (Deep). It could be a brand-less clone.")
    c.tool("deep", "page_inspector", {"url": f"https://{d}/", "genuine_snapshot": "sbi_login"}, 736, 2300, [
        ev("page_inspector", "C10", "visual_match", "phishing", "medium", 0.96, SBI,
           "Screenshot matches the saved SBI login page at 96%.", ssim=0.96, phash_distance=3,
           artifacts=[{"kind": "heatmap", "path": "deep/kx72-secure.top_heatmap.png", "caption": "Differences vs genuine SBI login"}]),
        ev("page_inspector", "C11", "form_target_changed", "phishing", "medium", 0.85, SBI,
           "Same structure as SBI's page, but the form posts to /auth.php on kx72-secure.top.",
           suspect_action=f"https://{d}/auth.php"),
    ], 0.8, "Page Inspector: a copy of SBI's login page.")
    c.tool("deep", "vision_ai", {"screenshot": f"deep/{d}.png"}, 736, 2800, [
        ev("vision_ai", "C12", "claimed_brand_mismatch", "phishing", "strong", 0.95, SBI,
           "The page claims to be State Bank of India, but its owner isn't in SBI's family.",
           claimed_brand="State Bank of India", model="gemini-flash", temperature=0),
        ev("vision_ai", "C13", "asks_sensitive", "phishing", "medium", 0.85, SBI,
           "Asks for username, password and OTP.", asks_for=["username", "password", "otp"]),
    ], 0.92, "Vision AI: claims SBI.")
    c.tool("deep", "credential_tracker", {"url": f"https://{d}/"}, 736, 4700, [
        ev("credential_tracker", "C14", "credentials_to_foreign_domain", "phishing", "strong", 0.9, SBI,
           "Dummy credentials were POSTed to kx72-secure.top/auth.php, outside SBI's family.",
           first_hop=f"https://{d}/auth.php", dummy_credentials=True, requests_captured=6),
        ev("credential_tracker", "C14", "direct_exfil_telegram", "phishing", "strong", 0.98, SBI,
           "The page also sent the data straight to api.telegram.org (bot token redacted; Telegram was never called by us).",
           channel="telegram", token_redacted="12345****:[REDACTED]", blocked_by_sandbox=True),
    ], 0.99, "Credential Tracker: the password goes to the page's owner and to Telegram.")
    c.hard_rule(5437, "H2_brand_claim_foreign_credentials", ["E10", "E12", "E13"], also_fired=["H4_direct_exfil_channel"])
    return c.final(5438, "phishing", 0.99, SBI, 0.08, "high",
                   "A random-looking name hosting a near-exact copy of SBI's login page that sends the password to Telegram.",
                   cf("judged by the name only (Stage 3 evidence removed)", ["E8", "E9", "E10", "E11", "E12", "E13"], "benign", 0.15,
                      "Would be BENIGN judged by the name alone, which is all a name-only tool ever sees."))


# ---------------------------------------------------------------------------
def case_genuine():
    d = "onlinesbi.sbi.bank.in"
    c = Case(d, f"https://{d}/", d, "gallery", "sbi.bank.in")
    c.open(f"New case: {d}. {SINGLE}")
    c.tool("quick", "address_reader", {"domain": d}, 1, 2, [
        ev("address_reader", "C1", "owner_resolved", "neutral", "strong", 0, None,
           "Real owner is sbi.bank.in (public suffix 'bank.in', a restricted registry).",
           owner="sbi.bank.in", public_suffix="bank.in", private_suffix=False),
        ev("address_reader", "C3", "single_script", "neutral", "strong", 0, None, "Plain ASCII: no hidden letters.", scripts=["Latin"]),
    ], 0.2, "Address Reader: owner is sbi.bank.in.")
    c.tool("quick", "family_verifier", {"owner": "sbi.bank.in"}, 3, 1, [
        ev("family_verifier", "C2", "genuine_family", "genuine", "strong", 0.98, SBI,
           "Proven SBI: under the restricted .bank.in registry, and sbi.bank.in is on SBI's official list.",
           proofs_checked=["brand_tld", "restricted_registry", "official_list"],
           proofs_matched=["restricted_registry", "official_list"],
           family_entry="sbi.bank.in", source="https://sbi.bank.in/en/web/personal-banking/digital/internet-banking",
           verified_on="2026-11-04"),
    ], 0.03, "Family Verifier: proven SBI family.")
    c.tool("quick", "trick_detector", {"domain": d, "owner": "sbi.bank.in"}, 4, 8, [
        ev("trick_detector", "C5", "no_trick", "neutral", "medium", 0, SBI,
           "No naming trick: it is a subdomain of SBI's own domain.", tokens=["onlinesbi", "sbi", "bank", "in"]),
        ev("trick_detector", "C4", "in_family", "neutral", "medium", 0, SBI,
           "Closeness 1.00: it is inside SBI's family.", closeness=1.0),
    ], 0.03, "Trick Detector: nothing to flag.")
    c.provisional("quick", 12, "genuine", "Genuine: proven SBI family. Confirming the page in later stages.")
    c.policy(12, "Genuine family: still confirm the page and the login destination in Deep.")
    c.tool("standard", "risk_model", {"domain": d}, 13, 36, [
        ev("risk_model", "C8", "ml_risk", "genuine", "weak", 0.88, None,
           "ML risk 0.12 (supporting signal only).", probability=0.12),
    ], 0.03, "Risk Model: low ML risk.")
    c.tool("standard", "page_probe", {"domain": d}, 13, 610, [
        ev("page_probe", "C9", "live_login_form", "neutral", "medium", 0, SBI,
           "Live SBI login page (expected for the bank's own site).", status="live", http_status=200, has_login_form=True),
    ], 0.03, "Page Probe: live login page.")
    c.provisional("standard", 623, "genuine", "Genuine: nothing contradicts the ownership proof.")
    c.policy(623, "Live page, so go to Stage 3 (Deep) to confirm.")
    c.tool("deep", "page_inspector", {"url": f"https://{d}/", "genuine_snapshot": "sbi_login"}, 624, 1800, [
        ev("page_inspector", "C10", "matches_genuine_snapshot", "genuine", "medium", 0.99, SBI,
           "Matches the saved genuine SBI login page at 99%.", ssim=0.99, phash_distance=1),
    ], 0.02, "Page Inspector: the genuine page.")
    c.tool("deep", "vision_ai", {"screenshot": f"deep/{d}.png"}, 624, 2700, [
        ev("vision_ai", "C12", "claimed_brand_matches_owner", "genuine", "strong", 0.95, SBI,
           "The page claims to be SBI, and the owner is in SBI's family.",
           claimed_brand="State Bank of India", model="gemini-flash", temperature=0),
    ], 0.02, "Vision AI: claims SBI, and it is SBI.")
    c.tool("deep", "credential_tracker", {"url": f"https://{d}/", "mode": "snapshot_replay"}, 624, 3100, [
        ev("credential_tracker", "C14", "credentials_stay_in_family", "genuine", "strong", 0.95, SBI,
           "The login form posts to onlinesbi.sbi.bank.in, inside SBI's family. Replayed from the saved snapshot: nothing was sent to SBI.",
           first_hop=f"https://{d}/retail/login", mode="snapshot_replay"),
    ], 0.02, "Credential Tracker: the password stays with SBI.")
    c.hard_rule(3724, "H1_genuine_family", ["E3", "E10"])
    return c.final(3725, "genuine", 0.02, SBI, 1.0, "high",
                   "Looks odd, but it's provably SBI's: under the restricted .bank.in registry and on SBI's official list, and the login stays on SBI.",
                   cf("ownership proof removed (not on the list, not under .bank.in)", ["E3"], "needs_review", 0.5,
                      "Would be NEEDS REVIEW without the ownership proof: the proof, not the looks, is what makes it green."))


# ---------------------------------------------------------------------------
def case_benign_noise():
    d = "thanksbitcoin.com"
    c = Case(d, d, d, "nrd_snapshot", d)
    c.open(f"New case: {d} from the newly-registered-domains snapshot. {BATCH}")
    c.tool("quick", "address_reader", {"domain": d}, 1, 2, [
        ev("address_reader", "C1", "owner_resolved", "neutral", "strong", 0, None,
           "Real owner is thanksbitcoin.com (public suffix 'com').", owner=d, public_suffix="com", private_suffix=False),
        ev("address_reader", "C3", "single_script", "neutral", "strong", 0, None, "Plain ASCII: no hidden letters.", scripts=["Latin"]),
    ], 0.05, "Address Reader: ordinary name.")
    c.tool("quick", "family_verifier", {"owner": d}, 3, 1, [
        ev("family_verifier", "C2", "no_brand_to_verify", "neutral", "strong", 0, None,
           "No protected brand in the name, so there is no family to check.", proofs_checked=[], proofs_matched=[]),
    ], 0.05, "Family Verifier: nothing to verify.")
    c.tool("quick", "trick_detector", {"domain": d, "owner": d}, 4, 9, [
        ev("trick_detector", "C5", "substring_not_token", "genuine", "weak", 0.7, None,
           "'sbi' appears only across a word boundary (thank|s|bi|tcoin); segmented as 'thanks bitcoin', so it isn't the brand.",
           substring_hit="sbi", tokens=["thanks", "bitcoin"]),
        ev("trick_detector", "C4", "far_from_all_brands", "genuine", "medium", 0.9, None,
           "Far from every protected brand (best: SBI at 0.11).", per_brand={"sbi": 0.11, "paytm": 0.03}),
    ], 0.04, "Trick Detector: a substring hit, not a brand token.")
    c.provisional("quick", 13, "benign", "Benign: no brand signal.")
    c.policy(13, "Batch input and no brand signal, so stop after Stage 1.")
    c.skip("standard", "Batch input with no brand signal: not escalated.")
    c.skip("deep", "Batch input with no brand signal: not escalated.")
    return c.final(14, "benign", 0.04, None, None, "high",
                   "Contains the letters 'sbi' only by accident inside 'thanks bitcoin'; it resembles no protected brand.",
                   None, notes="Substring tools (openSquat-style keyword match) flag this; token-aware parsing doesn't.")


CASES = {
    "01-invisible-letter.json": case_invisible_letter,
    "02-twin-letters.json": case_twin_letters,
    "03-sleeper-combosquat.json": case_sleeper,
    "04-subdomain-disguise.json": case_disguise,
    "05-brandless-clone.json": case_brandless_clone,
    "06-genuine-weirdo.json": case_genuine,
    "07-benign-substring.json": case_benign_noise,
}


def main() -> int:
    failed = False
    for name, build in CASES.items():
        verdict = build()
        problems = validate_verdict(verdict)
        if problems:
            failed = True
            print(f"{name}: INVALID")
            for p in problems:
                print(f"  - {p}")
            continue
        (HERE / name).write_text(json.dumps(verdict, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"{name}: ok ({verdict['label']}, {len(verdict['evidence'])} evidence, {len(verdict['trace'])} steps)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
