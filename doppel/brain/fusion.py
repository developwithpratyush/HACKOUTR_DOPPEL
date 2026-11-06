"""Rule-based fusion v1 (P5): evidence -> risk score, and the label policy.

**Risk score.** Log-odds points, hand-set (P11 replaces them with a combiner learned on the P3 train split):

    risk = sigmoid(PRIOR + sum over criteria of the strongest phishing points - the strongest genuine points)
    points = WEIGHT[strength] * score

Only the strongest item *per criterion* counts in each direction, so one fact reported twice (a twin-letter
trick and its closeness) isn't counted twice. PRIOR = logit(0.10). It's a **risk score**, not a calibrated
probability: the base rate of phishing among new domains is far lower than 10%, and we say so.

**ML risk (C8, P7)** is the one finding scored by its distance from a coin toss: ``points = WEIGHT * (2*score - 1)``.
Its score follows the contract convention (p or 1 - p, whichever side p is on), so plain ``WEIGHT * score`` would
jump from -0.25 to +0.25 as p crosses 0.5. Its strength is ``weak``, so it moves the log-odds by at most 0.5.

**Label policy**, in order (hard rules first, then the evidence):

| when | label |
|---|---|
| H1: ownership proven (Family Verifier) | genuine |
| a brand signal and the page is parked or missing | sleeper |
| a brand signal, a live login/payment form, risk >= PHISH_RISK | phishing |
| a brand signal otherwise (page not checked, page asks for nothing, vetted-registry or brand-owned host) | needs_review (confidence medium at risk >= REVIEW_TAU, else low: the P13 conformal line) |
| no brand signal, but a live login/payment form (could be a brand-less clone; Deep decides in P8) | needs_review |
| no brand signal | benign |

A name alone never yields PHISHING: brand affiliates and same-name businesses look exactly like combosquats
(docs/eval/p4-arena.md), so without page evidence the answer is NEEDS REVIEW, ranked by risk.

**Hard rules from the Credential Tracker (P9)**, checked before the table above (``hard_rules``), in the
contract's priority order: H2 the page claims a brand + credentials leave its family; H3 accepts made-up
credentials; H4 a direct exfil channel (Telegram, Discord, Google Forms). Any of them -> PHISHING. They never
fire on a proven family member: if a genuine page's login leaves the family, H1 doesn't fire either and the
answer is NEEDS REVIEW (possibly compromised: tell the brand; don't blocklist its domain).
"""

from __future__ import annotations

import math

WEIGHT = {"strong": 3.0, "medium": 1.6, "weak": 0.5}
PRIOR = math.log(0.10 / 0.90)
PHISH_RISK = 0.85
# P13 split-conformal review line (bench/p13_conformal.py -> docs/eval/p13-conformal.json): calibrated on the P3 dev
# look-alikes (n = 1,963, alpha = 0.05, k = 98), so at most 5% of real look-alikes score below it. It splits the
# NEEDS REVIEW queue (confidence medium above, low below); it never changes a label: as a BENIGN line it would cost
# 61 test look-alikes, and the no-degradation gate forbids any drop.
REVIEW_TAU = 0.446
CREDENTIAL_FINDINGS = {"live_login_form", "live_payment_form"}
EMPTY_PAGE_FINDINGS = {"parked", "no_page"}


def points(item: dict) -> float:
    if item["points_to"] == "neutral":
        return 0.0
    score = item["score"]
    if item.get("finding") == "ml_risk":
        score = max(0.0, 2 * score - 1)
    p = WEIGHT[item["strength"]] * score
    return p if item["points_to"] == "phishing" else -p


def risk(evidence: list[dict]) -> float:
    best_up: dict[str, float] = {}
    best_down: dict[str, float] = {}
    for it in evidence:
        p = points(it)
        c = it["criterion"]
        if p > 0:
            best_up[c] = max(best_up.get(c, 0.0), p)
        elif p < 0:
            best_down[c] = min(best_down.get(c, 0.0), p)
    z = PRIOR + sum(best_up.values()) + sum(best_down.values())
    return round(1 / (1 + math.exp(-z)), 3)


LEAVE_FINDINGS = {"credentials_to_foreign_domain", "direct_exfil_telegram", "direct_exfil_discord",
                  "direct_exfil_google_forms"}
DIRECT_FINDINGS = {"direct_exfil_telegram", "direct_exfil_discord", "direct_exfil_google_forms"}
RULE_TEXT = {
    "H2_brand_claim_foreign_credentials": ("The page claims a brand, the owner isn't in that brand's family, and the "
                                           "credentials leave to a domain outside it."),
    "H3_accepts_any_credentials": "The page accepts made-up credentials: a real login rejects them.",
    "H4_direct_exfil_channel": "What the victim types goes straight to Telegram, Discord or Google Forms.",
}


def hard_rules(evidence: list[dict], genuine: bool) -> list[tuple[str, list[str]]]:
    """Phishing hard rules H2-H4 that fire, in priority order, each with the evidence that fires it.

    Never for a proven family member: a genuine page whose login leaves the family is NEEDS REVIEW (possibly
    compromised), not a phishing domain to block (see ``leaves_family``)."""
    if genuine:
        return []
    by = lambda names: [e for e in evidence if e["finding"] in names and e["points_to"] == "phishing"]   # noqa: E731
    out = []
    claim, leave = by({"claimed_brand_mismatch"}), by(LEAVE_FINDINGS)
    if claim and leave:
        out.append(("H2_brand_claim_foreign_credentials", [claim[0]["evidence_id"]] + [e["evidence_id"] for e in leave]))
    if acc := by({"accepts_any_credentials"}):
        out.append(("H3_accepts_any_credentials", [e["evidence_id"] for e in acc]))
    if direct := by(DIRECT_FINDINGS):
        out.append(("H4_direct_exfil_channel", [e["evidence_id"] for e in direct]))
    return out


def leaves_family(evidence: list[dict]) -> list[dict]:
    """Credential Tracker items saying the typed details left the brand's family (C14)."""
    return [e for e in evidence if e["finding"] in LEAVE_FINDINGS and e["points_to"] == "phishing"]


def decide(*, genuine: bool, brand_signal: bool, review_host: bool, page: str | None, risk_score: float,
           credential_form: bool) -> tuple[str, str]:
    """(label, confidence). ``page`` is the Page Probe finding, or None when the probe didn't run."""
    if genuine:
        return "genuine", "high"
    if brand_signal and page in EMPTY_PAGE_FINDINGS:
        return "sleeper", "medium"
    if brand_signal and credential_form and risk_score >= PHISH_RISK and not review_host:
        return "phishing", "high" if risk_score >= 0.95 else "medium"
    if brand_signal or review_host:
        return "needs_review", "medium" if brand_signal and risk_score >= REVIEW_TAU else "low"
    if credential_form:
        return "needs_review", "low"
    return "benign", "high" if risk_score < 0.1 else "medium"
