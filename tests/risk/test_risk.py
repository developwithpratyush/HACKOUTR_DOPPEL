"""P7: the Risk Model (C8): host features, pure-Python inference, the evidence item, and its place in the brain."""

import json
import math
import time

import pytest

from doppel.brain import fusion
from doppel.brain.brain import Brain
from doppel.contract import REPO_ROOT, validate_evidence_item, validate_verdict
from doppel.risk import features as F
from doppel.risk.model import NEUTRAL_BAND, default_model, predict, risk_model

MODEL = default_model()


@pytest.mark.parametrize("raw,host", [
    ("https://www.SBI.co.in/login?x=1", "sbi.co.in"),
    ("http://www.www.example.com", "example.com"),
    ("www.com", "www.com"),                       # a registrable name that is just 'www'
    ("pаytm.com", "paytm.com"),                   # Cyrillic а folded: hidden letters are C3's job, not the model's
    ("xn--pytm-53d.com", "paytm.com"),            # the same name in punycode
    ("pāyţm.com", "paytm.com"),                   # marks stripped
    ("sbi-kyc.web.app:8443/x", "sbi-kyc.web.app"),
])
def test_model_host_strips_scheme_www_path_and_folds_letters(raw, host):
    assert F.model_host(raw) == host


def test_registrable_groups_free_hosting_users_together():
    assert F.registrable("a.b.example.co.in") == "example.co.in"
    assert F.registrable("sbi-kyc.web.app") == "web.app"     # ICANN level: one group per platform


def test_tfidf_vector_is_l2_normalised_and_includes_the_tld_token():
    v = F.sparse("paytm-kyc-update.com", MODEL.idf)
    assert math.isclose(math.sqrt(sum(x * x for x in v.values())), 1.0, rel_tol=1e-9)
    assert F.bucket("tld=com") in v
    assert len(F.dense("paytm.com")) == len(F.DENSE) == len(MODEL.d_w)


def test_predictions_are_probabilities_deterministic_and_fast():
    names = ["paytm.com", "sbi-kyc-update.in", "thanksbitcoin.com", "secure-login-verify-account.top", "8.8.8.8"]
    for n in names:
        p = predict(n)
        assert 0.0 <= p <= 1.0
        assert predict(n) == p
    t = time.perf_counter()
    for _ in range(200):
        for n in names:
            MODEL.predict_host(F.model_host(n))
    per_call_ms = (time.perf_counter() - t) / 1000 * 1000
    assert per_call_ms < 2.0, per_call_ms


def test_obvious_cases_point_the_right_way():
    assert predict("secure-update-account-verify-login.web.app") > 0.9
    assert predict("wikipedia.org") < 0.3


def test_calibration_is_monotone_and_clipped():
    xs = [i / 50 for i in range(51)]
    ys = [MODEL.calibrate(x) for x in xs]
    assert all(b >= a for a, b in zip(ys, ys[1:]))
    assert MODEL.calibrate(-1) == MODEL.iso_y[0] and MODEL.calibrate(2) == MODEL.iso_y[-1]


def test_contributions_add_up_to_the_logit():
    host = "hdfc-netbanking-kyc.online"
    full = MODEL.predict_host(host, explain=10_000)
    total = MODEL.b + sum(t["contribution"] for t in full.top)
    assert math.isclose(total, full.logit, abs_tol=0.002 * len(full.top) + 1e-6)
    assert full.raw == pytest.approx(1 / (1 + math.exp(-full.logit)), abs=1e-4)


@pytest.mark.parametrize("raw", ["paytrn.com", "sbi-kyc-update.in", "secure-login-verify.top", "sbi.co.in.example.org"])
def test_evidence_item_follows_the_contract_convention(raw):
    pred, [item] = risk_model(raw)
    assert validate_evidence_item(item) == []
    assert (item["tool"], item["stage"], item["criterion"], item["finding"], item["strength"]) == \
        ("risk_model", "standard", "C8", "ml_risk", "weak")
    p = item["details"]["probability"]
    assert p == pred.probability
    if abs(p - 0.5) < NEUTRAL_BAND:
        assert item["points_to"] == "neutral" and item["score"] == 0
    elif p >= 0.5:
        assert item["points_to"] == "phishing" and item["score"] == pytest.approx(p)
    else:
        assert item["points_to"] == "genuine" and item["score"] == pytest.approx(1 - p)
    assert item["details"]["model_input"] == pred.host
    assert "can't see look-alikes" in item["summary"]


def test_fusion_points_for_ml_risk_are_continuous_and_weak():
    def item(p):
        side = "phishing" if p >= 0.5 else "genuine"
        return {"finding": "ml_risk", "points_to": side, "strength": "weak", "score": p if p >= 0.5 else 1 - p,
                "criterion": "C8"}
    assert fusion.points(item(0.501)) == pytest.approx(fusion.points(item(0.499)), abs=0.01)
    assert fusion.points(item(1.0)) == pytest.approx(fusion.WEIGHT["weak"])
    assert fusion.points(item(0.0)) == pytest.approx(-fusion.WEIGHT["weak"])


BRAIN = Brain()


def test_brain_runs_the_risk_model_in_standard_and_the_trace_names_it():
    v = BRAIN.investigate("paytrn.com", "paste")
    assert validate_verdict(v) == []
    std = v["stages"][1]
    assert std["tools"] == ["human_eye_renderer", "risk_model", "page_probe"]
    ml = [e for e in v["evidence"] if e["tool"] == "risk_model"]
    assert len(ml) == 1 and ml[0]["evidence_id"] in std["evidence_ids"]
    step = next(s for s in v["trace"] if s.get("tool") == "risk_model")
    assert step["message"].startswith("Risk Model: ML risk") and step["evidence_ids"] == [ml[0]["evidence_id"]]
    assert v["meta"]["engine_version"].startswith("0.0.1+p")


def test_brain_skips_the_risk_model_for_proven_family_and_unescalated_batch_names():
    v = BRAIN.investigate("sbi.co.in", "paste")
    assert v["label"] == "genuine" and "risk_model" not in v["stages"][1]["tools"]
    v = BRAIN.investigate("107escondido.com", "nrd_snapshot")      # batch, no brand signal: stops after Quick
    assert all(e["tool"] != "risk_model" for e in v["evidence"])


def test_a_name_alone_still_never_reaches_phishing():
    # the ML model is weak evidence: a phishy-looking name without a page stays NEEDS REVIEW at most
    v = BRAIN.investigate("sbi-kyc-update-secure-login.top", "paste")
    ml = next(e for e in v["evidence"] if e["tool"] == "risk_model")
    assert ml["details"]["probability"] > 0.5
    assert v["label"] in ("needs_review", "sleeper")


def test_eval_report_records_parity_and_the_shift():
    r = json.loads((REPO_ROOT / "docs" / "eval" / "p7-risk-model.json").read_text(encoding="utf-8"))
    assert r["parity"]["max_abs_diff"] < 1e-3                      # pure Python == scikit-learn
    assert r["held_out"][0]["roc_auc"] > 0.85
    assert r["shift"]["nrd"]["share_ge_0.5"] > r["phiusiil_test_by_label"]["legitimate"]["share_ge_0.5"]
    leak = json.loads((REPO_ROOT / "docs" / "eval" / "p7-leakage.json").read_text(encoding="utf-8"))
    assert "URLSimilarityIndex" in leak["leaky"]
    assert leak["ablation"][0]["accuracy"] > 0.99 > leak["ablation"][-1]["accuracy"]
