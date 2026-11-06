"""P13 Campaign Radar: learned naming templates, certificate recipes (CT cache only), the campaigns they form,
the brain's weak C18 signal, and the split-conformal review line."""

import json

import pytest

from doppel.campaign.index import campaign_radar, load_campaigns
from doppel.campaign.radar import build, index
from doppel.campaign.recipe import recipe, same_recipe
from doppel.campaign.template import Templater
from doppel.family import load_registry

ECHALLAN = ["in-echallan.online", "in-echallan.date", "in-echallan.party", "in-echallan.trade", "ln-echallan.bid"]
INDIAPOST = ["indiapost.gov.atxxycp.top", "indiapost.gov.bdzhpc.top", "indiapost.gov.bilibil.top",
             "indiapost.gov.ceibigj.top"]
DECOYS = ["paytrn.com", "sbi-kyc-update.in", "hdfc-kyc-verify.in", "mail.berlin", "mail.boutique",
          "cpina31gmail-com.chatgpt.site", "fmfahadbb123gmail-com.workers.dev", "indiapostnm.vip", "indiapostlk.vip"]


@pytest.fixture(scope="module")
def reg():
    return load_registry()


@pytest.fixture(scope="module")
def tpl(reg):
    return Templater(reg)


def test_templates_are_learned_not_written(tpl):
    assert tpl.of("in-echallan.online")[0] == tpl.of("ln-echallan.bid")[0] == "in-<B>.<tld>"     # l posing as i
    assert tpl.of("indiapost.gov.atxxycp.top")[0] == "<B>.gov.<r>.<tld>"
    assert tpl.specific("in-<B>.<tld>") and tpl.specific("<B>.gov.<r>.<tld>")
    assert not tpl.specific("<B>.<tld>") and not tpl.specific("<B><r>.<tld>")          # strangers sharing a brand
    assert not tpl.specific(tpl.of("mail.berlin")[0])                                  # no brand spelled out
    assert not tpl.specific(tpl.of("cpina31gmail-com.chatgpt.site")[0])                # email-shaped: "com" is filler


def test_echallan_recipe_from_the_ct_cache():
    a, b = recipe("in-echallan.date"), recipe("in-echallan.party")
    assert a and b and a["shapes"] == b["shapes"]
    assert any("S3" in s for s in a["shapes"])                    # one random 3-letter subdomain per domain
    assert same_recipe(a, b) >= 0.6
    assert recipe("never-looked-up-example.com") is None          # no cache, no network: no recipe


def _items(names, source):
    return [{"name": n, "owner": n.split(".", 2)[-1] if n.startswith("indiapost.gov.") else n, "brand": None,
             "label": "needs_review", "risk": 0.9, "tricks": "", "source": source, "first_seen": None} for n in names]


def test_both_campaigns_found_and_decoys_stay_apart(reg, tpl):
    items = _items(ECHALLAN, "nrd") + _items(INDIAPOST, "pdb") + _items(DECOYS, "live")
    brand = {n: "parivahan" for n in ECHALLAN} | {n: "india_post" for n in INDIAPOST}
    for it in items:
        it["brand"] = brand.get(it["name"], "google")
    r = build(items, reg, tpl)
    sets = [set(c["members_ids"]) for c in r["campaigns"]]
    assert set(ECHALLAN) in sets
    assert {n.split(".", 2)[-1] for n in INDIAPOST} in sets
    echallan = next(c for c in r["campaigns"] if set(c["members_ids"]) == set(ECHALLAN))
    assert {"cert_recipe", "naming_template"} <= set(echallan["links"]) and echallan["recipe"]["first_cert"]
    linked = {m for s in sets for m in s}
    assert not linked & set(DECOYS)
    idx = index(r)
    assert idx["in-echallan.online"]["size"] == 5


def test_c18_is_weak_and_never_decides(reg):
    from doppel.address import address_reader
    from doppel.brain import fusion

    r, _ = address_reader("in-echallan.online")
    hit = {"campaign": "Cx", "size": 5, "links": ["cert_recipe", "naming_template"], "strength": "strong",
           "template": "in-<B>.<tld>", "peers": ECHALLAN[1:]}
    ev = campaign_radar(r, hit, reg.brands[0])
    assert ev[0]["criterion"] == "C18" and ev[0]["strength"] == "weak" and ev[0]["points_to"] == "phishing"
    assert fusion.points(ev[0]) <= 0.5
    assert fusion.decide(genuine=False, brand_signal=False, review_host=False, page=None, risk_score=0.99,
                         credential_form=False)[0] == "benign"


def test_committed_index_puts_the_campaigns_in_the_brain():
    from doppel.brain.brain import Brain
    from doppel.contract import validate_verdict

    if not load_campaigns():
        pytest.skip("no data/campaigns/index.json yet (run `doppel campaigns`)")
    b = Brain(deep=False)
    v = b.investigate("in-echallan.party", "file", counterfactual=False)
    c18 = [e for e in v["evidence"] if e["tool"] == "campaign_radar"]
    assert c18 and c18[0]["details"]["size"] == 5 and v["label"] == "needs_review"
    assert not validate_verdict(v)


def test_review_line_splits_the_queue_without_changing_labels():
    from doppel.brain import fusion

    hi = fusion.decide(genuine=False, brand_signal=True, review_host=False, page=None, risk_score=0.9, credential_form=False)
    lo = fusion.decide(genuine=False, brand_signal=True, review_host=False, page=None, risk_score=0.3, credential_form=False)
    assert hi == ("needs_review", "medium") and lo == ("needs_review", "low")


def test_conformal_quantile():
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("p13c", Path(__file__).resolve().parents[2] / "bench" / "p13_conformal.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    tau, k = m.tau_of([i / 100 for i in range(1, 100)])      # n = 99, alpha 0.05 -> k = floor(5) = 5
    assert k == 5 and tau == 0.05
    rec = Path(__file__).resolve().parents[2] / "docs" / "eval" / "p13-conformal.json"
    if rec.is_file():
        from doppel.brain import fusion

        assert json.loads(rec.read_text())["calibration"]["tau"] == fusion.REVIEW_TAU     # the constant is the bench's


def test_api_serves_the_radar():
    from fastapi.testclient import TestClient

    from doppel.api.app import app

    with TestClient(app) as c:
        r = c.get("/api/campaigns?limit=5").json()
    assert "campaigns" in r and len(r["campaigns"]) <= 5
    ids = {n["id"] for n in r["graph"]["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in r["graph"]["edges"])
