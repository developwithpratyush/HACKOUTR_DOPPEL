"""P11: Certificate Forensics (C16/C17), family auto-discovery and its guards, the ablation switch, fixes (a)-(d).

No network: ``DOPPEL_OFFLINE=1`` (tests/conftest.py). Certificates come from the committed cache (data/certs/)
and the committed discovery result (data/brands/discovered.yaml), or from hand-made certificate dicts.
"""

import pytest

from doppel.address import read_address
from doppel.brain.brain import Brain
from doppel.certs import ct, discover, forensics, tls
from doppel.certs.facts import covers, san_covers
from doppel.certs.index import load_index, parse
from doppel.contract import validate_evidence_item, validate_verdict
from doppel.deep import in_family_of
from doppel.family import check_family, load_registry

REG = load_registry()
BRAIN = Brain(deep=False)


def verdict(name, source="file", certs=None):
    v = BRAIN.investigate(name, source=source, certs=certs)
    assert validate_verdict(v) == [], validate_verdict(v)
    return v


def findings(v, tool=None):
    return {e["finding"] for e in v["evidence"] if tool is None or e["tool"] == tool}


# ------------------------------------------------------------------ certificate facts ---

def test_wildcard_covers_exactly_one_label():
    assert san_covers("*.google.co.in", "www.google.co.in")
    assert not san_covers("*.google.co.in", "google.co.in")
    assert not san_covers("*.google.co.in", "a.b.google.co.in")
    assert san_covers("Google.com", "google.com")
    assert covers({"sans": ["a.com", "*.b.com"]}, "x.b.com") == "*.b.com"


# ------------------------------------------------------------------ safety: no TLS to suspects ---

@pytest.mark.parametrize("host", ["in-echallan.online", "hdfc-pan-up-date2.web.app", "sbicard.com",
                                  "docs.google.com", "google.co.in"])
def test_live_tls_is_refused_for_anything_not_proven_genuine(host):
    with pytest.raises(tls.NotProvenGenuine):
        tls.read_seed(host, REG)


def test_live_tls_is_allowed_for_a_proven_seed_and_replays_from_cache():
    rec = tls.read_seed("google.com", REG)            # offline: served from data/certs/tls/
    assert rec["source"] == "live_tls" and "*.google.co.in" in rec["cert"]["sans"]


# ------------------------------------------------------------------ discovery guards ---

def _cert(sans, o=None, sha="x" * 64):
    return {"sha256": sha, "sans": sans, "subject": {"o": o, "c": None, "cn": None}, "issuer": {"o": "Test CA"},
            "validation": "OV" if o else "DV"}


def test_san_link_to_a_proven_seed_is_accepted():
    res = discover.classify(_cert(["google.com", "*.google.com", "*.google.co.in", "urchin.com"]), "google",
                            "google.com", "live_tls", "2026-11-06T00:00:00Z", REG)
    got = {(e["domain"], e["include_subdomains"]) for e in res["accepted"]}
    assert ("google.co.in", True) in got and ("urchin.com", True) in got


def test_guard3_platform_wildcard_proves_the_platform_never_the_tenant():
    # Google's withgoogle.com certificate really lists *.appspot.com; an HDFC scam lives on *.uk.r.appspot.com
    res = discover.classify(_cert(["withgoogle.com", "appspot.com", "*.appspot.com", "*.uk.r.appspot.com",
                                   "*.docs.google.com"]), "google", "withgoogle.com", "live_tls", "2026-11-06T00:00:00Z", REG)
    accepted = {e["domain"]: e for e in res["accepted"]}
    assert accepted["appspot.com"]["include_subdomains"] is False          # the platform's own name, exact
    assert not any(d.endswith(".appspot.com") for d in accepted)
    assert {p["san"] for p in res["platform_only"]} >= {"*.appspot.com", "*.uk.r.appspot.com", "*.docs.google.com"}


def test_guard2_shared_cdn_certificate_is_skipped():
    res = discover.classify(_cert(["google.com", "unrelated-shop.com"], o="Cloudflare, Inc."), "google",
                            "google.com", "live_tls", "2026-11-06T00:00:00Z", REG)
    assert not res.get("accepted") and "CDN" in res["review"][0]["reason"]


def test_guard1_a_certificate_without_a_proven_name_proves_nothing():
    res = discover.classify(_cert(["stranger.com", "other.com"]), "google", "google.com", "ct_sslmate",
                            "2026-11-06T00:00:00Z", REG)
    assert not res.get("accepted") and res["review"]


def test_a_certificate_spanning_two_brands_goes_to_review():
    res = discover.classify(_cert(["google.com", "paytm.com", "x.com"]), "google", "google.com", "live_tls",
                            "2026-11-06T00:00:00Z", REG)
    assert not res.get("accepted") and "another brand" in res["review"][0]["reason"]


def test_committed_discovery_proves_the_demo_names_and_not_the_traps():
    idx = load_index()
    for name, brand in [("google.co.in", "google"), ("www.google.co.in", "google"), ("google-analytics.com", "google"),
                        ("googleapis.com", "google"), ("urchin.com", "google"), ("gvt1.com", "google"),
                        ("upichalega.com", "npci"), ("rupay.co.in", "npci")]:
        assert idx.lookup(name) and idx.lookup(name)["brand"] == brand, name
    for name in ["x.googleapis.com", "us-central1-aiplatform.rep.googleapis.com", "evil.appspot.com",
                 "ezhzxywnitjrudyxhdfcuvotob-dot-gloff849483.uk.r.appspot.com", "hdfc-pan-up-date2.web.app"]:
        assert idx.lookup(name) is None, name


def test_registry_doesnt_hand_list_the_names_discovery_must_prove():
    google = REG.brand("google")
    assert not {e.domain for e in google.family} & {"google.co.in", "googleapis.com", "google-analytics.com"}


# ------------------------------------------------------------------ C16 in the brain + the ablation switch ---

def test_google_co_in_needs_review_without_certificates_and_genuine_with():
    off, on = verdict("google.co.in", "paste", certs=False), verdict("google.co.in", "paste", certs=True)
    assert off["label"] == "needs_review" and off["meta"]["checks_off"] == ["C16", "C17"]
    assert on["label"] == "genuine" and on["hard_rule"]["id"] == "H1_genuine_family"
    san = next(e for e in on["evidence"] if e["finding"] == "certificate_san_link")
    assert san["evidence_id"] in on["hard_rule"]["evidence_ids"]
    assert san["details"]["matched_san"] == "*.google.co.in" and len(san["details"]["cert_sha256"]) == 64
    assert on["counterfactual"]["label"] == "needs_review"
    assert "checks_off" not in on["meta"]


def test_a_name_no_rule_connects_to_google_is_proven_by_the_certificate():
    assert verdict("urchin.com", certs=False)["label"] == "benign"
    v = verdict("urchin.com")
    assert v["label"] == "genuine" and v["target_brand"]["id"] == "google"


def test_web_app_scam_is_not_proven_by_googles_wildcard():
    v = verdict("hdfc-pan-up-date2.web.app", "paste")
    assert v["label"] == "needs_review" and v["target_brand"]["id"] == "hdfc"
    item = next(e for e in v["evidence"] if e["tool"] == "cert_forensics")
    assert item["finding"] == "certificate_platform_only" and item["points_to"] == "neutral"
    assert "ct_history" not in {e["tool"] for e in v["evidence"]}      # never a CT lookup for a platform tenant


def test_googleapis_tenant_stays_unproven():
    v = verdict("us-central1-aiplatform.rep.googleapis.com")
    assert v["label"] == "needs_review"
    assert "certificate_platform_only" in findings(v, "cert_forensics")


def test_proof_when_present_never_required_echallan_stays_genuine():
    # The real e-Challan site has a free DV certificate (no Organisation), exactly like the attackers'.
    for certs in (True, False):
        v = verdict("echallan.parivahan.gov.in", "paste", certs=certs)
        assert v["label"] == "genuine", certs
    v = verdict("echallan.parivahan.gov.in", "paste")
    assert not findings(v) & {"certificate_organisation_other", "armed"}


def test_missing_organisation_is_neutral_in_fusion():
    from doppel.brain import fusion

    base = [{"criterion": "C2", "finding": "genuine_family", "points_to": "genuine", "strength": "strong", "score": 0.98}]
    dv = base + [{"criterion": "C17", "finding": "established_certificates", "points_to": "neutral",
                  "strength": "weak", "score": 0}]
    assert fusion.risk(dv) == fusion.risk(base)


def test_gmail_is_proven_by_the_official_list_not_the_certificate():
    for name in ["gmail.com", "pop.gmail.com", "imap.gmail.com", "smtp-relay.gmail.com"]:
        v = verdict(name, certs=False)
        assert v["label"] == "genuine", name
        assert any(e["finding"] == "genuine_family" for e in v["evidence"])


# ------------------------------------------------------------------ C16 organisation + C17 history (CT, cached) ---

def test_sbicard_shows_the_validated_company_and_stays_in_review():
    v = verdict("sbicard.com", "paste")
    assert v["label"] == "needs_review" and v["target_brand"]["id"] == "sbi"
    other = next(e for e in v["evidence"] if e["finding"] == "certificate_organisation_other")
    assert other["details"]["organisation"] == "SBI CARDS AND PAYMENT SERVICES LIMITED"
    assert "established_certificates" in findings(v, "ct_history")      # a year of certificates: not "armed"
    assert "SBI CARDS AND PAYMENT SERVICES LIMITED" in v["reason"]


def test_campaign_name_is_armed_but_never_phishing_on_its_certificate():
    v = verdict("in-echallan.online", "paste")
    armed = next(e for e in v["evidence"] if e["finding"] == "armed")
    assert armed["points_to"] == "phishing" and armed["strength"] == "weak"
    assert armed["details"]["first_seen"].startswith("2026-10-26")
    assert v["label"] == "needs_review"
    off = verdict("in-echallan.online", "paste", certs=False)
    assert v["risk_score"] > off["risk_score"]                          # higher priority in the queue


def test_exact_legal_name_proves_and_a_substring_does_not(monkeypatch):
    rec = {"domain": "sbi-newsite.com", "fetched_at": "2026-11-06T00:00:00Z", "source": "test", "truncated": False,
           "issuances": [{"sha256": "a" * 64, "sans": ["sbi-newsite.com"], "not_before": "2025-01-01T00:00:00Z",
                          "issuer": {"o": "DigiCert Inc"}, "validation": "EV",
                          "subject": {"o": "State Bank of India", "c": "IN", "cn": None}}]}
    monkeypatch.setattr(ct, "search", lambda *a, **k: rec)
    r = read_address("sbi-newsite.com")
    res, items = forensics.ct_history(r, REG.brand("sbi"), REG)
    assert res.proven and res.brand.id == "sbi"
    assert items[0]["finding"] == "certificate_organisation_match"
    rec["issuances"][0]["subject"]["o"] = "State Bank of India Securities"          # substring: never a match
    res, items = forensics.ct_history(r, REG.brand("sbi"), REG)
    assert not res.proven and items[0]["finding"] == "certificate_organisation_other"
    rec["issuances"][0]["subject"].update(o="STATE BANK OF INDIA", c="US")         # same name, other country
    res, _ = forensics.ct_history(r, REG.brand("sbi"), REG)
    assert not res.proven
    for it in items:
        assert validate_evidence_item(it) == []


def test_no_cached_ct_record_is_silent_in_batch_and_honest_when_single(monkeypatch):
    v = verdict("sbi-kyc-update-zzz.in", "file")
    assert "ct_history" not in {e["tool"] for e in v["evidence"]}
    v = verdict("sbi-kyc-update-zzz.in", "paste")                       # offline: says it wasn't checked
    assert "ct_not_checked" in findings(v, "ct_history")


# ------------------------------------------------------------------ Deep family membership ---

def test_deep_family_membership_uses_san_links_but_never_tenants():
    assert in_family_of(REG, "google", "www.gvt1.com", certs=True)
    assert not in_family_of(REG, "google", "www.gvt1.com", certs=False)
    assert not in_family_of(REG, "google", "docs.google.com", certs=True)       # user content
    assert not in_family_of(REG, "google", "evil.appspot.com", certs=True)      # platform tenant


# ------------------------------------------------------------------ detection fixes (a)-(c) ---

@pytest.mark.parametrize("name", ["ezhzxywnitjrudyxhdfcuvotob-dot-gloff849483.uk.r.appspot.com",
                                  "fjdhhjgudjgsiwokjfdkvhjshdfchvjhvhjdhv.weebly.com"])
def test_fix_a_brand_hidden_in_gibberish_on_free_hosting(name):
    v = verdict(name)
    assert v["label"] == "needs_review" and v["target_brand"]["id"] == "hdfc"
    combo = next(e for e in v["evidence"] if e["finding"] == "combosquat")
    assert combo["details"]["hidden_in"]


@pytest.mark.parametrize("name", ["repaymentportal.web.app", "abcdefgh.web.app", "googleplex-fans.com"])
def test_fix_a_doesnt_fire_on_ordinary_words(name):
    v = verdict(name)
    combo = [e for e in v["evidence"] if e["finding"] == "combosquat"]
    assert not any(e["details"].get("hidden_in") for e in combo)


@pytest.mark.parametrize("name", ["sbisec.co.jp", "sbisec-login.cfd", "thanksbitcoin.com", "lesbianbooks.com"])
def test_fix_b_short_brand_matches_only_as_a_token(name):
    v = verdict(name)
    assert (v["target_brand"] or {}).get("id") != "sbi", (name, v["reason"])


@pytest.mark.parametrize("name", ["redwolf6514gmail.com", "aucoindelacheminee26gmail.com", "537814gmail.com"])
def test_fix_c_email_shaped_names_are_not_imitations(name):
    v = verdict(name)
    assert v["label"] == "benign" and "email_shaped_name" in findings(v, "trick_detector")
    assert "@gmail.com" in v["reason"]


@pytest.mark.parametrize("name", ["brandaccountsgmail.com", "gmail-auth.live", "secure-gmail.com", "verifygmail.com"])
def test_fix_c_lure_words_keep_the_flag(name):
    assert verdict(name)["label"] == "needs_review", name


# ------------------------------------------------------------------ contract v1.1.0 ---

def test_contract_v11_accepts_new_criteria_and_old_documents():
    item = {"evidence_id": "E1", "tool": "campaign_radar", "stage": "standard", "criterion": "C18",
            "finding": "campaign_member", "points_to": "phishing", "strength": "medium", "score": 0.8,
            "target_brand": None, "summary": "x", "details": {}}
    assert validate_evidence_item(item) == []
    assert validate_evidence_item({**item, "criterion": "C19"})
    v = verdict("paytm.com")
    assert v["schema_version"] == "1.1.0"
    assert validate_verdict({**v, "schema_version": "1.0.0"}) == []


def test_index_parse_filters_unknown_brands():
    idx = parse({"accepted": [{"brand": "nope", "domain": "a.com", "include_subdomains": True},
                              {"brand": "google", "domain": "b.com", "include_subdomains": False}]}, {"google"})
    assert idx.lookup("a.com") is None and idx.lookup("b.com")["brand"] == "google"
    assert idx.lookup("x.b.com") is None
    assert check_family(read_address("google.co.in"), REG).genuine is False      # P2 itself never learns it


# ------------------------------------------------------------------ NPCI (optional 9th brand) precision ---

@pytest.mark.parametrize("name", ["repay.world", "cpci.com", "npc.fit", "rupa.games", "npcinv.com", "jupay.app"])
def test_exact_aliases_are_never_look_alike_targets(name):
    # measured on the NRD snapshot: as typo targets, 'npci' and 'rupay' flagged 41 unrelated names
    assert verdict(name)["label"] == "benign", name


@pytest.mark.parametrize("name", ["npci-upi-kyc.com", "rupay-card-update.in", "bhlmupi.com"])
def test_npci_look_alikes_are_still_caught(name):
    v = verdict(name)
    assert v["label"] == "needs_review" and v["target_brand"]["id"] == "npci"


# ------------------------------------------------------------------ approved legal names (human, 2026-11-06) ---

APPROVED = {"paytm": ["PAYTM MONEY LIMITED", "PAYTM INSURANCE BROKING PRIVATE LIMITED", "Paytm Payments Services Limited"],
            "income_tax": ["Directorate of Income Tax", "Directorate Of Income Tax (Systems)"]}


def _ct_with_org(monkeypatch, host, org, country="IN"):
    rec = {"domain": host, "fetched_at": "2026-11-06T00:00:00Z", "source": "test", "truncated": False,
           "issuances": [{"sha256": "b" * 64, "sans": [host], "not_before": "2025-01-01T00:00:00Z",
                          "issuer": {"o": "DigiCert Inc"}, "validation": "OV",
                          "subject": {"o": org, "c": country, "cn": None}}]}
    monkeypatch.setattr(ct, "search", lambda *a, **k: rec)
    return read_address(host)


def test_approved_legal_names_are_in_the_registry_with_their_provenance():
    import yaml

    from doppel.family.registry import REGISTRY_PATH
    raw = {b["id"]: b for b in yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))["brands"]}
    for bid, names in APPROVED.items():
        listed = {n["name"]: n for n in raw[bid]["legal_names"]}
        for name in names:
            assert listed[name]["source"].startswith("https://")
            assert listed[name]["note"].startswith("human-approved 2026-11-06: seen on the certificate of an official-list domain")
            host = listed[name]["source"].split("/")[2]
            assert check_family(read_address(host), REG).genuine, host      # seen on an already-proven domain


@pytest.mark.parametrize("bid,org", [(b, n) for b, ns in APPROVED.items() for n in ns]
                         + [("paytm", "paytm money limited"), ("income_tax", "DIRECTORATE OF INCOME TAX")])
def test_exact_case_folded_legal_name_proves(monkeypatch, bid, org):
    r = _ct_with_org(monkeypatch, "new-service-example.in", org)
    res, items = forensics.ct_history(r, REG.brand(bid), REG)
    assert res.proven and res.brand.id == bid
    assert items[0]["finding"] == "certificate_organisation_match"


@pytest.mark.parametrize("org", ["Paytm Money Ltd", "PAYTM MONEY", "Paytm Money Limited India", "PAYTM MONEY LIMITED.",
                                 "Directorate of Income-Tax", "Directorate of Income Tax Systems"])
def test_other_spellings_and_substrings_never_prove(monkeypatch, org):
    r = _ct_with_org(monkeypatch, "new-service-example.in", org)
    res, items = forensics.ct_history(r, REG.brand("paytm"), REG)
    assert not res.proven
    assert items[0]["finding"] == "certificate_organisation_other" and items[0]["points_to"] == "neutral"


def test_sbi_card_is_not_sbi_even_though_its_certificate_is_validated():
    # SBI CARDS AND PAYMENT SERVICES LIMITED was never proposed: sbicard.com isn't on SBI's official list
    assert "sbicard.com" not in {e.domain for e in REG.brand("sbi").family}
    assert not any(n.casefold() == "sbi cards and payment services limited" for n, _ in REG.brand("sbi").legal_names)
    assert verdict("sbicard.com", "paste")["label"] == "needs_review"


def test_proposals_come_only_from_proven_seeds_and_are_never_added(monkeypatch):
    def fake_read(host, reg, refresh=False, root=None):
        if tls.proven_brand(host, reg) is None:
            raise tls.NotProvenGenuine(host)
        return {"fetched_at": "2026-11-06T00:00:00Z", "cert": {
            "sha256": "c" * 64, "sans": [host], "subject": {"o": "NEW SUBSIDIARY LIMITED", "c": "IN", "cn": None},
            "issuer": {"o": "DigiCert Inc"}, "validation": "OV", "not_before": "x", "not_after": "y"}}

    monkeypatch.setattr(discover, "seed_hosts", lambda reg: {"paytm": ["paytm.com", "paytm-new-subsidiary.com"]})
    monkeypatch.setattr(tls, "read_seed", fake_read)
    before = REG.brand("paytm").legal_names
    res = discover.discover(REG, log=lambda *a: None)
    assert [(p["organisation"], p["seen_on"]) for p in res["legal_name_proposals"]] == [("NEW SUBSIDIARY LIMITED", ["paytm.com"])]
    assert [f["host"] for f in res["seed_failures"]] == ["paytm-new-subsidiary.com"]   # unproven: never read
    assert load_registry().brand("paytm").legal_names == before                           # never added by itself
