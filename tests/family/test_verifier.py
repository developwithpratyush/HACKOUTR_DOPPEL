"""Family Verifier: the three proofs, user-content platforms, and named imitations."""

import json

import pytest

from doppel.address import read_address
from doppel.contract import CONTRACTS_DIR, validate_evidence_item
from doppel.family import check_family, family_verifier

CYR_A = "а"


def fam(raw):
    return check_family(read_address(raw))


# --- required P2 cases ----------------------------------------------------------

def test_blog_google_is_genuine():
    f = fam("blog.google")
    assert f.genuine and f.brand.id == "google"
    assert "brand_tld" in f.proofs_matched


def test_bank_in_lookalike_is_not_family():
    f = fam("sbi.bank-in.com")
    assert not f.genuine
    assert (f.brand.id, f.matched_by, f.imitated) == ("sbi", "trust_signal", "sbi.bank.in")


# --- proofs -----------------------------------------------------------------------

@pytest.mark.parametrize("host,brand,proofs", [
    ("sbi.bank.in", "sbi", ["restricted_registry", "official_list"]),
    ("onlinesbi.sbi.bank.in", "sbi", ["restricted_registry", "official_list"]),
    ("bank.sbi", "sbi", ["brand_tld", "official_list"]),
    ("anything.sbi", "sbi", ["brand_tld"]),
    ("sbi.co.in", "sbi", ["official_list"]),
    ("www.hdfc.bank.in", "hdfc", ["restricted_registry", "official_list"]),
    ("www.hdfcbank.com", "hdfc", ["official_list"]),
    ("retailnetbanking.icici.bank.in", "icici", ["restricted_registry", "official_list"]),
    ("paytm.com", "paytm", ["official_list"]),
    ("www.indiapost.gov.in", "india_post", ["restricted_registry", "official_list"]),
    ("echallan.parivahan.gov.in", "parivahan", ["restricted_registry", "official_list"]),
    ("eportal.incometax.gov.in", "income_tax", ["restricted_registry", "official_list"]),
    ("withgoogle.com", "google", ["official_list"]),
    ("g.co", "google", ["official_list"]),
])
def test_genuine_family_and_which_proof(host, brand, proofs):
    f = fam(host)
    assert f.genuine, host
    assert f.brand.id == brand
    assert f.proofs_matched == proofs


def test_unverified_brand_tld_is_reported_unverified():
    f = fam("nic.hdfc")
    assert f.genuine and not f.verified
    item = family_verifier(read_address("nic.hdfc"))[1][0]
    assert item["details"]["verified"] is False and item["score"] < 0.98


# --- user content: owned by the brand, written by anyone ---------------------------

@pytest.mark.parametrize("host", ["forms.gle", "docs.google.com", "sites.google.com", "script.google.com"])
def test_user_content_hosts_are_never_genuine(host):
    f = fam(host)
    assert f.status == "user_content" and not f.genuine
    item = family_verifier(read_address(host))[1][0]
    assert item["finding"] == "brand_user_content_platform"
    assert item["points_to"] == "neutral"


# --- restricted registries ---------------------------------------------------------

@pytest.mark.parametrize("host", [
    "batlagunducoopurban.bank.in", "madurantakamcub.bank.in", "sreenivasapadmavathi.bank.in",
])
def test_new_cooperative_banks_from_nrd_are_a_bank_but_not_our_brand(host):
    f = fam(host)
    assert f.status == "restricted_other" and f.brand is None


def test_unlisted_bank_in_name_with_brand_is_flagged_for_review():
    f = fam("hdfcbank.bank.in")
    assert f.status == "restricted_unlisted" and f.brand.id == "hdfc"


# --- imitations, and how the brand was found ---------------------------------------

@pytest.mark.parametrize("host,brand,how", [
    ("sbi.bank.in.kyc-update.com", "sbi", "level_squat"),
    ("sbi.bank.in-kyc-verify.com", "sbi", "level_squat"),
    ("www.bank.sbi-kyc-verify.shop", "sbi", "level_squat"),   # found by the P3 generator
    ("echallan.parivahan.gov.in.pay-fine.icu", "parivahan", "level_squat"),
    ("icicibank.com.verify-now.xyz", "icici", "level_squat"),
    ("hdfcbank-in.com", "hdfc", "trust_signal"),
    ("statebankin.com", "sbi", "trust_signal"),
    ("blog-google.com", "google", "trust_signal"),
    ("incometax-gov-in.com", "income_tax", "trust_signal"),
    (f"p{CYR_A}ytm.com", "paytm", "skeleton"),
    ("paytrn.com", "paytm", "skeleton"),
    ("g00gle.com", "google", "skeleton"),
    ("sbi-kyc-update.in", "sbi", "alias_token"),
    ("sbi-kyc.web.app", "sbi", "alias_token"),
    ("hdfc-netbanking.weeblysite.com", "hdfc", "alias_token"),
])
def test_imitations_name_the_brand(host, brand, how):
    f = fam(host)
    assert f.status == "imitation", host
    assert f.brand.id == brand
    assert f.matched_by == how


@pytest.mark.parametrize("host", ["sbibankin.com", "sbigov.net", "sbikycupdate.com", "mysbilogin.online"])
def test_glued_short_brand_found_by_segmentation(host):
    # fixed in P4 (doppel/tricks/segment.py): sbi + bank + in, sbi + gov, sbi + kyc + update
    f = fam(host)
    assert f.brand is not None and f.brand.id == "sbi", host


@pytest.mark.parametrize("host", ["sbisec.co.jp", "thanksbitcoin.com", "sbinternal.com"])
def test_glued_short_brand_needs_lure_or_address_words(host):
    assert fam(host).status == "none"


@pytest.mark.parametrize("host", [
    # false positives found in the P2 NRD sweep (docs/eval/p2-family-sweep.md)
    "shinohara-bankin.com", "frigovin.com", "krit-spacefinin.info", "accessbankin.com",
    "akesbi.ca", "sbinternal.com", "login-sbisec-co-jp.com",
])
def test_sweep_false_positives_stay_quiet(host):
    assert fam(host).status == "none"


def test_ending_swap_is_not_a_level_squat():
    f = fam("paytm.com.mw")
    assert f.brand.id == "paytm" and f.matched_by == "alias_token"


def test_brand_tld_lookalike_is_weaker_than_a_family_rebuild():
    strong = family_verifier(read_address("sbi.bank-in.com"))[1][0]
    weak = family_verifier(read_address("278254-google.com"))[1][0]
    assert strong["strength"] == "strong" and weak["strength"] == "medium"


def test_restricted_mimicry_without_a_brand():
    f = fam("gov-in.org")
    assert f.status == "imitation" and f.brand is None and f.imitated == "gov.in"


@pytest.mark.parametrize("host", [
    "thanksbitcoin.com", "kx72-secure.top", "mybank-india.com", "banking-news.com", "example.com",
])
def test_no_brand_signal(host):
    assert fam(host).status == "none"


# --- evidence ----------------------------------------------------------------------

@pytest.mark.parametrize("host", [
    "sbi.bank.in", "nic.hdfc", "forms.gle", "batlagunducoopurban.bank.in", "hdfcbank.bank.in",
    "sbi.bank.in.kyc-update.com", "sbi.bank-in.com", "paytrn.com", "thanksbitcoin.com", "gov-in.org",
])
def test_evidence_matches_contract(host):
    _, items = family_verifier(read_address(host))
    assert len(items) == 1
    assert validate_evidence_item(items[0]) == []


def test_genuine_evidence_records_the_source():
    item = family_verifier(read_address("onlinesbi.sbi.bank.in"))[1][0]
    assert item["finding"] == "genuine_family"
    assert item["details"]["source"].startswith("https://sbi.bank.in/")
    assert item["details"]["proofs_matched"] == ["restricted_registry", "official_list"]


# --- the real tools agree with the hand-written gallery mocks (P0) -------------------

EXAMPLES = sorted((CONTRACTS_DIR / "examples").glob("*.json"))


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_quick_stage_findings_match_the_gallery_mocks(path):
    from doppel.address import address_reader

    mock = json.loads(path.read_text(encoding="utf-8"))
    expected = {(e["tool"], e["finding"]) for e in mock["evidence"]
                if e["tool"] in ("address_reader", "family_verifier")}
    reading, addr_items = address_reader(mock["input"]["raw"])
    _, fam_items = family_verifier(reading)
    got = {(e["tool"], e["finding"]) for e in addr_items + fam_items}
    assert got == expected
    assert reading.owner == mock["owner"]
