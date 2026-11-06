"""Address Reader: real owner, IDNA, scripts, skeleton, embedded domains."""

import pytest

from doppel.address import AddressError, address_reader, read_address
from doppel.address.unicode_data import is_mixed_script, skeleton
from doppel.contract import validate_evidence_item

CYR_A = "а"  # Cyrillic а


# --- required P2 cases (docs/BUILD_PHASES.md) --------------------------------

def test_bank_in_owner():
    assert read_address("sbi.bank.in").owner == "sbi.bank.in"


def test_genuine_name_as_prefix_has_foreign_owner():
    r = read_address("sbi.bank.in.kyc-update.com")
    assert r.owner == "kyc-update.com"
    assert r.embedded == {"domain": "sbi.bank.in", "suffix": "bank.in"}


def test_free_hosting_owner_is_the_user():
    r = read_address("sbi-kyc.web.app")
    assert r.owner == "sbi-kyc.web.app"
    assert r.hosting_platform == "web.app"


def test_cyrillic_paytm_is_mixed_script():
    r = read_address(f"p{CYR_A}ytm.com")
    assert r.host == "xn--pytm-53d.com"
    assert r.display == f"p{CYR_A}ytm.com"
    assert r.mixed_script
    assert r.labels[0].foreign[0]["codepoint"] == "U+0430"


# --- parsing ------------------------------------------------------------------

@pytest.mark.parametrize("raw", [
    "https://sbi.bank.in/login?x=1",
    "HTTPS://SBI.BANK.IN:443/",
    "user:pw@sbi.bank.in",
    "sbi.bank.in.",
    "<https://sbi.bank.in/path>",
])
def test_url_forms_reduce_to_the_host(raw):
    assert read_address(raw).host == "sbi.bank.in"


def test_punycode_input_decodes_to_unicode():
    assert read_address("xn--pytm-53d.com").display == f"p{CYR_A}ytm.com"


def test_platform_missing_from_psl_is_still_free_hosting():
    r = read_address("hdfc-netbanking.weeblysite.com")
    assert r.hosting_platform == "weeblysite.com"
    assert r.owner == "hdfc-netbanking.weeblysite.com"


def test_embedded_gov_in_domain():
    r = read_address("echallan.parivahan.gov.in.pay-fine.icu")
    assert r.owner == "pay-fine.icu"
    assert r.embedded == {"domain": "parivahan.gov.in", "suffix": "gov.in"}


def test_embedded_dot_com_domain():
    assert read_address("hdfcbank.com.secure-login.xyz").embedded["domain"] == "hdfcbank.com"


def test_ordinary_subdomain_is_not_embedded():
    assert read_address("mail.google.com").embedded is None
    assert read_address("retailnetbanking.icici.bank.in").embedded is None


def test_ip_address():
    r = read_address("http://192.168.1.5/login")
    assert r.is_ip
    assert address_reader("192.168.1.5")[1][0]["finding"] == "ip_address_host"


@pytest.mark.parametrize("bad", ["", "   ", "localhost", "http://[::1]/"])
def test_unusable_input_raises(bad):
    with pytest.raises(AddressError):
        read_address(bad)


# --- Unicode ------------------------------------------------------------------

def test_skeleton_catches_homoglyph_and_twin_letters():
    assert skeleton(f"p{CYR_A}ytm").lower() == skeleton("paytm").lower()
    assert skeleton("paytrn") == skeleton("paytm")            # rn ~ m
    assert skeleton("g00gle").lower() == skeleton("google").lower()


def test_whole_script_confusable():
    r = read_address("аррӏе.com")   # all-Cyrillic "apple"
    assert not r.mixed_script
    findings = [e["finding"] for e in address_reader(r.raw)[1]]
    assert "whole_script_confusable" in findings


def test_single_script_non_latin_is_not_flagged():
    # Devanagari-only label: legitimate Hindi IDN, nothing to flag
    assert not is_mixed_script("भारत")
    findings = [e["finding"] for e in address_reader("भारत.भारत")[1]]
    assert "single_script" in findings


def test_digits_and_hyphens_dont_make_mixed_script():
    assert not is_mixed_script("sbi-kyc-2024")


# --- evidence -----------------------------------------------------------------

@pytest.mark.parametrize("raw", [
    "sbi.bank.in", f"p{CYR_A}ytm.com", "sbi-kyc.web.app", "echallan.parivahan.gov.in.pay-fine.icu",
    "аррӏе.com", "192.168.1.5", "hdfc-netbanking.weeblysite.com",
])
def test_evidence_matches_contract(raw):
    _, items = address_reader(raw)
    for item in items:
        assert validate_evidence_item(item) == [], item


def test_mixed_script_evidence_names_the_hidden_letter():
    items = address_reader(f"p{CYR_A}ytm.com")[1]
    mixed = next(e for e in items if e["finding"] == "mixed_script")
    assert "U+0430" in mixed["summary"]
    assert mixed["details"]["edits"][0]["candidate_span"] == [1, 2]
