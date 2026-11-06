"""P4: visual edit distance, segmentation, the Trick Detector, and agreement with the gallery mocks."""

import json

import pytest

from doppel.address import address_reader, read_address
from doppel.contract import CONTRACTS_DIR, validate_evidence_item
from doppel.evidence import Ids
from doppel.family import family_verifier
from doppel.tricks.align import align, is_bitflip
from doppel.tricks.detector import default_detector, trick_detector
from doppel.tricks.segment import segmenter
from doppel.tricks.tld_risk import tld_risk

DET = default_detector()


def detect(host):
    return DET.detect(read_address(host))


# --- alignment ------------------------------------------------------------------

def test_rn_for_m_is_one_cheap_twin_edit():
    a = align("paytrn", "paytm")
    assert len(a.edits) == 1
    e = a.edits[0]
    assert (e["op"], e["candidate"], e["genuine"], e["kind"]) == ("substitute", "rn", "m", "twin_letters")
    assert e["candidate_span"] == [4, 6] and e["genuine_span"] == [4, 5]
    assert e["cost"] < 0.3
    assert a.similarity > 0.9   # plain Levenshtein similarity is 0.67


def test_cyrillic_a_is_a_near_free_homoglyph_with_codepoint():
    a = align("pаytm", "paytm")
    assert a.edits[0]["kind"] == "homoglyph" and a.edits[0]["codepoints"] == ["U+0430"]
    assert a.edits[0]["cost"] < 0.15


def test_unrelated_letters_cost_almost_a_full_edit():
    assert align("pazzm", "paytm").similarity < 0.7


def test_transposition_hyphen_and_doubles_are_single_cheap_edits():
    assert [e["op"] for e in align("hdfcbnak", "hdfcbank").edits] == ["transpose"]
    assert align("pay-tm", "paytm").edits[0]["kind"] == "hyphen"
    assert align("echalan", "echallan").cost == pytest.approx(0.6)


def test_local_alignment_finds_the_brand_inside_a_longer_name():
    a = align("paytrn-kyc-update", "paytm", local=True)
    assert a.span == (0, 6) and a.edits[0]["candidate"] == "rn"


def test_bitflip():
    assert is_bitflip("s", "c") and not is_bitflip("s", "x")


def test_edits_fit_the_contract_shape():
    for c, g in [("paytrn", "paytm"), ("pаytm", "paytm"), ("hdfcbnak", "hdfcbank"), ("sbii", "sbi")]:
        for e in align(c, g).edits:
            assert set(e) <= {"op", "candidate", "genuine", "candidate_span", "genuine_span", "cost", "kind",
                              "codepoints"}
            assert 0 <= e["cost"] <= 1


# --- glyph matrix ----------------------------------------------------------------

def test_glyph_matrix_is_calibrated_and_ranks_twins_above_unrelated_letters():
    g = DET.glyphs
    assert g.meta["calibration"]["auc_ssim"] > 0.85
    assert g.cost("l", "i") < g.cost("e", "s") < g.cost("a", "x") + 0.01
    assert g.cost("о", "o") == 0.0        # Cyrillic о renders pixel-identical
    twins = {(m.fake, m.real): m.cost for m in g.multi}
    assert twins[("rn", "m")] < twins[("cl", "d")] < 1


# --- segmentation ------------------------------------------------------------------

@pytest.mark.parametrize("token,words", [
    ("thanksbitcoin", ("thanks", "bitcoin")), ("sbibankin", ("sbi", "bank", "in")),
    ("sbikycupdate", ("sbi", "kyc", "update")), ("indiapostredelivery", ("indiapost", "redelivery")),
])
def test_segmenter(token, words):
    assert segmenter().split(token) == words


# --- detector --------------------------------------------------------------------------

@pytest.mark.parametrize("host,brand,trick", [
    ("xn--pytm-53d.com", "paytm", "homoglyph"),
    ("pāyţm.com", "paytm", "homoglyph"),            # accented letters (dnstwist style); UTS-39 doesn't fold these
    ("paytrn.com", "paytm", "twin_letters"),
    ("hdfcbnak.com", "hdfc", "typo"),
    ("incometacks.in", "income_tax", "soundsquat"),
    ("sbi-kyc-update.in", "sbi", "combosquat"),
    ("sbi-kyc.web.app", "sbi", "combosquat"),
    ("paytrn-kyc.com", "paytm", "twin_letters"),
    ("paytm.co", "paytm", "tld_swap"),
    ("echallan.parivahan.gov.in.pay-fine.icu", "parivahan", "level_squat"),
    ("sbi.bank-in.com", "sbi", "trust_signal_mimicry"),
    ("sbibankin.com", "sbi", "trust_signal_mimicry"),
    ("icici-challan.com", "icici", "combosquat"),     # an exact brand token beats a fuzzy echallan match
])
def test_detector_names_brand_and_trick(host, brand, trick):
    res = detect(host)
    assert res.brand_signal and res.brand.id == brand, (host, res.brand, res.tricks)
    assert trick in res.tricks, (host, res.tricks)


@pytest.mark.parametrize("host", [
    "thanksbitcoin.com", "kx72-secure.top", "dubaiapartments.ru", "kumilu.com", "patoumi.com",
    "chercici.com", "mailerteam.bond", "shinohara-bankin.com", "akesbi.ca", "sbinternal.com",
])
def test_detector_stays_quiet_on_unrelated_names(host):
    res = detect(host)
    assert not res.brand_signal, (host, res.brand, res.tricks, [m.via for m in res.matches])


@pytest.mark.parametrize("host", ["onlinesbi.sbi.bank.in", "blog.google", "paytm.com", "www.hdfcbank.com"])
def test_genuine_family_is_never_a_trick(host):
    res = detect(host)
    assert res.in_family and not res.tricks and res.closeness == 1.0


def test_abused_tld_is_weak_and_sourced():
    assert tld_risk("top")["abused"] and not tld_risk("in")["abused"]
    _, ev = trick_detector(read_address("kx72-secure.top"))
    item = next(e for e in ev if e["finding"] == "abused_tld")
    assert item["strength"] == "weak" and item["score"] <= 0.5


@pytest.mark.parametrize("host", ["xn--pytm-53d.com", "paytrn.com", "sbi-kyc-update.in", "kx72-secure.top",
                                  "onlinesbi.sbi.bank.in", "thanksbitcoin.com", "hdfcbnak.com", "paytm.co"])
def test_evidence_items_validate(host):
    _, ev = trick_detector(read_address(host))
    for item in ev:
        assert validate_evidence_item(item) == [], item


def test_evidence_names_the_exact_swap():
    _, ev = trick_detector(read_address("paytrn.com"))
    twin = next(e for e in ev if e["finding"] == "twin_letters")
    assert twin["details"]["edits"][0]["candidate"] == "rn" and "'rn' for 'm'" in twin["summary"]


# --- the real tools agree with the hand-written gallery mocks (P0) --------------------------

EXAMPLES = sorted((CONTRACTS_DIR / "examples").glob("*.json"))


@pytest.mark.parametrize("path", EXAMPLES, ids=[p.stem for p in EXAMPLES])
def test_trick_detector_findings_match_the_gallery_mocks(path):
    mock = json.loads(path.read_text(encoding="utf-8"))
    expected = {e["finding"] for e in mock["evidence"] if e["tool"] == "trick_detector"}
    ids = Ids()
    reading, _ = address_reader(mock["input"]["raw"], ids)
    fam, _ = family_verifier(reading, ids=ids)
    res, ev = trick_detector(reading, fam, ids=ids)
    assert expected <= {e["finding"] for e in ev}, (path.name, [e["finding"] for e in ev])
    want = mock["evidence"]
    brands = {e["target_brand"]["id"] for e in want if e["tool"] == "trick_detector" and e["target_brand"]}
    if brands:
        assert res.brand and res.brand.id in brands


SMS_CASES = [("pаytm.com", "paytm.com", None, {"sms_view_identical", "sms_view_near_identical"}),
             ("paytrn.com", "paytm.com", None, {"sms_view_near_identical"}),
             ("sbi-kyc-update.in", "sbi.bank.in", "sbi", {"sms_view_brand_prominent"}),
             ("echallan.parivahan.gov.in.pay-fine.icu", "echallan.parivahan.gov.in", None, {"sms_view_prefix_match"})]


@pytest.mark.parametrize("cand,gen,token,findings", SMS_CASES)
def test_human_eye_renderer_matches_the_mocks(cand, gen, token, findings, tmp_path):
    from doppel.perception.renderer import human_eye_renderer

    info, ev = human_eye_renderer(cand, gen, brand_token=token, out_dir=tmp_path)
    assert ev[0]["finding"] in findings, (cand, ev[0]["finding"], info)
    assert validate_evidence_item(ev[0]) == []
    assert (tmp_path / ev[0]["details"]["artifacts"][0]["path"].split("/")[-1]).exists()
