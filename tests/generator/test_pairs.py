"""Look-alike generators and the committed pairs dataset (data/pairs/pairs.csv)."""

import csv
import random
from collections import Counter
from pathlib import Path

import pytest

from doppel.address import read_address
from doppel.contract import REPO_ROOT
from doppel.family import check_family, load_registry
from doppel.generator import own
from doppel.generator.pairs import COLUMNS, HELD_OUT_BRANDS, split_for
from doppel.generator.techniques import GENERATED, TECHNIQUES

PAIRS = REPO_ROOT / "data" / "pairs" / "pairs.csv"
REG = load_registry()


# --- generators ----------------------------------------------------------------

def gen(it):
    return [c for c, _, _ in it]


def test_twin_letters_make_paytrn():
    assert "paytrn.com" in gen(own.twin_letters("paytm", "com"))


def test_homoglyphs_hide_a_cyrillic_letter():
    cands = gen(own.homoglyphs("paytm", "com"))
    mixed = [c for c in cands if read_address(c).mixed_script]
    assert mixed, cands
    assert any("а" in c for c in cands)  # Cyrillic а for a


def test_soundsquats_sound_the_same():
    cands = gen(own.soundsquats("incometax", "in"))
    assert "incometacks.in" in cands
    assert all(own.sound_key(c.split(".")[0]) == own.sound_key("incometax") for c in cands)


def test_trust_signals_rebuild_bank_in():
    cands = gen(own.trust_signals(REG.brand("sbi"), REG, random.Random(1)))
    assert any(c.startswith("sbi.bank-in.") for c in cands)
    assert any(c.startswith("sbi-bank-in.") for c in cands)


def test_level_squats_use_a_genuine_prefix():
    for c in gen(own.level_squats(REG.brand("sbi"), ["kyc", "verify"], random.Random(1), 20)):
        f = check_family(read_address(c), REG)
        assert f.status == "imitation" and f.matched_by == "level_squat", c


def test_brand_labels_skip_generic_words():
    assert "bank" not in own.brand_labels(REG.brand("sbi"))


# --- the dataset -----------------------------------------------------------------

@pytest.fixture(scope="module")
def rows():
    if not PAIRS.exists():
        pytest.skip("run `python -m doppel.generator.pairs` first")
    with PAIRS.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_columns(rows):
    assert list(rows[0].keys()) == COLUMNS


def test_candidates_are_unique(rows):
    dupes = [c for c, n in Counter(r["candidate"] for r in rows).items() if n > 1]
    assert not dupes


def test_values_are_in_range(rows):
    assert {r["label"] for r in rows} <= {"0", "1"}
    assert {r["kind"] for r in rows} == {"lookalike", "real_phish", "genuine", "hard_negative", "benign"}
    assert {r["split"] for r in rows} == {"train", "dev", "test_seen", "test_unseen", "test_real"}
    assert {r["technique"] for r in rows} <= set(TECHNIQUES) | {"none"}
    for r in rows:
        assert (r["label"] == "1") == (r["kind"] in ("lookalike", "real_phish")), r


def test_every_generated_technique_is_present(rows):
    present = {r["technique"] for r in rows if r["kind"] == "lookalike"}
    assert set(GENERATED) <= present


def test_held_out_brands_never_leak_into_train_or_dev(rows):
    for r in rows:
        if r["target_brand"] in HELD_OUT_BRANDS:
            assert r["split"] in ("test_unseen", "test_real"), r


def test_real_phishing_is_test_only(rows):
    assert all(r["split"] == "test_real" for r in rows if r["kind"] == "real_phish")


def test_test_unseen_has_negatives(rows):
    labels = Counter(r["label"] for r in rows if r["split"] == "test_unseen")
    assert labels["0"] > 500 and labels["1"] > 500


def test_split_is_a_pure_function_of_the_row(rows):
    for r in rows[:2000]:
        assert split_for(r["candidate"], r["target_brand"] or None, r["kind"]) == r["split"]


def test_synthetic_lookalikes_are_registrable_and_not_genuine(rows):
    closed = set(REG.brand_tld_rows)
    sample = [r for r in rows if r["kind"] == "lookalike"][::25]
    for r in sample:
        rd = read_address(r["candidate"])
        assert not any(rd.is_under(s) for s in REG.restricted), r
        assert rd.tld not in closed, r
        assert check_family(rd, REG).status not in ("genuine", "user_content"), r


def test_genuine_rows_are_genuine(rows):
    for r in rows:
        if r["kind"] == "genuine":
            assert check_family(read_address(r["candidate"]), REG).genuine, r


def test_t3_rows_contain_non_ascii(rows):
    assert all(not r["display"].isascii() for r in rows if r["technique"] == "T3" and r["kind"] == "lookalike")
