"""The contract validates the gallery examples and rejects broken verdicts."""

import copy
import json
from pathlib import Path

import pytest

from doppel.contract import (
    CONTRACTS_DIR,
    REPO_ROOT,
    load_yaml,
    validate_document,
    validate_evidence_item,
    validate_registry,
    validate_scan_result,
    validate_verdict,
)

EXAMPLES = sorted((CONTRACTS_DIR / "examples").glob("*.json"))


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_there_is_an_example_for_every_final_label():
    labels = {load(p)["label"] for p in EXAMPLES}
    assert labels == {"genuine", "phishing", "sleeper", "needs_review", "benign"}


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_is_valid(path):
    assert validate_verdict(load(path)) == []


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_examples_are_marked_mock(path):
    assert load(path)["meta"]["mock"] is True


def test_every_evidence_item_validates_on_its_own():
    for path in EXAMPLES:
        for ev in load(path)["evidence"]:
            assert validate_evidence_item(ev) == [], (path.name, ev["evidence_id"])


def test_scan_result_wraps_verdicts():
    verdicts = [load(p) for p in EXAMPLES]
    by_label: dict[str, int] = {}
    for v in verdicts:
        by_label[v["label"]] = by_label.get(v["label"], 0) + 1
    scan = {
        "schema_version": "1.0.0",
        "generated_at": "2026-11-05T10:00:00+05:30",
        "verdicts": verdicts,
        "summary": {"total": len(verdicts), "by_label": by_label,
                    "reached_stage": {"quick": 7, "standard": 6, "deep": 5}, "elapsed_ms": 6000},
    }
    assert validate_scan_result(scan) == []
    assert validate_document(scan) == []
    scan["summary"]["total"] = 99
    assert any("summary.total" in e for e in validate_scan_result(scan))


@pytest.fixture
def phishing():
    return load(CONTRACTS_DIR / "examples" / "01-invisible-letter.json")


@pytest.fixture
def sleeper():
    return load(CONTRACTS_DIR / "examples" / "03-sleeper-combosquat.json")


def errors_after(verdict, mutate):
    v = copy.deepcopy(verdict)
    mutate(v)
    return validate_verdict(v)


def test_suspicious_is_not_a_final_label(phishing):
    assert errors_after(phishing, lambda v: v.update(label="suspicious"))


def test_suspicious_is_allowed_as_provisional(phishing):
    assert phishing["stages"][0]["provisional"]["label"] == "suspicious"


def test_unknown_tool_rejected(phishing):
    assert errors_after(phishing, lambda v: v["evidence"][0].update(tool="chatgpt"))


def test_dangling_evidence_reference_rejected(phishing):
    errs = errors_after(phishing, lambda v: v["hard_rule"]["evidence_ids"].append("E99"))
    assert any("E99" in e for e in errs)


def test_duplicate_evidence_id_rejected(phishing):
    errs = errors_after(phishing, lambda v: v["evidence"][1].update(evidence_id="E1"))
    assert any("duplicate" in e for e in errs)


def test_hard_rule_must_match_label(phishing):
    errs = errors_after(phishing, lambda v: v.update(label="needs_review"))
    assert any("hard rule" in e for e in errs)


def test_genuine_needs_ownership_proof(phishing):
    def make_genuine(v):
        v["label"] = "genuine"
        v["hard_rule"] = None
        v["trace"] = [s for s in v["trace"] if s["kind"] != "hard_rule"]
        for i, s in enumerate(v["trace"], 1):
            s["step"] = i
        v["trace"][-1]["label"] = "genuine"
    errs = errors_after(phishing, make_genuine)
    assert any("H1_genuine_family" in e for e in errs)


def test_sleeper_cannot_run_deep(sleeper, phishing):
    def run_deep(v):
        v["stages"][2] = copy.deepcopy(phishing["stages"][2])
    assert errors_after(sleeper, run_deep)


def test_skipped_stage_needs_a_reason(sleeper):
    assert errors_after(sleeper, lambda v: v["stages"][2].pop("skip_reason"))


def test_trace_must_end_with_final_verdict(phishing):
    assert errors_after(phishing, lambda v: v["trace"].pop())


def test_trace_out_of_order_rejected(phishing):
    errs = errors_after(phishing, lambda v: v["trace"][3].update(t_ms=999999))
    assert any("starts before" in e for e in errs)


def test_counterfactual_must_flip_the_label(phishing):
    errs = errors_after(phishing, lambda v: v["counterfactual"].update(label="phishing"))
    assert any("flip" in e for e in errs)


def test_neutral_evidence_has_zero_score(phishing):
    errs = errors_after(phishing, lambda v: v["evidence"][0].update(score=0.4))
    assert any("neutral" in e for e in errs)


def test_registry_is_valid():
    registry = load_yaml(REPO_ROOT / "data" / "brands" / "registry.yaml")
    assert validate_registry(registry) == []


def test_registry_rejects_verified_entry_without_source():
    registry = load_yaml(REPO_ROOT / "data" / "brands" / "registry.yaml")
    registry["brands"][0]["genuine_family"][0]["source"] = None
    assert validate_registry(registry)


def test_registry_covers_the_example_brands():
    """The mock verdicts cite brand ids that the registry must define."""
    registry = load_yaml(REPO_ROOT / "data" / "brands" / "registry.yaml")
    ids = {b["id"] for b in registry["brands"]}
    cited = {v["target_brand"]["id"] for v in map(load, EXAMPLES) if v["target_brand"]}
    assert cited <= ids
    assert {"sbi", "hdfc", "icici", "paytm", "india_post", "parivahan", "income_tax", "google"} <= ids


def test_registry_rejects_brand_tld_without_iana_row():
    registry = load_yaml(REPO_ROOT / "data" / "brands" / "registry.yaml")
    registry["brands"][0]["brand_tlds"].append("statebank")
    assert any(".statebank" in e for e in validate_registry(registry))


def test_registry_rejects_user_content_host_in_family():
    registry = load_yaml(REPO_ROOT / "data" / "brands" / "registry.yaml")
    google = next(b for b in registry["brands"] if b["id"] == "google")
    google["user_content_hosts"].append({"host": "g.co", "what": "test", "source": None})
    assert any("both genuine family and user content" in e for e in validate_registry(registry))


def test_registry_rejects_alias_that_is_also_a_lure():
    registry = load_yaml(REPO_ROOT / "data" / "brands" / "registry.yaml")
    registry["lure_words"].append({"word": "paytm", "lang": "en", "category": "payment"})
    assert any("also an alias" in e for e in validate_registry(registry))


def test_forms_gle_is_user_content_not_family():
    """Anyone can publish a Google Form, so ownership must not make it green."""
    registry = load_yaml(REPO_ROOT / "data" / "brands" / "registry.yaml")
    google = next(b for b in registry["brands"] if b["id"] == "google")
    assert "forms.gle" not in {e["domain"] for e in google["genuine_family"]}
    assert "forms.gle" in {u["host"] for u in google["user_content_hosts"]}


def test_registry_rejects_wrong_proof():
    registry = load_yaml(REPO_ROOT / "data" / "brands" / "registry.yaml")
    sbi = registry["brands"][0]
    sbi["genuine_family"].append({"domain": "sbi.bank-in.com", "include_subdomains": False,
                                  "proof": "restricted_registry", "source": None, "verified_on": None})
    assert any("restricted_registry" in e for e in validate_registry(registry))
