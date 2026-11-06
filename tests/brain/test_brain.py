"""P5: the brain (stages, fusion, labels, counterfactual, trace), the Page Probe, batch scan, exporters, CLI."""

import csv
import io
import json

import pytest
from typer.testing import CliRunner

from doppel.brain import fusion
from doppel.brain.brain import Brain
from doppel.brain.probe import probe
from doppel.brain.scan import read_inputs, scan
from doppel.cli import app
from doppel.contract import CONTRACTS_DIR, validate_scan_result, validate_verdict
from doppel.export.formats import to_blocklist, to_csv, to_html, to_json

BRAIN = Brain()
EXAMPLES = sorted((CONTRACTS_DIR / "examples").glob("*.json"))
# Without the Deep stage (no Playwright/snapshots on this machine) the brand-less clone can't be proven
# phishing from name + page probe alone. With it (P8), every gallery case gets the mock's label.
P5_LABEL = {} if BRAIN.deep else {"05-brandless-clone": "needs_review"}
LIVE_PAGE = {"01-invisible-letter", "02-twin-letters", "04-subdomain-disguise", "05-brandless-clone", "06-genuine-weirdo"}


@pytest.mark.parametrize("path", EXAMPLES, ids=[p.stem for p in EXAMPLES])
def test_gallery_cases_get_the_mock_label_and_a_valid_verdict(path):
    mock = json.loads(path.read_text(encoding="utf-8"))
    v = BRAIN.investigate(mock["input"]["raw"], mock["input"]["source"])
    assert validate_verdict(v) == [], validate_verdict(v)
    assert v["label"] == P5_LABEL.get(path.stem, mock["label"]), (path.stem, v["label"], v["reason"])
    if mock["target_brand"] and v["label"] != "needs_review" or path.stem == "02-twin-letters":
        assert v["target_brand"]["id"] == mock["target_brand"]["id"]
    deep_ran = BRAIN.deep and path.stem in LIVE_PAGE          # Deep opens live fixture pages only
    assert v["stages"][2]["status"] == ("completed" if deep_ran else "skipped")
    if deep_ran:
        assert v["stages"][2]["tools"] == ["page_inspector", "vision_ai", "credential_tracker"]
        if mock["hard_rule"]:                                  # P9: the mocks' hard rules (H1, H2) now really fire
            assert v["hard_rule"]["id"] == mock["hard_rule"]["id"]


@pytest.mark.parametrize("raw,source", [
    ("paytrn.com", "paste"), ("sbi.bank-in.com", "paste"), ("sbi-kyc.web.app", "nrd_snapshot"),
    ("hdfcbank.bank.in", "paste"), ("forms.gle", "paste"), ("blog.google", "nrd_snapshot"),
    ("thanksbitcoin.com", "paste"), ("pāyţm.com", "fool_it"), ("8.8.8.8", "paste"), ("www.google.com", "api"),
])
def test_every_verdict_validates(raw, source):
    v = BRAIN.investigate(raw, source)
    assert validate_verdict(v) == [], (raw, validate_verdict(v))


def test_batch_stops_after_quick_without_a_brand_signal():
    v = BRAIN.investigate("bestpizza-delivery.in", "nrd_snapshot")
    assert v["label"] == "benign"
    assert [s["status"] for s in v["stages"]] == ["completed", "skipped", "skipped"]


def test_batch_escalates_on_a_brand_signal_but_never_visits_the_page():
    v = BRAIN.investigate("sbi-kyc-verify.shop", "nrd_snapshot")
    assert v["label"] == "needs_review" and v["target_brand"]["id"] == "sbi"
    probe_ev = next(e for e in v["evidence"] if e["tool"] == "page_probe")
    assert probe_ev["finding"] == "not_probed"


def test_probe_reads_only_local_fixtures():
    assert probe("some-unknown-domain.xyz").status == "not_probed"
    assert probe("sbi-kyc-update.in").status == "parked"
    r = probe("xn--pytm-53d.com")
    assert r.status == "live" and r.login and "password" in r.asks_for
    assert probe("echallan.parivahan.gov.in.pay-fine.icu").payment


def test_a_name_alone_never_yields_phishing():
    for raw in ("paytrn-kyc.com", "echallan.parivahan.gov.in.pay-fine.top", "xn--pytm-53d.in"):
        assert BRAIN.investigate(raw, "file")["label"] == "needs_review", raw


def test_genuine_needs_h1_and_has_a_flipping_counterfactual():
    v = BRAIN.investigate("onlinesbi.sbi.bank.in", "paste")
    assert v["hard_rule"]["id"] == "H1_genuine_family"
    assert v["counterfactual"]["label"] == "needs_review"


@pytest.mark.parametrize("raw,cf_domain,cf_label", [
    ("paytrn.com", "paytm.com", "genuine"),                 # undo rn -> m
    ("xn--pytm-53d.com", "paytm.com", "genuine"),           # undo the Cyrillic letter
    ("sbi-kyc-update.in", "kyc-update.in", "benign"),       # drop the brand token
    ("echallan.parivahan.gov.in.pay-fine.icu", "pay-fine.icu", "benign"),  # strip the borrowed prefix
])
def test_counterfactual_undoes_the_trick(raw, cf_domain, cf_label):
    v = BRAIN.investigate(raw, "gallery")
    cf = v["counterfactual"]
    assert cf["counterfactual_domain"] == cf_domain and cf["label"] == cf_label and cf["label"] != v["label"]


def test_trace_risk_moves_with_the_evidence():
    v = BRAIN.investigate("xn--pytm-53d.com", "gallery")
    tools = [s for s in v["trace"] if s["kind"] == "tool"]
    assert tools[0]["risk_before"] == fusion.risk([])
    assert tools[-1]["risk_after"] == v["risk_score"]
    assert v["trace"][-1]["kind"] == "final_verdict"


def test_fusion_counts_one_fact_once_per_criterion():
    item = {"criterion": "C5", "points_to": "phishing", "strength": "medium", "score": 0.9}
    assert fusion.risk([item]) == fusion.risk([item, dict(item)])
    assert fusion.risk([item]) > fusion.risk([])


def test_scan_inputs_and_exports(tmp_path):
    f = tmp_path / "in.csv"
    f.write_text("id,url\n1,https://paytrn.com/x\n2,thanksbitcoin.com\n3,localhost\n4,onlinesbi.sbi.bank.in\n", encoding="utf-8")
    items, source = read_inputs([str(f)])
    assert items == ["https://paytrn.com/x", "thanksbitcoin.com", "localhost", "onlinesbi.sbi.bank.in"]
    assert source == "file"
    verdicts, stats = scan(items, source, workers=1)
    assert stats["errors"] == 1 and len(verdicts) == 3
    assert validate_scan_result(json.loads(to_json(verdicts, stats))) == []
    rows = list(csv.DictReader(io.StringIO(to_csv(verdicts, stats))))
    assert {r["domain"]: r["label"] for r in rows} == {"paytrn.com": "needs_review", "thanksbitcoin.com": "benign",
                                                       "onlinesbi.sbi.bank.in": "genuine"}
    block = to_blocklist(verdicts, stats, include_review=True)
    assert "paytrn.com" in block and "onlinesbi.sbi.bank.in" not in block
    page = to_html(verdicts, stats)
    assert "<!doctype html>" in page and "paytrn.com" in page


def test_single_domain_is_a_single_investigation():
    assert read_inputs(["paytrn.com"]) == (["paytrn.com"], "paste")


def test_cli_scan_writes_every_format(tmp_path):
    res = CliRunner().invoke(app, ["scan", "paytrn.com", "thanksbitcoin.com", "-f", "all", "-o", str(tmp_path)])
    assert res.exit_code == 0, res.output
    for ext in ("json", "csv", "txt", "html"):
        assert (tmp_path / f"doppel-scan.{ext}").exists()
