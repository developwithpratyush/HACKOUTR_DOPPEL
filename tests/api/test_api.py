"""P6: the FastAPI layer (doppel/api). Every verdict it returns must pass the contract."""

import pytest
from fastapi.testclient import TestClient

from doppel.api.app import MAX_BATCH, app
from doppel.contract import validate_scan_result, validate_verdict


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:     # runs the lifespan (warm-up)
        yield c


def test_health_says_what_is_built(client):
    h = client.get("/api/health").json()
    assert h["ok"] and h["contract"] == "1.1.0"
    assert h["built"]["quick"] and h["built"]["cert_forensics"] and h["cert_family_links"] > 40
    # P9: the Deep tools are built wherever the Deep stage can run (Playwright + snapshots)
    assert h["built"]["credential_tracker"] == h["built"]["page_inspector"] == h["built"]["vision_ai"]
    assert "sbi" in h["brands"] and h["warm_ms"] is not None


def test_investigate_with_certificates_off_is_the_ablation(client):
    on = client.post("/api/investigate", json={"raw": "google.co.in"}).json()
    off = client.post("/api/investigate", json={"raw": "google.co.in", "certs": False}).json()
    assert on["label"] == "genuine" and off["label"] == "needs_review"
    assert off["meta"]["checks_off"] == ["C16", "C17"] and "checks_off" not in on["meta"]


def test_brands_give_the_family_tree(client):
    sbi = next(b for b in client.get("/api/brands").json()["brands"] if b["id"] == "sbi")
    proofs = {f["domain"]: f["proof"] for f in sbi["family"]}
    assert proofs["sbi.bank.in"] == "restricted_registry" and proofs["bank.sbi"] == "brand_tld"


@pytest.mark.parametrize("raw,source,label", [
    ("paytrn.com", "paste", "needs_review"),
    ("https://pаytm.com/login", "gallery", "phishing"),
    ("onlinesbi.sbi.bank.in", "paste", "genuine"),
    ("sbi-kyc-update.in", "fool_it", "sleeper"),
    ("chai-and-code.in", "api", "benign"),
])
def test_investigate_returns_a_valid_verdict(client, raw, source, label):
    r = client.post("/api/investigate", json={"raw": raw, "source": source})
    assert r.status_code == 200
    v = r.json()
    assert validate_verdict(v) == [], validate_verdict(v)
    assert v["label"] == label and v["input"]["source"] == source


def test_render_artifact_is_served(client):
    v = client.post("/api/investigate", json={"raw": "paytrn.com"}).json()
    art = next(e for e in v["evidence"] if e["tool"] == "human_eye_renderer")["details"]["artifacts"]
    assert art and art[0]["path"].startswith("runs/renders/")
    png = client.get("/" + art[0]["path"])
    assert png.status_code == 200 and png.content[:4] == b"\x89PNG"


def test_fixture_page_is_served(client):
    v = client.post("/api/investigate", json={"raw": "kx72-secure.top"}).json()
    fixture = next(e for e in v["evidence"] if e["tool"] == "page_probe")["details"]["fixture"]
    assert client.get("/fixtures/" + fixture).status_code == 200


def test_bad_input_and_batch_sources_are_refused(client):
    assert client.post("/api/investigate", json={"raw": "not a domain at all!!"}).status_code == 422
    assert client.post("/api/investigate", json={"raw": "x.com", "source": "nrd_snapshot"}).status_code == 422
    assert client.post("/api/investigate", json={"raw": ""}).status_code == 422


def test_scan_ranks_counts_and_exports(client):
    items = ["chai-and-code.in", "paytrn.com", "sbi-kyc-update.in", "onlinesbi.sbi.bank.in", "# comment", "!!!"]
    r = client.post("/api/scan", json={"items": items})
    assert r.status_code == 200
    out = r.json()
    sid = out.pop("scan_id")
    skipped = out.pop("skipped")
    summary = dict(out["summary"])
    out["summary"] = {k: v for k, v in summary.items() if k not in ("inputs", "not_domains")}
    assert validate_scan_result(out) == [], validate_scan_result(out)
    assert summary["inputs"] == 5 and summary["not_domains"] == 1 and skipped[0]["input"] == "!!!"
    labels = [v["label"] for v in out["verdicts"]]
    assert labels[0] == "sleeper" and labels[-1] == "genuine"            # ranked
    sources = {v["input"]["source"] for v in out["verdicts"]}
    assert sources == {"file"}
    for fmt, needle in [("json", '"verdicts"'), ("csv", "domain,display,label"), ("blocklist", "sbi-kyc-update.in"),
                        ("html", "<table>")]:
        e = client.get(f"/api/scan/{sid}/export/{fmt}")
        assert e.status_code == 200 and needle in e.text, fmt
        assert "attachment" in e.headers["content-disposition"]
    assert "paytrn.com" in client.get(f"/api/scan/{sid}/export/blocklist?include_review=true").text
    assert client.get(f"/api/scan/{sid}/export/pdf").status_code == 404
    assert client.get("/api/scan/nope/export/json").status_code == 404


def test_upload_csv_uses_the_domain_column(client):
    csv_text = "id,domain\n1,paytrn.com\n2,chai-and-code.in\n"
    r = client.post("/api/scan/upload", files={"file": ("list.csv", csv_text.encode(), "text/csv")})
    assert r.status_code == 200
    assert {v["domain"] for v in r.json()["verdicts"]} == {"paytrn.com", "chai-and-code.in"}


def test_batch_limits(client):
    assert client.post("/api/scan", json={"items": ["a.com"] * (MAX_BATCH + 1)}).status_code == 422
    assert client.post("/api/scan", json={"items": ["# only a comment"]}).status_code == 422


def test_report_returns_a_printable_case_file_and_refuses_a_broken_verdict(client):
    v = client.post("/api/investigate", json={"raw": "sbi-kyc-update.in", "source": "paste"}).json()
    r = client.post("/api/report", json={"verdict": v, "lang": "en", "llm": False})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "sbi-kyc-update.in" in r.text and "SLEEPER" in r.text and 'id="E1"' in r.text
    v["label"] = "genuine"                                   # no H1: the contract rejects it, so no case file
    assert client.post("/api/report", json={"verdict": v, "llm": False}).status_code == 422
