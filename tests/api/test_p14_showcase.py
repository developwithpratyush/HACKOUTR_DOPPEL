"""P14: the generic baselines, the stale-kit check, offline health, pinned replay recordings, and the offline pack."""
import json
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from doppel.api.app import app
from doppel.baselines import LEV_TAU, generic
from doppel.contract import REPO_ROOT
from doppel.deep import pages


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def by(rows):
    return {r["method"]: r for r in rows}


def test_baselines_fail_where_the_stage_says():
    g = generic()
    gi = by(g.compare("google.co.in"))
    assert gi["keyword"]["flagged"] is True                 # keyword alerts on Google's own site
    assert gi["levenshtein"]["flagged"] is True
    kx = by(g.compare("kx72-secure.top"))
    assert kx["keyword"]["flagged"] is False and kx["levenshtein"]["flagged"] is False   # blind to the no-brand kit
    assert by(g.compare("hdfc-pan-up-date2.web.app"))["blocklist"]["flagged"] is True
    if "dnstwist" in gi:
        assert by(g.compare("goog1e.com"))["dnstwist"]["flagged"] is True
        assert by(g.compare("in-echallan.online"))["dnstwist"]["flagged"] is False
    assert 0 < LEV_TAU < 1


def test_baselines_endpoint_reads_the_verdicts_ml(client):
    v = client.post("/api/investigate", json={"raw": "in-echallan.online", "source": "paste"}).json()
    r = client.post("/api/baselines", json={"verdict": v})
    assert r.status_code == 200
    rows = by(r.json()["rows"])
    assert rows["ml"]["flagged"] is True and rows["ml"]["detail"].startswith("0.9")
    assert rows["padlock"]["flagged"] is False               # armed: it shows a padlock
    assert client.post("/api/baselines", json={"verdict": {}}).status_code == 422


def test_health_reports_offline_and_stale(client, monkeypatch):
    h = client.get("/api/health").json()
    assert "offline" in h and isinstance(h["stale_fixtures"], list)
    monkeypatch.setenv("DOPPEL_OFFLINE", "1")
    assert client.get("/api/health").json()["offline"] is True


def test_stale_clone_detected(tmp_path, monkeypatch):
    if not pages.SITES.exists():
        pytest.skip("no fixtures")
    site = next((h for h, s in pages.sites().items() if s.get("clone_of") and s.get("status") != "none"), None)
    if site is None or not pages.generated_path(site).exists():
        pytest.skip("no generated clone on this machine")
    gen = pages.generated_path(site)
    old = gen.stat().st_mtime
    try:
        os.utime(gen, (old, pages.SITES.stat().st_mtime - 60))
        assert any(s.startswith(site) for s in pages.stale_clones())
    finally:
        os.utime(gen, (old, old))
    assert not any(s.startswith(site + ":") and "older than demo" in s for s in pages.stale_clones())


def test_serve_refuses_on_stale_kits(monkeypatch):
    from doppel import cli

    monkeypatch.setattr("doppel.deep.pages.stale_clones", lambda: ["kx72-secure.top: clone not generated"])
    res = CliRunner().invoke(cli.app, ["serve", "--port", "1"])
    assert res.exit_code == 2 and "Refusing to start" in res.output


def test_live_keep_pins_a_recording(tmp_path, monkeypatch):
    import doppel.live as live
    from doppel import cli

    rec = tmp_path / "recordings"
    rec.mkdir()
    for i, size in enumerate((10, 500, 20)):
        (rec / f"stream-20261106-0{i}.jsonl.gz").write_bytes(b"x" * size)
    monkeypatch.setattr(live, "LIVE_DIR", tmp_path)
    res = CliRunner().invoke(cli.app, ["live", "keep"])
    assert res.exit_code == 0, res.output
    assert [p.name for p in (rec / "keep").iterdir()] == ["stream-20261106-01.jsonl.gz"]   # biggest complete hour


def test_offline_pack_is_complete():
    idx_f = REPO_ROOT / "demo" / "finale" / "pack" / "index.json"
    if not idx_f.exists():
        pytest.skip("pack not built")
    idx = json.loads(idx_f.read_text(encoding="utf-8"))
    for d in ("echallan.parivahan.gov.in.pay-fine.icu", "google.co.in", "in-echallan.online", "kx72-secure.top"):
        rec = json.loads((idx_f.parent / idx["cases"][d]["file"]).read_text(encoding="utf-8"))
        assert rec["verdict"]["domain"] == d and rec["baselines"]
    g = json.loads((idx_f.parent / idx["cases"]["google.co.in"]["file"]).read_text(encoding="utf-8"))
    assert g["verdict_certs_off"]["label"] == "needs_review"          # the certificate toggle works offline
    ctx = json.loads((idx_f.parent / "context.json").read_text(encoding="utf-8"))
    assert ctx["arena"]["levenshtein"] == {"flagged": 15, "of": 19} and ctx["arena"]["doppel"]["flagged"] == 0
