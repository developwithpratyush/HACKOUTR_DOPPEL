"""P12: the API's Live Hunt endpoints read the collector's state file and catch store (never the network)."""

import json
import time

import pytest
from fastapi.testclient import TestClient

import doppel.live as live
from doppel.api.app import app
from doppel.contract import validate_verdict
from doppel.live.collector import Pipeline
from doppel.live.messages import parse
from doppel.live.naive import KeywordBaseline
from doppel.live.store import Store


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def live_dir(tmp_path, monkeypatch, client):
    monkeypatch.setattr(live, "LIVE_DIR", tmp_path)
    from doppel.api.app import engine

    store = Store(tmp_path / "live" / "catches.db")
    store.open_session("live", "test")
    p = Pipeline(store, engine().brain, KeywordBaseline(engine().brain.reg), "live")
    p.feed(time.time(), parse({"message_type": "dns_entries", "data": ["paytrn.com", "hdfc-kyc-verify.in", "bakery.com"]}))
    p.flush()
    store.alarm("silent", "The stream went silent: test.")
    (tmp_path / "live" / "state.json").write_text(json.dumps({"mode": "live",
                                                              "written": time.time(), "pid": 1, "connected": True,
                                                              "ticker": [], "session_totals": dict(p.totals)}))
    (tmp_path / "recordings").mkdir()
    (tmp_path / "recordings" / "stream-20261106-01.jsonl.gz").write_bytes(b"")
    return tmp_path


def test_state_has_counters_catches_and_alarms(client, live_dir):
    r = client.get("/api/live/state?mode=live").json()
    assert r["running"] and r["state"]["connected"]
    assert r["summary"]["totals"]["uniq"] == 3 and r["summary"]["totals"]["flags"] == 2
    assert {c["name"] for c in r["catches"]} == {"paytrn.com", "hdfc-kyc-verify.in"}
    assert "verdict" not in r["catches"][0]                       # cards are light; the verdict comes on click
    assert r["alarms_open"][0]["kind"] == "silent"


def test_a_catch_opens_with_its_stored_verdict(client, live_dir):
    c = client.get("/api/live/catch", params={"name": "paytrn.com"}).json()
    assert c["label"] == "needs_review" and c["verdict"]["input"]["source"] == "ct_feed"
    assert not validate_verdict(c["verdict"])                     # contract-valid: the Explorer replays it as is
    assert client.get("/api/live/catch", params={"name": "nope.com"}).status_code == 404


def test_replay_mode_without_a_store_is_empty_not_an_error(client, live_dir):
    r = client.get("/api/live/state?mode=replay").json()
    assert r["running"] is False and r["catches"] == [] and r["summary"] == {}
    assert client.get("/api/live/state?mode=bogus").status_code == 422


def test_recordings_and_replay_guard(client, live_dir):
    assert client.get("/api/live/recordings").json()["recordings"][0]["name"] == "stream-20261106-01.jsonl.gz"
    bad = client.post("/api/live/replay", json={"files": ["../../secrets.txt"]})
    assert bad.status_code == 422
