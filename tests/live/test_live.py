"""P12 Live Hunt: parsing both stream formats, dedupe, the keyword baseline, the pipeline through the real brain,
replay, the watchdog against a local fake stream, lead time against a polled list, and the capped CT enricher.

No test touches the network: the stream is a local websocket server, the list and CT search are fakes.
"""

import asyncio
import json
import threading
import time

import pytest

from doppel.live import collector as col
from doppel.live.dedupe import RecentNames
from doppel.live.enrich import Enricher, facts
from doppel.live.leadtime import ListWatch, parents
from doppel.live.messages import parse
from doppel.live.naive import KeywordBaseline
from doppel.live.report import build, lead_rows
from doppel.live.store import Store

OLD = {"message_type": "certificate_update", "data": {
    "seen": 1762400000.5, "leaf_cert": {"all_domains": ["*.paytrn-kyc.com", "paytrn-kyc.com", "1.2.3.4"],
                                        "not_before": 1762399990, "issuer": {"O": "Let's Encrypt", "CN": "R11"}}}}
NEW = {"message_type": "dns_entries", "data": ["WWW.Example.org.", "example.org", "*.example.org"]}


@pytest.fixture(scope="module")
def brain():
    from doppel.brain.brain import Brain

    return Brain(deep=False)


# ------------------------------------------------------------------ messages / dedupe / naive ---

def test_both_stream_formats_parse():
    old = parse(OLD)
    assert old.kind == "certificate_update" and old.names == ["paytrn-kyc.com"]     # wildcard folded, IP dropped
    assert old.issuer == "Let's Encrypt" and old.not_before == 1762399990 and old.seen == 1762400000.5
    new = parse(NEW)
    assert new.kind == "dns_entries" and new.names == ["www.example.org", "example.org"]
    assert parse({"message_type": "heartbeat"}).kind == "heartbeat"
    unk = parse({"message_type": "cert_v3", "payload": {}})
    assert unk.kind == "unknown" and unk.raw_type == "cert_v3" and not unk.names


def test_dedupe_remembers_and_rotates():
    r = RecentNames(capacity=100, fp=0.001)
    assert not r.seen_or_add("a.com") and r.seen_or_add("a.com")
    for i in range(250):
        r.seen_or_add(f"n{i}.com")
    assert r.rotations == 2 and r.seen_or_add("n249.com")


def test_keyword_baseline_is_naive(brain):
    kw = KeywordBaseline(brain.reg)
    assert kw.hit("lesbian-bills.com") == "sbi"           # the noise a substring alert raises
    assert kw.hit("paytrn.com") is None                   # and the look-alike it can't see


# ------------------------------------------------------------------ pipeline ---

def test_pipeline_counts_flags_genuine_and_arming(tmp_path, brain):
    store = Store(tmp_path / "catches.db")
    store.watch_add([{"owner": "sbi-kyc-update.in", "brand": "sbi", "label": "needs_review", "risk": 0.9,
                      "tricks": "combosquat", "reason": "x", "added": 1.0, "source": "test", "cert_known": 0}])
    offered = []
    p = col.Pipeline(store, brain, KeywordBaseline(brain.reg), "live", on_flag=lambda row, armed: offered.append((row["name"], armed)))
    e = parse({"message_type": "dns_entries", "data": ["paytrn.com", "www.sbi-kyc-update.in", "lesbian-bills.com",
                                                        "google.co.in", "paytrn.com", "plain-bakery.com"]})
    p.feed(1000.0, e)
    p.flush()
    t = store.totals()
    assert t["certs"] == 1 and t["names"] == 5 and t["uniq"] == 5        # the duplicate inside the entry folded
    assert t["flags"] == 2 and t["genuine"] == 1                          # paytrn + the sbi name; google.co.in by its certificate
    assert t["naive_only"] >= 1 and t["doppel_only"] >= 1                 # "lesbian-bills" vs "paytrn"
    c = store.catch("paytrn.com")
    assert c["label"] == "needs_review" and c["brand"] == "paytm" and c["naive"] is None
    assert c["verdict"]["input"]["source"] == "ct_feed" and c["first_seen"] == 1000.0
    arm = store.armings()
    assert arm and arm[0]["owner"] == "sbi-kyc-update.in" and arm[0]["name"] == "www.sbi-kyc-update.in"
    assert ("www.sbi-kyc-update.in", True) in offered and ("paytrn.com", False) in offered


def test_replay_reads_a_recording_with_its_own_timestamps(tmp_path, brain):
    rec = col.Recorder(tmp_path / "recordings")
    t0 = 1762400000.0
    for i, names in enumerate([["paytrn.com", "a-bakery.com"], ["g00gle-login.com"], ["b-bakery.com"]]):
        rec.write(t0 + i * 0.01, parse({"message_type": "dns_entries", "data": names}))
    rec.close()
    files = sorted((tmp_path / "recordings").glob("*.jsonl.gz"))
    c = col.Collector("replay", root=tmp_path, recording=files, speed=1000, ct_daily_cap=0, brain=brain)
    c.run()
    st = json.loads((tmp_path / "replay" / "state.json").read_text())
    assert st["mode"] == "replay" and st["replay"]["finished"] and st["stream_now"] == pytest.approx(t0 + 0.02)
    s = Store(tmp_path / "replay" / "catches.db")
    assert {r["name"] for r in s.recent_catches()} == {"paytrn.com", "g00gle-login.com"}
    assert s.catch("paytrn.com")["first_seen"] == pytest.approx(t0)       # the recording's time, not the replay's


# ------------------------------------------------------------------ watchdog (a local fake stream) ---

def test_watchdog_alarms_on_format_change_and_silence(tmp_path, brain, monkeypatch):
    websockets = pytest.importorskip("websockets")
    from websockets.asyncio.server import serve

    monkeypatch.setattr(col, "WATCHDOG_EVERY_S", 0.2)
    monkeypatch.setattr(col, "SILENCE_S", 1.0)
    monkeypatch.setattr(col, "FORMAT_WINDOW_S", 0.8)
    monkeypatch.setattr(col, "RECONNECT_MAX_S", 0.3)
    connections = []

    async def handler(ws):
        connections.append(time.time())
        if len(connections) == 1:
            await ws.send(json.dumps({"message_type": "dns_entries", "data": ["paytrn.com"]}))
            for _ in range(15):                         # the format changes: messages, but no names
                await ws.send(json.dumps({"message_type": "cert_v9", "payload": {}}))
                await asyncio.sleep(0.1)
            await asyncio.sleep(3)                      # then silence
        else:
            await ws.send(json.dumps({"message_type": "dns_entries", "data": ["plain-bakery.com"]}))
            await asyncio.sleep(1)

    ready, port = threading.Event(), []

    def server():
        async def main():
            async with serve(handler, "127.0.0.1", 0) as srv:
                port.append(srv.sockets[0].getsockname()[1])
                ready.set()
                await asyncio.sleep(8)
        asyncio.run(main())

    th = threading.Thread(target=server, daemon=True)
    th.start()
    assert ready.wait(5)
    c = col.Collector("live", root=tmp_path, url=f"ws://127.0.0.1:{port[0]}", ct_daily_cap=0, brain=brain,
                      jobs=False, record=False)
    c.run(duration_s=6)
    kinds = {a["kind"] for a in c.store.alarms()}
    assert "format" in kinds and "silent" in kinds
    assert len(connections) >= 2 and c.reconnects >= 1                    # silence forced a reconnect
    assert c.store.catch("paytrn.com") is not None


def test_forced_reconnect_comes_back(tmp_path, brain, monkeypatch):
    from websockets.asyncio.server import serve

    monkeypatch.setattr(col, "WATCHDOG_EVERY_S", 0.2)
    monkeypatch.setattr(col, "RECONNECT_MAX_S", 0.3)
    connections = []

    async def handler(ws):
        connections.append(time.time())
        for _ in range(40):
            await ws.send(json.dumps({"message_type": "dns_entries", "data": [f"n{len(connections)}-{time.time()}.com"]}))
            await asyncio.sleep(0.05)

    ready, port = threading.Event(), []

    def server():
        async def main():
            async with serve(handler, "127.0.0.1", 0) as srv:
                port.append(srv.sockets[0].getsockname()[1])
                ready.set()
                await asyncio.sleep(5)
        asyncio.run(main())

    threading.Thread(target=server, daemon=True).start()
    assert ready.wait(5)
    c = col.Collector("live", root=tmp_path, url=f"ws://127.0.0.1:{port[0]}", ct_daily_cap=0, brain=brain,
                      jobs=False, record=False)
    threading.Timer(0.8, lambda: (tmp_path / "live" / "RECONNECT").write_text("x")).start()
    c.run(duration_s=3)
    assert c.forced == 1 and c.reconnects >= 1 and len(connections) >= 2
    assert c.rate() < 100                                  # the rate isn't inflated by the fresh connection
    assert not (tmp_path / "live" / "RECONNECT").exists()


# ------------------------------------------------------------------ lead time ---

class FakeList:
    def __init__(self):
        self.lists = []

    def __call__(self, etag):
        body = "\n".join(self.lists.pop(0)).encode()
        return 200, None, body


def _filler(n=1200):
    return [f"filler{i}.top" for i in range(n)]


def test_lead_time_before_after_and_same_window(tmp_path):
    store = Store(tmp_path / "catches.db")
    fake = FakeList()
    lw = ListWatch(tmp_path, store, every_h=1, fetch=fake)
    fake.lists.append(_filler() + ["already-listed.top"])
    assert lw.poll(now=1000.0)
    for name, f in (("already-listed.top", 1500.0), ("ahead.top", 2000.0), ("window.top", 5000.0),
                    ("login.owner-match.xyz", 2100.0), ("never.top", 2200.0)):
        row = {"name": name, "owner": name.split(".", 1)[1] if name.startswith("login.") else name,
               "first_seen": f, "last_seen": f, "label": "needs_review", "platform": None}
        row.update(lw.status_at_flag(name, row["owner"], None))
        store.upsert_catch(row, None)
    assert store.catch("already-listed.top")["pdb_status"] == "listed_before"
    fake.lists.append(_filler())                                          # poll at 4600: nothing new yet
    lw.poll(now=4600.0)
    fake.lists.append(_filler() + ["ahead.top", "window.top", "owner-match.xyz"])
    lw.poll(now=8200.0)
    a = store.catch("ahead.top")
    assert a["pdb_status"] == "listed_after" and a["pdb_prev_poll"] == 4600.0 and a["pdb_listed_poll"] == 8200.0
    assert store.catch("window.top")["pdb_status"] == "listed_same_window"   # flagged after the last clean poll
    om = store.catch("login.owner-match.xyz")
    assert om["pdb_status"] == "listed_after" and om["pdb_match"] == "owner"
    assert store.catch("never.top")["pdb_status"] == "not_listed"
    counts, rows = lead_rows(store)
    assert counts[("stream", "listed_after")] == 2 and counts[("stream", "listed_before")] == 1
    ahead = next(r for r in rows if r["name"] == "ahead.top")
    assert ahead["lead_min_h"] == pytest.approx((4600 - 2000) / 3600) and ahead["lead_max_h"] == pytest.approx(6200 / 3600)


def test_a_broken_list_download_never_unlists(tmp_path):
    store = Store(tmp_path / "catches.db")
    fake = FakeList()
    lw = ListWatch(tmp_path, store, every_h=1, fetch=fake)
    fake.lists.append(["just.one.top"])
    assert not lw.poll(now=10.0) and lw.poll_t is None
    assert parents({"a.b.x.top"}) == {"b.x.top", "x.top"}


# ------------------------------------------------------------------ CT enricher ---

def _rec(sans, nb="2026-11-06T01:00:00Z", fetched=None):
    return {"source": "fake", "fetched_at": fetched or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "issuances": [{"sans": sans, "not_before": nb, "issuer": {"o": "Let's Encrypt"},
                           "subject": {"o": None}}], "rate_limit_remaining": "50"}


def test_enricher_picks_highest_priority_under_the_cap(tmp_path, monkeypatch):
    store = Store(tmp_path / "catches.db")
    looked = []

    def search(owner, include_subdomains=True, network=True):
        if not network:
            return None
        looked.append(owner)
        return _rec([owner, "*." + owner])

    monkeypatch.setattr("doppel.live.enrich.ct.search", search)
    en = Enricher(tmp_path / "catches.db", rejudge=lambda n: None, daily_cap=2, search=search)
    en.gap = 0
    now = time.time()
    rows = [("low-google.com", "google", 0.6, None), ("high-sbi.in", "sbi", 0.7, None),
            ("tenant.pages.dev", "hdfc", 0.99, "pages.dev"), ("mid-paytm.in", "paytm", 0.65, None)]
    for name, brand, risk, plat in rows:
        row = {"name": name, "owner": name, "brand": brand, "risk": risk, "label": "needs_review",
               "first_seen": now, "last_seen": now, "platform": plat}
        store.upsert_catch(row, None)
        en.offer(row)
    assert store.catch("tenant.pages.dev")["ct_status"] == "skipped_platform"
    assert en.step() == "looked_up" and en.step() == "looked_up" and en.step() is None   # the cap holds
    assert looked == ["high-sbi.in", "mid-paytm.in"]                    # Indian brands first, by risk
    c = store.catch("high-sbi.in")
    assert c["ct_status"] == "looked_up" and c["ct_count"] == 1 and c["ct_cert_not_before"].startswith("2026-11-06")
    assert store.ct_used(en._day()) == 2


def test_enricher_rate_limit_pauses(tmp_path, monkeypatch):
    from doppel.certs import ct

    store = Store(tmp_path / "catches.db")

    def search(owner, include_subdomains=True, network=True):
        if not network:
            return None
        raise ct.RateLimited("429")

    monkeypatch.setattr("doppel.live.enrich.ct.search", search)
    en = Enricher(tmp_path / "catches.db", rejudge=lambda n: None, daily_cap=5, search=search)
    en.gap = 0
    row = {"name": "x-sbi.in", "owner": "x-sbi.in", "brand": "sbi", "risk": 0.8, "label": "needs_review",
           "first_seen": time.time(), "last_seen": time.time(), "platform": None}
    store.upsert_catch(row, None)
    en.offer(row)
    assert en.step() == "rate_limited" and en.paused_until > time.time() + 3000
    assert any(a["kind"] == "ct_quota" for a in store.alarms(open_only=True))


def test_facts_pick_the_certificate_that_named_it():
    rec = {"source": "x", "fetched_at": "2026-11-06T05:00:00Z", "issuances": [
        {"sans": ["a.x.top"], "not_before": "2026-11-01T00:00:00Z", "issuer": {"o": "LE"}, "subject": {}},
        {"sans": ["*.x.top"], "not_before": "2026-11-06T04:00:00Z", "issuer": {"o": "GTS"}, "subject": {}},
        {"sans": ["*.x.top"], "not_before": "2026-11-07T00:00:00Z", "issuer": {"o": "GTS"}, "subject": {}}]}
    seen = time.mktime(time.strptime("2026-11-06T04:00:41", "%Y-%m-%dT%H:%M:%S")) - time.timezone
    f = facts(rec, "b.x.top", seen)
    assert f["ct_count"] == 3 and f["ct_first"].startswith("2026-11-01")
    assert f["ct_cert_not_before"] == "2026-11-06T04:00:00Z"            # issued 41 s before the stream showed it


# ------------------------------------------------------------------ report ---

def test_report_builds_from_the_store(tmp_path, brain):
    store = Store(tmp_path / "live" / "catches.db")
    p = col.Pipeline(store, brain, KeywordBaseline(brain.reg), "live")
    store.open_session("live", "test", t=100.0)
    p.feed(160.0, parse({"message_type": "dns_entries", "data": ["paytrn.com", "sbi-kyc-update.in", "bakery.com"]}))
    p.flush()
    md = build(tmp_path, "live")
    assert "Unique names judged | **3**" in md and "`paytrn.com`" in md and "Names only." in md


def test_priority_prefers_clear_shapes_over_short_typos():
    short = {"risk": 0.9, "brand": "sbi", "owner": "ubi.dev", "tricks": "typo,brand_closeness", "label": "needs_review"}
    combo = {"risk": 0.85, "brand": "sbi", "owner": "sbi-kyc-update.in", "tricks": "combosquat,brand_closeness",
             "label": "needs_review"}
    assert Enricher.priority(combo, False) > Enricher.priority(short, False)
    assert Enricher.priority(short, True) > Enricher.priority(short, False)          # an armed sleeper goes first


def test_first_lookup_waits_one_gap(tmp_path):
    en = Enricher(tmp_path / "catches.db", rejudge=lambda n: None, daily_cap=24)
    row = {"name": "x-hdfc.in", "owner": "x-hdfc.in", "brand": "hdfc", "risk": 0.9, "label": "needs_review",
           "first_seen": time.time(), "last_seen": time.time(), "platform": None, "tricks": "combosquat"}
    Store(tmp_path / "catches.db").upsert_catch(row, None)
    en.search = lambda *a, **k: pytest.fail("looked up before the first gap")
    en.offer(row)
    assert en.step() is None
