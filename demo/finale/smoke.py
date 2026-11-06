"""P14 smoke check: does every finale beat (docs/finale-examples.md §0) still give the verdict the docs promise?

    .venv/Scripts/python.exe demo/finale/smoke.py          # PASS/FAIL per case, exit 1 on any FAIL

The expected verdicts below are the pinned example pack: each row cites the section of finale-examples.md it
comes from. Runs with DOPPEL_OFFLINE=1, so certificates come from the CT cache only (no lookups, no key used),
and pages are the local fixture kits (demo/fixtures/sites.yaml). Nothing here ever contacts a suspect.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

os.environ["DOPPEL_OFFLINE"] = "1"
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from doppel.brain.brain import investigate  # noqa: E402

G, R, P, B = "genuine", "needs_review", "phishing", "benign"

# (beat, domain, source, certs, expected label, evidence id that must appear or None, finale-examples section)
CASES = [
    ("1 opener", "echallan.parivahan.gov.in.pay-fine.icu", "gallery", None, P, None, "§1 fake"),
    ("1 opener", "echallan.parivahan.gov.in", "paste", None, G, None, "§1 real"),
    ("3 cert", "google.co.in", "paste", False, R, None, "§2.1 cert off"),
    ("3 cert", "google.co.in", "paste", True, G, "certificate_san_link", "§2.1 cert on"),
    ("3 cert", "googleapis.com", "paste", True, G, None, "§2.1"),
    ("3 cert", "upichalega.com", "paste", True, G, None, "§2.3"),
    ("4 padlock", "hdfc-pan-up-date2.web.app", "paste", True, R, "certificate_platform_only", "§2.6"),
    ("4 padlock", "sbicard.com", "paste", True, R, "certificate_organisation_other", "§2.7"),
    ("5 campaign", "in-echallan.online", "paste", True, R, "campaign_member", "§4.1"),
    ("6 deep", "kx72-secure.top", "gallery", None, P, None, "§6.1"),
    ("6 deep", "xn--pytm-53d.com", "gallery", None, P, None, "§6.2"),
    ("7 fool", "sbi-secure-login.com", "paste", None, R, None, "§5"),
    ("7 fool", "paytm.com.verify-kyc.in", "paste", None, R, None, "§5"),
    ("7 fool", "onlinesbi.co", "paste", None, R, None, "§5"),
    ("7 fool", "goog1e.com", "paste", None, R, None, "§5"),
    ("7 fool", "icicibank.com.in", "paste", None, R, None, "§5"),
    ("7 fool", "hdfcbank-rewards.in", "paste", None, R, None, "§5"),
    ("7 fool", "google.one", "paste", None, R, None, "§5"),
    ("7 fool", "one.google", "paste", None, G, None, "§5"),
    ("7 fool", "sbi.bank.in", "paste", None, G, None, "§5"),
    ("7 fool", "yonobusiness.sbi", "paste", None, G, None, "§7"),
]


def check_campaign() -> tuple[bool, str]:
    """§4.1: the radar holds the 5-name e-Challan island with the certificate recipe."""
    radar = json.loads((ROOT / "data" / "campaigns" / "radar.json").read_text(encoding="utf-8"))
    want = {"in-echallan.online", "in-echallan.date", "in-echallan.party", "in-echallan.trade", "ln-echallan.bid"}
    for c in radar["campaigns"]:
        if want <= set(c["members_ids"]):
            return "recipe" in c["strength"], f"{c['size']} members, {c['strength']}, {len(c['armed'])} armed"
    return False, "e-Challan island missing (rerun `doppel campaigns`)"


def check_live() -> tuple[bool, str]:
    """§3: the saved catch store still loads (the stage replays from it)."""
    from doppel.live.report import summary

    s = summary(mode="live")
    flat = json.dumps(s, default=str)
    return bool(s) and '"flag' in flat, f"catch store loads ({len(flat):,} bytes of summary)"


def block_network() -> None:
    """--no-network: any socket to a non-loopback address raises. Proves the stage runs with the internet off."""
    import socket

    local = lambda h: str(h) in ("::1", "localhost") or str(h).startswith("127.")   # noqa: E731
    real_connect, real_cc, real_gai = socket.socket.connect, socket.create_connection, socket.getaddrinfo

    def connect(self, addr):
        if isinstance(addr, tuple) and not local(addr[0]):
            raise OSError(f"network blocked by smoke --no-network: {addr}")
        return real_connect(self, addr)

    def create_connection(addr, *a, **k):
        if not local(addr[0]):
            raise OSError(f"network blocked by smoke --no-network: {addr}")
        return real_cc(addr, *a, **k)

    def getaddrinfo(host, *a, **k):             # a DNS lookup is network use too
        if host is not None and not local(host):
            raise OSError(f"DNS blocked by smoke --no-network: {host}")
        return real_gai(host, *a, **k)

    socket.socket.connect, socket.create_connection, socket.getaddrinfo = connect, create_connection, getaddrinfo


def check_stale() -> tuple[bool, str]:
    """The Deep kits must be fresh (serve refuses to start otherwise)."""
    from doppel.deep.pages import stale_clones

    st = stale_clones()
    return not st, "all fixture kits fresh" if not st else "; ".join(st)[:150]


def check_pack(got: dict[str, str]) -> tuple[bool, str]:
    """The offline pack (build_pack.py) must hold every stage case with today's label."""
    idx_f = ROOT / "demo" / "finale" / "pack" / "index.json"
    if not idx_f.exists():
        return False, "no pack: run demo/finale/build_pack.py"
    idx = json.loads(idx_f.read_text(encoding="utf-8"))
    off = [d for d, lab in got.items() if idx["cases"].get(d, {}).get("label") != lab]
    return not off, (f"{len(idx['cases'])} recorded cases, labels current ({idx['generated_at']})" if not off
                     else f"stale for {', '.join(off[:4])}: rerun build_pack.py")


def check_baselines() -> tuple[bool, str]:
    """The generic-tools rows compute: keyword fires on Google's own google.co.in, the blocklist knows the HDFC scam."""
    from doppel.baselines import generic

    g = generic()
    a = {r["method"]: r["flagged"] for r in g.compare("google.co.in")}
    b = {r["method"]: r["flagged"] for r in g.compare("hdfc-pan-up-date2.web.app")}
    ok = a.get("keyword") is True and b.get("blocklist") is True and "dnstwist" in a
    return ok, f"keyword on google.co.in {a.get('keyword')}, blocklist on the HDFC scam {b.get('blocklist')}, dnstwist {'dnstwist' in a}"


BUDGET_S = {"1 opener": 90, "3 cert": 45, "4 padlock": 40, "5 campaign": 45, "6 deep": 40, "7 fool": 60}


def main() -> int:
    if "--no-network" in sys.argv:
        block_network()
        print("network: blocked (only loopback allowed)", end="\n\n")
    fails, t0 = 0, time.time()
    spent: dict[str, float] = {}
    got: dict[str, str] = {}
    for beat, dom, src, certs, want, ev, ref in CASES:
        t = time.time()
        try:
            v = investigate(dom, src, certs=certs)
            got_l, risk = v["label"], v.get("risk", v.get("risk_score"))
            ok = got_l == want and (ev is None or ev in json.dumps(v))
            note = f"{got_l} ({risk})" + ("" if ev is None or ev in json.dumps(v) else f", missing {ev}")
            if certs is not False:
                got[v["domain"]] = got_l
        except Exception as exc:  # a crash is a FAIL, not a stop
            ok, note = False, f"error: {exc!r}"[:120]
        spent[beat] = spent.get(beat, 0) + time.time() - t
        fails += not ok
        tag = "" if certs is None else (" [cert on]" if certs else " [cert off]")
        print(f"{'PASS' if ok else 'FAIL'}  {beat:<11} {dom + tag:<52} want {want:<12} got {note}  {ref}")
    checks = (("5 campaign", check_campaign), ("2 live", check_live), ("fixtures", check_stale),
              ("pack", lambda: check_pack(got)), ("baselines", check_baselines))
    for name, fn in checks:
        try:
            ok, note = fn()
        except Exception as exc:
            ok, note = False, f"error: {exc!r}"[:120]
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name:<11} {note}")
    print()
    print("engine time per stage beat (the rest of each beat is talking):")
    for beat, s in spent.items():
        print(f"  {beat:<11} {s:6.1f} s   budget {BUDGET_S.get(beat, 0)} s")
    total = len(CASES) + len(checks)
    print()
    print(f"{total - fails}/{total} pass in {time.time() - t0:.1f} s")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
