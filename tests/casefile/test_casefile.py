"""P10: the Case-File Writer. No network: the LLM is replaced by canned answers, or is unavailable (offline)."""

import json
import re

import pytest

from doppel.casefile import CaseFileRefused, llm, write
from doppel.casefile import writer as W
from doppel.casefile.report import render
from doppel.contract import REPO_ROOT

VERDICTS = {v["domain"]: v for v in json.loads(
    (REPO_ROOT / "ui" / "src" / "lib" / "testdata" / "real-verdicts.json").read_text(encoding="utf-8"))}
V05 = VERDICTS["kx72-secure.top"]          # PHISHING by H2 (+H3, H4), Telegram exfil
V06 = VERDICTS["onlinesbi.sbi.bank.in"]    # GENUINE by H1
TOKEN_SHAPE = re.compile(r"[0-9]{8,10}:[A-Za-z0-9_-]{35}")


def _fake(monkeypatch, answer: dict | Exception):
    def chat(messages, **kw):
        if isinstance(answer, Exception):
            raise answer
        return llm.Answer(json.dumps(answer, ensure_ascii=False), "fake-model", "groq", 5.0, 100)
    monkeypatch.setattr(llm, "chat", chat)


# ------------------------------------------------------------------ facts ---

def test_fact_sheet_has_the_verdict_line_and_one_line_per_evidence_item():
    fs = W.facts(V05)
    assert fs[0]["id"] == "V" and "FINAL LABEL PHISHING" in fs[0]["text"] and "H2_brand_claim_foreign_credentials" in fs[0]["text"]
    assert [f["id"] for f in fs[1:]] == [e["evidence_id"] for e in V05["evidence"]]
    assert not TOKEN_SHAPE.search(json.dumps(fs))


# ------------------------------------------------------------------ validator ---

FACTS = {f["id"]: f["text"] for f in W.facts(V05)}


@pytest.mark.parametrize("text,cites,lang,ok", [
    ("The page copies State Bank of India's page.", [], "en", False),
    ("The page copies State Bank of India's page.", ["E99"], "en", False),
    ("Overall the site looks legitimate.", ["V"], "en", False),
    ("This is not a phishing site.", ["V"], "en", False),
    ("The risk score is 0.42.", ["V"], "en", False),
    ("It copies the genuine page at 87%.", ["E8"], "en", False),
    ("It copies the genuine page at 100%.", ["E8"], "en", True),
    ("The password also goes to sbi-secure-login.com.", ["E13"], "en", False),
    ("The password goes to kx72-secure.top.", ["E13"], "en", True),
    ("The page sends the password to Telegram.", ["E12"], "hi", False),
    ("पेज पासवर्ड सीधे Telegram पर भेजता है।", ["E12"], "hi", True),
    ("Doppel marked it GENUINE.", ["V"], "en", False),
    ("Judged by the name alone it would be BENIGN.", ["V"], "en", True),
    ("In Stage 1 the name looked unrelated to any brand.", ["E4"], "en", True),
])
def test_validator(text, cites, lang, ok):
    assert (W.validate({"text": text, "cites": cites}, "phishing", FACTS, lang) is None) == ok


def test_digits_inside_domains_are_not_numbers():
    assert W._numbers("owner xn--pytm-53d.com, closeness 0.99, 99.6%, U+0430, E14") == [0.99, 0.996]


# ------------------------------------------------------------------ the writer ---

def test_llm_sentences_are_kept_or_rejected_and_empty_sections_fall_back(monkeypatch):
    _fake(monkeypatch, {
        "label": "genuine",                                            # the LLM can't change anything: ignored
        "summary": [{"text": "kx72-secure.top is PHISHING: it copies State Bank of India's page.", "cites": ["V", "E8"]},
                    {"text": "It looks legitimate overall.", "cites": ["V"]}],
        "name": [{"text": "The owner is kx72-secure.top.", "cites": []}],
        "page": [{"text": "The page sends what you type straight to Telegram.", "cites": ["E12"]}, "a bare string"],
    })
    cf = write(V05)
    by = {s.id: s for s in cf.sections}
    assert [x.text for x in by["summary"].sentences] == ["kx72-secure.top is PHISHING: it copies State Bank of India's page."]
    assert by["summary"].rejected[0]["why"].startswith("contradicts the label")
    assert by["name"].method == "template" and by["name"].rejected[0]["why"] == "no citation"
    assert by["page"].method == "llm" and by["page"].rejected[0]["why"] == "not a sentence object"
    assert cf.narration["accepted"] == 2 and cf.narration["rejected"] == 3 and cf.narration["model"] == "fake-model"
    assert cf.verdict["label"] == "phishing"


def test_offline_gives_a_complete_template_case_file(monkeypatch):
    _fake(monkeypatch, llm.LLMUnavailable("offline"))
    for v in VERDICTS.values():
        cf = write(v)
        assert all(s.method == "template" and s.sentences and all(x.cites for x in s.sentences) for s in cf.sections)
        assert cf.actions and cf.narration["error"].startswith("LLMUnavailable")


def test_refuses_an_invalid_verdict_or_one_without_evidence():
    bad = json.loads(json.dumps(V05))
    bad["label"] = "genuine"                                             # contradicts its own hard rule
    with pytest.raises(CaseFileRefused):
        write(bad, use_llm=False)
    with pytest.raises(ValueError):
        write(V05, lang="fr", use_llm=False)


# ------------------------------------------------------------------ actions ---

def test_actions_come_from_rules():
    a05 = " ".join(a["text"] for a in W.actions(V05))
    assert "Block kx72-secure.top" in a05 and "Telegram" in a05 and "****:[REDACTED]" in a05
    assert "State Bank of India's security team" in a05
    assert W.actions(V06)[0]["text"].startswith("No action")
    assert "Watch-list" in W.actions(VERDICTS["sbi-kyc-update.in"])[0]["text"]
    e04 = W.actions(VERDICTS["echallan.parivahan.gov.in.pay-fine.icu"])
    assert any("challan-pay-secure.xyz" in a["text"] for a in e04)          # the collection endpoint
    assert all(a["cites"] for v in VERDICTS.values() for a in W.actions(v))


# ------------------------------------------------------------------ the HTML ---

def test_html_is_self_contained_cited_and_redacted(monkeypatch):
    _fake(monkeypatch, llm.LLMUnavailable("offline"))
    cf = write(V05, "hi")
    html = render(cf)
    assert '<html lang="hi">' in html and "केस फ़ाइल" in html
    for e in V05["evidence"]:
        assert f'id="{e["evidence_id"]}"' in html                       # every item in the appendix
    for s in cf.sections:
        for x in s.sentences:
            for c in x.cites:
                assert f'href="#{"verdict" if c == "V" else c}"' in html
    assert not re.search(r'(src|href)="https?://', html)                 # opens offline, prints anywhere
    assert not TOKEN_SHAPE.search(html)
    assert "data:image/png;base64," in html or not any(
        (REPO_ROOT / a["path"]).exists() for e in V05["evidence"] for a in e["details"].get("artifacts") or [])


# ------------------------------------------------------------------ the client ---

def test_client_replays_the_cache_offline_and_says_when_it_cant(monkeypatch, tmp_path):
    monkeypatch.setattr(llm, "CACHE", tmp_path)
    monkeypatch.setenv("DOPPEL_OFFLINE", "1")
    msgs = [{"role": "user", "content": "hello"}]
    with pytest.raises(llm.LLMUnavailable):
        llm.chat(msgs)
    opts = {"json": True, "t": 0.0, "max": 2000, "tools": None}
    (tmp_path / f"{llm._key(llm.models()[0], msgs, opts)}.json").write_text(
        json.dumps({"model": llm.models()[0], "text": '{"ok": 1}'}), encoding="utf-8")
    ans = llm.chat(msgs)
    assert ans.method == "cache" and ans.json() == {"ok": 1}


# ------------------------------------------------------------------ CLI ---

def test_cli_writes_a_template_case_file(tmp_path):
    from typer.testing import CliRunner

    from doppel.cli import app

    src = tmp_path / "v.json"
    src.write_text(json.dumps(V05, ensure_ascii=False), encoding="utf-8")
    out = tmp_path / "cf.html"
    r = CliRunner().invoke(app, ["report", str(src), "--no-llm", "--out", str(out)])
    assert r.exit_code == 0, r.output
    assert "kx72-secure.top" in out.read_text(encoding="utf-8")
