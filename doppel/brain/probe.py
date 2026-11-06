"""Page Probe (Stage 2, Standard; C9): is there a page, and does it ask for credentials?

**Safety first.** The probe never contacts an unknown domain. It reads only local fixtures listed in
``demo/fixtures/sites.yaml`` (pages we made, served nowhere). Any other name, including every NRD or
CT-feed name, gets ``not_probed``: the verdict then rests on the name evidence alone and says so.
P8 replaces the file read with Playwright against localhost-served copies; the findings stay the same.

Findings: live_login_form, live_payment_form, live_no_credentials, parked, no_page, not_probed.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

from doppel.contract import REPO_ROOT, load_yaml
from doppel.evidence import Ids, evidence

TOOL, STAGE = "page_probe", "standard"
FIXTURES = REPO_ROOT / "demo" / "fixtures" / "sites.yaml"

PARKED_SIGNS = re.compile(r"\b(domain (is )?parked|parked free|buy this domain|for sale|coming soon|"
                          r"this domain may be for sale)\b", re.I)
CARD = re.compile(r"card|cvv|cvc|expir|cc-number|upi.?pin|mpin", re.I)
OTP = re.compile(r"\botp\b|one.?time|verification code", re.I)
LOGIN = re.compile(r"pass(word)?|user(name)?|login|mobile|customer.?id", re.I)


class _Form(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.inputs: list[dict] = []
        self.forms: list[str] = []
        self.text: list[str] = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "input":
            self.inputs.append(a)
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        self.text.append(data)


@dataclass
class ProbeResult:
    status: str                       # live | parked | none | not_probed
    login: bool = False
    payment: bool = False
    asks_for: list[str] = field(default_factory=list)
    title: str = ""
    form_actions: list[str] = field(default_factory=list)
    fixture: str | None = None


def _sites(path: Path = FIXTURES) -> dict:
    return load_yaml(path).get("sites", {}) if path.exists() else {}


def probe(host: str, fixtures: Path = FIXTURES) -> ProbeResult:
    site = _sites(fixtures).get(host)
    if site is None:
        return ProbeResult("not_probed")
    if site["status"] == "none":
        return ProbeResult("none")
    html, fixture = None, site.get("page")
    if fixtures == FIXTURES:                       # the same page the Deep sandbox renders (P8: a generated clone)
        from doppel.deep.pages import page_html

        html, info = page_html(host)
        if info.get("source") == "generated_clone":
            fixture = f"generated/{host}.html (clone of {info['clone_of']})"
    if html is None:
        html = (fixtures.parent / site["page"]).resolve().read_text(encoding="utf-8")
    p = _Form()
    p.feed(html)
    text = " ".join(p.text)
    fields = [" ".join(f"{k}={v}" for k, v in i.items()) for i in p.inputs]
    asks = []
    if any(i.get("type") == "password" for i in p.inputs):
        asks.append("password")
    if any(CARD.search(f) for f in fields):
        asks.append("card")
    if any(OTP.search(f) for f in fields):
        asks.append("otp")
    if any(LOGIN.search(f) for f in fields) and "password" not in asks:
        asks.append("username")
    status = "parked" if site["status"] == "parked" or (not p.inputs and PARKED_SIGNS.search(text)) else "live"
    return ProbeResult(status, login="password" in asks, payment="card" in asks, asks_for=asks,
                       title=p.title.strip(), form_actions=p.forms, fixture=fixture)


def page_probe(host: str, ids: Ids | None = None, fixtures: Path = FIXTURES,
               brand: dict | None = None, in_family: bool = False) -> tuple[ProbeResult, list[dict]]:
    """Stage-2 tool. ``in_family``: the owner is proven genuine, so a login form there is expected (neutral)."""
    ids = ids or Ids()
    t0 = time.perf_counter()
    r = probe(host, fixtures)
    common = {"tool": TOOL, "stage": STAGE, "criterion": "C9"}
    det = {"status": r.status, "fixture": r.fixture, "mock": r.fixture is not None}
    if r.status == "not_probed":
        item = evidence(ids, **common, finding="not_probed", points_to="neutral", strength="medium", score=0,
                        summary=("Page not opened: Doppel never visits unknown domains. This verdict rests on the "
                                 "name evidence alone."), **det)
    elif r.status == "none":
        item = evidence(ids, **common, finding="no_page", points_to="phishing", strength="medium", score=0.5,
                        summary="No page answers: registered but not set up yet.", **det)
    elif r.status == "parked":
        item = evidence(ids, **common, finding="parked", points_to="phishing", strength="medium", score=0.6,
                        summary="Registrar parking page: no content, no form. Registered, not weaponised yet.",
                        has_login_form=False, **det)
    elif in_family and (r.login or r.payment):
        item = evidence(ids, **common, finding="live_login_form", points_to="neutral", strength="medium", score=0,
                        target_brand=brand, summary="Live login page, as expected on the brand's own site.",
                        has_login_form=True, asks_for=r.asks_for, title=r.title, **det)
    elif r.payment:
        item = evidence(ids, **common, finding="live_payment_form", points_to="phishing", strength="medium",
                        score=0.75, summary=f"A live page with a payment form (asks for {', '.join(r.asks_for)}).",
                        has_login_form=True, asks_for=r.asks_for, form_actions=r.form_actions, title=r.title, **det)
    elif r.login:
        item = evidence(ids, **common, finding="live_login_form", points_to="phishing", strength="medium", score=0.7,
                        summary=f"A live page with a login form (asks for {', '.join(r.asks_for)}).",
                        has_login_form=True, asks_for=r.asks_for, form_actions=r.form_actions, title=r.title, **det)
    else:
        item = evidence(ids, **common, finding="live_no_credentials", points_to="genuine", strength="medium",
                        score=0.4, summary="A live page with ordinary content and no login or payment form.",
                        has_login_form=False, title=r.title, **det)
    item["duration_ms"] = round((time.perf_counter() - t0) * 1000, 3)
    return r, [item]
