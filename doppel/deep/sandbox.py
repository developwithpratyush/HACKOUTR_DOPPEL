"""The sandboxed browser for the Deep stage (P8): render a fixture page safely and read what's on it.

**What can this browser reach?** Nothing real.
- Chromium starts with ``--host-resolver-rules=MAP * ~NOTFOUND``: every hostname fails to resolve, so even a
  request that slipped past the routes below couldn't leave the machine.
- Every request goes through Playwright routes, highest priority first:
  1. the fixture pages (``demo/fixtures``; a generated clone or a hand-made mock) and, for reference renders,
     the genuine page's static form;
  2. the genuine snapshot's HAR (``routeFromHAR``): the brand's own styles, images and fonts, as recorded;
  3. everything else is **aborted and logged** (``details.sandbox.blocked``).
- Service workers are blocked, and form submissions are answered locally (they never leave).

**Credential Tracker sessions (P9, ``track_*``)** use the same routes with two changes: the lowest route becomes
a local **sink** (anything not a fixture page or a recorded asset gets an empty "ok" from this process, so a
kit's next step runs and can be watched; top-level navigations off the fixture are still refused), and
WebSockets are routed to a mocked server that never connects. Note that Playwright does not route HTTP
redirects: a 302 from somewhere is stopped only by the resolver rule, which is why fixture backends bounce
with a meta refresh (a routed navigation) instead.

Playwright's sync API is bound to the thread that started it, so one worker thread owns the browser and
every render is submitted to it.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from html import escape
from pathlib import Path
from urllib.parse import urlsplit

from doppel.contract import REPO_ROOT
from doppel.deep import pages

RUNS = REPO_ROOT / "runs" / "deep"
REF_CACHE = RUNS / "ref"
DESKTOP = {"width": 1280, "height": 800}
MOBILE = {"width": 390, "height": 844}
LAUNCH_ARGS = ["--host-resolver-rules=MAP * ~NOTFOUND", "--disable-background-networking", "--no-first-run"]
RENDER_TIMEOUT_S = 40
TRACK_TIMEOUT_S = 90
SETTLE_MIN_MS, SETTLE_QUIET_MS, SETTLE_MAX_MS = 1300, 500, 4000   # after a submit: a kit may send late (setTimeout)
MAX_BODY = 8000
SEARCH_HEADERS = {"authorization", "cookie", "x-data", "x-token", "x-auth"}   # not referer: it echoes a GET form

# Reads the page the way a person sees it: visible inputs/forms, visible text, and text a person CAN'T see
# (display:none, off-screen, zero-size font, same colour as the background): the prompt-injection guard.
_READ_JS = r"""
() => {
  const W = innerWidth, H = innerHeight;
  const rgb = c => { const m = (c || '').match(/[\d.]+/g); return m ? m.slice(0, 4).map(Number) : null; };
  const bgOf = el => { for (let e = el; e; e = e.parentElement) { const c = rgb(getComputedStyle(e).backgroundColor);
                        if (c && (c.length < 4 || c[3] > 0.5)) return c; } return [255, 255, 255]; };
  const shown = el => {
    if (!el || !el.getBoundingClientRect) return false;
    const r = el.getBoundingClientRect(), s = getComputedStyle(el);
    if (r.width < 2 || r.height < 2 || s.visibility === 'hidden' || s.display === 'none') return false;
    if (r.right < 0 || r.bottom < 0 || r.left > W * 3) return false;
    for (let e = el; e; e = e.parentElement) if (parseFloat(getComputedStyle(e).opacity) < 0.05) return false;
    return true;
  };
  const textVisible = el => {
    if (!shown(el)) return false;
    const s = getComputedStyle(el);
    if (parseFloat(s.fontSize) < 4) return false;
    const c = rgb(s.color), b = bgOf(el);
    if (c && b && Math.abs(c[0]-b[0]) + Math.abs(c[1]-b[1]) + Math.abs(c[2]-b[2]) < 24) return false;
    return true;
  };
  const label = el => (el.labels && el.labels[0] ? el.labels[0].innerText : '') || '';
  const inputs = [...document.querySelectorAll('input, select, textarea')].map(el => ({
    tag: el.tagName.toLowerCase(), type: (el.getAttribute('type') || el.tagName).toLowerCase(),
    name: el.getAttribute('name') || '', id: el.id || '', placeholder: el.getAttribute('placeholder') || '',
    autocomplete: el.getAttribute('autocomplete') || '', aria: el.getAttribute('aria-label') || '',
    label: label(el).slice(0, 80), visible: shown(el), form_action: el.form && el.form.getAttribute('action') ? el.form.action : null }));
  const forms = [...document.forms].map(f => ({ action: f.getAttribute('action') ? f.action : null,
    method: (f.getAttribute('method') || 'get').toLowerCase(), visible: shown(f), inputs: f.elements.length }));
  const visible = [], hidden = [];
  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const t = n.textContent.replace(/\s+/g, ' ').trim();
    const p = n.parentElement;
    if (!t || !p || ['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE'].includes(p.tagName)) continue;
    (textVisible(p) ? visible : hidden).push(t);
  }
  const scripts = [...document.querySelectorAll('script[src]')].map(s => s.src);
  const iframes = [...document.querySelectorAll('iframe')].map(f => f.src || '(inline)');
  return { inputs, forms, visible_text: visible.join(' ').slice(0, 6000), hidden_text: hidden.filter(t => t.length > 3).slice(0, 60),
           scripts, iframes, title: document.title };
}
"""


SINK_HEADERS = {"access-control-allow-origin": "*", "access-control-allow-headers": "*",
                "access-control-allow-methods": "*", "content-type": "application/json"}
PLACEHOLDER = "<html><body><p>Processing...</p></body></html>"


def _top_navigation(req) -> bool:
    try:
        return req.is_navigation_request() and req.frame.parent_frame is None
    except Exception:                                   # noqa: BLE001 - some requests have no frame (workers)
        return False


def backend_page(backend: dict | None) -> tuple[str, str]:
    """How a fixture's 'server' answers a submitted form: (html, answered_by).

    Plays the kit's backend from ``sites.yaml`` (``accepts: any`` + ``then:`` / ``accepts: none``). A bounce is a
    meta refresh, i.e. a new navigation that goes through the routes (Playwright doesn't route HTTP redirects, so
    a fixture never uses a 302: only the no-DNS resolver would stop it)."""
    if not backend:
        return PLACEHOLDER, "sandbox_placeholder"
    if backend.get("accepts") == "any":
        then = backend.get("then")
        refresh = f'<meta http-equiv="refresh" content="0;url={escape(then, quote=True)}">' if then else ""
        return (f"<html><head>{refresh}<title>Please wait</title></head><body><p>Verifying your details, please wait..."
                "</p></body></html>"), "fixture_backend"
    if backend.get("accepts") == "none":
        return ("<html><head><title>Login</title></head><body><p style='color:#b00'>Invalid username or password. "
                "Please try again.</p><form method='post'><input name='username' placeholder='Username'>"
                "<input type='password' name='password' placeholder='Password'><button>Login</button></form>"
                "</body></html>"), "fixture_backend"
    raise ValueError(f"unknown backend {backend!r}")


@dataclass
class Render:
    url: str
    host: str
    title: str
    desktop: str                      # PNG path (repo-relative)
    mobile: str
    dom_file: str
    inputs: list[dict]
    forms: list[dict]
    visible_text: str
    hidden_text: list[str]
    scripts: list[str]
    iframes: list[str]
    sandbox: dict                     # requests served / blocked
    source: dict                      # which fixture page (generated clone or hand-made mock)
    ms: float
    screenshot_sha256: str = ""
    posts: list[dict] = field(default_factory=list)

    def dom(self) -> str:
        return (REPO_ROOT / self.dom_file).read_text(encoding="utf-8")


def _rel(p: Path) -> str:
    return p.relative_to(REPO_ROOT).as_posix()


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)


class Sandbox:
    def __init__(self) -> None:
        self._ex = ThreadPoolExecutor(max_workers=1, thread_name_prefix="doppel-sandbox")
        self._pw = None
        self._browser = None

    # all of these run on the sandbox thread
    def _ensure(self):
        if self._browser is None:
            from playwright.sync_api import sync_playwright

            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(args=LAUNCH_ARGS)
        return self._browser

    def _context(self, documents: dict[str, str], har_brands: list[str], log: dict,
                 backend: dict | None = None, track: bool = False):
        """A fresh, isolated browser context with the sandbox's routes (see the module docstring).

        ``track`` (the Credential Tracker): requests to anything that isn't a fixture page or a recorded asset are
        answered by a local **sink** (an empty "ok") instead of being refused, so a kit's next step runs and can be
        watched; top-level navigations off the fixture are still refused. Either way nothing is sent: the request
        is answered inside this process, and no hostname resolves."""
        browser = self._ensure()
        ctx = browser.new_context(viewport=DESKTOP, service_workers="block", locale="en-IN",
                                  device_scale_factor=1)
        documents_hosts = {k[1:] if k.startswith("*") else urlsplit(k).hostname for k in documents}

        def block(route):
            req = route.request
            log["blocked"].append(req.url[:200])
            if track and not _top_navigation(req):
                log["sunk"] = log.get("sunk", 0) + 1
                route.fulfill(status=204 if req.method == "OPTIONS" else 200, headers=SINK_HEADERS, body='{"ok":true}')
            else:
                route.abort("blockedbyclient")

        ctx.route("**/*", block)                                     # lowest priority: refuse (or sink)
        refs = pages.references()
        for b in har_brands:                                         # the brand's own recorded assets
            if b in refs:
                ctx.route_from_har(str(refs[b].har), not_found="fallback")

        def serve(route):
            req = route.request
            key = req.url.split("#", 1)[0]
            host = urlsplit(req.url).hostname
            submission = req.method != "GET" or (log.get("submitted") and _top_navigation(req)
                                                 and bool(urlsplit(req.url).query))
            if host in documents_hosts and submission:
                body, answered_by = backend_page(backend)
                log["posts"].append({"url": req.url[:300], "method": req.method,
                                     "body_bytes": len(req.post_data_buffer or b""), "answered_by": answered_by})
                route.fulfill(status=200, content_type="text/html; charset=utf-8", body=body)
                return
            if track and log.get("submitted") and host not in documents_hosts and _top_navigation(req):
                log["blocked"].append(req.url[:200])       # after a login, the page leaves: watch, don't follow
                route.abort("blockedbyclient")             # (not even to a recorded genuine page and its scripts)
                return
            html = documents.get(key) or documents.get(key.rstrip("/")) or documents.get(key + "/")
            if html is None and host in documents_hosts and req.resource_type == "document":
                html = documents.get("*" + host)
            if html is not None:
                log["fixture"] += 1
                route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html)
            else:
                route.fallback()

        ctx.route("**/*", serve)                                     # highest priority: our pages
        ctx.on("requestfinished", lambda r: log.__setitem__("har", log["har"] + 1)
               if urlsplit(r.url).hostname not in documents_hosts and not log.get("submitted") else None)
        return ctx

    def _render(self, url: str, documents: dict[str, str], har_brands: list[str], out_stem: str,
                source: dict) -> Render:
        t0 = time.perf_counter()
        log = {"fixture": 0, "har": 0, "blocked": [], "posts": []}
        ctx = self._context(documents, har_brands, log)
        page = ctx.new_page()
        try:
            page.goto(url, wait_until="load", timeout=20_000)
            try:
                page.wait_for_load_state("networkidle", timeout=4_000)
            except Exception:                                          # noqa: BLE001 - idle is best effort
                pass
            page.wait_for_timeout(600)
            desktop = RUNS / f"{out_stem}_desktop.png"
            desktop.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(desktop))
            facts = page.evaluate(_READ_JS)
            dom_file = RUNS / f"{out_stem}_dom.html"
            dom_file.write_text(page.content(), encoding="utf-8")
            page.set_viewport_size(MOBILE)
            page.wait_for_timeout(400)
            mobile = RUNS / f"{out_stem}_mobile.png"
            page.screenshot(path=str(mobile))
            final_url = page.url
        finally:
            ctx.close()
        blocked_hosts = sorted({urlsplit(u).hostname or "?" for u in log["blocked"]})
        return Render(
            url=final_url, host=urlsplit(url).hostname or "", title=facts["title"], desktop=_rel(desktop),
            mobile=_rel(mobile), dom_file=_rel(dom_file), inputs=facts["inputs"], forms=facts["forms"],
            visible_text=facts["visible_text"], hidden_text=facts["hidden_text"], scripts=facts["scripts"],
            iframes=facts["iframes"],
            sandbox={"served_fixture": log["fixture"], "served_from_har": log["har"],
                     "blocked": len(log["blocked"]), "blocked_hosts": blocked_hosts[:20],
                     "resolver": "MAP * ~NOTFOUND"},
            source=source, ms=round((time.perf_counter() - t0) * 1000, 1),
            screenshot_sha256=hashlib.sha256(desktop.read_bytes()).hexdigest(), posts=log["posts"])

    def _track(self, url: str, documents: dict[str, str], har_brands: list[str], backend: dict | None,
               attempts: int, seed: str) -> list[dict]:
        """Credential Tracker sessions (P9): fill canaries, submit, record every request. One fresh context each.

        A second session (a different made-up login) runs only if the first one showed how the page behaves after
        a login (accepted or rejected); otherwise C15 can't be tested and the session would be wasted time."""
        from doppel.deep import tracker as TR

        out = []
        host = urlsplit(url).hostname or ""
        for n in range(attempts):
            t0 = time.perf_counter()
            clock = lambda: round((time.perf_counter() - t0) * 1000, 1)          # noqa: E731
            log = {"fixture": 0, "har": 0, "blocked": [], "posts": []}
            ctx = self._context(documents, har_brands, log, backend=backend, track=True)
            reqs: list[dict] = []
            sockets: list[dict] = []

            def on_request(r):
                try:
                    body = r.post_data_buffer or b""
                except Exception:                                          # noqa: BLE001
                    body = b""
                reqs.append({"t_ms": clock(), "url": r.url[:4000], "method": r.method, "type": r.resource_type,
                             "top_nav": _top_navigation(r), "body": body[:MAX_BODY].decode("utf-8", "replace"),
                             "headers": {k: v[:300] for k, v in r.headers.items() if k.lower() in SEARCH_HEADERS}})

            def on_socket(ws):                         # a mocked server: the socket never connects anywhere
                rec = {"t_ms": clock(), "url": ws.url[:2000], "messages": []}
                sockets.append(rec)
                ws.on_message(lambda m: rec["messages"].append(str(m)[:MAX_BODY]))

            ctx.on("request", on_request)
            ctx.route_web_socket("**/*", on_socket)
            rec: dict = {"attempt": n + 1, "url": url, "form": None, "submitted": False, "how": None}
            try:
                page = ctx.new_page()
                page.goto(url, wait_until="load", timeout=20_000)
                page.wait_for_timeout(300)
                plan = TR.plan_fill(page.evaluate(TR.FIELDS_JS), seed=f"{seed}-{n + 1}")
                if plan is not None:
                    mark = len(reqs)
                    page.evaluate(TR.FILL_JS, plan["values"])
                    log["submitted"] = True
                    how = page.evaluate(TR.SUBMIT_JS, plan["target"])
                    page.wait_for_timeout(500)
                    if how == "button" and len(reqs) == mark and plan["target"]["form"] is not None:
                        how = page.evaluate(TR.FALLBACK_SUBMIT_JS, plan["target"])   # a dead button: submit the form
                    self._settle(page, reqs)
                    try:
                        after = page.evaluate(TR.AFTER_JS)
                    except Exception:                                      # noqa: BLE001 - mid-navigation
                        page.wait_for_timeout(500)
                        try:
                            after = page.evaluate(TR.AFTER_JS)
                        except Exception:                                  # noqa: BLE001
                            after = None
                    sunk = log.get("sunk", 0)
                    rec.update(form=plan["form"], canaries=plan["canaries"], submitted=how != "none", how=how,
                               requests=reqs[mark:], sockets=sockets, posts=log["posts"], after=after,
                               page_load_requests=mark, sunk=sunk, refused=len(log["blocked"]) - sunk)
            finally:
                ctx.close()
            rec["ms"] = clock()
            out.append(rec)
            if rec["form"] is None or TR.outcome(rec, host)["state"] not in ("accepted", "rejected"):
                break
        return out

    @staticmethod
    def _settle(page, reqs: list) -> None:
        """Wait until the page has been quiet for a moment (a kit may send late), within a cap."""
        t0 = time.perf_counter()
        last_n, last_change = len(reqs), t0
        while True:
            page.wait_for_timeout(200)
            now = time.perf_counter()
            if len(reqs) != last_n:
                last_n, last_change = len(reqs), now
            if (now - t0) * 1000 >= SETTLE_MIN_MS and (now - last_change) * 1000 >= SETTLE_QUIET_MS:
                return
            if (now - t0) * 1000 >= SETTLE_MAX_MS:
                return

    # public API (any thread)
    def track_fixture(self, host: str, attempts: int = 2, path: str = "/") -> dict | None:
        """Credential Tracker sessions on a fixture site (None if the host has no live fixture page)."""
        html, info = pages.page_html(host)
        if html is None:
            return None
        brands = [info["clone_of"]] if info.get("clone_of") else []
        return self.track_html(host, html, info.get("backend"), attempts, brands, path, source=info)

    def track_html(self, host: str, html: str, backend: dict | None = None, attempts: int = 2,
                   har_brands: list[str] | tuple = (), path: str = "/", source: dict | None = None) -> dict:
        """Credential Tracker sessions on any page served as ``host`` (fixtures, the kit zoo in tests and bench)."""
        from doppel.deep import tracker as TR

        t0 = time.perf_counter()
        url = f"https://{host}{path}"
        docs = {url: html, "*" + host: html}
        runs = self._ex.submit(self._track, url, docs, list(har_brands), backend, attempts,
                               secrets.token_hex(4)).result(TRACK_TIMEOUT_S)
        return {"url": url, "host": host, "attempts": runs, "static": TR.static_indicators(html),
                "backend": backend, "source": source or {}, "ms": round((time.perf_counter() - t0) * 1000, 1)}

    def render_fixture(self, host: str, path: str = "/") -> Render | None:
        """Render a fixture site (None if the host has no live fixture page)."""
        html, info = pages.page_html(host)
        if html is None:
            return None
        url = f"https://{host}{path}"
        docs = {url: html, "*" + host: html}
        brands = [info["clone_of"]] if info.get("clone_of") else []
        return self._ex.submit(self._render, url, docs, brands, _safe(host), info).result(RENDER_TIMEOUT_S)

    def render_reference(self, brand: str, refresh: bool = False) -> Render | None:
        """The genuine page's static form, rendered in this same sandbox (cached under runs/deep/ref/)."""
        ref = pages.references().get(brand)
        if ref is None:
            return None
        cache = REF_CACHE / f"{brand}.json"
        if cache.exists() and not refresh:
            r = Render(**json.loads(cache.read_text(encoding="utf-8")))
            if (REPO_ROOT / r.desktop).exists():
                return r
        url = ref.url.split("#", 1)[0]
        docs = {url: pages.static_html(ref), "*" + ref.host: pages.static_html(ref)}
        r = self._ex.submit(self._render, url, docs, [brand], f"ref/{_safe(brand)}",
                            {"source": "genuine_snapshot", "brand": brand, "url": ref.url}).result(RENDER_TIMEOUT_S)
        REF_CACHE.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(asdict(r), indent=1), encoding="utf-8")
        return r

    def close(self) -> None:
        def _stop():
            if self._browser is not None:
                self._browser.close()
                self._pw.stop()
                self._browser = self._pw = None
        self._ex.submit(_stop).result(30)


_SANDBOX: Sandbox | None = None


def sandbox() -> Sandbox:
    global _SANDBOX
    if _SANDBOX is None:
        _SANDBOX = Sandbox()
    return _SANDBOX


def available() -> bool:
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    return True
