"""Capture the genuine reference pages (P8): screenshots, rendered DOM and a HAR for offline replay.

    .venv/Scripts/python.exe scripts/data/snapshot_genuine.py [brand ...]

For each brand in data/brands/reference_pages.yaml:
  data/snapshots/<brand>/desktop.png   1280x800 viewport
  data/snapshots/<brand>/mobile.png    390x844 viewport
  data/snapshots/<brand>/dom.html      the DOM after the page rendered
  data/snapshots/<brand>/page.har.zip  every response, for routeFromHAR replay (desktop)
  data/snapshots/MANIFEST.json         URL, final URL, title, hashes, time (committed)

**Safety:** a URL is opened only if its host is PROVEN genuine by the Family Verifier (H1), and every
redirect or sub-request is allowed to proceed (it's the brand's own page, loaded as a normal browser would).
Brand page content stays in the gitignored folder; only the manifest is committed.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from doppel.address import read_address  # noqa: E402
from doppel.contract import load_yaml  # noqa: E402
from doppel.family import family_verifier, load_registry  # noqa: E402

PAGES = ROOT / "data" / "brands" / "reference_pages.yaml"
OUT = ROOT / "data" / "snapshots"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/{major}.0.0.0 Safari/537.36")       # the real browser's major version, without "Headless"
DESKTOP = {"width": 1280, "height": 800}
MOBILE = {"width": 390, "height": 844}


def proven_genuine(url: str, reg) -> bool:
    fam, _ = family_verifier(read_address(urlsplit(url).hostname or url), reg)
    return fam.genuine


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(page, url: str) -> None:
    try:
        page.goto(url, wait_until="networkidle", timeout=45_000)
    except Exception:                                   # noqa: BLE001 - busy pages never go idle
        page.goto(url, wait_until="load", timeout=45_000)
    page.wait_for_timeout(2500)


def capture(pw, brand: str, url: str) -> dict:
    d = OUT / brand
    d.mkdir(parents=True, exist_ok=True)
    browser = pw.chromium.launch()
    ua = UA.format(major=browser.version.split(".")[0])
    t0 = time.time()
    try:
        ctx = browser.new_context(viewport=DESKTOP, user_agent=ua, locale="en-IN",
                                  record_har_path=str(d / "page.har.zip"), record_har_content="attach")
        page = ctx.new_page()
        load(page, url)
        page.screenshot(path=str(d / "desktop.png"))
        (d / "dom.html").write_text(page.content(), encoding="utf-8")
        final, title = page.url, page.title()
        has_password = page.locator("input[type=password]").count() > 0
        ctx.close()                                     # writes the HAR
        mctx = browser.new_context(viewport=MOBILE, user_agent=ua, locale="en-IN", is_mobile=True, has_touch=True)
        mpage = mctx.new_page()
        load(mpage, url)
        mpage.screenshot(path=str(d / "mobile.png"))
        mctx.close()
    finally:
        browser.close()
    return {"url": url, "final_url": final, "title": title.strip()[:160], "has_password_field": has_password,
            "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "seconds": round(time.time() - t0, 1),
            "files": {f.name: {"sha256": sha(f), "bytes": f.stat().st_size} for f in sorted(d.iterdir())}}


def main(argv: list[str]) -> int:
    from playwright.sync_api import sync_playwright

    pages = load_yaml(PAGES)["pages"]
    reg = load_registry()
    wanted = argv or list(pages)
    manifest_path = OUT / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    with sync_playwright() as pw:
        for brand in wanted:
            url = pages[brand]["url"]
            if not proven_genuine(url, reg):
                print(f"REFUSED {brand}: {url} is not proven genuine by the Family Verifier")
                continue
            try:
                rec = capture(pw, brand, url)
            except Exception as exc:                    # noqa: BLE001 - report and continue
                print(f"FAILED  {brand}: {type(exc).__name__}: {str(exc)[:200]}")
                manifest[brand] = {"url": url, "error": f"{type(exc).__name__}: {str(exc)[:300]}",
                                   "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
                continue
            manifest[brand] = {**rec, "page": pages[brand]["page"]}
            print(f"ok      {brand}: {rec['final_url']} '{rec['title'][:50]}' password={rec['has_password_field']} "
                  f"({rec['seconds']} s)")
    OUT.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(dict(sorted(manifest.items())), indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
