"""P8 evaluation: the visual-match threshold, the Page Inspector on the fixtures, and Vision AI accuracy.

    .venv/Scripts/python.exe bench/p8_deep_eval.py            # ~5-10 min (Gemini calls; cached after)

1. **Visual calibration:** content-masked SSIM (and plain SSIM, pHash) for every pair of genuine references
   (unrelated pages) and for every fixture against its best reference.
2. **Vision AI accuracy** on our own labelled set (Lee et al. / Phishpedia data have no usable licence for us,
   docs/ps08-prior-art.md), for each model in the chain:
   - genuine pages of our 8 brands: live desktop + mobile screenshots (data/snapshots)
   - the generated clones and the prompt-injection page, rendered in the sandbox
   - 10 well-known genuine pages of other brands (captured here into data/snapshots/_vlm/, gitignored)
   - pages that present no brand: an ordinary blog, a parked page, an nginx default page, a brandless login form
   Brand pages are correct when the claimed brand names the expected organisation; no-brand pages when the
   claim is null. Screenshot + visible text where the sandbox rendered it, screenshot only for live captures.
3. **Prompt-injection ablation:** the injection page with the guard (visible text only) vs without (hidden
   text passed along as page text).
"""

from __future__ import annotations

import datetime as dt
import itertools
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from doppel.contract import REPO_ROOT  # noqa: E402
from doppel.deep import inspector as I  # noqa: E402
from doppel.deep import pages as P  # noqa: E402
from doppel.deep import vision as V  # noqa: E402
from doppel.deep.sandbox import Render, sandbox  # noqa: E402
from doppel.family import load_registry  # noqa: E402

OUT = REPO_ROOT / "docs" / "eval" / "p8-deep.json"
VLM_DIR = REPO_ROOT / "data" / "snapshots" / "_vlm"
MODELS = ["gemini-3-flash-preview", "gemini-3.1-flash-lite"]
FIXTURES = ["kx72-secure.top", "xn--pytm-53d.com", "echallan.parivahan.gov.in.pay-fine.icu", "onlinesbi.sbi.bank.in",
            "kyc-helpdesk.online", "paytrn.com", "sbi-kyc-update.in"]
GLOBAL = {  # well-known genuine pages (never a suspect site): expected name keyword
    "github": ("https://github.com/login", "github"), "amazon": ("https://www.amazon.in/", "amazon"),
    "flipkart": ("https://www.flipkart.com/", "flipkart"), "irctc": ("https://www.irctc.co.in/nget/train-search", "irctc"),
    "airtel": ("https://www.airtel.in/", "airtel"), "phonepe": ("https://www.phonepe.com/", "phonepe"),
    "wikipedia": ("https://www.wikipedia.org/", "wikipedia"), "microsoft": ("https://www.microsoft.com/en-in", "microsoft"),
    "linkedin": ("https://www.linkedin.com/login", "linkedin"), "netflix": ("https://www.netflix.com/in/login", "netflix"),
}
NEUTRAL = {  # pages that present no brand (made here, rendered in the sandbox)
    "nginx_default": "<html><head><title>Welcome to nginx!</title></head><body style='font-family:sans-serif;width:35em;margin:40px auto'>"
                     "<h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working."
                     " Further configuration is required.</p><p><em>Thank you for using nginx.</em></p></body></html>",
    "brandless_login": "<html><head><title>Sign in</title></head><body style='font-family:Arial;background:#f3f4f6'>"
                       "<div style='width:340px;margin:120px auto;background:#fff;padding:28px;border-radius:10px;box-shadow:0 4px 18px #0002'>"
                       "<h2 style='margin-top:0'>Sign in to continue</h2><input placeholder='Email' style='width:100%;padding:10px;margin:6px 0'>"
                       "<input type='password' placeholder='Password' style='width:100%;padding:10px;margin:6px 0'>"
                       "<button style='width:100%;padding:10px;background:#2563eb;color:#fff;border:0;border-radius:6px'>Continue</button>"
                       "</div></body></html>",
}


def capture_global() -> None:
    from playwright.sync_api import sync_playwright

    VLM_DIR.mkdir(parents=True, exist_ok=True)
    todo = {k: v for k, v in GLOBAL.items() if not (VLM_DIR / f"{k}.png").exists()}
    if not todo:
        return
    with sync_playwright() as pw:
        b = pw.chromium.launch()
        ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{b.version.split('.')[0]}.0.0.0 Safari/537.36"
        for name, (url, _) in todo.items():
            ctx = b.new_context(viewport={"width": 1280, "height": 800}, user_agent=ua, locale="en-IN")
            page = ctx.new_page()
            try:
                page.goto(url, wait_until="load", timeout=40_000)
                page.wait_for_timeout(3000)
                page.screenshot(path=str(VLM_DIR / f"{name}.png"))
                print(f"captured {name}")
            except Exception as exc:                  # noqa: BLE001
                print(f"FAILED {name}: {type(exc).__name__}: {str(exc)[:120]}")
            ctx.close()
        b.close()


def _render_html(sb, name: str, html: str) -> Render:
    url = f"https://{name}.test/"
    return sb._ex.submit(sb._render, url, {url: html, f"*{name}.test": html}, [], f"eval_{name}",
                         {"source": "eval_neutral"}).result(60)


def visual(sb, refs: dict[str, Render]) -> dict:
    pairs = []
    for a, b in itertools.combinations(sorted(refs), 2):
        v = I.compare(refs[a], refs[b], b)
        pairs.append({"a": a, "b": b, "masked_ssim": v.masked_ssim, "ssim": v.ssim, "phash": v.phash_distance})
    fixtures = []
    for host in FIXTURES:
        r = sb.render_fixture(host)
        scores = sorted((I.compare(r, refs[b], b) for b in refs), key=lambda v: -v.masked_ssim)
        best = scores[0]
        fixtures.append({"host": host, "source": r.source.get("source"), "clone_of": r.source.get("clone_of"),
                         "best": best.brand, "masked_ssim": best.masked_ssim, "ssim": best.ssim, "phash": best.phash_distance,
                         "second": scores[1].brand, "second_masked_ssim": scores[1].masked_ssim,
                         "kit_edits": [t["kind"] for t in r.source.get("transforms", [])], "render_ms": r.ms,
                         "blocked": r.sandbox["blocked"]})
    return {"threshold": I.VISUAL_MATCH, "unrelated_pairs": pairs, "fixtures": fixtures,
            "max_unrelated_masked": max(p["masked_ssim"] for p in pairs),
            "max_unrelated_plain": max(p["ssim"] for p in pairs)}


def labelled_set(sb, reg) -> list[dict]:
    names = {b.id: b.name for b in reg.brands}
    items = []
    for b, rec in P.manifest().items():
        if "error" in rec or b.startswith("_"):
            continue
        for view in ("desktop", "mobile"):
            p = P.SNAPSHOTS / b / f"{view}.png"
            if p.exists():
                items.append({"id": f"genuine:{b}:{view}", "kind": "our brand, genuine (live)", "png": p, "text": "",
                              "expect": names[b], "expect_id": b})
    for host in FIXTURES:
        r = sb.render_fixture(host)
        clone = r.source.get("clone_of")
        expect_id = clone or ("sbi" if host == "kyc-helpdesk.online" else None)
        kind = ("clone (sandbox)" if clone else "injection page (sandbox)" if host == "kyc-helpdesk.online"
                else "no brand (sandbox)")
        items.append({"id": f"fixture:{host}", "kind": kind, "png": REPO_ROOT / r.desktop, "text": r.visible_text,
                      "expect": names.get(expect_id), "expect_id": expect_id, "hidden": r.hidden_text})
    for name, html in NEUTRAL.items():
        r = _render_html(sb, name, html)
        items.append({"id": f"neutral:{name}", "kind": "no brand (sandbox)", "png": REPO_ROOT / r.desktop,
                      "text": r.visible_text, "expect": None, "expect_id": None})
    for name, (_, kw) in GLOBAL.items():
        p = VLM_DIR / f"{name}.png"
        if p.exists():
            items.append({"id": f"global:{name}", "kind": "other brand, genuine (live)", "png": p, "text": "",
                          "expect": kw, "expect_id": None, "keyword": kw})
    return items


def ask(model: str, png: bytes, text: str) -> tuple[dict | None, float, str | None]:
    import os

    os.environ["DOPPEL_VISION_MODEL"] = model
    t = time.perf_counter()
    try:
        obj, used, _ = V._ask_gemini(png, text)
        return obj, (time.perf_counter() - t) * 1000, used
    except Exception as exc:                          # noqa: BLE001
        return None, (time.perf_counter() - t) * 1000, f"error: {str(exc)[:160]}"


def correct(item: dict, claimed: str | None, brands) -> bool:
    if item["expect"] is None:
        return claimed is None
    if claimed is None:
        return False
    if item.get("keyword"):
        return item["keyword"] in claimed.lower().replace(" ", "")
    m = V.match_brand(claimed, brands)
    return m is not None and m.id == item["expect_id"]


def main() -> int:
    t0 = time.time()
    reg = load_registry()
    brands = list(reg.brands)
    capture_global()
    sb = sandbox()
    refs = {b: sb.render_reference(b) for b in P.references()}
    vis = visual(sb, refs)
    print(f"visual: max unrelated masked {vis['max_unrelated_masked']}, plain {vis['max_unrelated_plain']}")
    items = labelled_set(sb, reg)
    print(f"labelled set: {len(items)} pages")
    results = {}
    for model in MODELS:
        rows = []
        for it in items:
            obj, ms, used = ask(model, it["png"].read_bytes(), it["text"])
            claimed = obj["claimed_brand"] if obj else None
            rows.append({"id": it["id"], "kind": it["kind"], "expect": it["expect"], "claimed": claimed,
                         "ok": obj is not None and correct(it, claimed, brands), "asks_for": obj["asks_for"] if obj else None,
                         "confidence": obj["confidence"] if obj else None, "ms": round(ms), "answered_by": used})
            print(f"  {model:24} {it['id']:45} expect={it['expect']!s:28} got={claimed!s:30} {'ok' if rows[-1]['ok'] else 'WRONG'}")
        answered = [r for r in rows if not str(r["answered_by"]).startswith("error")]
        by_kind = {}
        for k in sorted({r["kind"] for r in rows}):
            sub = [r for r in answered if r["kind"] == k]
            by_kind[k] = {"n": len(sub), "correct": sum(r["ok"] for r in sub)}
        live_ms = [r["ms"] for r in answered if r["answered_by"] == model]
        results[model] = {"rows": rows, "n": len(rows), "answered": len(answered),
                          "correct": sum(r["ok"] for r in answered), "by_kind": by_kind,
                          "p50_ms_uncached": round(statistics.median(live_ms)) if live_ms else None}
    # injection ablation
    inj = next(i for i in items if i["id"] == "fixture:kyc-helpdesk.online")
    ablation = {}
    for model in MODELS:
        guarded, _, _ = ask(model, inj["png"].read_bytes(), inj["text"])
        unguarded, _, _ = ask(model, inj["png"].read_bytes(), inj["text"] + " " + " ".join(inj["hidden"]))
        ablation[model] = {"guarded": guarded, "unguarded": unguarded}
    sb.close()
    report = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
              "prompt_version": V.PROMPT_VERSION, "visual": vis, "vlm": results, "injection_ablation": ablation,
              "labelled_set": [{"id": i["id"], "kind": i["kind"], "expect": i["expect"]} for i in items],
              "seconds": round(time.time() - t0, 1)}
    OUT.write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO_ROOT)} in {time.time() - t0:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
