"""P14 offline pack: real recorded verdicts for every stage case, so the UI still works if the API process dies.

    .venv/Scripts/python.exe demo/finale/build_pack.py      # ~1-2 min, cache only (DOPPEL_OFFLINE=1)

Writes ``demo/finale/pack/``:
  index.json        case -> file, label, risk, engine version, when recorded
  <case>.json       {verdict, verdict_certs_off?, baselines}: exactly what the API returns
  context.json      the registry (/api/brands), Campaign Radar (/api/campaigns), the live summary, the arena cell
and ``docs/eval/p14-scoreboard.md``: docs/finale-examples.md §7, every cell computed here (never typed).

The UI loads the pack lazily (``ui/src/lib/pack.ts``) when the API is unreachable or with ``?mock=1``, and labels
every recorded screen REPLAY. Rebuild it after any detection change (smoke.py checks it's current).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

os.environ["DOPPEL_OFFLINE"] = "1"
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

PACK = ROOT / "demo" / "finale" / "pack"
SCOREBOARD = ROOT / "docs" / "eval" / "p14-scoreboard.md"
LABEL = {"phishing": "PHISHING", "needs_review": "NEEDS REVIEW", "genuine": "GENUINE", "benign": "BENIGN", "sleeper": "SLEEPER"}

# docs/finale-examples.md §7, in order
SCORE_ROWS = [
    ("google.co.in", "paste", "genuine"), ("google-analytics.com", "paste", "genuine"),
    ("yonobusiness.sbi", "paste", "genuine"), ("echallan.parivahan.gov.in", "paste", "genuine"),
    ("in-echallan.online", "paste", "look-alike, armed"), ("mspeedpost.com", "paste", "look-alike, armed"),
    ("hdfc-pan-up-date2.web.app", "paste", "listed phishing"), ("kx72-secure.top", "gallery", "local kit"),
]


def slug(d: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "_", d.lower())[:80]


def cases() -> list[tuple[str, str]]:
    """(raw, source): the smoke pack, the gallery (ui/src/lib/gallery.ts) and the scoreboard rows, deduplicated."""
    from demo.finale.smoke import CASES

    out: dict[str, str] = {}
    for _beat, dom, src, *_ in CASES:
        out.setdefault(dom, src)
    gal = (ROOT / "ui" / "src" / "lib" / "gallery.ts").read_text(encoding="utf-8")
    for raw, src in re.findall(r'raw: "([^"]+)", source: "([a-z_]+)"', gal):
        out.setdefault(raw, src)
    for dom, src, _ in SCORE_ROWS:
        out.setdefault(dom, src)
    return list(out.items())


def arena_cell() -> dict:
    """The one arena number for the stage: Levenshtein (tuned on dev) on the brands' own genuine addresses."""
    a = json.loads((ROOT / "docs" / "eval" / "p4-arena.json").read_text(encoding="utf-8"))["methods"]

    def fp(method: str) -> tuple[int, int]:
        hit = n = 0
        for split in ("test_seen", "test_unseen"):
            g = a[method][split]["fp"]["genuine"]
            hit += round(g["rate"] * g["n"] / 100)
            n += g["n"]
        return hit, n

    out = {}
    for m in ("levenshtein", "dnstwist", "phishing_catcher", "doppel"):
        h, n = fp(m)
        out[m] = {"flagged": h, "of": n}
    return out


def main() -> int:
    from doppel.api import app as api
    from doppel.baselines import generic

    e = api.engine()
    g = generic(e.brain.reg)
    PACK.mkdir(parents=True, exist_ok=True)
    for old in PACK.glob("*.json"):
        old.unlink()
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    index: dict = {"generated_at": now, "engine": api.ENGINE, "cases": {}, "aliases": {}}
    for raw, src in cases():
        v = e.investigate(raw, src)
        rec = {"raw": raw, "source": src, "verdict": v, "baselines": g.compare(v["domain"], v)}
        if any(x["criterion"] == "C16" and x["points_to"] == "genuine" for x in v["evidence"]):
            rec["verdict_certs_off"] = e.investigate(raw, src, certs=False)
        f = slug(v["domain"]) + ".json"
        (PACK / f).write_text(json.dumps(rec, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        index["cases"][v["domain"]] = {"file": f, "label": v["label"], "risk": v["risk_score"], "source": src}
        index["aliases"][raw.lower()] = v["domain"]
        print(f"{LABEL.get(v['label'], v['label']):<13} {v['risk_score']:.3f}  {v['domain']}")
    ctx = {"brands": api.brands(), "campaigns": api.campaigns_view(limit=60), "arena": arena_cell()}
    try:
        ctx["live"] = api.live_state(mode="live", limit=30)
    except Exception as exc:                      # noqa: BLE001 - no catch store yet
        ctx["live"] = None
        print(f"live summary skipped: {exc}")
    (PACK / "context.json").write_text(json.dumps(ctx, ensure_ascii=False, separators=(",", ":"), default=str), encoding="utf-8")
    (PACK / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    write_scoreboard(now, ctx["arena"])
    size = sum(p.stat().st_size for p in PACK.glob("*.json"))
    print(f"\n{len(index['cases'])} cases, {size / 1e6:.1f} MB -> {PACK.relative_to(ROOT)}; scoreboard -> {SCOREBOARD.relative_to(ROOT)}")
    return 0


def write_scoreboard(now: str, arena: dict) -> None:
    order = ["keyword", "levenshtein", "dnstwist", "phishing_catcher", "ml", "padlock", "blocklist"]
    heads = ["Keyword", "Levenshtein", "dnstwist", "phishing_catcher", "ML alone", "Padlock = safe", "Public blocklist"]
    idx = json.loads((PACK / "index.json").read_text(encoding="utf-8")) if (PACK / "index.json").exists() else None
    lines = [
        "# P14 scoreboard: generic methods vs Doppel, on the finale examples",
        "",
        f"**Generated by `demo/finale/build_pack.py` on {now}; don't edit by hand.** Owner: Signature side.",
        "Each cell is the method run on the name (`doppel/baselines.py`, the arena's own implementations and dev-tuned",
        "thresholds). ✅ = the right call for that row, ❌ = the wrong call, – = the method has nothing to say.",
        "\"Right\" comes from the row's ground truth (column 2), not from Doppel's answer.",
        "",
        "| Example | Truth | " + " | ".join(heads) + " | **Doppel** |",
        "|---|---|" + "---|" * (len(heads) + 1),
    ]
    for dom, _src, truth in SCORE_ROWS:
        rec = json.loads((PACK / idx["cases"][dom]["file"]).read_text(encoding="utf-8")) if idx and dom in idx["cases"] else None
        if rec is None:
            continue
        bad = truth != "genuine"
        by = {r["method"]: r for r in rec["baselines"]}
        cells = []
        for m in order:
            r = by.get(m)
            if r is None or r["flagged"] is None:
                cells.append("–")
                continue
            if m == "padlock":                    # "padlock = safe" is right only on genuine names
                ok = not bad
            else:
                ok = r["flagged"] == bad
            cells.append(f"{'✅' if ok else '❌'} {r['detail']}")
        v = rec["verdict"]
        dok = (v["label"] in ("genuine", "benign")) != bad
        lines.append(f"| `{dom}` | {truth} | " + " | ".join(cells) + f" | {'✅' if dok else '❌'} {LABEL[v['label']]} ({v['risk_score']:.2f}) |")
    lv = arena["levenshtein"]
    lines += ["", "## The one arena cell for the stage", "",
              f"On the brands' **own genuine addresses** (P4 arena, test splits, n = {lv['of']}), Levenshtein tuned on dev flags "
              f"**{lv['flagged']} of {lv['of']}**, dnstwist {arena['dnstwist']['flagged']}, phishing_catcher "
              f"{arena['phishing_catcher']['flagged']}, Doppel **{arena['doppel']['flagged']}**: it proves the family first.", ""]
    SCOREBOARD.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
