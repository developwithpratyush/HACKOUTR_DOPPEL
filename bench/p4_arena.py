"""P4 arena: Doppel's name checks vs three common methods, per trick family, on the brand-split pairs.

    python bench/p4_arena.py            # ~3-5 min; writes docs/eval/p4-arena.{json,md} + heatmap PNG

Methods (each says "flagged" and, if it can, which brand):
  doppel        Address Reader + Family Verifier + Trick Detector (Quick stage, names only)
  p2_only       Family Verifier alone (the P3 baseline, for reference)
  levenshtein   plain normalised Levenshtein of the owner label vs every brand name; flag at >= tau
  dnstwist      dnstwist permutations of each brand's seed domains (configured generously: our lure words as
                its dictionary, our attacker-TLD list as its TLD dictionary); flag if the name is in the set
  phishing_catcher  our reimplementation of x0rz/phishing_catcher's scoring (GPL-3; logic re-written, no code
                copied): suspicious TLD +20, entropy x10, keyword weights, Levenshtein-1 to strong keywords +70,
                many hyphens / deep nesting; our brand aliases added as strong (70-point) keywords, as a user
                would configure it; flag at score >= threshold

Protocol:
- Thresholds (Doppel's TAU_CLOSE, Levenshtein's tau, phishing_catcher's score) are tuned on **dev only**,
  maximising (right-brand detection rate - false-positive rate) over dev positives and negatives.
- Reported on test_seen and test_unseen (held-out brands icici and india_post). Never tuned on.
- Detection = flagged AND the right target brand (a method that flags without naming a brand gets no credit).
- False-positive rate = flagged at all, on genuine family rows, hard negatives and benign NRD names.
"""

from __future__ import annotations

import csv
import json
import math
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import dnstwist  # noqa: E402
from rapidfuzz.distance import Levenshtein  # noqa: E402

from doppel.address import read_address  # noqa: E402
from doppel.address.unicode_data import skeleton  # noqa: E402
from doppel.family import check_family, load_registry  # noqa: E402
from doppel.generator.pairs import seeds  # noqa: E402
from doppel.generator.techniques import ATTACKER_TLDS  # noqa: E402
from doppel.tricks.detector import TrickDetector, _name_parts  # noqa: E402
from doppel.tricks.segment import brand_strings  # noqa: E402

PAIRS = REPO / "data" / "pairs" / "pairs.csv"
OUT = REPO / "docs" / "eval"
TECHS = ["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T11", "T12", "T13"]
TECH_NAMES = {"T1": "typo", "T2": "twin letters", "T3": "homoglyph", "T4": "combosquat", "T5": "ending swap",
              "T6": "level-squat", "T7": "trust signal", "T11": "free hosting", "T12": "soundsquat",
              "T13": "bitsquat"}
EXPECTED_TRICK = {"T1": "typo", "T2": "twin_letters", "T3": "homoglyph", "T4": "combosquat", "T5": "tld_swap",
                  "T6": "level_squat", "T7": "trust_signal_mimicry", "T11": "combosquat", "T12": "soundsquat",
                  "T13": "bitsquat"}
NEG_KINDS = ["genuine", "hard_negative", "benign"]
METHODS = ["doppel", "p2_only", "levenshtein", "dnstwist", "phishing_catcher"]
LABELS = {"doppel": "Doppel (P4)", "p2_only": "P2 Family Verifier alone", "levenshtein": "Plain Levenshtein",
          "dnstwist": "dnstwist matching", "phishing_catcher": "phishing_catcher heuristic"}


def load_rows() -> list[dict]:
    with PAIRS.open(encoding="utf-8") as f:
        return [r for r in csv.DictReader(f) if r["split"] in ("dev", "test_seen", "test_unseen")
                and (r["kind"] == "lookalike" or r["kind"] in NEG_KINDS)]


# ----------------------------------------------------------------- methods ---

class Doppel:
    def __init__(self, reg, tau: float) -> None:
        self.det = TrickDetector(reg, tau=tau)
        self.reg = reg

    def __call__(self, r, fam) -> tuple[bool, str | None, dict]:
        res = self.det.detect(r, fam)
        flagged = fam.status in ("imitation", "restricted_unlisted") or res.brand_signal
        brand = (res.brand.id if res.brand and res.brand_signal else None) or (fam.brand.id if fam.brand and flagged else None)
        return flagged, brand, {"tricks": res.tricks, "closeness": res.closeness}


def p2_only(r, fam) -> tuple[bool, str | None, dict]:
    flagged = fam.status in ("imitation", "restricted_unlisted")
    return flagged, fam.brand.id if flagged and fam.brand else None, {}


from doppel.baselines import Dnstwist, Lev, PhishingCatcher  # noqa: E402  (moved in P14; unchanged)


# -------------------------------------------------------------- evaluation ---

def evaluate(rows, decide) -> dict:
    """decide(row) -> (flagged, brand). Returns per split/technique detection and per kind FP."""
    det: dict = defaultdict(lambda: defaultdict(Counter))
    fp: dict = defaultdict(lambda: defaultdict(Counter))
    for row in rows:
        flagged, brand = decide(row)[:2]
        if row["label"] == "1":
            c = det[row["split"]][row["technique"]]
            c["n"] += 1
            c["hit"] += int(flagged and brand == row["target_brand"])
            c["flagged"] += int(flagged)
        else:
            c = fp[row["split"]][row["kind"]]
            c["n"] += 1
            c["fp"] += int(flagged)
    return {"det": det, "fp": fp}


def youden(ev: dict, split: str) -> float:
    pos = sum(c["n"] for c in ev["det"][split].values())
    hit = sum(c["hit"] for c in ev["det"][split].values())
    neg = sum(c["n"] for c in ev["fp"][split].values())
    fps = sum(c["fp"] for c in ev["fp"][split].values())
    return hit / pos - fps / neg


def rate(c: Counter, key: str) -> float | None:
    return round(100 * c[key] / c["n"], 1) if c["n"] else None


def main() -> None:
    t0 = time.perf_counter()
    reg = load_registry()
    rows = load_rows()
    print(f"{len(rows):,} rows", flush=True)
    readings = {}
    for row in rows:
        r = read_address(row["candidate"])
        readings[row["candidate"]] = (r, check_family(r, reg))
    dev = [r for r in rows if r["split"] == "dev"]
    test = [r for r in rows if r["split"] != "dev"]

    tuned = {}
    # Doppel: tune TAU_CLOSE on dev
    grid = [0.70, 0.75, 0.80, 0.85, 0.90]
    best = None
    for tau in grid:
        d = Doppel(reg, tau)
        j = youden(evaluate(dev, lambda row: d(*readings[row["candidate"]])), "dev")
        print(f"  doppel tau={tau}: dev J={j:.3f}", flush=True)
        best = max(best or (j, tau), (j, tau))
    tuned["doppel_tau_close"] = {"value": best[1], "dev_J": round(best[0], 4), "grid": grid}
    doppel = Doppel(reg, best[1])

    lev = Lev(reg)
    lev_scores = {row["candidate"]: lev.score(readings[row["candidate"]][0]) for row in rows}
    grid_l = [0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9]
    bl = max((youden(evaluate(dev, lambda row, t=t: (lev_scores[row["candidate"]][0] >= t,
                                                      lev_scores[row["candidate"]][1])), "dev"), t) for t in grid_l)
    tuned["levenshtein_tau"] = {"value": bl[1], "dev_J": round(bl[0], 4), "grid": grid_l}

    pc = PhishingCatcher(reg)
    pc_scores = {row["candidate"]: pc.score(readings[row["candidate"]][0]) for row in rows}
    grid_p = [40, 50, 60, 65, 70, 75, 80, 90, 100, 110]
    bp = max((youden(evaluate(dev, lambda row, t=t: (pc_scores[row["candidate"]][0] >= t,
                                                      pc_scores[row["candidate"]][1])), "dev"), t) for t in grid_p)
    tuned["phishing_catcher_score"] = {"value": bp[1], "dev_J": round(bp[0], 4), "grid": grid_p}

    print("  building dnstwist index…", flush=True)
    dt = Dnstwist(reg)

    # matched operating point: each threshold baseline at Doppel's dev false-positive rate on benign names
    dev_doppel = evaluate(dev, lambda row: doppel(*readings[row["candidate"]]))
    target_fp = dev_doppel["fp"]["dev"]["benign"]["fp"] / max(1, dev_doppel["fp"]["dev"]["benign"]["n"])

    def matched(scores: dict, grid_m: list[float]) -> float:
        ok = []
        for t in grid_m:
            ev = evaluate(dev, lambda row, t=t: (scores[row["candidate"]][0] >= t, scores[row["candidate"]][1]))
            c = ev["fp"]["dev"]["benign"]
            if c["fp"] / max(1, c["n"]) <= target_fp:
                ok.append(t)
        return min(ok) if ok else max(grid_m)

    lev_m = matched(lev_scores, [round(0.5 + 0.01 * i, 2) for i in range(50)])
    pc_m = matched(pc_scores, list(range(40, 200, 5)))
    tuned["matched_benign_fp_on_dev"] = {"doppel_dev_benign_fp": round(100 * target_fp, 2),
                                         "levenshtein_tau": lev_m, "phishing_catcher_score": pc_m}

    t1 = time.perf_counter()
    doppel_out = {row["candidate"]: doppel(*readings[row["candidate"]]) for row in test}
    doppel_ms = (time.perf_counter() - t1) * 1000 / len(test)
    deciders = {
        "doppel": lambda row: doppel_out[row["candidate"]],
        "p2_only": lambda row: p2_only(*readings[row["candidate"]]),
        "levenshtein": lambda row: (lev_scores[row["candidate"]][0] >= bl[1], lev_scores[row["candidate"]][1]),
        "dnstwist": lambda row: dt(*readings[row["candidate"]]),
        "phishing_catcher": lambda row: (pc_scores[row["candidate"]][0] >= bp[1], pc_scores[row["candidate"]][1]),
        "levenshtein@matched": lambda row: (lev_scores[row["candidate"]][0] >= lev_m, lev_scores[row["candidate"]][1]),
        "phishing_catcher@matched": lambda row: (pc_scores[row["candidate"]][0] >= pc_m, pc_scores[row["candidate"]][1]),
    }
    results = {m: evaluate(test, f) for m, f in deciders.items()}
    not_dnstwist = [r for r in test if not r["source"].startswith("dnstwist:")]
    results_own = {m: evaluate(not_dnstwist, f) for m, f in deciders.items()}

    # trick-label agreement on test; error examples from DEV only (we look at dev errors, never test)
    agree: dict = defaultdict(Counter)
    for row in test:
        flagged, brand, info = doppel_out[row["candidate"]]
        if row["label"] == "1":
            agree[row["technique"]]["n"] += 1
            agree[row["technique"]]["agree"] += int(EXPECTED_TRICK[row["technique"]] in info["tricks"])
    closeness: dict = defaultdict(lambda: {"doppel": [], "levenshtein": []})
    for row in test:
        flagged, brand, info = doppel_out[row["candidate"]]
        if row["label"] == "1" and flagged and brand == row["target_brand"] and info.get("closeness") is not None:
            closeness[row["technique"]]["doppel"].append(info["closeness"])
            closeness[row["technique"]]["levenshtein"].append(lev_scores[row["candidate"]][0])

    def median(xs):
        xs = sorted(xs)
        return round(xs[len(xs) // 2], 3) if xs else None

    median_closeness = {t: {k: median(v) for k, v in closeness[t].items()} for t in TECHS}
    misses: dict = defaultdict(list)
    fps: dict = defaultdict(list)
    fp_count: Counter = Counter()
    for row in dev:
        flagged, brand, info = doppel(*readings[row["candidate"]])
        disp = readings[row["candidate"]][0].display
        if row["label"] == "1" and not (flagged and brand == row["target_brand"]):
            if len(misses[row["technique"]]) < 8:
                misses[row["technique"]].append(f"{disp} ({row['target_brand']}{' → ' + brand if brand else ''})")
        elif row["label"] == "0" and flagged:
            fp_count[row["kind"]] += 1
            if len(fps[row["kind"]]) < 12:
                fps[row["kind"]].append(f"{disp} → {brand} {info.get('tricks', [])}")

    summary = {"generated": time.strftime("%Y-%m-%d"), "seconds": round(time.perf_counter() - t0, 1),
               "rows": {"dev": len(dev), "test": len(test)}, "tuned_on_dev": tuned,
               "doppel_ms_per_domain_quick": round(doppel_ms, 3), "methods": {}, "methods_excluding_dnstwist_rows": {},
               "doppel_trick_label_agreement": {t: rate(agree[t], "agree") for t in TECHS},
               "median_closeness_detected": median_closeness,
               "dev_misses_sample": misses, "dev_false_positive_sample": fps, "dev_false_positive_count": fp_count}
    for key, res in (("methods", results), ("methods_excluding_dnstwist_rows", results_own)):
        for m, ev in res.items():
            out = {}
            for split in ("test_seen", "test_unseen"):
                out[split] = {"detection": {t: {"rate": rate(ev["det"][split][t], "hit"), "n": ev["det"][split][t]["n"]}
                                            for t in TECHS},
                              "fp": {k: {"rate": rate(ev["fp"][split][k], "fp"), "n": ev["fp"][split][k]["n"]}
                                     for k in NEG_KINDS}}
            both_det = {t: Counter() for t in TECHS}
            both_fp = {k: Counter() for k in NEG_KINDS}
            for split in ("test_seen", "test_unseen"):
                for t in TECHS:
                    both_det[t].update(ev["det"][split][t])
                for k in NEG_KINDS:
                    both_fp[k].update(ev["fp"][split][k])
            out["both"] = {"detection": {t: {"rate": rate(both_det[t], "hit"), "n": both_det[t]["n"]} for t in TECHS},
                           "fp": {k: {"rate": rate(both_fp[k], "fp"), "n": both_fp[k]["n"]} for k in NEG_KINDS}}
            summary[key][m] = out
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "p4-arena.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    heatmap(summary, OUT / "p4-arena-heatmap.png")
    write_report(summary, OUT / "p4-arena.md")
    print(json.dumps({"tuned": tuned, "ms": summary["doppel_ms_per_domain_quick"]}, indent=1))
    for m in deciders:
        b = summary["methods"][m]["both"]
        print(f"{m:26}", " ".join(f"{t}:{b['detection'][t]['rate']}" for t in TECHS), "| FP",
              " ".join(f"{k}:{b['fp'][k]['rate']}" for k in NEG_KINDS))


# ------------------------------------------------------------------ heatmap ---

# Sequential single-hue ramp (blue 100 -> 700) from the dataviz reference palette; light surface.
RAMP = ["#cde2fb", "#b7d3f6", "#9ec5f4", "#86b6ef", "#6da7ec", "#5598e7", "#3987e5", "#2a78d6", "#256abf",
        "#1c5cab", "#184f95", "#104281", "#0d366b"]
# False-positive rates are a second sequential context, so they take the next hue (orange): dark = bad.
RAMP_FP = ["#fde6db", "#f7b89c", "#eb6834", "#b8451b", "#7a2a0c"]
SURFACE, INK, INK2, MUTED, NA = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9"
HEAT_METHODS = ["doppel", "p2_only", "levenshtein", "levenshtein@matched", "dnstwist", "phishing_catcher",
                "phishing_catcher@matched"]
HEAT_LABELS = {"doppel": "Doppel (P4)", "p2_only": "P2 Family Verifier alone",
               "levenshtein": "Levenshtein (dev-tuned)", "levenshtein@matched": "Levenshtein (Doppel's FP rate)",
               "dnstwist": "dnstwist matching", "phishing_catcher": "phishing_catcher (dev-tuned)",
               "phishing_catcher@matched": "phishing_catcher (Doppel's FP rate)"}


def heatmap(summary: dict, path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap

    cmap = LinearSegmentedColormap.from_list("seq_blue", RAMP)
    cmap_fp = LinearSegmentedColormap.from_list("seq_orange", RAMP_FP)
    cols = [f"{t}\n{TECH_NAMES[t]}" for t in TECHS] + ["FP\ngenuine", "FP\nhard neg.", "FP\nbenign"]
    fig, ax = plt.subplots(figsize=(15, 5.2), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)
    for i, m in enumerate(HEAT_METHODS):
        both = summary["methods"][m]["both"]
        vals = [both["detection"][t]["rate"] for t in TECHS] + [both["fp"][k]["rate"] for k in NEG_KINDS]
        for j, v in enumerate(vals):
            x, y = j + (0.35 if j >= len(TECHS) else 0), i
            fp_col = j >= len(TECHS)
            color = NA if v is None else (cmap_fp if fp_col else cmap)(v / 100)
            ax.add_patch(plt.Rectangle((x + 0.02, y + 0.03), 0.96, 0.94, facecolor=color, edgecolor=SURFACE,
                                       linewidth=2))
            txt = "n/a" if v is None else f"{v:.0f}%" if v >= 10 or v == 0 else f"{v:.1f}%"
            dark = v is not None and v >= (45 if fp_col else 55)
            ax.text(x + 0.5, y + 0.5, txt, ha="center", va="center", fontsize=9,
                    color="#ffffff" if dark else INK, fontweight="bold" if m == "doppel" else "normal")
    ax.set_xlim(0, len(cols) + 0.35)
    ax.set_ylim(len(HEAT_METHODS), 0)
    ax.set_xticks([j + 0.5 + (0.35 if j >= len(TECHS) else 0) for j in range(len(cols))], cols, fontsize=8.5,
                  color=INK2)
    ax.set_yticks([i + 0.5 for i in range(len(HEAT_METHODS))], [HEAT_LABELS[m] for m in HEAT_METHODS], fontsize=9.5,
                  color=INK)
    ax.tick_params(length=0)
    ax.xaxis.tick_top()
    for s in ax.spines.values():
        s.set_visible(False)
    n_pos = sum(v["n"] for v in summary["methods"]["doppel"]["both"]["detection"].values())
    ax.set_title(f"Right-brand detection per trick (left; higher is better) and false-positive rate (right; lower is "
                 f"better)\ntest_seen + test_unseen, {n_pos:,} look-alikes; thresholds tuned on dev only",
                 fontsize=10.5, color=INK, loc="left", pad=34)
    fig.text(0.01, 0.01, "Blue: detection, 0% light to 100% dark. Orange: false positives, 0% light to 100% dark. dnstwist's T1/T2/T13 are inflated: dnstwist also "
             "generated those rows (see the report).", fontsize=8, color=MUTED)
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)



# ------------------------------------------------------------------- report ---

def _cell(x: dict) -> str:
    return "–" if x["rate"] is None else f"{x['rate']:g}%"


def write_report(s: dict, path: Path) -> None:
    """docs/eval/p4-arena.md, rendered from the JSON so the numbers always match. Don't edit by hand."""
    glyphs = json.loads((REPO / "doppel" / "perception" / "glyph_costs.json").read_text(encoding="utf-8"))
    cal, t = glyphs["calibration"], s["tuned_on_dev"]
    both = {m: s["methods"][m]["both"] for m in s["methods"]}
    n_pos = sum(v["n"] for v in both["doppel"]["detection"].values())
    n_neg = {k: v["n"] for k, v in both["doppel"]["fp"].items()}
    head = "| Method | " + " | ".join(f"{x} {TECH_NAMES[x]}" for x in TECHS) + " | FP genuine | FP hard neg. | FP benign |"
    sep = "|---|" + "---|" * (len(TECHS) + 3)

    def row(m: str, label: str, res: dict) -> str:
        return (f"| {label} | " + " | ".join(_cell(res["detection"][x]) for x in TECHS) + " | "
                + " | ".join(_cell(res["fp"][k]) for k in NEG_KINDS) + " |")

    order = ["doppel", "p2_only", "levenshtein", "levenshtein@matched", "dnstwist", "phishing_catcher",
             "phishing_catcher@matched"]
    counts = "| n | " + " | ".join(f"{both['doppel']['detection'][x]['n']:,}" for x in TECHS) + " | " + \
        " | ".join(f"{n_neg[k]:,}" for k in NEG_KINDS) + " |"
    own = s["methods_excluding_dnstwist_rows"]
    lines = [
        "# P4 arena: Doppel's name checks vs common methods",
        "",
        f"Generated by `python bench/p4_arena.py` on {s['generated']} ({s['seconds']} s). **Rendered from "
        "`p4-arena.json`; don't edit by hand.** Heatmap: `p4-arena-heatmap.png`. Owner: Signature side.",
        "",
        "![arena heatmap](p4-arena-heatmap.png)",
        "",
        "## What was measured",
        "",
        f"- **Data:** `data/pairs/pairs.csv` (P3, deliverable 2). Reported on `test_seen` + `test_unseen`: "
        f"{n_pos:,} synthetic look-alikes, {n_neg['genuine']} genuine family names, {n_neg['hard_negative']} hard "
        f"negatives and {n_neg['benign']:,} benign NRD names. `test_unseen` holds whole brands (ICICI, India Post) "
        "that no threshold was tuned on.",
        "- **Detection** = the method flags the name **and names the right brand**. A flag without the right brand "
        "earns nothing. **False-positive rate** = flagged at all.",
        f"- **Tuning:** every threshold was chosen on `dev` only ({s['rows']['dev']:,} rows), maximising "
        "(detection − false-positive rate). Doppel: `TAU_CLOSE` = "
        f"**{t['doppel_tau_close']['value']}** (dev J {t['doppel_tau_close']['dev_J']}); Levenshtein: "
        f"τ = {t['levenshtein_tau']['value']} (dev J {t['levenshtein_tau']['dev_J']}); phishing_catcher: score ≥ "
        f"{t['phishing_catcher_score']['value']} (dev J {t['phishing_catcher_score']['dev_J']}).",
        f"- **Matched operating point:** the same baselines re-thresholded so their dev false-positive rate on "
        f"benign names is no higher than Doppel's ({t['matched_benign_fp_on_dev']['doppel_dev_benign_fp']}%): "
        f"Levenshtein τ = {t['matched_benign_fp_on_dev']['levenshtein_tau']}, phishing_catcher ≥ "
        f"{t['matched_benign_fp_on_dev']['phishing_catcher_score']}. That's the fair comparison: at equal false alarms, "
        "how much does each catch?",
        f"- **Speed:** the Trick Detector took **{s['doppel_ms_per_domain_quick']} ms per domain** on one core, "
        "pure Python (on top of P2's Address Reader + Family Verifier, ~0.13 ms: ~8k domains/s in the P2 sweep).",
        "",
        "## Results (test_seen + test_unseen)",
        "",
        head, sep, counts,
        *[row(m, HEAT_LABELS[m], both[m]) for m in order],
        "",
        "### Seen vs unseen brands (Doppel)",
        "",
        head, sep,
        row("doppel", "test_seen", s["methods"]["doppel"]["test_seen"]),
        row("doppel", "test_unseen (ICICI, India Post)", s["methods"]["doppel"]["test_unseen"]),
        "",
        "### dnstwist is partly marking its own homework",
        "",
        "dnstwist generated most of the T1, T2 (ASCII), T3 (accented) and T13 rows in P3, so its 95–100% there is "
        "by construction. On the look-alikes **our own generators** made (Cyrillic/Greek homoglyphs, rn/vv/cl twins):",
        "",
        "| Method | T2 twin letters | T3 homoglyph |",
        "|---|---|---|",
        *[f"| {HEAT_LABELS[m]} | {_cell(own[m]['both']['detection']['T2'])} (n={own[m]['both']['detection']['T2']['n']}) "
          f"| {_cell(own[m]['both']['detection']['T3'])} (n={own[m]['both']['detection']['T3']['n']}) |"
          for m in ("doppel", "levenshtein", "dnstwist", "phishing_catcher")],
        "",
        "### Does the visual distance rate look-alikes as close as they look?",
        "",
        "Median closeness on correctly detected look-alikes: Doppel's closeness (visual edit distance, or the "
        "structural rule that fired) vs plain normalised Levenshtein of the same name to the nearest brand name.",
        "",
        "| Technique | Doppel closeness | Levenshtein similarity |",
        "|---|---|---|",
        *[f"| {x} {TECH_NAMES[x]} | {s['median_closeness_detected'][x]['doppel']} | "
          f"{s['median_closeness_detected'][x]['levenshtein']} |" for x in TECHS],
        "",
        "### Does the evidence name the right trick?",
        "",
        "Share of detected test look-alikes whose trick list contains the generator's technique:",
        "",
        "| " + " | ".join(TECHS) + " |",
        "|" + "---|" * len(TECHS),
        "| " + " | ".join(f"{s['doppel_trick_label_agreement'][x]}%" for x in TECHS) + " |",
        "",
        "Lower rows aren't misses; the name is caught, under another label. T2 rows from dnstwist (`go0glc`, `hclfe`) "
        "use pairs our phone fonts draw clearly apart, so they're labelled `typo`. That's the measured truth for "
        "Roboto/Noto, not a confusion. T12: most sound-alikes also *look* close, so the typo label wins, "
        "and soundsquat is added only when the Metaphone keys match. T13: some flipped bits are also keyboard neighbours.",
        "",
        "## How to read this (honestly)",
        "",
        "1. **Where Doppel wins clearly: names that carry the brand plus something else.** Combosquat, level-squat, "
        "trust-signal mimicry and free hosting are the most common real tricks (combosquatting is ~100× more common "
        "than typos, Kintis et al. CCS 2017). At equal false alarms, Levenshtein catches "
        f"{_cell(both['levenshtein@matched']['detection']['T4'])} of T4, "
        f"{_cell(both['levenshtein@matched']['detection']['T6'])} of T6 and "
        f"{_cell(both['levenshtein@matched']['detection']['T11'])} of T11, and dnstwist almost none, even "
        "with our lure words as its dictionary.",
        "2. **On single-edit tricks (T1/T2/T3/T13), plain Levenshtein *flags* as many or more** (at equal false "
        f"alarms: T2 {_cell(both['levenshtein@matched']['detection']['T2'])} vs Doppel's "
        f"{_cell(both['doppel']['detection']['T2'])}). Our synthetic typos are one or two edits from short brand "
        "names, so any distance with a loose threshold finds them; Doppel deliberately refuses names with two "
        "ordinary edits (see the P5 update below), because on real new domains those are mostly noise. The visual "
        "distance's value there isn't recall. It's (a) the **closeness score**: only modestly higher on the median "
        f"(T2 {s['median_closeness_detected']['T2']['doppel']} vs {s['median_closeness_detected']['T2']['levenshtein']}, "
        f"T3 {s['median_closeness_detected']['T3']['doppel']} vs {s['median_closeness_detected']['T3']['levenshtein']}), "
        "because many dnstwist 'homoglyphs' don't actually look alike in phone fonts, but much higher for the real "
        "twins a victim can't see (paytrn 0.97 vs 0.67, Cyrillic pаytm 0.99 vs 0.80), so the dangerous ones rank first; "
        "(b) the **evidence** (\"'rn' for 'm', cost 0.17\"); (c) it stays explainable per edit. We say this rather "
        "than claim a recall win we didn't measure.",
        "3. **Genuine family: 0% false positives, by design.** The Family Verifier (P2) proves ownership first. "
        f"Levenshtein flags {_cell(both['levenshtein']['fp']['genuine'])} of the brands' own addresses "
        "(`onlinesbi.sbi`, `withgoogle.com`), because it has no idea what the family is.",
        "4. **Hard negatives: Doppel flags ~100%, by construction.** P3 *selected* them as popular real domains on "
        "which P2 already fires (brand affiliates such as `icicilombard.com`, `hdfclife.com`, `googlemail.com`; "
        "lookalike-named businesses). A name-only checker can't tell an affiliate from a combosquat. These must go "
        "to NEEDS REVIEW in fusion (P5/P11), and the Deep stage decides. Open issue O3 asks whether affiliates "
        "should join the registry.",
        "5. **Benign names were filtered by P2**, so P2's own false-positive rate on them is 0 by construction; the "
        "benign column measures only what P4 *adds*. The full real-world rate comes from the NRD run in P5.",
        "",
        "## Glyph confusability matrix (C7)",
        "",
        f"- Renders: {', '.join(glyphs['render']['fonts'])} (SIL OFL 1.1, vendored), {glyphs['render']['size_px']} px, "
        f"blur {glyphs['render']['blur_px']} px, SSIM window {glyphs['render']['ssim_window']}, candidate stretched "
        "to the genuine width.",
        f"- Calibrated against an **external ground truth**: confusable-vision 2026.09.26's verdicts (322 fonts): "
        f"{cal['pairs']:,} pairs ({cal['alike']} alike). **SSIM separates alike from not-alike with AUC "
        f"{cal['auc_ssim']}**. SSIM → cost by a one-feature logistic (w {cal['logistic']['w']}, b {cal['logistic']['b']}). "
        "No P3 pair was used, so the matrix doesn't leak into this evaluation.",
        "- Render settings were chosen from a small grid (size, blur, width handling, SSIM vs correlation vs IoU) on "
        "that same ground truth. Every setting scored AUC 0.88–0.90; single-glyph pixel similarity has a ceiling.",
        "- Measured multi-character twins (cost; 0 = indistinguishable): "
        + ", ".join(f"{m['fake']}→{m['real']} {m['cost']}" for m in glyphs["multi"][:6]) + ".",
        "- Measured, and honest: `0`→`o` costs "
        + f"{next((r['cost'] for r in glyphs['seed_check'] if r['fake'] == '0'), '?')} and `1`→`l` "
        + f"{next((r['cost'] for r in glyphs['seed_check'] if r['fake'] == '1'), '?')} in Roboto/Noto "
        "(the digit is taller or flagged). They're still caught as listed confusables (UTS-39), but they don't look "
        "identical in these fonts. Accented letters (ā, ţ) are visibly different at 16 px; the Trick Detector "
        "catches them by folding the marks and reports their real visual cost.",
        "- We tried searching all two-letter sequences for new twins; single-glyph SSIM rated a squeezed `xe` close "
        "to `e`, so only **listed** twins (our seed list, dnstwist's table, confusables.txt) are used, each one measured.",
        "",
        "## Error analysis (dev split only)",
        "",
        "Missed on dev (target brand → what Doppel said):",
        "",
        *[f"- **{x}**: " + ", ".join(f"`{v}`" for v in vals) for x, vals in s["dev_misses_sample"].items()],
        "",
        f"False positives on dev: {dict(s['dev_false_positive_count']) or 'none'}. Examples:",
        "",
        *[f"- **{k}**: " + ", ".join(f"`{v}`" for v in vals[:8]) for k, vals in s["dev_false_positive_sample"].items()],
        "",
        "Most misses are 1–3-letter names (`g.co`, `goo.gle`, `sbi.co.in` variants). With so few letters, one edit "
        "is as far as an unrelated word. Some, such as `rbi.co.in` (the Reserve Bank), are genuinely different "
        "institutions. Short brands also mean some short unrelated names are flagged (`spi.com` as an SBI typo); "
        "fusion should send those to NEEDS REVIEW.",
        "",
        "**Process note (honesty):** one round of rule fixes was made after reading a sample of errors that, in "
        "the first run, came from the *test* splits: a brand inside a longer name must look near-identical (no "
        "typo-level matches inside long words); a sound-alike must also look ≥ 0.6 alike; an exact brand token "
        "outranks a fuzzy match. These are general rules, not fitted thresholds, but the test splits were seen. "
        "From now on error samples come from `dev` (as above).",
        "",
        "**Update in P5 (2026-11-05): two precision rules from the real-world NRD run.** The benign names here "
        "were pre-filtered by P2, so they couldn't show a whole class of real false positives: names that are "
        "near-misses of a *long* brand name only through a generic word (`routebank` ~ statebank, "
        "`travelinsurance` ~ paytminsurance, `deedpost` ~ speedpost), and brands found inside unrelated words "
        "(`sleddingmail` ~ gmail). Now (1) a whole-name look-alike may carry at most **one ordinary visible edit** "
        "(look-alike swaps such as rn/m, 0/o, Cyrillic letters are free), and (2) a brand found inside a longer "
        "name must start and end on a word boundary. The cost on these synthetic pairs: T2 twin letters fell from "
        "99% to the figure above (dnstwist's double-swap variants such as `hbfcbark`, two ordinary edits a reader "
        "mostly notices) and T12 lost 2 of 11 rows; everything else was unchanged. The gain on real names is in "
        "`p5-nrd-run.md`. `TAU_CLOSE` was re-tuned on dev (still 0.7).",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
