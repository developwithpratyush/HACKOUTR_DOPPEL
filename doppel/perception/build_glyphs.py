"""Build the glyph confusability matrix (C7), once, offline.

    python -m doppel.perception.build_glyphs        # ~2 min; needs data/raw/ (scripts/data/fetch.py)

Writes ``doppel/perception/glyph_costs.json`` (committed; the Trick Detector reads it at runtime,
so Quick stays a table lookup).

What it measures, with ``render.visual_ssim`` (Roboto + Noto Sans, 16 px, lightly blurred):
1. every pair of ASCII letters and digits (630 pairs)
2. multi-character twins (rn ≈ m, vv ≈ w, cl ≈ d): the **listed** candidates only, from our seed
   list (data/lookalikes/ascii_twins.yaml), dnstwist's ASCII glyph table and Unicode confusables.
   Each one is measured; none is trusted unmeasured. We don't search all two-letter sequences:
   single-glyph SSIM isn't sharp enough for an open search (it rates a squeezed 'xe' close to 'e').
3. every Unicode look-alike candidate a domain can actually hold, against all ASCII letters and digits
   (and the two-character sequence it is listed as, if any). Candidates come from Unicode
   confusables.txt, the Latin letters with diacritics (dnstwist's āţ), and confusable-vision.

**From SSIM to a cost.** Raw SSIM isn't a probability, and blank space inflates it. We map it with a
one-feature logistic fitted on an external ground truth measured across 322 fonts by
confusable-vision's author, not by us:
- its in-place verdicts (alike = strict/broad tier, not alike = "no"), and
- every ASCII letter/digit pair: its within-font survey compared all of them and found only 0/o and
  1/l alike ("absent means compared and not alike"), which gives the clearly-different negatives.
``visual_sim = P(alike | ssim) / P(alike | ssim = 1)``, and ``cost = 1 − visual_sim``; a render that
is pixel-identical (SSIM ≥ 0.99) costs 0. No P3 pair is used here, so nothing leaks into the evaluation.
"""

from __future__ import annotations

import itertools
import json
import string
import time
import unicodedata

import idna
import numpy as np
import yaml

from doppel.address.unicode_data import _confusables
from doppel.contract import REPO_ROOT
from doppel.perception import render

OUT = REPO_ROOT / "doppel" / "perception" / "glyph_costs.json"
CV_DIR = REPO_ROOT / "data" / "raw" / "confusable-vision"
TWINS = REPO_ROOT / "data" / "lookalikes" / "ascii_twins.yaml"
ALNUM = string.ascii_lowercase + string.digits
IDENTICAL = 0.99          # SSIM at or above this: pixel-identical, cost 0
ASCII_ALIKE = {("0", "o"), ("1", "l")}   # the only ASCII pairs confusable-vision finds alike within one font
KEEP_UNICODE = 0.25       # keep a Unicode → ASCII entry at or above this


# ------------------------------------------------------------ helpers ---

def domain_char(ch: str) -> bool:
    """A character that can appear, unchanged, in a domain a browser shows (IDNA2008 + UTS-46)."""
    try:
        return idna.decode(idna.encode(f"a{ch}a", uts46=True, transitional=False)) == f"a{ch}a"
    except (idna.IDNAError, UnicodeError):
        return False


def cp(text: str) -> str:
    return chr(int(text[2:], 16))


def lower_alnum(s: str) -> bool:
    return bool(s) and all(c in ALNUM for c in s)


def fit_logistic(x: np.ndarray, y: np.ndarray, iters: int = 50) -> tuple[float, float]:
    """1-D logistic regression by Newton's method: P(y=1|x) = 1 / (1 + exp(-(w x + b)))."""
    X = np.column_stack([x, np.ones_like(x)])
    beta = np.zeros(2)
    for _ in range(iters):
        p = 1 / (1 + np.exp(-X @ beta))
        grad = X.T @ (y - p)
        hess = X.T @ (X * (p * (1 - p))[:, None]) + 1e-6 * np.eye(2)
        beta += np.linalg.solve(hess, grad)
    return float(beta[0]), float(beta[1])


def auc(scores: list[float], labels: list[bool]) -> float:
    """Rank-sum (Mann-Whitney) ROC AUC."""
    order = np.argsort(scores)
    ranks = np.empty(len(scores))
    ranks[order] = np.arange(1, len(scores) + 1)
    pos = np.array(labels)
    n1, n0 = pos.sum(), (~pos).sum()
    return float((ranks[pos].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


# ---------------------------------------------------------- the build ---

def calibration_set() -> list[tuple[str, str, bool]]:
    """(candidate, ascii target, alike) from confusable-vision: in-place verdicts + all ASCII pairs."""
    rows = [json.loads(l) for l in (CV_DIR / "in-place.jsonl").open(encoding="utf-8")]
    out = []
    for r in rows:
        if r["tier"] == "design" or not lower_alnum(r["b"]):
            continue
        a = cp(r["a"])
        if a.isascii():
            continue  # ASCII pairs come from the within-font survey below
        if render.fonts_drawing(a + r["b"]):
            out.append((a, r["b"], r["tier"] in ("strict", "broad")))
    out += [(a, b, (a, b) in ASCII_ALIKE) for a, b in itertools.combinations(ALNUM, 2)]
    return out


def multi_candidates() -> dict[tuple[str, str], list[str]]:
    """(fake, real) multi-character twins -> where they are listed. Lowercase, domain-possible only."""
    import dnstwist

    out: dict[tuple[str, str], list[str]] = {}
    for p in yaml.safe_load(TWINS.read_text(encoding="utf-8"))["pairs"]:
        if p["domain_possible"] and len(p["fake"]) != len(p["real"]):
            out.setdefault((p["fake"], p["real"]), []).append("ascii_twins.yaml")
    for real, fakes in dnstwist.Fuzzer("example.com").glyphs_ascii.items():
        for fake in fakes:
            if lower_alnum(fake) and lower_alnum(real) and len(fake) != len(real):
                key = (fake, real) if len(fake) > len(real) else (real, fake)
                out.setdefault(key, []).append("dnstwist")
    for c, target in _confusables().items():
        ch, t = chr(c), target.lower()
        if lower_alnum(ch) and lower_alnum(t) and len(t) > 1:
            out.setdefault((t, ch), []).append("confusables.txt")
    return out


def unicode_candidates() -> dict[str, set[str]]:
    """Unicode look-alike candidate -> the ASCII strings it is listed as (from any source)."""
    cands: dict[str, set[str]] = {}

    def add(ch: str, target: str | None):
        if ch.isascii() or len(ch) != 1:
            return
        cands.setdefault(ch, set())
        if target and lower_alnum(target) and len(target) <= 2:
            cands[ch].add(target)

    for c, target in _confusables().items():
        t = target.lower()
        if lower_alnum(t) and len(t) <= 2:
            add(chr(c), t)
    for c in itertools.chain(range(0x00C0, 0x0250), range(0x1E00, 0x1F00)):  # Latin with diacritics
        ch = chr(c)
        base = unicodedata.normalize("NFD", ch)[0]
        if base in string.ascii_lowercase:
            add(ch, base)
    for name in ("lookalikes.jsonl", "in-place.jsonl", "sequences.jsonl"):
        for line in (CV_DIR / name).open(encoding="utf-8"):
            r = json.loads(line)
            a, b = r["a"], r["b"]
            b_text = cp(b) if b.startswith("U+") else b
            a_text = cp(a)
            if lower_alnum(b_text):
                add(a_text, b_text)
            elif lower_alnum(a_text) and len(b_text) == 1:
                add(b_text, a_text)
    return {ch: t for ch, t in cands.items() if domain_char(ch) and render.fonts_drawing(ch)}


def build() -> dict:
    t0 = time.perf_counter()

    # 1. calibration: SSIM -> P(alike), on confusable-vision's in-place verdicts
    cal = calibration_set()
    cal_ssim = [render.visual_ssim(a, b)[0] for a, b, _ in cal]
    y = np.array([alike for _, _, alike in cal], dtype=float)
    w, b0 = fit_logistic(np.array(cal_ssim), y)
    p_top = 1 / (1 + np.exp(-(w + b0)))

    def vsim(s: float | None) -> float:
        if s is None:
            return 0.0
        if s >= IDENTICAL:
            return 1.0
        return float(min(1.0, (1 / (1 + np.exp(-(w * s + b0)))) / p_top))

    # 2. ASCII x ASCII
    ascii_pairs = {}
    for a, b in itertools.combinations(ALNUM, 2):
        ascii_pairs[a + b] = round(vsim(render.visual_ssim(a, b)[0]), 3)

    # 3. listed multi-character twins, each measured
    twins = yaml.safe_load(TWINS.read_text(encoding="utf-8"))["pairs"]
    multi = []
    for (fake, real), listed in sorted(multi_candidates().items()):
        s = render.visual_ssim(fake, real)[0]
        multi.append({"fake": fake, "real": real, "ssim": round(s, 3), "sim": round(vsim(s), 3),
                      "cost": round(1 - vsim(s), 3), "listed_in": sorted(set(listed))})
    multi.sort(key=lambda m: -m["sim"])

    # 4. Unicode candidates vs every ASCII letter/digit (+ their listed sequence)
    uni = {}
    cands = unicode_candidates()
    for ch, listed in sorted(cands.items()):
        row = {}
        for target in set(ALNUM) | listed:
            s = vsim(render.visual_ssim(ch, target)[0])
            if s >= KEEP_UNICODE:
                row[target] = round(s, 3)
        if row:
            uni[ch] = dict(sorted(row.items(), key=lambda kv: -kv[1])[:6])

    seed_check = []
    for p in twins:
        fake, real = p["fake"], p["real"]
        s, fonts = render.visual_ssim(fake, real)
        seed_check.append({"fake": fake, "real": real, "seed_status": p["status"], "ssim": round(s, 3),
                           "visual_sim": round(vsim(s), 3), "cost": round(1 - vsim(s), 3)})

    return {
        "schema_version": 1,
        "built": time.strftime("%Y-%m-%d"),
        "build_seconds": round(time.perf_counter() - t0, 1),
        "render": {"fonts": list(render.FONT_FILES), "size_px": render.SIZE, "blur_px": render.BLUR,
                   "ssim_window": render.WIN, "candidate_stretched_to_genuine_width": True},
        "calibration": {
            "ground_truth": "confusable-vision 2026.09.26 in-place tiers (strict/broad = alike, no = not); "
                            "CC BY 4.0, Paul Wood FRSA",
            "pairs": len(cal), "alike": int(y.sum()), "auc_ssim": round(auc(cal_ssim, list(y.astype(bool))), 3),
            "logistic": {"w": round(w, 4), "b": round(b0, 4)}, "p_alike_at_ssim_1": round(float(p_top), 4),
            "identical_ssim": IDENTICAL,
        },
        "seed_check": seed_check,
        "ascii": ascii_pairs,
        "multi": multi,
        "unicode": uni,
        "counts": {"ascii_pairs": len(ascii_pairs), "multi": len(multi), "unicode_candidates": len(cands),
                   "unicode_kept": len(uni)},
    }


if __name__ == "__main__":
    result = build()
    OUT.write_text(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("build_seconds", "calibration", "counts")}, indent=2))
    for row in result["seed_check"]:
        print(f"  seed {row['fake']:>3} -> {row['real']:<2} ssim {row['ssim']:.3f}  cost {row['cost']:.3f}  "
              f"({row['seed_status']})")
    for m in result["multi"]:
        print(f"  multi {m['fake']:>3} -> {m['real']:<2} ssim {m['ssim']:.3f}  cost {m['cost']:.3f}  {m['listed_in']}")
    top = sorted(result["ascii"].items(), key=lambda kv: -kv[1])[:20]
    print("  closest ASCII pairs:", ", ".join(f"{k[0]}/{k[1]} {v}" for k, v in top))
    for ch in ["а", "ο", "ā", "ţ", "é", "ı", "ɡ", "ѕ"]:
        print(f"  {ch} {result['unicode'].get(ch)}")
