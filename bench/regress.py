"""The no-degradation gate (P11, then every phase that touches detection).

    python bench/regress.py                  # measure, compare with docs/eval/baseline.json, exit 1 on any drop
    python bench/regress.py --save-baseline  # measure and store the numbers as the new baseline
    python bench/regress.py --no-speed       # skip the one-core speed run (~15 s)

What it measures, all through the real brain (``Brain.investigate``, batch source ``file``: Quick, plus
Standard when there's something to explain; no Deep, no counterfactual):

1. **Arena** (P4's pairs, ``test_seen`` + ``test_unseen``): look-alikes flagged with the right brand, per trick
   (hit counts), and the rows flagged at all per negative kind (genuine, hard negative, benign).
2. **Genuine set**: every registry family domain (bare, ``www.``, one subdomain) + ``bench/data/genuine_set.txt``.
   GENUINE count.
3. **Phishing.Database India slice** (``bench/data/pdb_india_slice.txt``): caught (flagged with the right brand),
   per brand.
4. **Short-brand noise**: every Phishing.Database name that contains "sbi" but isn't in the slice (SBI Securities,
   Coinbase look-alikes, "bills", "lesbian"...): how many Doppel calls State Bank. A keyword alert fires on all of them.
5. **Speed**: names per second on one core over the first 20,000 NRD names (``data/raw/nrd/nrd7.txt``).

Gate rules (``docs/BUILD_PHASES.md``, "The no-degradation gate"):
- arena hits per trick must not fall; benign false positives must stay at the baseline (0); genuine false
  positives must not rise;
- the GENUINE count must not fall; the slice's caught count per brand must not fall; the short-brand noise must
  not rise (gated once the baseline has it);
- speed must not fall by more than 10%.
Hard negatives are reported, not gated (they look like combosquats by construction, ``docs/eval/p4-arena.md``).

Writes ``runs/regress/last.json`` (every number, plus the names behind each count) and prints the comparison.
A planned drop is not waved through here: it is written, with its reason, in the phase's eval file.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
for _var in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_var, "1")

BASELINE = REPO / "docs" / "eval" / "baseline.json"
LAST = REPO / "runs" / "regress" / "last.json"
PAIRS = REPO / "data" / "pairs" / "pairs.csv"
GENUINE = REPO / "bench" / "data" / "genuine_set.txt"
SLICE = REPO / "bench" / "data" / "pdb_india_slice.txt"
NRD = REPO / "data" / "raw" / "nrd" / "nrd7.txt"
PDB = REPO / "data" / "raw" / "phishing_database" / "phishing-domains-ACTIVE.txt"
FLAGGED = {"needs_review", "phishing", "sleeper"}
SPEED_N = 20_000
SPEED_TOLERANCE = 0.10
TECHS = ["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T11", "T12", "T13"]

_BRAIN = None


def _init() -> None:
    global _BRAIN
    os.environ["DOPPEL_OFFLINE"] = "1"            # the gate never touches the network (certificates: cache only)
    from doppel.brain.brain import Brain

    _BRAIN = Brain(deep=False)


def _judge(names: list[str]) -> list[tuple[str, str | None]]:
    out = []
    for n in names:
        try:
            v = _BRAIN.investigate(n, source="file", counterfactual=False)
            out.append((v["label"], (v["target_brand"] or {}).get("id")))
        except Exception as exc:                   # noqa: BLE001 - an unreadable name is a result, not a crash
            out.append(("error", f"{type(exc).__name__}: {str(exc)[:60]}"))
    return out


def judge_all(names: list[str], workers: int) -> dict[str, tuple[str, str | None]]:
    uniq = list(dict.fromkeys(names))
    if workers <= 1:
        _init()
        return dict(zip(uniq, _judge(uniq)))
    chunks = [uniq[i:i + 200] for i in range(0, len(uniq), 200)]
    res: list = []
    with ProcessPoolExecutor(workers, initializer=_init) as pool:
        for part in pool.map(_judge, chunks):
            res += part
    return dict(zip(uniq, res))


# ------------------------------------------------------------------ inputs ---

def arena_rows() -> list[dict]:
    with PAIRS.open(encoding="utf-8") as f:
        return [r for r in csv.DictReader(f) if r["split"] in ("test_seen", "test_unseen")
                and r["kind"] in ("lookalike", "genuine", "hard_negative", "benign")]


def genuine_names() -> list[str]:
    from doppel.family import load_registry

    names = []
    for b in load_registry().brands:
        for e in b.family:
            names += [e.domain, "www." + e.domain] + (["login." + e.domain] if e.include_subdomains else [])
    names += [l.strip() for l in GENUINE.read_text(encoding="utf-8").splitlines()
              if l.strip() and not l.startswith("#")]
    return list(dict.fromkeys(names))


def slice_rows() -> list[tuple[str, str]]:
    rows = []
    for line in SLICE.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            brand, name = line.split()
            rows.append((brand, name))
    return rows


# ------------------------------------------------------------------ measure ---

def measure(workers: int, speed: bool) -> dict:
    t0 = time.perf_counter()
    rows = arena_rows()
    gen = genuine_names()
    sl = slice_rows()
    noise = sbi_noise_names({n for _, n in sl})
    verdicts = judge_all([r["candidate"] for r in rows] + gen + [n for _, n in sl] + noise, workers)

    det = {t: {"hit": 0, "n": 0} for t in TECHS}
    fp = defaultdict(lambda: {"flagged": 0, "n": 0, "names": []})
    misses = defaultdict(list)
    for r in rows:
        label, brand = verdicts[r["candidate"]]
        if r["kind"] == "lookalike":
            if r["technique"] not in det:
                continue
            c = det[r["technique"]]
            c["n"] += 1
            if label in FLAGGED and brand == r["target_brand"]:
                c["hit"] += 1
            else:
                misses[r["technique"]].append(r["candidate"])
        else:
            c = fp[r["kind"]]
            c["n"] += 1
            if label in FLAGGED:
                c["flagged"] += 1
                if r["kind"] != "hard_negative":
                    c["names"].append(r["candidate"])

    genuine = {n: verdicts[n][0] for n in gen}
    by_brand = defaultdict(lambda: {"caught": 0, "n": 0, "missed": []})
    for brand, name in sl:
        label, b = verdicts[name]
        c = by_brand[brand]
        c["n"] += 1
        if label in FLAGGED and b == brand:
            c["caught"] += 1
        else:
            c["missed"].append(f"{name} ({label}, {b})")

    out = {
        "generated": time.strftime("%Y-%m-%d %H:%M"),
        "arena": {"detection": det, "false_positives": {k: dict(v) for k, v in fp.items()},
                  "miss_samples": {t: m[:10] for t, m in misses.items()}},
        "genuine_set": {"genuine": sum(1 for v in genuine.values() if v == "genuine"), "n": len(genuine),
                        "not_genuine": {n: v for n, v in genuine.items() if v != "genuine"}},
        "pdb_india_slice": dict(by_brand),
        "sbi_noise": {"keyword_hits": len(noise), "flagged_as_sbi": sorted(n for n in noise if verdicts[n][0] in FLAGGED
                                                                           and verdicts[n][1] == "sbi")},
        "seconds_judging": round(time.perf_counter() - t0, 1),
    }
    if speed:
        out["speed"] = measure_speed()
    return out


def sbi_noise_names(exclude: set[str]) -> list[str]:
    """Phishing.Database names containing 'sbi' that aren't State Bank (the slice's 3 are excluded)."""
    if not PDB.exists():
        return []
    with PDB.open(encoding="utf-8") as f:
        return [l.strip() for l in f if "sbi" in l.lower() and l.strip() not in exclude]


def measure_speed() -> dict:
    """Names per second on one core: the first SPEED_N NRD names, batch source, best of two runs."""
    _init()
    names = []
    with NRD.open(encoding="utf-8") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                names.append(line.strip())
                if len(names) >= SPEED_N:
                    break
    for n in names[:300]:                                  # warm caches (segmenter, glyphs, model)
        _BRAIN.investigate(n, source="nrd_snapshot", counterfactual=False)
    best = 0.0
    for _ in range(2):
        t = time.perf_counter()
        for n in names:
            try:
                _BRAIN.investigate(n, source="nrd_snapshot", counterfactual=False)
            except Exception:                              # noqa: BLE001
                pass
        best = max(best, len(names) / (time.perf_counter() - t))
    return {"names_per_s_one_core": round(best, 1), "n": len(names)}


# ------------------------------------------------------------------ compare ---

def compare(base: dict, now: dict) -> list[str]:
    """Every gate failure, as a sentence. Empty = the gate passes."""
    fails = []
    for t in TECHS:
        b, n = base["arena"]["detection"][t], now["arena"]["detection"][t]
        if n["hit"] < b["hit"]:
            fails.append(f"arena {t}: {n['hit']}/{n['n']} right-brand detections (baseline {b['hit']}/{b['n']})")
    for kind in ("benign", "genuine"):
        b = base["arena"]["false_positives"].get(kind, {"flagged": 0})
        n = now["arena"]["false_positives"].get(kind, {"flagged": 0})
        if n["flagged"] > b["flagged"]:
            fails.append(f"arena false positives on {kind}: {n['flagged']} (baseline {b['flagged']}): "
                         + ", ".join(sorted(set(n.get('names', [])) - set(b.get('names', [])))[:8]))
    if now["genuine_set"]["genuine"] < base["genuine_set"]["genuine"]:
        lost = sorted(set(now["genuine_set"]["not_genuine"]) - set(base["genuine_set"]["not_genuine"]))
        fails.append(f"genuine set: {now['genuine_set']['genuine']} GENUINE (baseline {base['genuine_set']['genuine']}); "
                     f"lost: {', '.join(lost[:8])}")
    for brand, b in base["pdb_india_slice"].items():
        n = now["pdb_india_slice"].get(brand, {"caught": 0})
        if n["caught"] < b["caught"]:
            fails.append(f"Phishing.Database slice {brand}: {n['caught']}/{n.get('n', 0)} caught (baseline {b['caught']}/{b['n']})")
    if "sbi_noise" in base and "sbi_noise" in now:
        b, n = base["sbi_noise"]["flagged_as_sbi"], now["sbi_noise"]["flagged_as_sbi"]
        if len(n) > len(b):
            fails.append(f"short-brand noise: {len(n)} non-SBI 'sbi' names called State Bank (baseline {len(b)}): "
                         + ", ".join(sorted(set(n) - set(b))[:8]))
    if "speed" in base and "speed" in now:
        b, n = base["speed"]["names_per_s_one_core"], now["speed"]["names_per_s_one_core"]
        if n < b * (1 - SPEED_TOLERANCE):
            fails.append(f"speed: {n:,.0f} names/s on one core (baseline {b:,.0f}; more than {SPEED_TOLERANCE:.0%} slower)")
    return fails


def table(base: dict | None, now: dict) -> str:
    def cell(key_now, key_base=None):
        return key_now if base is None else f"{key_base} -> {key_now}"

    lines = ["Arena (test_seen + test_unseen), right-brand detections:"]
    for t in TECHS:
        n = now["arena"]["detection"][t]
        b = base["arena"]["detection"][t]["hit"] if base else None
        lines.append(f"  {t:4} {cell(n['hit'], b)} / {n['n']}")
    lines.append("Arena rows flagged per negative kind:")
    for k, n in sorted(now["arena"]["false_positives"].items()):
        b = base["arena"]["false_positives"].get(k, {}).get("flagged") if base else None
        lines.append(f"  {k:14} {cell(n['flagged'], b)} / {n['n']}")
    g = now["genuine_set"]
    lines.append(f"Genuine set: {cell(g['genuine'], base['genuine_set']['genuine'] if base else None)} / {g['n']} GENUINE")
    lines.append("Phishing.Database India slice, caught:")
    for brand, n in sorted(now["pdb_india_slice"].items()):
        b = base["pdb_india_slice"].get(brand, {}).get("caught") if base else None
        lines.append(f"  {brand:11} {cell(n['caught'], b)} / {n['n']}")
    if "sbi_noise" in now:
        b = len(base["sbi_noise"]["flagged_as_sbi"]) if base and "sbi_noise" in base else None
        lines.append(f"Short-brand noise: {cell(len(now['sbi_noise']['flagged_as_sbi']), b)} of "
                     f"{now['sbi_noise']['keyword_hits']} 'sbi' keyword hits called State Bank")
    if "speed" in now:
        b = base["speed"]["names_per_s_one_core"] if base and "speed" in base else None
        lines.append(f"Speed: {cell(now['speed']['names_per_s_one_core'], b)} names/s on one core")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--save-baseline", action="store_true")
    ap.add_argument("--no-speed", action="store_true")
    ap.add_argument("--workers", "-j", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    args = ap.parse_args()

    now = measure(args.workers, speed=not args.no_speed)
    LAST.parent.mkdir(parents=True, exist_ok=True)
    LAST.write_text(json.dumps(now, indent=1), encoding="utf-8")
    base = json.loads(BASELINE.read_text(encoding="utf-8")) if BASELINE.exists() else None
    print(table(base, now))
    if args.save_baseline:
        BASELINE.write_text(json.dumps(now, indent=1), encoding="utf-8")
        print(f"\nBaseline saved: {BASELINE.relative_to(REPO)}")
        return
    if base is None:
        print("\nNo baseline yet: run with --save-baseline first.")
        sys.exit(1)
    fails = compare(base, now)
    if fails:
        print("\nGATE FAILS:\n  - " + "\n  - ".join(fails))
        sys.exit(1)
    print("\nGate passes: nothing dropped.")


if __name__ == "__main__":
    main()
