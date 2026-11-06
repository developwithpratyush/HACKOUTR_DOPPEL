"""Build data/pairs/pairs.csv: synthetic look-alikes, real phishing names and negatives (deliverable 2).

    python -m doppel.generator.pairs          # needs data/raw/ (python scripts/data/fetch.py)

Rows: candidate, display, target_brand, technique, label, kind, split, source
  label 1 = look-alike of a protected brand, 0 = not.
  kind    lookalike (synthetic) | real_phish (PhiUSIIL) | genuine (family) | hard_negative | benign
  split   train | dev | test_seen | test_unseen (held-out brands) | test_real (real phishing names)

Rules:
- Deterministic: a fixed seed, and splits by a hash of the candidate.
- Held-out brands appear ONLY in test_unseen, so tests include brands the system never saw.
- test_unseen, test_seen and test_real are never used for tuning (decided before any model exists).
- A synthetic candidate is dropped if an attacker couldn't register it (under a restricted
  registry or a closed brand TLD), if it is genuine or brand user-content, or if it is a
  popular real domain (then it becomes a hard negative instead).
- Names only: nothing here contacts any domain.
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import re
import time
from collections import Counter, defaultdict
from pathlib import Path

from doppel.address import AddressError, read_address
from doppel.contract import REPO_ROOT
from doppel.family import check_family, load_registry
from doppel.family.registry import Brand, Registry
from doppel.generator import external, own
from doppel.generator.techniques import GENERATED, TECHNIQUES

SEED = 20261105
HELD_OUT_BRANDS = ("icici", "india_post")  # one bank, one government brand
CAP_PER_BRAND_TECHNIQUE = 400
BENIGN_SAMPLE = 10_000
RAW = REPO_ROOT / "data" / "raw"
OUT_DIR = REPO_ROOT / "data" / "pairs"
COLUMNS = ["candidate", "display", "target_brand", "technique", "label", "kind", "split", "source"]


def bucket(text: str) -> int:
    return int(hashlib.sha1(text.encode("utf-8")).hexdigest()[:8], 16) % 100


def split_for(candidate: str, brand_id: str | None, kind: str) -> str:
    if kind == "real_phish":
        return "test_real"
    if brand_id in HELD_OUT_BRANDS:
        return "test_unseen"
    b = bucket(candidate)
    if brand_id is None:  # benign: some go to test_unseen so that split has negatives too
        return "train" if b < 60 else "dev" if b < 75 else "test_seen" if b < 90 else "test_unseen"
    return "train" if b < 70 else "dev" if b < 85 else "test_seen"


def seeds(brand: Brand, reg: Registry) -> list[str]:
    """Registrable bases to fuzz: family domains outside restricted/brand-TLD endings, else <label>.in."""
    out = []
    for e in brand.family:
        tld = e.domain.rsplit(".", 1)[-1]
        restricted = any(e.domain == s or e.domain.endswith("." + s) for s in reg.restricted)
        if not restricted and tld not in reg.brand_tld_rows and not e.domain.startswith(("www.", "blog.")):
            out.append(e.domain)
    if not out:
        out = [f"{own.brand_labels(brand)[0]}.in"]
    return out


class Filter:
    """Decides whether a candidate is a usable synthetic look-alike."""

    def __init__(self, reg: Registry) -> None:
        self.reg = reg
        self.closed_tlds = set(reg.brand_tld_rows)

    def check(self, cand: str):
        try:
            r = read_address(cand)
        except (AddressError, UnicodeError, ValueError):
            return None, "unparseable"
        if any(r.is_under(s) for s in self.reg.restricted):
            return None, "restricted_registry"
        if r.tld in self.closed_tlds:
            return None, "brand_tld"
        f = check_family(r, self.reg)
        if f.status in ("genuine", "user_content", "restricted_other", "restricted_unlisted"):
            return None, f.status
        return (r, f), "ok"


def technique_from_family(r, f, brand: Brand) -> str:
    """For real or popular names: which technique the name resembles (from the P2 signal)."""
    if f.matched_by == "level_squat":
        return "T6"
    if f.matched_by == "trust_signal":
        return "T7"
    if f.matched_by == "skeleton":
        return "T2" if r.display.isascii() else "T3"
    if r.hosting_platform:
        return "T11"
    if r.owner.split(".")[0] in own.brand_labels(brand):
        return "T5"
    return "T4"


# ------------------------------------------------------------------ build ---

def synthetic(reg: Registry, rng: random.Random, drops: Counter) -> dict[str, dict]:
    filt = Filter(reg)
    shared_lures = list(reg.lure_words)
    rows: dict[str, dict] = {}
    for brand in reg.brands:
        lures = shared_lures + list(brand.lure_words)
        gens = []
        for seed_domain in seeds(brand, reg):
            label, tld = seed_domain.split(".", 1)
            gens += [external.dnstwist_variants(seed_domain), external.ail_variants(seed_domain),
                     own.twin_letters(label, tld), own.homoglyphs(label, tld), own.soundsquats(label, tld)]
        gens += [own.combosquats(brand, lures, rng, CAP_PER_BRAND_TECHNIQUE * 2),
                 own.tld_swaps(brand),
                 own.level_squats(brand, lures, rng, CAP_PER_BRAND_TECHNIQUE),
                 own.trust_signals(brand, reg, rng),
                 own.free_hosting(brand, lures, rng, CAP_PER_BRAND_TECHNIQUE * 2)]
        per_tech: dict[str, list[dict]] = defaultdict(list)
        seen: set[str] = set()
        for gen in gens:
            for cand, tech, source in gen:
                ok, why = filt.check(cand)
                if ok is None:
                    drops[why] += 1
                    continue
                r, _ = ok
                if r.host in seen or r.host in rows:
                    continue
                if tech == "T3" and r.display.isascii():
                    drops["T3_not_unicode"] += 1
                    continue
                seen.add(r.host)
                per_tech[tech].append({"candidate": r.host, "display": r.display, "target_brand": brand.id,
                                       "technique": tech, "label": 1, "kind": "lookalike", "source": source})
        for tech, items in per_tech.items():
            # our own generators first (they're targeted: Cyrillic homoglyphs, rn/m twins), then
            # dnstwist/ail fill the rest of the cap in a deterministic hashed order
            items.sort(key=lambda row: (not row["source"].startswith("own:"),
                                        hashlib.sha1(row["candidate"].encode()).hexdigest()))
            for row in items[:CAP_PER_BRAND_TECHNIQUE]:
                rows[row["candidate"]] = row
    return rows


_HOST_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b")


def genuine_rows(reg: Registry) -> dict[str, dict]:
    hosts: set[str] = {"nexusconnect.google", "about.google"}
    for brand in reg.brands:
        for e in brand.family:
            hosts.add(e.domain)
            hosts.add(f"www.{e.domain}")
            hosts.update(h for h in _HOST_RE.findall(e.note or "") if h.endswith(e.domain))
    rows = {}
    for h in sorted(hosts):
        r = read_address(h)
        f = check_family(r, reg)
        if f.genuine:
            rows[r.host] = {"candidate": r.host, "display": r.display, "target_brand": f.brand.id, "technique": "T10",
                            "label": 0, "kind": "genuine", "source": "registry"}
    return rows


def popular_domains() -> list[tuple[str, str]]:
    """(domain, source) from Majestic Million and PhiUSIIL's legitimate rows."""
    out = []
    with (RAW / "majestic" / "majestic_million.csv").open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            out.append((row["Domain"].lower(), "majestic"))
    csv.field_size_limit(10_000_000)
    with (RAW / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv").open(encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if row["label"] == "1":
                out.append((row["URL"], "phiusiil-legit"))
    return out


def hard_negative_rows(reg: Registry, synthetic_rows: dict[str, dict]) -> dict[str, dict]:
    rows = {}
    for raw, source in popular_domains():
        try:
            r = read_address(raw)
        except (AddressError, UnicodeError, ValueError):
            continue
        host = r.owner  # the established registrable domain
        if host in rows:
            continue
        if host in synthetic_rows:  # a generated look-alike that is actually a popular real domain
            syn = synthetic_rows.pop(host)
            rows[host] = {**syn, "label": 0, "kind": "hard_negative", "source": f"{source}+{syn['source']}"}
            continue
        f = check_family(read_address(host), reg)
        if f.status in ("imitation", "restricted_unlisted") and f.brand is not None:
            rh = read_address(host)
            rows[host] = {"candidate": rh.host, "display": rh.display, "target_brand": f.brand.id,
                          "technique": technique_from_family(rh, f, f.brand), "label": 0,
                          "kind": "hard_negative", "source": source}
    return rows


def benign_rows(reg: Registry, taken: set[str]) -> dict[str, dict]:
    names = []
    for line in (RAW / "nrd" / "nrd7.txt").open(encoding="utf-8"):
        d = line.strip()
        if d and not d.startswith("#"):
            names.append(d)
    names.sort(key=lambda d: hashlib.sha1(f"{SEED}:{d}".encode()).hexdigest())
    rows = {}
    for d in names:
        if len(rows) >= BENIGN_SAMPLE:
            break
        try:
            r = read_address(d)
        except (AddressError, UnicodeError, ValueError):
            continue
        if r.host in taken or check_family(r, reg).status != "none":
            continue
        rows[r.host] = {"candidate": r.host, "display": r.display, "target_brand": "", "technique": "none",
                        "label": 0, "kind": "benign", "source": "nrd7"}
    return rows


def real_phish_rows(reg: Registry, taken: set[str]) -> dict[str, dict]:
    rows = {}
    csv.field_size_limit(10_000_000)
    with (RAW / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv").open(encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if row["label"] != "0":
                continue
            try:
                r = read_address(row["URL"])
            except (AddressError, UnicodeError, ValueError):
                continue
            if r.host in rows or r.host in taken:
                continue
            fam = check_family(r, reg)
            if fam.status == "imitation" and fam.brand is not None:
                rows[r.host] = {"candidate": r.host, "display": r.display, "target_brand": fam.brand.id,
                                "technique": technique_from_family(r, fam, fam.brand), "label": 1,
                                "kind": "real_phish", "source": "phiusiil-phishing"}
    return rows


def p2_signal(rows: list[dict], reg: Registry) -> dict[str, dict]:
    """How often P2's Family Verifier already names the right brand, per technique (positives only)."""
    stats: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        if row["label"] != 1 or row["kind"] != "lookalike":
            continue
        f = check_family(read_address(row["candidate"]), reg)
        c = stats[row["technique"]]
        c["total"] += 1
        if f.brand is not None and f.brand.id == row["target_brand"]:
            c["right_brand"] += 1
        elif f.brand is not None:
            c["wrong_brand"] += 1
        else:
            c["no_signal"] += 1
    return {t: {**dict(c), "right_brand_pct": round(100 * c["right_brand"] / c["total"], 1)}
            for t, c in sorted(stats.items())}


def build() -> dict:
    t0 = time.perf_counter()
    reg = load_registry()
    rng = random.Random(SEED)
    drops: Counter = Counter()

    syn = synthetic(reg, rng, drops)
    gen = genuine_rows(reg)
    for h in gen:
        syn.pop(h, None)
    hard = hard_negative_rows(reg, syn)
    taken = set(syn) | set(gen) | set(hard)
    real = real_phish_rows(reg, taken)
    taken |= set(real)
    benign = benign_rows(reg, taken)

    rows = [*syn.values(), *real.values(), *gen.values(), *hard.values(), *benign.values()]
    for row in rows:
        row["split"] = split_for(row["candidate"], row["target_brand"] or None, row["kind"])
    rows.sort(key=lambda r: (r["split"], r["kind"], r["target_brand"], r["technique"], r["candidate"]))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with (OUT_DIR / "pairs.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)

    by_tech_split: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        if row["label"] == 1:
            by_tech_split[row["technique"]][row["split"]] += 1
    summary = {
        "seed": SEED,
        "held_out_brands": list(HELD_OUT_BRANDS),
        "cap_per_brand_technique": CAP_PER_BRAND_TECHNIQUE,
        "rows": len(rows),
        "by_kind": dict(Counter(r["kind"] for r in rows)),
        "by_split": dict(Counter(r["split"] for r in rows)),
        "by_label_split": {s: dict(Counter(r["label"] for r in rows if r["split"] == s))
                           for s in sorted({r["split"] for r in rows})},
        "positives_by_technique": {t: {"name": TECHNIQUES[t], **dict(c), "total": sum(c.values())}
                                   for t, c in sorted(by_tech_split.items(), key=lambda kv: int(kv[0][1:]))},
        "positives_by_brand": dict(Counter(r["target_brand"] for r in rows if r["label"] == 1)),
        "hard_negatives_by_brand": dict(Counter(r["target_brand"] for r in rows if r["kind"] == "hard_negative")),
        "dropped_candidates": dict(drops),
        "p2_family_verifier_signal": p2_signal(rows, reg),
        "techniques_not_generated": [t for t in TECHNIQUES if t not in GENERATED and t != "T10"],
        "build_seconds": round(time.perf_counter() - t0, 1),
    }
    (OUT_DIR / "SUMMARY.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def write_readme(summary: dict) -> Path:
    """data/pairs/README.md: the pairs datasheet, rendered from SUMMARY.json so the numbers always match."""
    splits = ["train", "dev", "test_seen", "test_unseen", "test_real"]
    p2 = summary["p2_family_verifier_signal"]
    lines = [
        "# Datasheet: look-alike pairs (`data/pairs/pairs.csv`, deliverable 2)",
        "",
        "Generated by `python -m doppel.generator.pairs` (seed "
        f"{summary['seed']}, {summary['build_seconds']} s). **Do not edit by hand**: this file is rendered "
        "from `SUMMARY.json`.",
        "",
        "## Columns",
        "",
        "| Column | Meaning |",
        "|---|---|",
        "| `candidate` | Host in lowercase ASCII (punycode for IDNs) |",
        "| `display` | Unicode form, as a victim would see it |",
        "| `target_brand` | Registry brand id it imitates or resembles (empty for benign) |",
        "| `technique` | T1–T13 from `docs/ps08-attack-catalog.md` (T10 = genuine; `none` = benign) |",
        "| `label` | **1** = look-alike of a protected brand, **0** = not |",
        "| `kind` | `lookalike` (synthetic), `real_phish` (PhiUSIIL phishing), `genuine` (registry family), "
        "`hard_negative` (popular real domain resembling a brand), `benign` (random NRD name, no brand signal) |",
        "| `split` | `train`, `dev`, `test_seen`, `test_unseen` (held-out brands: "
        f"{', '.join(summary['held_out_brands'])}), `test_real` |",
        "| `source` | The generator or list that produced the row |",
        "",
        f"## Size: {summary['rows']:,} rows",
        "",
        "| Kind | Rows |",
        "|---|---|",
        *[f"| {k} | {v:,} |" for k, v in sorted(summary["by_kind"].items(), key=lambda kv: -kv[1])],
        "",
        "| Split | Label 1 | Label 0 |",
        "|---|---|---|",
        *[f"| {sp} | {summary['by_label_split'].get(sp, {}).get('1', 0):,} | "
          f"{summary['by_label_split'].get(sp, {}).get('0', 0):,} |" for sp in splits],
        "",
        "## Positives per technique and split",
        "",
        "| Technique | " + " | ".join(splits) + " | Total |",
        "|---|" + "---|" * (len(splits) + 1),
        *[f"| {t} {v['name']} | " + " | ".join(f"{v.get(sp, 0):,}" for sp in splits) + f" | {v['total']:,} |"
          for t, v in summary["positives_by_technique"].items()],
        "",
        "Not generated as names: " + ", ".join(summary["techniques_not_generated"])
        + " (T8 brand-less clone is page-level; T9 sleeper is a status).",
        "",
        "## Early number: does P2 alone already name the right brand?",
        "",
        "Synthetic look-alikes only, by P2's Family Verifier (no closeness scoring yet). The low rows are "
        "exactly what P4's visual edit distance has to fix.",
        "",
        "| Technique | Right brand | No signal | Wrong brand |",
        "|---|---|---|---|",
        *[f"| {t} | **{v['right_brand_pct']}%** ({v.get('right_brand', 0):,}/{v['total']:,}) | "
          f"{v.get('no_signal', 0):,} | {v.get('wrong_brand', 0):,} |"
          for t, v in sorted(p2.items(), key=lambda kv: int(kv[0][1:]))],
        "",
        "## How rows were made",
        "",
        "- **Synthetic look-alikes:** dnstwist (typo, ASCII/Unicode homoglyph, bitsquat), ail-typo-squatting "
        "(hyphen insertion), and our own generators in `doppel/generator/own.py` (twin letters from "
        "`data/lookalikes/ascii_twins.yaml`, Cyrillic/Greek homoglyphs from Unicode confusables incl. "
        "whole-script, combosquat from the registry lure words, ending swap, level-squat, trust-signal "
        "mimicry, free hosting, soundsquat). The targeted generators are kept first, and dnstwist fills the "
        f"rest, up to {summary['cap_per_brand_technique']} per brand and technique.",
        "- **Dropped:** anything an attacker couldn't register (under a restricted registry or a closed brand "
        "TLD), anything genuine or on a brand's user-content host, and anything that is actually a popular "
        "real domain (that becomes a hard negative). Drops: "
        + ", ".join(f"{k} {v:,}" for k, v in summary["dropped_candidates"].items()) + ".",
        "- **Real phishing (`test_real`):** PhiUSIIL phishing rows whose host P2 links to one of our brands. "
        "**Caveat:** they were *selected* with P2's name signals, so name-level recall on this set is not a "
        "fair metric; use it for the later stages, real-world closeness and the demo.",
        "- **Hard negatives:** Majestic Million + PhiUSIIL legitimate domains that resemble a brand (P2 signal). "
        "Popular, established domains are presumed not phishing. Many are brand affiliates "
        "(icicilombard.com, hdfclife.com) or other companies with similar names (SBI Holdings Japan, US state "
        "banks). Per brand: " + ", ".join(f"{k} {v}" for k, v in summary["hard_negatives_by_brand"].items()) + ".",
        "- **Genuine:** every registry family domain, its `www.` form, and the subdomains named in registry notes.",
        f"- **Benign:** {summary['by_kind'].get('benign', 0):,} random names from the NRD snapshot with no P2 brand "
        "signal. Unverified: some may be phishing for *other* brands, but none imitate ours by name.",
        "",
        "## Splits",
        "",
        f"- Held-out brands ({', '.join(summary['held_out_brands'])}) appear **only** in `test_unseen`/`test_real`.",
        "- Other rows: a hash of the candidate decides (70/15/15 train/dev/test_seen; benign 60/15/15/10, the "
        "last 10% to test_unseen so that split has negatives).",
        "- `test_seen`, `test_unseen` and `test_real` are **never used for tuning**.",
        "",
        "## Known limitations",
        "",
        "- Synthetic look-alikes are *designed* imitations, not registered domains; the label means \"imitates "
        "the brand\", not \"is malicious\".",
        "- dnstwist's Unicode homoglyphs are mostly accented Latin letters (pāyţm), which UTS-39 skeletons don't "
        "fold, hence the low P2 number for T3. Mixed-script Cyrillic look-alikes come from our own generator.",
        "- T12 (soundsquat) is small: a rule set plus a simple phonetic key, not a full phonetic algorithm.",
        "- Hard negatives are presumed legitimate because they're popular; a popular compromised site would be "
        "mislabelled.",
        "",
    ]
    out = OUT_DIR / "README.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


if __name__ == "__main__":
    import sys

    if "--readme-only" in sys.argv:
        print(write_readme(json.loads((OUT_DIR / "SUMMARY.json").read_text(encoding="utf-8"))))
        raise SystemExit(0)
    s = build()
    write_readme(s)
    print(json.dumps({k: v for k, v in s.items() if k != "p2_family_verifier_signal"}, indent=2, ensure_ascii=False))
    print("P2 signal per technique:")
    for t, v in s["p2_family_verifier_signal"].items():
        print(f"  {t}: {v['right_brand_pct']}% right brand ({v})")
