"""Run Address Reader + Family Verifier over the hagezi NRD snapshot (names only, never contacted).

    python bench/p2_family_sweep.py [--limit N]

Reports throughput and how many new domains land in each Family Verifier status,
plus every flagged name per brand, for hand review. Writes docs/eval/p2-family-sweep.md.
"""

from __future__ import annotations

import argparse
import time
from collections import Counter, defaultdict
from pathlib import Path

import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from doppel.address import AddressError, read_address  # noqa: E402
from doppel.family import check_family, load_registry  # noqa: E402

NRD = REPO / "data" / "raw" / "nrd" / "nrd7.txt"
OUT = REPO / "docs" / "eval" / "p2-family-sweep.md"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="only the first N domains (0 = all)")
    args = ap.parse_args()
    reg = load_registry()
    domains = [l.strip() for l in NRD.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    if args.limit:
        domains = domains[: args.limit]

    status, how = Counter(), Counter()
    by_brand: dict[str, list[tuple[str, str]]] = defaultdict(list)
    errors = 0
    t0 = time.perf_counter()
    for d in domains:
        try:
            f = check_family(read_address(d), reg)
        except AddressError:
            errors += 1
            continue
        status[f.status] += 1
        if f.status != "none":
            how[f"{f.status}:{f.matched_by or '-'}"] += 1
            by_brand[f.brand.id if f.brand else "(no brand)"].append((d, f.status if f.status != "imitation" else f.matched_by))
    elapsed = time.perf_counter() - t0
    rate = len(domains) / elapsed

    lines = [
        "# P2 sweep: Address Reader + Family Verifier on newly registered domains",
        "",
        f"**Input:** hagezi NRD 7-day snapshot (list version in `data/STATS.json`), {len(domains):,} domains, names only.",
        f"**Throughput:** {rate:,.0f} domains/s on one core ({elapsed:.1f} s total, pure Python, no network). "
        f"{errors} names failed IDNA parsing.",
        "",
        "## Status counts",
        "",
        "| Status | Domains |",
        "|---|---|",
        *[f"| {k} | {v:,} |" for k, v in status.most_common()],
        "",
        "## How the brand was found",
        "",
        "| Status : signal | Domains |",
        "|---|---|",
        *[f"| {k} | {v:,} |" for k, v in how.most_common()],
        "",
        "## Genuine and restricted-registry names (all)",
        "",
        *[f"- `{d}` ({st}, {brand})" for brand, items in sorted(by_brand.items()) for d, st in items
          if st in ("genuine", "restricted_other", "restricted_unlisted", "user_content")],
        "",
        "## Flagged names per brand (for hand review; first 40 each)",
        "",
        "These are **brand signals, not verdicts**: P4's Trick Detector and later stages decide.",
        "",
    ]
    for brand, items in sorted(by_brand.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"### {brand}: {len(items):,}")
        lines.append("")
        lines.extend(f"- `{d}` ({s})" for d, s in items[:40])
        lines.append("")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:30]))
    print(f"\nwrote {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
