"""Measure the raw datasets and write data/STATS.json (the numbers in data/DATASHEET.md).

    python scripts/data/fetch.py     # first
    python scripts/data/profile.py

Every number in the datasheet comes from this script, so it can be re-derived.
Domains are only counted, never contacted.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

from publicsuffixlist import PublicSuffixList

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from doppel.contract import load_yaml  # noqa: E402

RAW = REPO / "data" / "raw"
OUT = REPO / "data" / "STATS.json"

csv.field_size_limit(10_000_000)


def host_of(url: str) -> str:
    h = url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return h.split("@")[-1].split(":")[0].strip(".").lower()


def profile_phiusiil(psl: PublicSuffixList, icann: PublicSuffixList) -> dict:
    path = RAW / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv"
    labels, usi100, www_https, idn, private = Counter(), Counter(), Counter(), Counter(), Counter()
    platforms: Counter = Counter()
    rows, columns = 0, []
    domains: dict[int, set[str]] = {0: set(), 1: set()}
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames or []
        for row in reader:
            rows += 1
            y = int(row["label"])
            labels[y] += 1
            if float(row["URLSimilarityIndex"]) == 100.0:
                usi100[y] += 1
            url = row["URL"]
            if url.lower().startswith("https://www."):
                www_https[y] += 1
            host = host_of(url)
            if "xn--" in host:
                idn[y] += 1
            # The host's suffix comes from the PSL *private* section (free hosting such as
            # web.app) when the full list and the ICANN-only list disagree.
            if psl.publicsuffix(host) != icann.publicsuffix(host):
                private[y] += 1
                if y == 0:
                    platforms[psl.publicsuffix(host)] += 1
            reg = psl.privatesuffix(host)
            if reg:
                domains[y].add(reg)
    pct = lambda c, y: round(100 * c[y] / labels[y], 2)
    return {
        "file": "phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv",
        "rows": rows,
        "columns": len(columns),
        "label_meaning": {"1": "legitimate", "0": "phishing"},
        "by_label": {"legitimate": labels[1], "phishing": labels[0]},
        "url_similarity_index_is_100_pct": {"legitimate": pct(usi100, 1), "phishing": pct(usi100, 0)},
        "starts_https_www_pct": {"legitimate": pct(www_https, 1), "phishing": pct(www_https, 0)},
        "idn_hosts": {"legitimate": idn[1], "phishing": idn[0]},
        "on_psl_private_suffix_pct": {"legitimate": pct(private, 1), "phishing": pct(private, 0)},
        "top_private_suffixes_in_phishing": dict(platforms.most_common(10)),
        "distinct_registrable_domains": {"legitimate": len(domains[1]), "phishing": len(domains[0])},
    }


def profile_nrd(psl: PublicSuffixList, aliases: dict[str, list[str]]) -> dict:
    path = RAW / "nrd" / "nrd7.txt"
    header = {}
    total, idn = 0, 0
    tld, suffix = Counter(), Counter()
    alias_substring = Counter()
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                if ":" in line:
                    k, v = line[1:].split(":", 1)
                    header[k.strip()] = v.strip()
                continue
            d = line.lower()
            total += 1
            if "xn--" in d:
                idn += 1
            tld[d.rsplit(".", 1)[-1]] += 1
            for s in ("bank.in", "fin.in", "gov.in", "co.in", "nic.in"):
                if d.endswith("." + s):
                    suffix[s] += 1
            label = d.replace(".", "-")
            for brand, names in aliases.items():
                if any(a in label for a in names):
                    alias_substring[brand] += 1
    return {
        "file": "nrd/nrd7.txt",
        "header": header,
        "domains": total,
        "idn_domains": idn,
        "tld_in": tld["in"],
        "under_suffix": dict(suffix),
        "top_tlds": dict(tld.most_common(10)),
        "alias_substring_hits": dict(alias_substring),
        "note": "alias_substring_hits counts raw substrings (e.g. 'sbi' inside 'thanksbitcoin'): an upper bound, not brand matches.",
    }


def profile_unicode() -> dict:
    path = RAW / "unicode" / "confusables.txt"
    version = date = None
    entries, prototypes_ascii = 0, 0
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if line.startswith("# Version:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("# Date:"):
            date = line.split(":", 1)[1].strip()
        elif line and not line.startswith("#"):
            entries += 1
            target = line.split(";")[1].split()
            if all(int(cp, 16) < 0x80 for cp in target):
                prototypes_ascii += 1
    return {"file": "unicode/confusables.txt", "version": version, "date": date,
            "mappings": entries, "mappings_to_pure_ascii": prototypes_ascii}


def count_lines(path: Path) -> int:
    with path.open(encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def profile_homoglyphs() -> dict:
    cv = RAW / "confusable-vision"
    tiers = Counter(json.loads(l)["tier"] for l in (cv / "in-place.jsonl").open(encoding="utf-8"))
    codebox = [l for l in (RAW / "homoglyph" / "codebox_chars.txt").read_text(encoding="utf-8").splitlines()
               if l.strip() and not l.startswith("#")]
    life4 = json.loads((RAW / "homoglyph" / "life4_confusables.json").read_text(encoding="utf-8"))
    return {
        "confusable_vision": {
            "release": "2026.09.26",
            "lookalike_pairs": count_lines(cv / "lookalikes.jsonl"),
            "sequence_pairs": count_lines(cv / "sequences.jsonl"),
            "in_place_tiers": dict(tiers),
        },
        "codebox_homoglyph_groups": len(codebox),
        "life4_homoglyphs_entries": len(life4),
    }


def main() -> int:
    psl = PublicSuffixList()
    icann = PublicSuffixList(only_icann=True)
    registry = load_yaml(REPO / "data" / "brands" / "registry.yaml")
    aliases = {b["id"]: b["aliases"] for b in registry["brands"]}
    stats = {
        "phiusiil": profile_phiusiil(psl, icann),
        "nrd7": profile_nrd(psl, aliases),
        "unicode_confusables": profile_unicode(),
        "homoglyphs": profile_homoglyphs(),
        "registry": {
            "brands": len(registry["brands"]),
            "genuine_family_entries": sum(len(b["genuine_family"]) for b in registry["brands"]),
            "shared_lure_words": len(registry["lure_words"]),
            "lure_words_by_lang": dict(Counter(w["lang"] for w in registry["lure_words"])),
        },
    }
    manifest = json.loads((RAW / "MANIFEST.json").read_text(encoding="utf-8"))
    stats["sources"] = {k: {"sha256": v["sha256"], "bytes": v["bytes"], "fetched_at": v["fetched_at"]}
                        for k, v in manifest.items()}
    OUT.write_text(json.dumps(stats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in stats.items() if k != "sources"}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
