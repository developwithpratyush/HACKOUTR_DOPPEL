"""Download every raw dataset P1 needs into data/raw/ (gitignored).

    python scripts/data/fetch.py            # fetch what's missing, verify checksums
    python scripts/data/fetch.py --force    # re-download everything
    python scripts/data/fetch.py --only nrd7

Each source is pinned (a commit SHA or a static URL) and has an expected
SHA-256, so a fresh clone rebuilds byte-identical files. Unicode's
confusables.txt has no versioned URL for 18.0.0, so it's fetched from
`latest` and its version line is checked instead of a hash.

Writes data/raw/MANIFEST.json: url, bytes, sha256, fetched_at for every file.
Standard library only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import shutil
import sys
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RAW = REPO / "data" / "raw"
USER_AGENT = "doppel-data-fetch/0.1 (hackathon research)"

NRD_COMMIT = "b9bd225102836b2e9baad0031f535af9cc7fac6b"  # hagezi/nrd, 2026-11-04 release
CV_COMMIT = "e5b74b38d9882c197be942369fffff8c16348df7"   # paultendo/confusable-vision, release 2026.09.26
CV_RELEASE = "2026.09.26"
ROBOTO_COMMIT = "1c627bfa375fc51cf86fabeca4f6e08a95f0aa5c"  # google/fonts, last change to ofl/roboto
NOTO_COMMIT = "8b0a1d0f5983c89bc2b93f1b5fb55f9e252744b5"    # google/fonts, last change to ofl/notosans


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    dest: str                      # path under data/raw/
    licence: str
    sha256: str | None = None      # expected hash of the downloaded file
    unpack: str | None = None      # "zip" or "gunzip"
    expect_text: str | None = None  # a line that must appear (for unpinned files)
    vendor: str | None = None       # also copy into the repo (small, redistributable files the code needs)


CV = f"https://raw.githubusercontent.com/paultendo/confusable-vision/{CV_COMMIT}/data/release/{CV_RELEASE}"

SOURCES = [
    Source(
        "phiusiil",
        "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
        "phiusiil/phiusiil.zip", "CC BY 4.0",
        sha256="0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a", unpack="zip",
    ),
    Source(
        "nrd7",
        f"https://raw.githubusercontent.com/hagezi/nrd/{NRD_COMMIT}/domains/nrd7.txt",
        "nrd/nrd7.txt", "GPL-3.0 (list; used as data)",
        sha256="00d5382963f2df5cd6bc2bd013543ed8d293a375cd2b7a820d8460283c00d36d",
    ),
    Source(
        "confusables",
        "https://www.unicode.org/Public/security/latest/confusables.txt",
        "unicode/confusables.txt", "Unicode License v3",
        expect_text="# Version: 18.0.0",
        vendor="doppel/address/unicode/confusables.txt",
    ),
    Source(
        "unicode_scripts",
        "https://www.unicode.org/Public/UCD/latest/ucd/Scripts.txt",
        "unicode/Scripts.txt", "Unicode License v3",
        expect_text="# Scripts-18.0.0.txt",
        vendor="doppel/address/unicode/Scripts.txt",
    ),
    Source(
        "unicode_script_extensions",
        "https://www.unicode.org/Public/UCD/latest/ucd/ScriptExtensions.txt",
        "unicode/ScriptExtensions.txt", "Unicode License v3",
        expect_text="# ScriptExtensions-18.0.0.txt",
        vendor="doppel/address/unicode/ScriptExtensions.txt",
    ),
    Source(
        "unicode_property_value_aliases",
        "https://www.unicode.org/Public/UCD/latest/ucd/PropertyValueAliases.txt",
        "unicode/PropertyValueAliases.txt", "Unicode License v3",
        expect_text="# PropertyValueAliases-18.0.0.txt",
        vendor="doppel/address/unicode/PropertyValueAliases.txt",
    ),
    Source(
        "cv_lookalikes",
        f"{CV}/lookalikes.jsonl.gz", "confusable-vision/lookalikes.jsonl.gz", "CC BY 4.0",
        sha256="ce22254585c6926eb896bc7089cd010818f42d19071320b72e4d3f90a668cd06", unpack="gunzip",
    ),
    Source(
        "cv_sequences",
        f"{CV}/sequences.jsonl.gz", "confusable-vision/sequences.jsonl.gz", "CC BY 4.0",
        sha256="78d586eb880bc1a05575b805a613802b47767977a97ae32f841415124e917f02", unpack="gunzip",
    ),
    Source(
        "cv_in_place",
        f"{CV}/in-place.jsonl.gz", "confusable-vision/in-place.jsonl.gz", "CC BY 4.0",
        sha256="9c17050099077abd59d9597b5f5d982b906f93f6d49808c6bb47bc5cb87f8216", unpack="gunzip",
    ),
    Source(
        "cv_dataset_md",
        f"{CV}/DATASET.md", "confusable-vision/DATASET.md", "CC BY 4.0",
        sha256="30c8d38ee2feec96da48ff36df358f25e6c459c59bd9e3b4f5d42c8223f6a10e",
    ),
    Source(
        "cv_sha256sums",
        f"{CV}/SHA256SUMS", "confusable-vision/SHA256SUMS", "CC BY 4.0",
        sha256="bce120a08a232f4a12c8248e90ff0e911392bb37aa650a3c95b4926433039c0d",
    ),
    Source(
        # Daily list, no versioned URL: the header is checked and the hash recorded in MANIFEST.json.
        # The hard negatives drawn from it are committed in data/pairs/pairs.csv, so results stay reproducible.
        "majestic_million",
        "https://downloads.majestic.com/majestic_million.csv",
        "majestic/majestic_million.csv", "CC BY 3.0",
        expect_text="GlobalRank,TldRank,Domain",
    ),
    # P4: phone/SMS fonts for the glyph confusability matrix (doppel/perception/build_glyphs.py).
    # Roboto is Android's system font; Noto Sans covers Latin, Greek and Cyrillic look-alikes.
    Source(
        "font_roboto",
        f"https://raw.githubusercontent.com/google/fonts/{ROBOTO_COMMIT}/ofl/roboto/Roboto%5Bwdth,wght%5D.ttf",
        "fonts/Roboto.ttf", "SIL OFL 1.1",
        sha256="d7598e12c5dbef095ff8272cfc55da0250bd07fbdecbac8a530b9b277872a134",
        vendor="doppel/perception/fonts/Roboto.ttf",
    ),
    Source(
        "font_roboto_licence",
        f"https://raw.githubusercontent.com/google/fonts/{ROBOTO_COMMIT}/ofl/roboto/OFL.txt",
        "fonts/Roboto-OFL.txt", "SIL OFL 1.1",
        sha256="061402327a96aadb0bfb694a960ed289ecd38d383e396243831ab81feb109c41",
        vendor="doppel/perception/fonts/Roboto-OFL.txt",
    ),
    Source(
        "font_noto_sans",
        f"https://raw.githubusercontent.com/google/fonts/{NOTO_COMMIT}/ofl/notosans/NotoSans%5Bwdth,wght%5D.ttf",
        "fonts/NotoSans.ttf", "SIL OFL 1.1",
        sha256="bfb7bb691513f12e734dc346c03a03f784912432d7e3fa8e56efcf906fe86b3d",
        vendor="doppel/perception/fonts/NotoSans.ttf",
    ),
    Source(
        "font_noto_sans_licence",
        f"https://raw.githubusercontent.com/google/fonts/{NOTO_COMMIT}/ofl/notosans/OFL.txt",
        "fonts/NotoSans-OFL.txt", "SIL OFL 1.1",
        sha256="cee9892f9f0cc8fe882c9e9537ee6a89621d86ee7ceaf70b02e2b2b1c25c061a",
        vendor="doppel/perception/fonts/NotoSans-OFL.txt",
    ),
    Source(
        "codebox_homoglyph",
        "https://raw.githubusercontent.com/codebox/homoglyph/522d0612bab0cc438bce63363a1243c9981761ff/raw_data/chars.txt",
        "homoglyph/codebox_chars.txt", "MIT",
        sha256="635f56f2eab035d002e51ec6430ec4baf0e28fdf6cf53ab06e3e5512711911b6",
    ),
    Source(
        "life4_homoglyphs",
        "https://raw.githubusercontent.com/life4/homoglyphs/8e5552dbde82cc8dc418ecf2ca3921568af5ad8f/homoglyphs/confusables.json",
        "homoglyph/life4_confusables.json", "MIT",
        sha256="6ca4f3c2df4fb15192eddc6d72f0c63fcd455b63dbcd2ff7232e1036a864eb6f",
    ),
]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp, tmp.open("wb") as out:
        shutil.copyfileobj(resp, out, length=1 << 20)
    tmp.replace(dest)


def unpack(src: Source, path: Path) -> list[str]:
    if src.unpack == "zip":
        with zipfile.ZipFile(path) as z:
            z.extractall(path.parent)
            return [str((path.parent / n).relative_to(RAW)) for n in z.namelist()]
    if src.unpack == "gunzip":
        out = path.with_suffix("")  # drop .gz
        with gzip.open(path, "rb") as fin, out.open("wb") as fout:
            shutil.copyfileobj(fin, fout)
        return [str(out.relative_to(RAW))]
    return []


def verify_confusable_vision(manifest: dict) -> list[str]:
    """Check the downloaded .gz files against the release's own SHA256SUMS."""
    sums_path = RAW / "confusable-vision" / "SHA256SUMS"
    if not sums_path.exists():
        return []
    problems = []
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        digest, name = parts[0], parts[1].lstrip("*")
        local = RAW / "confusable-vision" / name
        if local.exists() and sha256_of(local) != digest:
            problems.append(f"confusable-vision/{name}: hash differs from the release's SHA256SUMS")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force", action="store_true", help="re-download even if the file exists")
    ap.add_argument("--only", nargs="*", help="source names to fetch")
    args = ap.parse_args(argv)

    manifest_path = RAW / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    failed = []

    for src in SOURCES:
        if args.only and src.name not in args.only:
            continue
        dest = RAW / src.dest
        if args.force or not dest.exists():
            print(f"fetch  {src.name:18} {src.url}")
            try:
                download(src.url, dest)
            except Exception as exc:  # network errors are reported, not fatal for other sources
                failed.append(f"{src.name}: download failed: {exc}")
                continue
        else:
            print(f"cached {src.name:18} {dest.relative_to(REPO)}")

        digest = sha256_of(dest)
        if src.sha256 and digest != src.sha256:
            failed.append(f"{src.name}: sha256 {digest} != pinned {src.sha256}")
        if src.expect_text and src.expect_text not in dest.read_text(encoding="utf-8", errors="replace")[:4000]:
            failed.append(f"{src.name}: expected '{src.expect_text}' in the header (the upstream file changed)")
        extracted = unpack(src, dest)
        if src.vendor:
            target = REPO / src.vendor
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(dest, target)
        manifest[src.name] = {
            "url": src.url,
            "file": src.dest,
            "extracted": extracted,
            "licence": src.licence,
            "bytes": dest.stat().st_size,
            "sha256": digest,
            "fetched_at": manifest.get(src.name, {}).get("fetched_at") if not args.force and
            manifest.get(src.name, {}).get("sha256") == digest else dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        }

    failed += verify_confusable_vision(manifest)
    RAW.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"\nmanifest: {manifest_path.relative_to(REPO)}")
    for f in failed:
        print(f"PROBLEM {f}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
