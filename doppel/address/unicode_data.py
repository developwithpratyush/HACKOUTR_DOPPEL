"""Unicode data for the Address Reader: scripts and the UTS #39 skeleton.

Our own implementation (no library), read from the Unicode 18.0.0 files vendored in
``doppel/address/unicode/`` (Unicode License v3; refreshed by scripts/data/fetch.py).

- ``script_set(ch)``: the augmented Script_Extensions set of a character (UTS #39 §5.1).
- ``resolved_scripts(text)``: intersection over all characters; empty means mixed-script.
- ``skeleton(text)``: UTS #39 §4 skeleton: NFD, map each code point through
  confusables.txt, NFD again. Two strings are confusable when their skeletons match.
"""

from __future__ import annotations

import unicodedata
from bisect import bisect_right
from functools import lru_cache
from pathlib import Path

UNICODE_DIR = Path(__file__).resolve().parent / "unicode"

# Scripts that don't decide anything on their own (digits, hyphen, combining marks).
NEUTRAL = frozenset({"Zyyy", "Zinh"})  # Common, Inherited

# UTS #39 §5.1 augmentation: CJK writing systems combine several scripts.
AUGMENT = {
    "Hani": {"Hanb", "Jpan", "Kore"},
    "Hira": {"Jpan"},
    "Kana": {"Jpan"},
    "Hang": {"Kore"},
    "Bopo": {"Hanb"},
}


def _data_lines(name: str):
    path = UNICODE_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"{path} is missing; run `python scripts/data/fetch.py`")
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            yield [field.strip() for field in line.split(";")]


def _range(field: str) -> tuple[int, int]:
    if ".." in field:
        lo, hi = field.split("..")
        return int(lo, 16), int(hi, 16)
    cp = int(field, 16)
    return cp, cp


@lru_cache(maxsize=None)
def _script_codes() -> dict[str, str]:
    """Long script name (Latin) -> short code (Latn), from PropertyValueAliases.txt."""
    codes = {}
    for fields in _data_lines("PropertyValueAliases.txt"):
        if fields[0] == "sc":
            short, long_ = fields[1], fields[2]
            codes[long_] = short
            codes[short] = short
    return codes


def _range_table(name: str, value) -> tuple[list[int], list[int], list]:
    rows = sorted((*_range(f[0]), value(f[1])) for f in _data_lines(name))
    return [r[0] for r in rows], [r[1] for r in rows], [r[2] for r in rows]


@lru_cache(maxsize=None)
def _scripts():
    codes = _script_codes()
    return _range_table("Scripts.txt", lambda v: codes[v])


@lru_cache(maxsize=None)
def _script_extensions():
    return _range_table("ScriptExtensions.txt", lambda v: frozenset(v.split()))


def _lookup(table, cp: int):
    starts, ends, values = table
    i = bisect_right(starts, cp) - 1
    if i >= 0 and cp <= ends[i]:
        return values[i]
    return None


def script_of(ch: str) -> str:
    """Short script code of one character (Zzzz if unassigned)."""
    return _lookup(_scripts(), ord(ch)) or "Zzzz"


def script_set(ch: str) -> frozenset[str]:
    """Augmented Script_Extensions of one character."""
    ext = _lookup(_script_extensions(), ord(ch))
    base = set(ext) if ext else {script_of(ch)}
    for code in list(base):
        base |= AUGMENT.get(code, set())
    return frozenset(base)


def scripts_used(text: str) -> list[str]:
    """Distinct (non-neutral) scripts in a string, in order of first appearance."""
    seen: list[str] = []
    for ch in text:
        code = script_of(ch)
        if code not in NEUTRAL and code not in seen:
            seen.append(code)
    return seen


def resolved_scripts(text: str) -> frozenset[str] | None:
    """UTS #39 resolved script set. None = only neutral characters; empty = mixed-script."""
    resolved: set[str] | None = None
    for ch in text:
        sset = script_set(ch)
        if sset & NEUTRAL:
            continue
        resolved = set(sset) if resolved is None else resolved & sset
    return None if resolved is None else frozenset(resolved)


def is_mixed_script(text: str) -> bool:
    resolved = resolved_scripts(text)
    return resolved is not None and not resolved


SCRIPT_NAMES = {"Latn": "Latin", "Cyrl": "Cyrillic", "Grek": "Greek", "Armn": "Armenian",
                "Deva": "Devanagari", "Arab": "Arabic", "Hebr": "Hebrew", "Hani": "Han",
                "Hira": "Hiragana", "Kana": "Katakana", "Hang": "Hangul", "Thai": "Thai",
                "Geor": "Georgian", "Cher": "Cherokee", "Copt": "Coptic"}


def script_name(code: str) -> str:
    return SCRIPT_NAMES.get(code, code)


# ------------------------------------------------------------- skeleton ---

@lru_cache(maxsize=None)
def _confusables() -> dict[int, str]:
    table = {}
    for fields in _data_lines("confusables.txt"):
        source = int(fields[0], 16)
        target = "".join(chr(int(cp, 16)) for cp in fields[1].split())
        table[source] = target
    return table


def confusables_version() -> str:
    head = (UNICODE_DIR / "confusables.txt").read_text(encoding="utf-8")[:600]
    for line in head.splitlines():
        if line.startswith("# Version:"):
            return line.split(":", 1)[1].strip()
    return "unknown"


def skeleton(text: str) -> str:
    """UTS #39 skeleton(X): NFD, replace each code point by its prototype, NFD."""
    table = _confusables()
    decomposed = unicodedata.normalize("NFD", text)
    mapped = "".join(table.get(ord(ch), ch) for ch in decomposed)
    return unicodedata.normalize("NFD", mapped)


def codepoint(ch: str) -> str:
    return f"U+{ord(ch):04X}"
