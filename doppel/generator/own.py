"""Our own look-alike generators (the parts dnstwist and ail-typo-squatting don't cover).

Every generator yields ``(candidate, technique, generator_name)``. Candidates are hostnames
(Unicode allowed; the pairs builder converts and filters them). Deterministic: no randomness
except through ``rng`` seeded by the caller.
"""

from __future__ import annotations

import random
import unicodedata
from collections.abc import Iterator
from pathlib import Path

import yaml

from doppel.address.unicode_data import _confusables, script_of
from doppel.contract import REPO_ROOT
from doppel.family.registry import Brand, Registry
from doppel.generator.techniques import ATTACKER_TLDS, HOSTING_PLATFORMS

Gen = Iterator[tuple[str, str, str]]
TWINS_FILE = REPO_ROOT / "data" / "lookalikes" / "ascii_twins.yaml"


def brand_labels(brand: Brand) -> list[str]:
    """The names an attacker imitates: aliases plus the first label of each family domain."""
    labels = list(brand.aliases)
    for e in brand.family:
        first = e.domain.split(".")[0]
        # only labels that carry the brand: onlinesbi, hdfcbank, withgoogle (not "bank" from bank.sbi)
        if first not in labels and any(a in first for a in brand.aliases):
            labels.append(first)
    return labels


# ---------------------------------------------------------------- T2 twins ---

def _twin_pairs() -> list[tuple[str, str]]:
    data = yaml.safe_load(TWINS_FILE.read_text(encoding="utf-8"))
    return [(p["real"], p["fake"]) for p in data["pairs"] if p["domain_possible"]]


def twin_letters(label: str, tld: str) -> Gen:
    for real, fake in _twin_pairs():
        start = label.find(real)
        while start != -1:
            yield f"{label[:start]}{fake}{label[start + len(real):]}.{tld}", "T2", "own:twins"
            start = label.find(real, start + 1)


# ------------------------------------------------------------- T3 homoglyph ---

def _latin_lookalikes() -> dict[str, list[str]]:
    """Latin lowercase letter -> single Cyrillic/Greek/Armenian letters whose skeleton is that letter."""
    out: dict[str, list[str]] = {}
    for cp, target in _confusables().items():
        ch = chr(cp)
        if (len(target) == 1 and "a" <= target <= "z" and ch.islower()
                and script_of(ch) in ("Cyrl", "Grek", "Armn") and unicodedata.category(ch) == "Ll"):
            out.setdefault(target, []).append(ch)
    return out


def homoglyphs(label: str, tld: str) -> Gen:
    look = _latin_lookalikes()
    # one hidden letter (mixed script), at every position
    for i, ch in enumerate(label):
        for sub in look.get(ch, [])[:2]:
            yield f"{label[:i]}{sub}{label[i + 1:]}.{tld}", "T3", "own:homoglyph-1"
    # the whole label in Cyrillic, when every letter has a Cyrillic twin (whole-script confusable)
    cyr = []
    for ch in label:
        options = [s for s in look.get(ch, []) if script_of(s) == "Cyrl"]
        if not options:
            break
        cyr.append(options[0])
    else:
        yield f"{''.join(cyr)}.{tld}", "T3", "own:homoglyph-whole"


# ------------------------------------------------------------- T4 combosquat --

def combosquats(brand: Brand, lures: list[str], rng: random.Random, n: int) -> Gen:
    labels = [a for a in brand.aliases if len(a) >= 3]
    seen = 0
    for _ in range(n * 4):
        if seen >= n:
            break
        alias = rng.choice(labels)
        words = rng.sample(lures, k=rng.choice([1, 1, 2]))
        sep = rng.choice(["-", "-", ""])
        parts = [alias, *words] if rng.random() < 0.75 else [*words, alias]
        seen += 1
        yield f"{sep.join(parts)}.{rng.choice(ATTACKER_TLDS)}", "T4", "own:combosquat"


# ------------------------------------------------------------- T5 TLD swap ----

def tld_swaps(brand: Brand) -> Gen:
    for label in brand_labels(brand):
        for tld in ATTACKER_TLDS:
            yield f"{label}.{tld}", "T5", "own:tld-swap"


# ------------------------------------------------------------ T6 level-squat --

def _attacker_owner(lures: list[str], rng: random.Random) -> str:
    style = rng.random()
    if style < 0.5:
        name = "-".join(rng.sample(lures, k=2))
    elif style < 0.8:
        name = f"{rng.choice(lures)}{rng.randint(1, 999)}"
    else:
        name = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(5, 9)))
    return f"{name}.{rng.choice(ATTACKER_TLDS)}"


def level_squats(brand: Brand, lures: list[str], rng: random.Random, n: int) -> Gen:
    hosts = [e.domain for e in brand.family]
    hosts += [f"www.{e.domain}" for e in brand.family if not e.domain.startswith("www.")]
    for _ in range(n):
        genuine = rng.choice(hosts)
        owner = _attacker_owner(lures, rng)
        if rng.random() < 0.7:
            yield f"{genuine}.{owner}", "T6", "own:level-squat-dot"
        else:  # the genuine name runs into the owner label: sbi.bank.in-kyc-verify.com
            yield f"{genuine}-{owner}", "T6", "own:level-squat-hyphen"


# ------------------------------------------------------- T7 trust signals ------

TRUST_WORDS = ["blog", "accounts", "mail", "support", "secure", "login", "drive", "pay", "my"]


def trust_signals(brand: Brand, reg: Registry, rng: random.Random) -> Gen:
    labels = [a for a in brand.aliases if len(a) >= 3]
    for alias in labels:
        for suffix in brand.restricted_suffixes or ["bank.in", "gov.in"]:
            dashed = suffix.replace(".", "-")
            glued = suffix.replace(".", "")
            for form in (f"{alias}.{dashed}", f"{alias}{dashed}", f"{alias}-{dashed}", f"{alias}{glued}",
                         f"{alias}.{glued}"):
                yield f"{form}.{rng.choice(ATTACKER_TLDS)}", "T7", "own:trust-suffix"
    for e in brand.family:  # the whole genuine address with dots turned into hyphens
        dashed = e.domain.replace(".", "-")
        for tld in rng.sample(ATTACKER_TLDS, k=3):
            yield f"{dashed}.{tld}", "T7", "own:dot-to-dash"
    for tld in brand.brand_tlds:  # blog-google.com, accounts-google.online
        for word in TRUST_WORDS:
            yield f"{word}-{tld}.{rng.choice(ATTACKER_TLDS)}", "T7", "own:brand-tld-dash"


# ------------------------------------------------------- T11 free hosting ------

def free_hosting(brand: Brand, lures: list[str], rng: random.Random, n: int) -> Gen:
    labels = [a for a in brand.aliases if len(a) >= 3]
    for _ in range(n):
        alias, lure = rng.choice(labels), rng.choice(lures)
        sub = rng.choice([f"{alias}-{lure}", f"{alias}{lure}", f"{alias}-{lure}-{rng.randint(1, 99)}",
                          f"{alias}-{rng.randint(1000, 99999)}", f"{lure}-{alias}"])
        yield f"{sub}.{rng.choice(HOSTING_PLATFORMS)}", "T11", "own:free-hosting"


# ---------------------------------------------------------- T12 soundsquat -----

SOUND_RULES = [("ph", "f"), ("f", "ph"), ("ck", "k"), ("k", "ck"), ("c", "k"), ("k", "c"), ("x", "ks"),
               ("x", "cks"), ("s", "z"), ("z", "s"), ("ee", "i"), ("i", "ee"), ("oo", "u"), ("u", "oo"),
               ("w", "v"), ("v", "w"), ("y", "i"), ("i", "y"), ("ai", "ay"), ("ay", "ai"), ("q", "k"),
               ("a", "aa"), ("aa", "a"), ("e", "ee"), ("tm", "tem"), ("sh", "s")]

_KEY_RULES = [("ph", "f"), ("ck", "k"), ("cks", "ks"), ("q", "k"), ("x", "ks"), ("z", "s"), ("w", "v"),
              ("y", "i"), ("ee", "i"), ("oo", "u"), ("aa", "a"), ("c", "k"), ("tem", "tm"), ("sh", "s")]


def sound_key(label: str) -> str:
    """A tiny phonetic key: spellings that sound alike map to the same key."""
    key = label.lower()
    for a, b in _KEY_RULES:
        key = key.replace(a, b)
    out = []
    for ch in key:  # collapse doubled letters
        if not out or out[-1] != ch:
            out.append(ch)
    return "".join(out)


def soundsquats(label: str, tld: str) -> Gen:
    base = sound_key(label)
    for a, b in SOUND_RULES:
        start = label.find(a)
        while start != -1:
            cand = label[:start] + b + label[start + len(a):]
            if cand != label and sound_key(cand) == base:
                yield f"{cand}.{tld}", "T12", "own:soundsquat"
            start = label.find(a, start + 1)


def load_twins_file() -> Path:
    return TWINS_FILE
