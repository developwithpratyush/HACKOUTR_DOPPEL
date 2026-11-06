"""Combosquat parser (C5): split glued labels into words, so a brand counts only as a real token.

``thanksbitcoin`` contains the letters ``sbi`` but means "thanks bitcoin"; ``sbibankin`` means
"sbi bank in". Substring matching can't tell them apart (1,010 raw ``sbi`` hits in the NRD
snapshot, mostly noise). We segment with wordninja (MIT; English Wikipedia unigram frequencies,
Zipf costs) after adding our own vocabulary: brand aliases, the first labels of family domains, the
registry's lure words and a few address words (bank, in, gov, online…).

Our words are inserted at rank ``VOCAB_RANK`` of the frequency list: common enough to be found
inside glued text, rare enough that real English words still win (thanks + bitcoin beats
thank + sbi + t + coin). Set by hand before evaluation.
"""

from __future__ import annotations

import gzip
import re
from functools import lru_cache
from math import log
from pathlib import Path

import wordninja

from doppel.family.registry import Registry, load_registry

VOCAB_RANK = 1000
KNOWN_RANK = 30_000   # leftovers of a glued token must be common words (lombard, mall), not fragments (bnak)
ADDRESS_WORDS = ["bank", "in", "gov", "co", "net", "org", "com", "online", "india", "my", "e", "m", "www"]
_SPLIT = re.compile(r"[^a-z0-9]+")


class Segmenter:
    def __init__(self, extra_words: list[str]) -> None:
        path = Path(wordninja.__file__).resolve().parent / "wordninja" / "wordninja_words.txt.gz"
        with gzip.open(path) as f:
            words = f.read().decode().split()
        extra = list(dict.fromkeys(w for w in extra_words if w))
        words = [w for w in words if w not in set(extra)]
        words[VOCAB_RANK:VOCAB_RANK] = extra
        lm = wordninja.LanguageModel.__new__(wordninja.LanguageModel)
        lm._wordcost = {k: log((i + 1) * log(len(words))) for i, k in enumerate(words)}
        lm._maxword = max(len(x) for x in words)
        self._lm = lm
        self.vocab = frozenset(extra)
        self._rank = {w: i for i, w in enumerate(words)}

    def known(self, word: str) -> bool:
        """A real word: ours, or among the KNOWN_RANK most frequent English words (3+ letters)."""
        return word in self.vocab or (len(word) >= 3 and self._rank.get(word, KNOWN_RANK) < KNOWN_RANK)

    @lru_cache(maxsize=200_000)
    def split(self, token: str) -> tuple[str, ...]:
        """Words of one hyphen-free token (lowercase ASCII); digits stay together."""
        if not token:
            return ()
        if not token.isascii():
            return (token,)
        return tuple(w for w in self._lm.split(token) if w)


def tokens(text: str) -> list[str]:
    """Hyphen/dot-separated tokens of a host part."""
    return [t for t in _SPLIT.split(text.lower()) if t]


def brand_strings(reg: Registry) -> dict[str, list[str]]:
    """brand id -> the names an attacker imitates: aliases + family first labels that carry an alias."""
    out: dict[str, list[str]] = {}
    for b in reg.brands:
        names = list(b.aliases)
        for e in b.family:
            first = e.domain.split(".")[0]
            if first not in names and any(a in first for a in b.aliases):
                names.append(first)
        out[b.id] = names
    return out


_SEGMENTERS: dict[int, tuple[Registry, Segmenter]] = {}


def segmenter(reg: Registry | None = None) -> Segmenter:
    """One segmenter per registry object (the registry isn't hashable, so cache by identity)."""
    reg = reg or load_registry()
    hit = _SEGMENTERS.get(id(reg))
    if hit is None or hit[0] is not reg:
        vocab = [n for names in brand_strings(reg).values() for n in names]
        vocab += list(reg.lure_words) + [w for b in reg.brands for w in b.lure_words] + ADDRESS_WORDS
        hit = _SEGMENTERS[id(reg)] = (reg, Segmenter(vocab))
    return hit[1]
