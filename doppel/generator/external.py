"""Wrappers around dnstwist (Apache-2.0) and ail-typo-squatting (BSD-2-Clause), imported, not vendored.

Their fuzzer names are mapped onto our technique codes. dnstwist's ``homoglyph`` fuzzer
mixes ASCII look-alikes (rn for m) with Unicode ones, so the code is decided per candidate:
ASCII -> T2 (twin letters), non-ASCII -> T3 (homoglyph).
"""

from __future__ import annotations

from collections.abc import Iterator

import ail_typo_squatting as ail
import dnstwist

Gen = Iterator[tuple[str, str, str]]

DNSTWIST_MAP = {
    "addition": "T1", "insertion": "T1", "omission": "T1", "repetition": "T1", "replacement": "T1",
    "transposition": "T1", "vowel-swap": "T1", "hyphenation": "T1",
    "bitsquatting": "T13",
    "homoglyph": None, "cyrillic": "T3",   # None: decided per candidate
}


def dnstwist_variants(domain: str) -> Gen:
    fuzzer = dnstwist.Fuzzer(domain)
    fuzzer.generate()
    for d in fuzzer.domains:
        name = d["fuzzer"]
        if name not in DNSTWIST_MAP:
            continue  # *original, subdomain, various, dictionary, tld-swap: covered by our own generators
        cand = d["domain"]
        try:
            unicode_cand = cand.encode("ascii").decode("idna") if "xn--" in cand else cand
        except UnicodeError:
            continue
        technique = DNSTWIST_MAP[name] or ("T2" if unicode_cand.isascii() else "T3")
        yield unicode_cand, technique, f"dnstwist:{name}"


def ail_variants(domain: str, limit: int = 500) -> Gen:
    for cand in ail.addDash(domain, [], False, limit):
        if cand != domain:
            yield cand, "T1", "ail:addDash"
