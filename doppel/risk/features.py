"""Host-only lexical features for the Risk Model (C8). Shared by training and inference, so they can't drift.

A bare new domain has no page, no path and no scheme, so the model sees only the host:

1. **Normalise:** lowercase, IDNA-decode, strip a leading ``www.`` (100% of PhiUSIIL's legitimate rows
   start ``https://www.``: keeping it would teach the model "has www = safe").
2. **Fold look-alike letters to ASCII** (``pаytm.com`` -> ``paytm.com``). PhiUSIIL has 0 legitimate IDNs,
   so raw punycode would look perfectly predictive: a dataset artifact, not a signal. Hidden letters are
   C3's job (Address Reader); the ML model judges the name as a person reads it.
3. **Character 3-5-grams** of ``<host>``, hashed into ``N_BUCKETS`` buckets with CRC-32 (stable across
   runs and machines, unlike Python's ``hash``), TF-IDF weighted (sublinear tf, smoothed idf) and
   L2-normalised, plus one ``tld=<tld>`` token (one-hot TLD; the logistic model learns its weight, which
   is target encoding without the fold leakage).
4. **Dense lexical statistics** (standardised at training time): length, labels, subdomain depth, digits,
   hyphens, entropy, vowels, runs, IP host.

Everything here is pure Python, so inference needs no numpy or scikit-learn.
"""

from __future__ import annotations

import math
import unicodedata
import zlib
from collections import Counter
from functools import lru_cache

from publicsuffixlist import PublicSuffixList

from doppel.address.reader import AddressError, extract_host, to_ascii_and_unicode
from doppel.address.unicode_data import skeleton

N_BUCKETS = 1 << 18
NGRAM = (3, 5)
VOWELS = set("aeiou")
DENSE = ["log_len", "labels", "sub_depth", "log_name_len", "digit_ratio", "hyphens", "entropy", "vowel_ratio",
         "digit_run", "consonant_run", "max_label_len", "is_ip"]
DENSE_TEXT = {      # (below the training average, above it): how an explanation reads
    "log_len": ("short host", "long host"), "labels": ("few labels", "many labels"),
    "sub_depth": ("no subdomains", "subdomains"), "log_name_len": ("short name", "long name"),
    "digit_ratio": ("few digits", "many digits"), "hyphens": ("no hyphens", "hyphens"),
    "entropy": ("few distinct letters", "many distinct letters"), "vowel_ratio": ("few vowels", "many vowels"),
    "digit_run": ("no digit runs", "a long digit run"), "consonant_run": ("short consonant runs", "a long consonant run"),
    "max_label_len": ("short labels", "a long label"), "is_ip": ("not an IP", "an IP address"),
}


@lru_cache(maxsize=None)
def _icann() -> PublicSuffixList:
    return PublicSuffixList(only_icann=True)


def fold(text: str) -> str:
    """Marks stripped, non-ASCII letters mapped through their UTS #39 prototype; ASCII left alone."""
    out = []
    for ch in unicodedata.normalize("NFD", text):
        if unicodedata.category(ch) == "Mn":
            continue
        out.append(ch if ch.isascii() else skeleton(ch).lower())
    return "".join(out)


def model_host(raw: str) -> str:
    """The string the model reads: host only, lowercase, Unicode folded to ASCII, no leading ``www.``.

    Raises ``AddressError`` when there is no usable host.
    """
    host = extract_host(raw)
    try:
        _, display = to_ascii_and_unicode(host)
    except AddressError:
        display = host.lower()
    h = fold(display.lower())
    while h.startswith("www.") and h.count(".") >= 2:
        h = h[4:]
    if not h:
        raise AddressError(f"no host in {raw!r}")
    return h


def registrable(host: str) -> str:
    """ICANN-level registrable domain (web.app for x.web.app): the grouping key for the splits."""
    return _icann().privatesuffix(host) or host


def _is_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _run(s: str, ok) -> int:
    best = cur = 0
    for ch in s:
        cur = cur + 1 if ok(ch) else 0
        best = max(best, cur)
    return best


def dense(host: str) -> list[float]:
    """Raw (unstandardised) dense features, in ``DENSE`` order."""
    ip = _is_ip(host)
    labels = host.split(".")
    reg = host if ip else registrable(host)
    name = reg.split(".", 1)[0]
    sub_depth = 0 if ip else max(0, len(labels) - reg.count(".") - 1)
    chars = host.replace(".", "")
    n = max(1, len(chars))
    letters = [c for c in chars if c.isalpha()]
    counts = Counter(chars)
    entropy = -sum(c / n * math.log2(c / n) for c in counts.values())
    return [
        math.log1p(len(host)),
        float(len(labels)),
        float(sub_depth),
        math.log1p(len(name)),
        sum(c.isdigit() for c in chars) / n,
        float(chars.count("-")),
        entropy,
        (sum(c in VOWELS for c in letters) / len(letters)) if letters else 0.0,
        float(_run(chars, str.isdigit)),
        float(_run(chars, lambda c: c.isalpha() and c not in VOWELS)),
        float(max(len(l) for l in labels)),
        1.0 if ip else 0.0,
    ]


def bucket(token: str) -> int:
    return zlib.crc32(token.encode("utf-8")) & (N_BUCKETS - 1)


def tokens(host: str) -> Counter:
    """Character 3-5-grams of ``<host>`` plus the ``tld=`` token, with counts."""
    s = f"<{host}>"
    c: Counter = Counter()
    lo, hi = NGRAM
    for n in range(lo, hi + 1):
        for i in range(len(s) - n + 1):
            c[s[i:i + n]] += 1
    c["tld=" + host.rsplit(".", 1)[-1]] += 1
    return c


def bucket_counts(host: str) -> dict[int, int]:
    """Token counts merged per hash bucket (colliding tokens share one bucket)."""
    acc: dict[int, int] = {}
    for tok, cnt in tokens(host).items():
        b = bucket(tok)
        acc[b] = acc.get(b, 0) + cnt
    return acc


def sparse(host: str, idf) -> dict[int, float]:
    """{bucket: tf-idf value} (sublinear tf, L2-normalised). ``idf`` is indexable by bucket."""
    vals = {b: (1.0 + math.log(c)) * idf[b] for b, c in bucket_counts(host).items()}
    norm = math.sqrt(sum(v * v for v in vals.values())) or 1.0
    return {b: v / norm for b, v in vals.items()}
