"""Naming templates, learned from the names themselves (no per-campaign regex).

Every label of the host (the public suffix excepted) is cut at hyphens, and each part becomes:

- ``<B>``  a protected brand's alias (also glued: ``indiapostnm`` -> ``<B><r>``)
- ``<n>``  digits
- a literal word, when it is a real word (the segmenter's vocabulary: English + our lure words), or a short
  affix of 1-3 letters, folded for look-alike letters (``ln`` -> ``in``, ``0`` -> ``o``)
- ``<r>``  anything else (random-looking: ``atxxycp``, ``kx72``)

and the public suffix becomes ``<tld>`` (kept apart, so a campaign that rotates endings still matches).

    in-echallan.online, ln-echallan.bid        -> in-<B>.<tld>
    indiapost.gov.atxxycp.top                  -> <B>.gov.<r>.<tld>

**Specific enough to link** only when the brand is spelled out (``<B>``) and the template carries a literal token
that isn't URL filler (``in``, ``gov``, ``verify``; not ``com``/``www``), or has 4+ labels. ``<B>.<tld>`` or
``<B>-<r>.<tld>`` would join strangers who merely share a brand; ``mail.<tld>`` (a typo of gmail registered in many
endings) has no brand at all; ``<r><B>-com`` is email-shaped names of different people.
"""

from __future__ import annotations

import re
from functools import lru_cache

from doppel.address import address_reader

FOLD = str.maketrans({"l": "i", "1": "i", "0": "o", "5": "s", "3": "e"})
PLACEHOLDER = re.compile(r"<[A-Za-z]+>")
FILLER = {"com", "net", "org", "www", "at", "co"}     # URL filler: in an email-shaped name it means nothing


class Templater:
    def __init__(self, reg, seg=None) -> None:
        from doppel.tricks.segment import segmenter

        self.seg = seg or segmenter(reg)
        self.aliases = sorted({a.lower() for b in reg.brands for a in b.aliases if len(a) >= 3}, key=len, reverse=True)
        self.alias_brand = {a.lower(): b.id for b in reg.brands for a in b.aliases}

    def _part(self, part: str, glued: bool = False) -> str:
        if not part:
            return ""
        if part.isdigit():
            return "<n>"
        if part in self.alias_brand:
            return "<B>"
        for a in self.aliases:                       # a brand glued to something: <B> + the rest, abstracted
            if a in part:
                i = part.index(a)
                return self._part(part[:i], True) + "<B>" + self._part(part[i + len(a):], True)
        if len(part) <= 3 and part.isalpha():          # a short affix: a literal on its own (in-, ln-), noise glued
            return "<r>" if glued and not self.seg.known(part) else part.translate(FOLD)
        if not part.isascii():
            return "<r>"
        words = [w for w in self.seg.split(part) if w]
        if words and all(w.isdigit() or self.seg.known(w) for w in words):
            return "".join("<n>" if w.isdigit() else w for w in words)
        out = "".join("<n>" if w.isdigit() else "<r>" for w in words) or "<r>"
        return re.sub(r"(?:<[rn]>){3,}", "<r>", re.sub(r"(<r>)+", "<r>", out))   # a long random run is one <r>

    @lru_cache(maxsize=100_000)
    def of(self, host: str) -> tuple[str, str]:
        """(template, public suffix)."""
        r, _ = address_reader(host)
        suffix = r.public_suffix or ""
        rest = r.host[: -len(suffix) - 1] if suffix and r.host.endswith("." + suffix) else r.host
        labels = [l for l in rest.split(".") if l]
        if labels and labels[0] == "www":
            labels = labels[1:]
        out = [re.sub(r"(<r>)+", "<r>", "-".join(self._part(p) for p in label.split("-"))) for label in labels]
        return ".".join(out + ["<tld>"]), suffix

    @staticmethod
    def specific(template: str) -> bool:
        """The brand spelled out (``<B>``), plus a literal token that isn't URL filler, or 4+ labels."""
        if "<B>" not in template:          # typos of a word (speedtest.*, mail.*) across endings aren't one operator
            return False
        parts = [x for x in re.split(r"[.\-]", PLACEHOLDER.sub(" ", template)) for x in x.split()]
        literal = "".join(x for x in parts if x not in FILLER)
        return len(literal) >= 2 or template.count(".") >= 3
