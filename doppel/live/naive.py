"""The naive baseline, run on the very same names: alert when a protected brand's name appears as a substring.

It's what a keyword alert (or a phishing_catcher-style substring list) does: every alias of every registry brand,
3+ letters, anywhere in the host. It flags ``sbi`` inside "lesbian" and "bills", Amazon cloud hosts with
"google" in them, and Google's own servers; it misses every look-alike that doesn't spell the brand
(``paytrn``, ``g00gle``, Cyrillic letters). Shown side by side with Doppel's queue on the Live Hunt screen.
"""

from __future__ import annotations

import re


class KeywordBaseline:
    def __init__(self, reg) -> None:
        words = sorted({a.lower() for b in reg.brands for a in (b.aliases or []) if len(a) >= 3}, key=len, reverse=True)
        self.words = words
        self._rx = re.compile("|".join(re.escape(w) for w in words)) if words else None

    def hit(self, name: str) -> str | None:
        """The keyword that fired, or None."""
        if self._rx is None:
            return None
        m = self._rx.search(name)
        return m.group(0) if m else None
