"""Runtime view of the glyph confusability matrix (``glyph_costs.json``, built by ``build_glyphs.py``).

``cost(a, b)`` is how noticeable it is to read ``a`` where ``b`` belongs: 0 = indistinguishable,
1 = obvious. The Trick Detector's alignment uses it, so Quick stays a table lookup (no rendering).
"""

from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from doppel.address.unicode_data import skeleton

GLYPH_FILE = Path(__file__).resolve().parent / "glyph_costs.json"

# Unmeasured fallbacks (characters no font of ours draws, or pairs below the kept threshold)
LISTED_CONFUSABLE = 0.3   # confusables.txt maps it to this letter, but we couldn't render it
SAME_BASE_LETTER = 0.75   # a letter with a diacritic, unmeasured
MEASURED_UNLIKE = 0.85    # measured below the kept similarity (0.25), but listed/related to the letter


@dataclass(frozen=True)
class Multi:
    fake: str
    real: str
    cost: float


class Glyphs:
    def __init__(self, data: dict) -> None:
        self.meta = {k: data[k] for k in ("render", "calibration", "built")}
        self._ascii = {k: 1 - v for k, v in data["ascii"].items()}
        self._uni = {ch: {t: 1 - s for t, s in row.items()} for ch, row in data["unicode"].items()}
        multi = [Multi(m["fake"], m["real"], m["cost"]) for m in data["multi"] if m["cost"] < 0.95]
        # Unicode characters that read as two ASCII letters (ǉ -> lj)
        multi += [Multi(ch, t, c) for ch, row in self._uni.items() for t, c in row.items() if len(t) == 2]
        self.multi = multi
        self.multi_by_first: dict[str, list[Multi]] = {}
        for m in multi:
            self.multi_by_first.setdefault(m.fake[0], []).append(m)
            if len(m.fake) == 1 or m.fake.isascii():  # reading direction doesn't matter for ASCII twins
                self.multi_by_first.setdefault(m.real[0], []).append(Multi(m.real, m.fake, m.cost))

    @lru_cache(maxsize=65536)
    def cost(self, a: str, b: str) -> float:
        """Visual substitution cost of reading candidate character ``a`` as genuine character ``b``."""
        if a == b:
            return 0.0
        if a.isascii() and b.isascii():
            key = a + b if a < b else b + a
            return round(self._ascii.get(key, 1.0), 3)
        if not a.isascii():
            row = self._uni.get(a)
            if row is not None and b in row:
                return round(row[b], 3)
            related = skeleton(a).lower() == b or unicodedata.normalize("NFD", a)[0] == b
            if row is not None:   # measured, and less alike than the kept threshold (cost > 0.75)
                return MEASURED_UNLIKE if related else 1.0
            if skeleton(a).lower() == b:
                return LISTED_CONFUSABLE
            if unicodedata.normalize("NFD", a)[0] == b:
                return SAME_BASE_LETTER
            return 1.0
        return 1.0  # genuine names are ASCII; a Unicode genuine character never occurs


@lru_cache(maxsize=None)
def load_glyphs(path: Path = GLYPH_FILE) -> Glyphs:
    if not path.exists():
        raise FileNotFoundError(f"{path} is missing; run `python -m doppel.perception.build_glyphs`")
    return Glyphs(json.loads(path.read_text(encoding="utf-8")))
