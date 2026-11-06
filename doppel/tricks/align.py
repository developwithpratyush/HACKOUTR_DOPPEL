"""Visual edit distance (C4): our own weighted alignment with multi-character edits.

Plain Levenshtein says ``paytrn`` is 2 edits from ``paytm``, the same as ``pazzm``. A reader
disagrees: ``rn`` looks like ``m``. This DP charges each edit what it costs **the eye**:

| edit | cost |
|---|---|
| substitute ``a`` for ``b`` | ``glyphs.cost(a, b)`` from the rendered glyph matrix (0 for a pixel-identical homoglyph) |
| multi-character twin (``rn`` for ``m``, ``ǉ`` for ``lj``) | its measured cost |
| insert / delete a letter | 1 |
| insert / delete a hyphen | ``HYPHEN`` (a hyphen is small, and people expect them in addresses) |
| repeat / drop a doubled letter (``paytmm``, ``echalan``) | ``REPEAT`` (doubles are hard to spot) |
| swap two neighbours (``hdfcbnak``) | ``TRANSPOSE`` (words are read as shapes) |

The four constants are **set by hand before any evaluation** (not tuned on the pairs dataset), from the
reading literature's simple point that doubled letters, hyphens and transpositions are less noticeable
than a wrong letter. Only the closeness *threshold* is tuned, on the ``dev`` split.

``align`` returns the total cost and the aligned edits in the contract ``edit`` shape, so the UI can
highlight exactly what was swapped. ``local=True`` aligns the whole genuine name against the best
matching *part* of the candidate (``paytrn`` inside ``paytrn-kyc-update``).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from doppel.address.unicode_data import skeleton
from doppel.perception.glyphs import Glyphs, load_glyphs

HYPHEN = 0.5
REPEAT = 0.6
TRANSPOSE = 0.6
INDEL = 1.0
TWIN_MAX = 0.55     # an ASCII substitution at or below this cost counts as "twin letters"

KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def _keyboard_neighbours() -> dict[str, set[str]]:
    pos = {ch: (r, c) for r, row in enumerate(KEYBOARD_ROWS) for c, ch in enumerate(row)}
    out: dict[str, set[str]] = {}
    for a, (ra, ca) in pos.items():
        out[a] = {b for b, (rb, cb) in pos.items() if b != a and abs(ra - rb) <= 1 and abs(ca - cb) <= 1}
    return out


KEYBOARD = _keyboard_neighbours()


def is_bitflip(a: str, b: str) -> bool:
    x = ord(a) ^ ord(b)
    return len(a) == len(b) == 1 and x != 0 and (x & (x - 1)) == 0


def codepoints(text: str) -> list[str]:
    return [f"U+{ord(ch):04X}" for ch in text]


@dataclass
class Alignment:
    candidate: str
    genuine: str
    cost: float
    edits: list[dict] = field(default_factory=list)
    span: tuple[int, int] = (0, 0)       # the aligned part of the candidate
    local: bool = False

    @property
    def similarity(self) -> float:
        """1 − cost / length: of the longer string (global), or of the genuine name (local)."""
        n = len(self.genuine) if self.local else max(len(self.candidate), len(self.genuine))
        return max(0.0, 1.0 - self.cost / n) if n else 0.0

    @property
    def coverage(self) -> float:
        """Share of the candidate the genuine name accounts for."""
        letters = sum(ch.isalnum() for ch in self.candidate) or 1
        return min(1.0, (self.span[1] - self.span[0]) / letters) if self.local else 1.0

    @property
    def kinds(self) -> set[str]:
        return {e["kind"] for e in self.edits}


def _sub_kind(a: str, b: str, cost: float) -> str:
    if not a.isascii():
        return "homoglyph"
    # the technique is "twin letters" when the eye can't tell them apart, or when Unicode lists them
    # as confusable (0/o): the cost still says how visible it is in our phone fonts
    if cost <= TWIN_MAX or skeleton(a).lower() == skeleton(b).lower():
        return "twin_letters"
    if b in KEYBOARD.get(a, ()):
        return "keyboard"
    if is_bitflip(a, b):
        return "bitflip"
    return "typo"


def align(candidate: str, genuine: str, glyphs: Glyphs | None = None, local: bool = False) -> Alignment:
    """Minimum visual-cost alignment of ``candidate`` to ``genuine`` (lowercase, Unicode allowed)."""
    g = glyphs or load_glyphs()
    c, t = candidate, genuine
    n, m = len(c), len(t)
    INF = float("inf")
    D = [[INF] * (m + 1) for _ in range(n + 1)]
    back: list[list[tuple | None]] = [[None] * (m + 1) for _ in range(n + 1)]
    D[0][0] = 0.0
    for i in range(1, n + 1):          # leading candidate characters: free when local, else inserts
        D[i][0] = 0.0 if local else D[i - 1][0] + _ins_cost(c, i - 1)
        back[i][0] = ("skip" if local else "insert", 1, 0, D[i][0] - D[i - 1][0])
    for j in range(1, m + 1):
        D[0][j] = D[0][j - 1] + _del_cost(t, j - 1)
        back[0][j] = ("delete", 0, 1, D[0][j] - D[0][j - 1])

    for i in range(n + 1):
        for j in range(m + 1):
            if i == 0 and j == 0:
                continue
            best, how = D[i][j], back[i][j]

            def consider(cost: float, step: tuple) -> None:
                nonlocal best, how
                if cost < best - 1e-12:
                    best, how = cost, step

            if i and j:
                sc = g.cost(c[i - 1], t[j - 1])
                consider(D[i - 1][j - 1] + sc, ("match" if sc == 0 and c[i - 1] == t[j - 1] else "substitute",
                                                1, 1, sc))
            if i and j:
                ic = _ins_cost(c, i - 1)
                consider(D[i - 1][j] + ic, ("insert", 1, 0, ic))
            if j:
                dc = _del_cost(t, j - 1)
                consider(D[i][j - 1] + dc, ("delete", 0, 1, dc))
            if i >= 2 and j >= 2 and c[i - 2] == t[j - 1] and c[i - 1] == t[j - 2] and c[i - 1] != c[i - 2]:
                consider(D[i - 2][j - 2] + TRANSPOSE, ("transpose", 2, 2, TRANSPOSE))
            # multi-character twins ending here: candidate c[i-k:i] reads as genuine t[j-l:j]
            for k in (1, 2):
                if i < k:
                    continue
                for mt in g.multi_by_first.get(c[i - k], ()):
                    l = len(mt.real)
                    if len(mt.fake) == k and j >= l and c[i - k:i] == mt.fake and t[j - l:j] == mt.real:
                        consider(D[i - k][j - l] + mt.cost, ("multi", k, l, mt.cost))
            D[i][j], back[i][j] = best, how

    end = n
    if local:
        end = min(range(n + 1), key=lambda i: (D[i][m], -i))
    edits, i, j = [], end, m
    while i > 0 or j > 0:
        op, k, l, cost = back[i][j]
        if op == "skip":
            break
        ci, gj = c[i - k:i], t[j - l:j]
        if op not in ("match",) and cost >= 0:
            edits.append(_edit(op, ci, gj, i - k, i, j - l, j, cost))
        i, j = i - k, j - l
    start = i
    edits.reverse()
    return Alignment(candidate, genuine, round(D[end][m], 4), [e for e in edits if e], (start, end), local)


def _ins_cost(c: str, i: int) -> float:
    ch = c[i]
    if ch == "-":
        return HYPHEN
    if (i > 0 and c[i - 1] == ch) or (i + 1 < len(c) and c[i + 1] == ch):
        return REPEAT
    return INDEL


def _del_cost(t: str, j: int) -> float:
    ch = t[j]
    if ch == "-":
        return HYPHEN
    if (j > 0 and t[j - 1] == ch) or (j + 1 < len(t) and t[j + 1] == ch):
        return REPEAT
    return INDEL


def _edit(op: str, cand: str, gen: str, cs: int, ce: int, gs: int, ge: int, cost: float) -> dict | None:
    if op == "substitute":
        kind = _sub_kind(cand, gen, cost)
    elif op == "multi":
        op = "substitute"
        kind = "homoglyph" if not cand.isascii() else "twin_letters"
    elif op in ("insert", "delete"):
        kind = "hyphen" if (cand or gen) == "-" else "typo"
    else:  # transpose
        kind = "typo"
    e = {"op": op, "candidate": cand, "genuine": gen, "candidate_span": [cs, ce], "genuine_span": [gs, ge],
         "cost": round(min(1.0, cost), 3), "kind": kind}
    if not cand.isascii():
        e["codepoints"] = codepoints(cand)
    return e
