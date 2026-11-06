"""Render text the way a phone shows it, and measure how alike two renders look (SSIM).

Shared by the offline glyph-matrix builder (``build_glyphs.py``) and the runtime
Human-Eye Renderer (``renderer.py``).

Fonts: Roboto (Android's system font) and Noto Sans (Android's fallback for Latin, Greek
and Cyrillic), both SIL OFL 1.1, vendored in ``doppel/perception/fonts/`` by
``scripts/data/fetch.py``. Font-dependent by nature: we fix these two fonts and say so.

Settings (chosen in P4 against an external ground truth, confusable-vision's verdicts; see
docs/eval/p4-arena.md): 16 px text (SMS body size), the candidate stretched to the genuine
string's width (a reader doesn't notice that ``rn`` is a little wider than ``m``), a Gaussian blur
of 1 px, SSIM with a 7×7 window, averaged over the fonts that draw both strings.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

FONT_DIR = Path(__file__).resolve().parent / "fonts"
FONT_FILES = {"Roboto": "Roboto.ttf", "Noto Sans": "NotoSans.ttf"}

SIZE = 16
BLUR = 1.0
WIN = 7


@lru_cache(maxsize=None)
def font_path(name: str) -> Path:
    path = FONT_DIR / FONT_FILES[name]
    if not path.exists():
        raise FileNotFoundError(f"{path} is missing; run `python scripts/data/fetch.py --only font_roboto font_noto_sans`")
    return path


@lru_cache(maxsize=None)
def font(name: str, size: int = SIZE) -> ImageFont.FreeTypeFont:
    f = ImageFont.truetype(str(font_path(name)), size)
    f.set_variation_by_name("Regular")
    return f


@lru_cache(maxsize=None)
def cmap(name: str) -> frozenset[int]:
    from fontTools.ttLib import TTFont  # only needed to know which characters a font draws

    return frozenset(TTFont(str(font_path(name))).getBestCmap())


def fonts_drawing(text: str) -> list[str]:
    """The fonts that have a glyph for every character of ``text``."""
    return [n for n in FONT_FILES if all(ord(ch) in cmap(n) for ch in text)]


def render(text: str, name: str, size: int = SIZE, width: int | None = None) -> Image.Image:
    """White-on-black render on a fixed baseline; optionally stretched to ``width`` pixels."""
    f = font(name, size)
    height, baseline = int(size * 1.6), int(size * 1.15)
    w = max(1, int(np.ceil(f.getlength(text)))) + 2
    img = Image.new("L", (w, height), 0)
    ImageDraw.Draw(img).text((1, baseline), text, font=f, fill=255, anchor="ls")
    if width and width != img.width:
        img = img.resize((width, height), Image.LANCZOS)
    return img


def _pad_pair(a: Image.Image, b: Image.Image) -> tuple[np.ndarray, np.ndarray]:
    w = max(a.width, b.width) + 6
    ca, cb = Image.new("L", (w, a.height)), Image.new("L", (w, b.height))
    ca.paste(a, ((w - a.width) // 2, 0))
    cb.paste(b, ((w - b.width) // 2, 0))
    if BLUR:
        ca, cb = ca.filter(ImageFilter.GaussianBlur(BLUR)), cb.filter(ImageFilter.GaussianBlur(BLUR))
    return np.asarray(ca, dtype=float) / 255, np.asarray(cb, dtype=float) / 255


def ssim_pair(candidate: str, genuine: str, name: str, size: int | None = None, full: bool = False):
    """SSIM between the candidate (stretched to the genuine width) and the genuine string, in one font."""
    from skimage.metrics import structural_similarity

    size = size or SIZE
    g = render(genuine, name, size)
    c = render(candidate, name, size, width=g.width)
    A, B = _pad_pair(c, g)
    return structural_similarity(A, B, data_range=1.0, win_size=WIN, full=full)


def visual_ssim(candidate: str, genuine: str, size: int | None = None) -> tuple[float | None, list[str]]:
    """Mean SSIM over the fonts that draw both strings, and those fonts (None if no font draws both)."""
    names = fonts_drawing(candidate + genuine)
    if not names:
        return None, []
    return float(np.mean([ssim_pair(candidate, genuine, n, size) for n in names])), names
