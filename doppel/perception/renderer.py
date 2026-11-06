"""Human-Eye Renderer (Stage 2, Standard): would a person reading the SMS notice the difference?

The victim decides in the message (SMS, WhatsApp, a notification), not in the address bar: browsers
show mixed-script names as punycode and keep the real owner visible, messages don't. So we render the
link the way a phone draws message text (Roboto / Noto Sans, 16 px) next to the genuine address and
measure how alike they look (SSIM). The output is one evidence item plus a PNG: both renders and the
SSIM difference map (dark = where they differ), for the Decision Trace Explorer.

Findings (C7):
  sms_view_identical       SSIM >= 0.99: pixel-identical (a Cyrillic letter in paytm)
  sms_view_near_identical  the visual edit distance is small (closeness >= 0.9): a reader wouldn't notice
  sms_view_prefix_match    the link *starts* with the genuine address (level-squat): readers check the start
  sms_view_brand_prominent the brand name leads the link (combosquat): reads as an official address
  sms_view_distinct        a reader can see it isn't the genuine address
"""

from __future__ import annotations

import time
from pathlib import Path

import idna
import numpy as np
from PIL import Image, ImageDraw

from doppel.contract import REPO_ROOT
from doppel.evidence import Ids, brand_ref, evidence
from doppel.perception import render
from doppel.tricks.align import align

TOOL, STAGE = "human_eye_renderer", "standard"
RENDER_DIR = REPO_ROOT / "runs" / "renders"
IDENTICAL, NEAR = 0.99, 0.9


def _sms_ssim(candidate: str, genuine: str) -> tuple[float, np.ndarray | None]:
    """SSIM of the two strings as message text, averaged over the fonts drawing both, plus the map."""
    names = render.fonts_drawing(candidate + genuine)
    if not names:
        return 0.0, None
    scores, maps = [], []
    for n in names:
        s, smap = render.ssim_pair(candidate, genuine, n, full=True)
        scores.append(s)
        maps.append(smap)
    h = min(m.shape[0] for m in maps)
    w = min(m.shape[1] for m in maps)
    return float(np.mean(scores)), np.mean([m[:h, :w] for m in maps], axis=0)


def _save_png(candidate: str, genuine: str, smap: np.ndarray | None, path: Path) -> None:
    """Two message bubbles (candidate on top) and the SSIM difference strip, at 2x for a sharp display."""
    name = render.fonts_drawing(candidate + genuine)[0] if render.fonts_drawing(candidate + genuine) else "Noto Sans"
    big = 32
    f = render.font(name, big)
    width = int(max(f.getlength(candidate), f.getlength(genuine))) + 48
    strip = 0 if smap is None else 70
    img = Image.new("RGB", (width, 2 * 62 + strip + 20), "#fcfcfb")
    d = ImageDraw.Draw(img)
    for i, (text, label) in enumerate(((candidate, "link in the message"), (genuine, "genuine address"))):
        y = 10 + i * 62
        d.rounded_rectangle((8, y, width - 8, y + 52), radius=16, fill="#e9eef6")
        d.text((24, y + 36), text, font=f, fill="#0b0b0b", anchor="ls")
        d.text((width - 14, y + 50), label, font=render.font(name, 11), fill="#52514e", anchor="rs")
    if smap is not None:
        diff = np.clip(1 - smap, 0, 1)                       # 0 = same, 1 = different
        heat = Image.fromarray((255 - diff * 255).astype(np.uint8)).resize((width - 16, strip - 10), Image.NEAREST)
        img.paste(Image.merge("RGB", (heat, heat, heat)), (8, 2 * 62 + 14))
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path)


def human_eye_renderer(candidate: str, genuine: str, brand=None, ids: Ids | None = None,
                       closeness: float | None = None, brand_token: str | None = None,
                       out_dir: Path | None = RENDER_DIR, ascii_host: str | None = None) -> tuple[dict, list[dict]]:
    """Stage-2 tool. ``candidate`` is the Unicode display form; ``genuine`` the family address it imitates.

    Returns ({ssim, visual_edit_distance, view}, [evidence]). Pass ``out_dir=None`` to skip the PNG.
    """
    ids = ids or Ids()
    t0 = time.perf_counter()
    cand, gen = candidate.lower(), genuine.lower()
    b = brand_ref(brand)
    prefix = len(gen) if cand.startswith(gen + ".") or cand.startswith(gen + "-") else 0
    view = cand[: len(gen)] if prefix else cand
    s, smap = _sms_ssim(view, gen)
    a = align(cand, gen)
    ved = round(a.cost / max(len(cand), len(gen)), 3)
    close = closeness if closeness is not None else a.similarity
    artifacts = []
    if out_dir is not None:
        if ascii_host is None:
            try:
                ascii_host = idna.encode(cand, uts46=True).decode("ascii")
            except (idna.IDNAError, UnicodeError):
                ascii_host = cand.encode("ascii", "backslashreplace").decode("ascii")
        path = Path(out_dir) / f"{ascii_host.replace('/', '_').replace(chr(92), '_')}_sms.png"
        _save_png(cand, gen, smap, path)
        rel = path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path
        artifacts = [{"kind": "render", "path": str(rel).replace("\\", "/"), "caption": "SMS view, candidate vs genuine"}]
    common = {"tool": TOOL, "stage": STAGE, "criterion": "C7", "target_brand": b, "artifacts": artifacts}

    if prefix:
        item = evidence(ids, **common, finding="sms_view_prefix_match", points_to="phishing", strength="medium",
                        score=0.9, summary=(f"In the message, the first {prefix} characters are the genuine "
                                            f"'{gen}'; a reader who checks the start is fooled."),
                        matching_prefix_chars=prefix, ssim=round(s, 3))
    elif s >= IDENTICAL:
        item = evidence(ids, **common, finding="sms_view_identical", points_to="phishing", strength="medium",
                        score=0.98, summary=f"Rendered as message text, it is pixel-identical to {gen} (SSIM {s:.2f}).",
                        ssim=round(s, 3), visual_edit_distance=ved)
    elif close >= NEAR:
        item = evidence(ids, **common, finding="sms_view_near_identical", points_to="phishing", strength="medium",
                        score=round(close, 3),
                        summary=(f"As message text it reads as {gen}: visual closeness {close:.2f}, SSIM {s:.2f}; "
                                 "a reader would not notice."),
                        ssim=round(s, 3), visual_edit_distance=ved)
    elif brand_token and cand.startswith(brand_token):
        item = evidence(ids, **common, finding="sms_view_brand_prominent", points_to="phishing", strength="medium",
                        score=0.5, summary=f"In the message, '{brand_token}' leads the link, so it reads as an official address.",
                        visual_edit_distance=ved, ssim=round(s, 3))
    else:
        item = evidence(ids, **common, finding="sms_view_distinct", points_to="genuine", strength="medium",
                        score=round(1 - close, 3),
                        summary=f"A reader can see it isn't {gen} (visual closeness {close:.2f}, SSIM {s:.2f}).",
                        visual_edit_distance=ved, ssim=round(s, 3))
    item["duration_ms"] = round((time.perf_counter() - t0) * 1000, 3)
    return {"ssim": round(s, 3), "visual_edit_distance": ved, "prefix": prefix}, [item]
