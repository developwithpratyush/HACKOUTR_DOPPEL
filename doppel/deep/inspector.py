"""Page Inspector (Stage 3, Deep; C10 visual copy, C11 code changes).

**C10: does it copy a genuine page?** The suspect page and every genuine reference are rendered in the same
sandbox (``sandbox.py``) at 1280x800. Similarity is **content-masked SSIM**: the SSIM map averaged only where
either page has something drawn (local contrast), because plain SSIM calls any two mostly-white pages alike
(measured: an ordinary blog vs Google's sign-in page scores 0.915 plain, 0.164 masked). Measured on our set:
unrelated genuine pages <= 0.151 (28 pairs), non-clone pages <= 0.183, clones >= 0.592, so the match
threshold is 0.40. pHash distance and plain SSIM are kept in the details. The **heatmap** marks where the
suspect differs from the genuine page: exactly the regions a kit edited.

**C11: what did they change?** Both rendered DOMs: tag-sequence similarity, form targets (and whether each
target is inside the brand's family), visible sensitive fields added, external scripts and iframes added.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from difflib import SequenceMatcher
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from doppel.contract import REPO_ROOT
from doppel.deep import fields as FLD
from doppel.deep.pages import references
from doppel.deep.sandbox import RUNS, Render, Sandbox
from doppel.evidence import Ids, evidence

TOOL, STAGE = "page_inspector", "deep"
VISUAL_MATCH = 0.40          # content-masked SSIM; see the module docstring for how it was set
STRUCTURE_SAME = 0.50        # tag-sequence similarity above which "same page, changed parts" applies
CMP_SIZE = (640, 400)
CONTENT_STD = 6.0            # local grey-level std that counts as "something drawn"
DIFF_CUT = 0.35              # 1 - local SSIM above this marks a changed pixel


@dataclass
class Visual:
    brand: str
    masked_ssim: float
    ssim: float
    phash_distance: int
    changed_share: float
    regions: list[dict]
    heatmap: str | None = None


def _grey(path: str):
    import numpy as np
    from PIL import Image

    return np.asarray(Image.open(REPO_ROOT / path).convert("L").resize(CMP_SIZE), dtype=np.float64)


def _local_std(x, k=7):
    import numpy as np
    from scipy.ndimage import uniform_filter

    m = uniform_filter(x, k)
    return np.sqrt(np.maximum(uniform_filter(x * x, k) - m * m, 0))


def compare(suspect: Render, ref: Render, brand: str, heatmap_to: Path | None = None) -> Visual:
    import imagehash
    import numpy as np
    from PIL import Image
    from scipy.ndimage import gaussian_filter, label
    from skimage.metrics import structural_similarity

    a, b = _grey(suspect.desktop), _grey(ref.desktop)
    plain, smap = structural_similarity(a, b, data_range=255, full=True)
    mask = (_local_std(a) > CONTENT_STD) | (_local_std(b) > CONTENT_STD)
    masked = float(smap[mask].mean()) if mask.any() else 1.0
    diff = gaussian_filter(np.clip(1 - smap, 0, 1), 2) * mask
    changed = diff > DIFF_CUT
    lab, n = label(changed)
    sx = 1280 / CMP_SIZE[0]
    regions = []
    for i in range(1, n + 1):
        ys, xs = np.nonzero(lab == i)
        if len(xs) < 0.002 * changed.size:
            continue
        regions.append({"x": int(xs.min() * sx), "y": int(ys.min() * sx), "w": int((xs.max() - xs.min() + 1) * sx),
                        "h": int((ys.max() - ys.min() + 1) * sx), "share": round(len(xs) / changed.size, 4)})
    regions.sort(key=lambda r: -r["share"])
    ph = imagehash.phash(Image.open(REPO_ROOT / suspect.desktop)) - imagehash.phash(Image.open(REPO_ROOT / ref.desktop))
    v = Visual(brand, round(masked, 4), round(float(plain), 4), int(ph), round(float(changed.mean()), 4), regions[:6])
    if heatmap_to is not None:
        v.heatmap = _heatmap(suspect, diff, regions[:6], heatmap_to)
    return v


def _heatmap(suspect: Render, diff, regions, out: Path) -> str:
    import numpy as np
    from PIL import Image, ImageDraw

    base = Image.open(REPO_ROOT / suspect.desktop).convert("RGB")
    heat = Image.fromarray((np.clip(diff / max(DIFF_CUT * 2, 1e-6), 0, 1) * 255).astype("uint8")).resize(base.size)
    red = Image.new("RGB", base.size, (225, 29, 72))
    alpha = heat.point(lambda v: int(v * 0.7))
    shaded = Image.blend(base, Image.new("RGB", base.size, (255, 255, 255)), 0.35)
    shaded.paste(red, (0, 0), alpha)
    d = ImageDraw.Draw(shaded)
    for r in regions:
        d.rectangle([r["x"], r["y"], r["x"] + r["w"], r["y"] + r["h"]], outline=(225, 29, 72), width=3)
    out.parent.mkdir(parents=True, exist_ok=True)
    shaded.save(out)
    return out.relative_to(REPO_ROOT).as_posix()


# ------------------------------------------------------------------ DOM ---

class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


def structure_similarity(a: str, b: str, cap: int = 4000) -> float:
    pa, pb = _Tags(), _Tags()
    pa.feed(a)
    pb.feed(b)
    return round(SequenceMatcher(None, pa.tags[:cap], pb.tags[:cap], autojunk=False).ratio(), 4)


def _host(url: str | None) -> str | None:
    return urlsplit(url).hostname if url else None


def _ext_hosts(urls: list[str], own: set[str]) -> set[str]:
    return {h for u in urls if (h := _host(u)) and h not in own}


@dataclass
class DomDiff:
    structure: float
    genuine_actions: list[str]
    suspect_actions: list[str]
    foreign_actions: list[str]     # suspect form targets outside the brand's family
    added_fields: list[str]
    added_script_hosts: list[str]
    added_iframes: int


def dom_diff(suspect: Render, ref: Render, in_family) -> DomDiff:
    s_act = sorted({f["action"] for f in suspect.forms if f["action"]})
    g_act = sorted({f["action"] for f in ref.forms if f["action"]})
    foreign = [a for a in s_act if (h := _host(a)) and not in_family(h)]
    added = [f for f in FLD.asks_for(suspect.inputs) if f not in FLD.asks_for(ref.inputs)]
    own = {suspect.host, ref.host}
    return DomDiff(structure_similarity(suspect.dom(), ref.dom()), g_act, s_act, foreign, added,
                   sorted(_ext_hosts(suspect.scripts, own) - _ext_hosts(ref.scripts, own)),
                   max(0, len(suspect.iframes) - len(ref.iframes)))


# ------------------------------------------------------------------ the tool ---

def page_inspector(suspect: Render, sb: Sandbox, target_brand, genuine: bool, in_family_of, brand_of,
                   ids: Ids | None = None) -> tuple[dict, list[dict]]:
    """Evidence for C10 (+ C11 when the page copies a genuine one).

    ``target_brand``: the brand from the name evidence (or None); ``in_family_of(brand_id, host)`` and
    ``brand_of(brand_id)`` come from the registry. Compares with every genuine reference and keeps the best."""
    t0 = time.perf_counter()
    ids = ids or Ids()
    refs = {b: sb.render_reference(b) for b in references()}
    refs = {b: r for b, r in refs.items() if r is not None}
    if not refs:
        item = evidence(ids, tool=TOOL, stage=STAGE, criterion="C10", finding="no_genuine_snapshot",
                        points_to="neutral", strength="medium", score=0,
                        summary="No genuine snapshots on this machine (run scripts/data/snapshot_genuine.py), so there's nothing to compare with.",
                        duration_ms=(time.perf_counter() - t0) * 1000)
        return {"best": None}, [item]
    scores = {b: compare(suspect, r, b) for b, r in refs.items()}
    best = max(scores.values(), key=lambda v: v.masked_ssim)
    target_id = target_brand.id if target_brand is not None else None
    chosen = best if best.masked_ssim >= VISUAL_MATCH or target_id not in scores else scores[target_id]
    stem = "".join(c if c.isalnum() or c in ".-_" else "_" for c in suspect.host)
    chosen = compare(suspect, refs[chosen.brand], chosen.brand, heatmap_to=RUNS / f"{stem}_heatmap.png")
    brand = brand_of(chosen.brand)
    ref_ref = {"id": brand.id, "name": brand.name}
    ranking = sorted(({"brand": b, "masked_ssim": v.masked_ssim} for b, v in scores.items()),
                     key=lambda r: -r["masked_ssim"])[:4]
    visual = {"masked_ssim": chosen.masked_ssim, "ssim": chosen.ssim, "phash_distance": chosen.phash_distance,
              "changed_share": chosen.changed_share, "regions": chosen.regions, "compared_with": refs[chosen.brand].url,
              "ranking": ranking, "threshold": VISUAL_MATCH,
              "artifacts": [{"kind": "heatmap", "path": chosen.heatmap,
                             "caption": f"Where this page differs from the genuine {brand.name} page"},
                            {"kind": "screenshot", "path": suspect.desktop, "caption": "Suspect page (sandbox render)"},
                            {"kind": "screenshot", "path": refs[chosen.brand].desktop,
                             "caption": f"Genuine {brand.name} page (saved snapshot, same sandbox)"}]}
    pct = f"{chosen.masked_ssim:.0%}"
    items = []
    ms = (time.perf_counter() - t0) * 1000
    if chosen.masked_ssim >= VISUAL_MATCH and genuine:
        items.append(evidence(ids, tool=TOOL, stage=STAGE, criterion="C10", finding="matches_genuine_snapshot",
                              points_to="genuine", strength="medium", score=chosen.masked_ssim, target_brand=ref_ref,
                              summary=f"Matches the saved genuine {brand.name} page at {pct}.", duration_ms=ms, **visual))
    elif chosen.masked_ssim >= VISUAL_MATCH:
        where = f"; {len(chosen.regions)} region(s) differ" if chosen.regions else "; nothing visibly changed"
        items.append(evidence(ids, tool=TOOL, stage=STAGE, criterion="C10", finding="visual_match",
                              points_to="phishing", strength="medium", score=chosen.masked_ssim, target_brand=ref_ref,
                              summary=f"Screenshot matches the saved genuine {brand.name} page at {pct}{where}.",
                              duration_ms=ms, **visual))
    else:
        items.append(evidence(ids, tool=TOOL, stage=STAGE, criterion="C10", finding="visual_mismatch",
                              points_to="genuine", strength="weak", score=round(1 - chosen.masked_ssim, 4),
                              target_brand=ref_ref,
                              summary=f"Doesn't copy any saved genuine page (closest: {brand.name} at {pct}).",
                              duration_ms=ms, **visual))
        return {"best": chosen, "diff": None}, items

    # C11: same page, what changed?
    diff = dom_diff(suspect, refs[chosen.brand], lambda h: in_family_of(chosen.brand, h))
    common = {"structure_similarity": diff.structure, "genuine_actions": diff.genuine_actions,
              "suspect_actions": diff.suspect_actions, "added_script_hosts": diff.added_script_hosts,
              "added_iframes": diff.added_iframes}
    if diff.foreign_actions and not genuine:
        hosts = ", ".join(sorted({_host(a) for a in diff.foreign_actions}))
        items.append(evidence(ids, tool=TOOL, stage=STAGE, criterion="C11", finding="form_target_changed",
                              points_to="phishing", strength="medium", score=max(0.6, min(0.95, diff.structure)),
                              target_brand=ref_ref, suspect_action=diff.foreign_actions[0],
                              genuine_action=diff.genuine_actions[0] if diff.genuine_actions else None,
                              summary=f"Same layout as {brand.name}'s page, but its form now posts to {hosts}, outside {brand.name}'s family.",
                              **common))
    if diff.added_fields and not genuine:
        items.append(evidence(ids, tool=TOOL, stage=STAGE, criterion="C11", finding="fields_added",
                              points_to="phishing", strength="medium", score=0.85, target_brand=ref_ref,
                              added_inputs=diff.added_fields,
                              summary=f"Fields the genuine {brand.name} page doesn't have were added: {', '.join(f.replace('_', ' ') for f in diff.added_fields)}.",
                              **common))
    return {"best": chosen, "diff": diff}, items
