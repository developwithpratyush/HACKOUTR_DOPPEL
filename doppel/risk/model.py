"""Risk Model (C8) inference: ``predict(domain) -> probability`` and the ``risk_model`` evidence item.

The model is a logistic regression over host-only features (``features.py``) with isotonic calibration,
trained on leakage-audited PhiUSIIL by ``python -m doppel.risk.train``. Inference is pure Python: the
weights live in ``model/risk_model.json`` (dense part, calibration, metadata) and ``model/ngram.f32.gz``
(idf + weight per hashed n-gram bucket), so the brain doesn't need numpy or scikit-learn.

**What the probability means.** It's calibrated on PhiUSIIL's held-out split, whose phishing share is
the model's ``base_rate`` (~38%), and PhiUSIIL's legitimate rows are popular homepages. On new domains the
number is a *supporting* signal only: it says "looks like the phishing hosts in that dataset", not "is a
look-alike of a brand". It's blind to look-alikes by design (``paytrn.com`` reads as an ordinary short
.com), which is why it's ``weak`` evidence and never decides a verdict (see docs/eval/p7-risk-model.md).
"""

from __future__ import annotations

import array
import bisect
import gzip
import json
import math
import sys
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from doppel.evidence import Ids, evidence
from doppel.risk import features as F

MODEL_DIR = Path(__file__).resolve().parent / "model"
META_FILE = MODEL_DIR / "risk_model.json"
NGRAM_FILE = MODEL_DIR / "ngram.f32.gz"
TOOL, STAGE, CRITERION = "risk_model", "standard", "C8"
NEUTRAL_BAND = 0.1          # |p - 0.5| below this: the model has no opinion


@dataclass(frozen=True)
class Prediction:
    host: str               # what the model read
    probability: float      # calibrated (PhiUSIIL base rate)
    raw: float              # uncalibrated logistic output
    logit: float
    top: list[dict]         # biggest contributions: {feature, kind, contribution}


class RiskModel:
    def __init__(self, meta: dict, idf: array.array, weights: array.array) -> None:
        self.meta = meta
        self.idf = idf
        self.w = weights
        d = meta["dense"]
        self.d_mean, self.d_std, self.d_w = d["mean"], d["std"], d["weights"]
        self.b = meta["intercept"]
        self.iso_x, self.iso_y = meta["calibration"]["x"], meta["calibration"]["y"]

    @classmethod
    def load(cls, meta_file: Path = META_FILE, ngram_file: Path = NGRAM_FILE) -> "RiskModel":
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        n = meta["n_buckets"]
        raw = gzip.decompress(ngram_file.read_bytes())
        both = array.array("f")
        both.frombytes(raw)
        if sys.byteorder != "little":
            both.byteswap()
        if len(both) != 2 * n:
            raise ValueError(f"{ngram_file}: expected {2 * n} floats, got {len(both)}")
        return cls(meta, both[:n], both[n:])

    @property
    def version(self) -> str:
        return self.meta["version"]

    @property
    def base_rate(self) -> float:
        return self.meta["base_rate"]

    def calibrate(self, raw: float) -> float:
        """Isotonic map (``np.interp`` with clipping, as scikit-learn does)."""
        xs, ys = self.iso_x, self.iso_y
        if raw <= xs[0]:
            return ys[0]
        if raw >= xs[-1]:
            return ys[-1]
        i = bisect.bisect_right(xs, raw)
        x0, x1, y0, y1 = xs[i - 1], xs[i], ys[i - 1], ys[i]
        return y0 if x1 == x0 else y0 + (y1 - y0) * (raw - x0) / (x1 - x0)

    def predict_host(self, host: str, explain: int = 0) -> Prediction:
        """``host`` must already be in model form (``features.model_host``)."""
        z = self.b
        contrib: dict[str, float] = {}
        per_tok = [(tok, F.bucket(tok), cnt) for tok, cnt in F.tokens(host).items()]
        counts: dict[int, int] = {}
        for _, b, cnt in per_tok:                     # colliding tokens share a bucket, as in training
            counts[b] = counts.get(b, 0) + cnt
        vals = {b: (1.0 + math.log(c)) * self.idf[b] for b, c in counts.items()}
        norm = math.sqrt(sum(v * v for v in vals.values())) or 1.0
        for b, v in vals.items():
            z += self.w[b] * v / norm
        if explain:                                   # a bucket's contribution split over its tokens by count
            for tok, b, cnt in per_tok:
                contrib[tok] = self.w[b] * vals[b] / norm * cnt / counts[b]
        side = {}
        for j, (x, m, s, w) in enumerate(zip(F.dense(host), self.d_mean, self.d_std, self.d_w)):
            c = w * (x - m) / s
            z += c
            if explain:
                contrib["dense:" + F.DENSE[j]] = c
                side[F.DENSE[j]] = int(x > m)
        raw = 1.0 / (1.0 + math.exp(-z))
        top = []
        if explain:
            ranked = sorted(contrib.items(), key=lambda kv: -abs(kv[1]))[:explain]
            for k, c in ranked:
                kind = "lexical" if k.startswith("dense:") else "tld" if k.startswith("tld=") else "ngram"
                name = F.DENSE_TEXT[k[6:]][side[k[6:]]] if kind == "lexical" else k
                top.append({"feature": name, "kind": kind, "contribution": round(c, 3)})
        return Prediction(host=host, probability=round(self.calibrate(raw), 4), raw=round(raw, 4),
                          logit=round(z, 4), top=top)

    def predict(self, domain: str) -> float:
        """Probability for a domain, URL or SMS link (the host is all the model reads)."""
        return self.predict_host(F.model_host(domain)).probability


@lru_cache(maxsize=1)
def default_model() -> RiskModel:
    return RiskModel.load()


def predict(domain: str) -> float:
    """``risk_model.predict(domain) -> probability`` (BUILD_PHASES P7)."""
    return default_model().predict(domain)


def available() -> bool:
    return META_FILE.exists() and NGRAM_FILE.exists()


def _pretty(feature: str) -> str:
    if feature.startswith("tld="):
        return f"ending .{feature[4:]}"
    return "'" + feature.replace("<", "^").replace(">", "$") + "'"


def risk_model(display_or_raw: str, ids: Ids | None = None, model: RiskModel | None = None) -> tuple[Prediction, list[dict]]:
    """The C8 tool: one ``ml_risk`` evidence item (contract convention: p >= 0.5 -> phishing with score p,
    else genuine with score 1 - p; inside the no-opinion band it's neutral with score 0)."""
    t0 = time.perf_counter()
    ids = ids or Ids()
    m = model or default_model()
    pred = m.predict_host(F.model_host(display_or_raw), explain=6)
    p = pred.probability
    if abs(p - 0.5) < NEUTRAL_BAND:
        points_to, score = "neutral", 0.0
    elif p >= 0.5:
        points_to, score = "phishing", p
    else:
        points_to, score = "genuine", 1.0 - p
    up = [t for t in pred.top if t["contribution"] > 0][:3]
    down = [t for t in pred.top if t["contribution"] < 0][:2]
    why = ", ".join((_pretty(t["feature"]) if t["kind"] != "lexical" else t["feature"]) for t in (up if p >= 0.5 else down))
    reads = ("reads like the dataset's phishing hosts" if points_to == "phishing" else
             "reads like the dataset's ordinary sites" if points_to == "genuine" else "has no clear opinion")
    summary = (f"ML risk {p:.2f}: the PhiUSIIL model {reads}"
               + (f" ({why})" if why and points_to != "neutral" else "")
               + ". Supporting signal only: it can't see look-alikes.")
    item = evidence(
        ids, tool=TOOL, stage=STAGE, criterion=CRITERION, finding="ml_risk", points_to=points_to,
        strength="weak", score=score, summary=summary, target_brand=None,
        duration_ms=(time.perf_counter() - t0) * 1000,
        probability=p, raw_probability=pred.raw, model_input=pred.host, base_rate=m.base_rate,
        model_version=m.version, top_features=pred.top,
    )
    return pred, [item]
