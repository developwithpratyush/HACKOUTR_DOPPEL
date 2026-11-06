"""Train, evaluate and export the Risk Model (P7, C8).

    python -m doppel.risk.train            # ~5 min; needs the `risk` extra and data/raw (scripts/data/fetch.py)
    python -m doppel.risk.train --quick    # smaller C grid and NRD sample, for a smoke run

Steps (numbers land in docs/eval/p7-risk-model.{json,md} and p7-reliability.png):

1. PhiUSIIL -> one row per **host** (scheme, path and a leading ``www.`` stripped; look-alike letters
   folded), conflicting hosts dropped. Hosts that appear anywhere in ``data/pairs/pairs.csv`` are kept out,
   so the P3 evaluation is clean (``test_real`` *is* PhiUSIIL phishing).
2. **Split by registrable domain** (ICANN level, so every ``*.web.app`` host lands on one side): 80% train,
   20% held-out test, seeded.
3. On train: 5-fold GroupKFold -> pick C by out-of-fold log-loss -> fit **isotonic calibration** on the
   out-of-fold scores of the chosen C -> fit the final logistic model on all of train.
4. Held-out test: ROC-AUC, accuracy, Brier, log-loss, reliability bins; the same split for the comparison
   models (n-grams only, lexical stats only with gradient boosting).
5. **Distribution shift:** the P3 held-out pairs (look-alikes vs benign NRD, hard negatives, genuine), the
   201 real brand phish (``test_real``), and a sample of the NRD snapshot (unlabelled new domains).
6. Export the pure-Python model to ``doppel/risk/model/``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import math
import sys
import time
from collections import defaultdict

from doppel.contract import REPO_ROOT
from doppel.risk import data as D
from doppel.risk import features as F
from doppel.risk.model import META_FILE, MODEL_DIR, NGRAM_FILE, RiskModel

SEED = 20261105
TEST_SHARE = 0.2
C_GRID = [0.25, 0.5, 1.0, 2.0, 8.0]
EVAL_DIR = REPO_ROOT / "docs" / "eval"
OUT_JSON = EVAL_DIR / "p7-risk-model.json"
OUT_PNG = EVAL_DIR / "p7-reliability.png"
NRD_SAMPLE_EVERY = 10
P3_TEST_SPLITS = ("test_seen", "test_unseen")
VERSION = "p7-lr-1"


# ------------------------------------------------------------------ features ---

def token_buckets(hosts):
    """Per host: list of (bucket, count) after merging colliding tokens (``features.bucket_counts``)."""
    return [list(F.bucket_counts(h).items()) for h in hosts]


def fit_idf(tb, idx):
    import numpy as np

    df = np.zeros(F.N_BUCKETS, dtype=np.float64)
    for i in idx:
        for b, _ in tb[i]:
            df[b] += 1
    n = len(idx)
    return np.log((1.0 + n) / (1.0 + df)) + 1.0     # scikit-learn's smooth idf


def ngram_matrix(tb, idx, idf):
    """CSR tf-idf rows (L2-normalised) for the given row indices; the same values as ``features.sparse``."""
    import numpy as np
    from scipy.sparse import csr_matrix

    indptr, indices, vals = [0], [], []
    for i in idx:
        row = tb[i]
        v = np.array([(1.0 + math.log(c)) * idf[b] for b, c in row])
        v /= (np.sqrt((v * v).sum()) or 1.0)
        indices.extend(b for b, _ in row)
        vals.extend(v.tolist())
        indptr.append(len(indices))
    return csr_matrix((vals, indices, indptr), shape=(len(idx), F.N_BUCKETS), dtype=np.float64)


def dense_matrix(hosts, idx):
    import numpy as np

    return np.array([F.dense(hosts[i]) for i in idx], dtype=np.float64)


def standardise(train_dense):
    import numpy as np

    mean = train_dense.mean(axis=0)
    std = train_dense.std(axis=0)
    std[std == 0] = 1.0
    return mean, std


def design(tb, hosts, idx, idf, mean, std, ngrams=True, lexical=True):
    from scipy.sparse import csr_matrix, hstack

    parts = []
    if ngrams:
        parts.append(ngram_matrix(tb, idx, idf))
    if lexical:
        parts.append(csr_matrix((dense_matrix(hosts, idx) - mean) / std))
    return hstack(parts, format="csr") if len(parts) > 1 else parts[0]


# ------------------------------------------------------------------ metrics ---

def metrics(y, p):
    import numpy as np
    from sklearn.metrics import accuracy_score, brier_score_loss, log_loss, roc_auc_score

    y, p = np.asarray(y), np.clip(np.asarray(p, dtype=float), 1e-6, 1 - 1e-6)
    return {"n": int(len(y)), "positives": int(y.sum()), "roc_auc": round(float(roc_auc_score(y, p)), 4),
            "accuracy": round(float(accuracy_score(y, p >= 0.5)), 4),
            "brier": round(float(brier_score_loss(y, p)), 4), "log_loss": round(float(log_loss(y, p)), 4),
            "tpr_at_0.5": round(float((p[y == 1] >= 0.5).mean()), 4),
            "fpr_at_0.5": round(float((p[y == 0] >= 0.5).mean()), 4)}


def reliability(y, p, bins=10):
    import numpy as np

    y, p = np.asarray(y), np.asarray(p)
    out = []
    edges = np.linspace(0, 1, bins + 1)
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (p >= lo) & ((p < hi) if hi < 1 else (p <= hi))
        if m.sum():
            out.append({"bin": [round(float(lo), 2), round(float(hi), 2)], "n": int(m.sum()),
                        "mean_p": round(float(p[m].mean()), 4), "observed": round(float(y[m].mean()), 4)})
    return out


def share_at(p, cuts=(0.5, 0.8, 0.9)):
    import numpy as np

    p = np.asarray(p)
    return {f"share_ge_{c}": round(float((p >= c).mean()), 4) for c in cuts} | {"mean_p": round(float(p.mean()), 4),
                                                                              "n": int(len(p))}


# ------------------------------------------------------------------ main ---

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--quick", action="store_true", help="small C grid and NRD sample (smoke run)")
    args = ap.parse_args(argv)

    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.isotonic import IsotonicRegression
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import GroupKFold, GroupShuffleSplit

    t_all = time.time()
    log = lambda *a: print(f"[{time.time() - t_all:6.1f}s]", *a, flush=True)  # noqa: E731

    # 1. data ---------------------------------------------------------------------------
    df = D.load_phiusiil()
    hosts_df, conflicted = D.unique_hosts(df)
    prow = D.pairs_rows()
    excluded = D.pairs_hosts(prow)
    in_pairs = hosts_df["host"].isin(excluded)
    log(f"PhiUSIIL rows {len(df)}, unique hosts {len(hosts_df)}, conflicted {len(conflicted)}, "
        f"kept out (in pairs.csv) {int(in_pairs.sum())}")
    hosts_df = hosts_df[~in_pairs].reset_index(drop=True)
    hosts = hosts_df["host"].tolist()
    y = hosts_df["y"].to_numpy()
    groups = hosts_df["group"].to_numpy()

    # 2. split by registrable domain -------------------------------------------------------
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=TEST_SHARE, random_state=SEED).split(hosts, y, groups))
    assert not set(groups[tr]) & set(groups[te])
    log(f"train {len(tr)} hosts / {len(set(groups[tr]))} groups; test {len(te)} / {len(set(groups[te]))}")

    tb = token_buckets(hosts)
    idf = fit_idf(tb, tr)
    mean, std = standardise(dense_matrix(hosts, tr))
    Xtr = design(tb, hosts, tr, idf, mean, std)
    Xte = design(tb, hosts, te, idf, mean, std)
    ytr, yte = y[tr], y[te]
    log(f"design matrix {Xtr.shape}, nnz/row {Xtr.nnz / Xtr.shape[0]:.1f}")

    # 3. C by group-fold OOF log-loss; isotonic on the OOF scores --------------------------
    folds = list(GroupKFold(n_splits=5).split(Xtr, ytr, groups[tr]))
    grid = [2.0, 8.0] if args.quick else C_GRID
    tuning = []
    best = None
    for C in grid:
        oof = np.zeros(len(tr))
        for a, b in folds:
            m = LogisticRegression(C=C, solver="liblinear", max_iter=2000)
            m.fit(Xtr[a], ytr[a])
            oof[b] = m.predict_proba(Xtr[b])[:, 1]
        res = {"C": C, **metrics(ytr, oof)}
        tuning.append(res)
        log(f"C={C}: OOF AUC {res['roc_auc']} log-loss {res['log_loss']}")
        if best is None or res["log_loss"] < best[0]["log_loss"]:
            best = (res, oof)
    C = best[0]["C"]
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(best[1], ytr)
    lr = LogisticRegression(C=C, solver="liblinear", max_iter=2000).fit(Xtr, ytr)
    raw_te = lr.predict_proba(Xte)[:, 1]
    p_te = iso.predict(raw_te)
    shipped = {"name": "Logistic regression: char 3-5-gram TF-IDF + TLD + lexical stats (shipped)",
               "uncalibrated": metrics(yte, raw_te), **metrics(yte, p_te)}
    log(f"held-out: AUC {shipped['roc_auc']} acc {shipped['accuracy']} brier {shipped['brier']}")

    # 4. comparison models on the same split -----------------------------------------------
    comps = [shipped]
    Xn_tr = design(tb, hosts, tr, idf, mean, std, lexical=False)
    Xn_te = design(tb, hosts, te, idf, mean, std, lexical=False)
    m = LogisticRegression(C=C, solver="liblinear", max_iter=2000).fit(Xn_tr, ytr)
    comps.append({"name": "Logistic regression: n-grams + TLD only", **metrics(yte, m.predict_proba(Xn_te)[:, 1])})
    Dtr, Dte = dense_matrix(hosts, tr), dense_matrix(hosts, te)
    hgb = HistGradientBoostingClassifier(random_state=SEED).fit(Dtr, ytr)
    comps.append({"name": "Gradient boosting: lexical stats only (12 numbers, no n-grams)",
                  **metrics(yte, hgb.predict_proba(Dte)[:, 1])})
    comps.append({"name": "Always 'legitimate' (majority class)", **metrics(yte, np.full(len(yte), 0.0))})
    log("comparisons done")

    model = _export(lr, iso, idf, mean, std, C, ytr, shipped, len(tr), conflicted)
    rm = RiskModel.load()
    # the pure-Python model must reproduce scikit-learn on held-out hosts
    sample = te[:: max(1, len(te) // 2000)]
    diffs = [abs(rm.predict_host(hosts[i]).probability - float(iso.predict([lr.predict_proba(
        design(tb, hosts, [i], idf, mean, std))[0, 1]])[0])) for i in sample]
    parity = {"hosts": len(sample), "max_abs_diff": round(max(diffs), 6), "mean_abs_diff": round(float(np.mean(diffs)), 6)}
    log(f"pure-Python parity: {parity}")

    # 5. distribution shift ------------------------------------------------------------------
    p3 = defaultdict(list)
    p3_y, p3_p = [], []
    real = []
    for r in prow:
        if r["split"] not in P3_TEST_SPLITS + ("test_real",):
            continue
        try:
            p = rm.predict(r["candidate"])
        except ValueError:
            continue
        if r["split"] == "test_real":
            real.append(p)
            continue
        key = r["kind"] if r["kind"] != "lookalike" else f"lookalike {r['technique']}"
        p3[key].append(p)
        p3_y.append(int(r["label"]))
        p3_p.append(p)
    p3_report = {"overall": metrics(p3_y, p3_p), "by_kind": {k: share_at(v) for k, v in sorted(p3.items())},
                 "test_real": share_at(real)}
    log(f"P3 held-out AUC {p3_report['overall']['roc_auc']}; test_real share>=0.5 {p3_report['test_real']['share_ge_0.5']}")

    every = NRD_SAMPLE_EVERY * (10 if args.quick else 1)
    t = time.perf_counter()
    nrd_p = []
    for name in D.nrd_names(every=every):
        try:
            nrd_p.append(rm.predict(name))
        except ValueError:
            pass
    per_name_us = (time.perf_counter() - t) / max(1, len(nrd_p)) * 1e6
    nrd_report = {**share_at(nrd_p), "sample_every": every, "per_name_us": round(per_name_us, 1)}
    log(f"NRD sample {len(nrd_p)}: share>=0.5 {nrd_report['share_ge_0.5']}, {per_name_us:.0f} us/name")

    report = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "model_version": VERSION, "seed": SEED, "python": sys.version.split()[0],
        "data": {"phiusiil_rows": int(len(df)), "unique_hosts": int(len(hosts_df) + int(in_pairs.sum())),
                 "conflicted_hosts_dropped": len(conflicted), "conflicted_examples": conflicted[:12],
                 "kept_out_in_pairs": int(in_pairs.sum()), "train_hosts": int(len(tr)), "test_hosts": int(len(te)),
                 "train_groups": int(len(set(groups[tr]))), "test_groups": int(len(set(groups[te]))),
                 "train_phishing_share": round(float(ytr.mean()), 4), "test_phishing_share": round(float(yte.mean()), 4)},
        "tuning": tuning, "chosen_C": C, "held_out": comps, "parity": parity,
        "reliability": {"phiusiil_test": reliability(yte, p_te), "p3_test": reliability(p3_y, p3_p)},
        "phiusiil_test_by_label": {"legitimate": share_at(p_te[yte == 0]), "phishing": share_at(p_te[yte == 1])},
        "shift": {"p3": p3_report, "nrd": nrd_report},
        "top_weights": model["top_weights"],
        "seconds": round(time.time() - t_all, 1),
    }
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    _plot(report, yte, p_te, nrd_p, p3)
    log(f"wrote {OUT_JSON.relative_to(REPO_ROOT)}, {OUT_PNG.relative_to(REPO_ROOT)}, model in "
        f"{MODEL_DIR.relative_to(REPO_ROOT)}")
    return 0


def _export(lr, iso, idf, mean, std, C, ytr, shipped, n_train, conflicted) -> dict:
    import numpy as np

    coef = lr.coef_[0]
    w_ng = coef[: F.N_BUCKETS].astype(np.float32)
    w_d = coef[F.N_BUCKETS:]
    blob = np.concatenate([idf.astype(np.float32), w_ng]).astype("<f4").tobytes()
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    NGRAM_FILE.write_bytes(gzip.compress(blob, compresslevel=9, mtime=0))
    # readable top weights: which tokens push hardest, found by scanning the training vocabulary is costly,
    # so report the biggest dense weights and leave n-gram explanations to per-domain contributions
    meta = {
        "version": VERSION, "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "source": "PhiUSIIL (UCI 967, CC BY 4.0): host-only, www/scheme/path stripped, split by registrable domain",
        "n_buckets": F.N_BUCKETS, "ngram": list(F.NGRAM), "hash": "crc32", "C": C,
        "base_rate": round(float(ytr.mean()), 4), "train_hosts": n_train,
        "intercept": float(lr.intercept_[0]),
        "dense": {"names": F.DENSE, "mean": [float(x) for x in mean], "std": [float(x) for x in std],
                  "weights": [float(x) for x in w_d]},
        "calibration": {"method": "isotonic on 5-fold GroupKFold out-of-fold scores",
                        "x": [float(x) for x in iso.X_thresholds_], "y": [float(x) for x in iso.y_thresholds_]},
        "held_out": {k: shipped[k] for k in ("roc_auc", "accuracy", "brier", "n")},
        "ngram_sha256": hashlib.sha256(NGRAM_FILE.read_bytes()).hexdigest(),
    }
    META_FILE.write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
    order = np.argsort(-np.abs(w_d))
    return {"top_weights": [{"feature": F.DENSE[j], "weight": round(float(w_d[j]), 3)} for j in order]}


def _plot(report, yte, p_te, nrd_p, p3) -> None:
    from doppel.risk.plot import plot_reliability

    plot_reliability(report, yte, p_te, nrd_p, p3, OUT_PNG)


if __name__ == "__main__":
    raise SystemExit(main())
