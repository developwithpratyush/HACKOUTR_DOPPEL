"""P7 leakage audit on PhiUSIIL: why "99.9% accuracy" isn't real for new domains.

    .venv/Scripts/python.exe bench/p7_leakage.py       # ~1-2 min -> docs/eval/p7-leakage.json

1. **Single-feature ROC-AUC** for every numeric column (and the TLD, target-encoded out of fold), oriented
   so 0.5 = useless and 1.0 = a perfect giveaway. Columns with AUC > 0.98 are dropped as leaky.
2. **Availability for a bare new domain:** a name from an NRD feed or a CT log has no page (HTML columns),
   no scheme or path (URL columns), and none of the dataset-derived statistics (similarity to the
   dataset's own legitimate URLs, TLD/character probabilities computed from the dataset).
3. **Ablation** with the same gradient-boosting model, row level (as published results are): all columns
   on a random row split -> split by registrable domain -> leaky columns dropped -> page columns dropped ->
   only what a bare domain has. The shipped host-only model is added from docs/eval/p7-risk-model.json.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from doppel.contract import REPO_ROOT  # noqa: E402
from doppel.risk.data import TEXT_COLUMNS, load_phiusiil  # noqa: E402

OUT = REPO_ROOT / "docs" / "eval" / "p7-leakage.json"
SEED = 20261105
LEAK_AUC = 0.98

PAGE = ["LineOfCode", "LargestLineLength", "HasTitle", "DomainTitleMatchScore", "URLTitleMatchScore", "HasFavicon",
        "Robots", "IsResponsive", "NoOfURLRedirect", "NoOfSelfRedirect", "HasDescription", "NoOfPopup", "NoOfiFrame",
        "HasExternalFormSubmit", "HasSocialNet", "HasSubmitButton", "HasHiddenFields", "HasPasswordField", "Bank",
        "Pay", "Crypto", "HasCopyrightInfo", "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef",
        "NoOfExternalRef"]
URL = ["URLLength", "IsHTTPS", "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
       "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL",
       "SpacialCharRatioInURL", "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio", "CharContinuationRate"]
DERIVED = ["URLSimilarityIndex", "TLDLegitimateProb", "URLCharProb"]
HOST = ["DomainLength", "IsDomainIP", "TLDLength", "NoOfSubDomain"]
WHY = {
    "page": "needs the fetched page (HTML)",
    "url": "needs the full URL (scheme, path, query)",
    "derived": "computed from the dataset's own statistics or its legitimate-URL list",
    "host": "computable from the host, but PhiUSIIL counts the 'www.' that every legitimate row has",
}


def kind(col: str) -> str:
    return "page" if col in PAGE else "url" if col in URL else "derived" if col in DERIVED else "host"


def auc(y, x) -> float:
    from sklearn.metrics import roc_auc_score

    a = roc_auc_score(y, x)
    return max(a, 1 - a)


def oof_target_encode(values, y, groups, k=20):
    import numpy as np
    from sklearn.model_selection import GroupKFold

    out = np.zeros(len(values))
    p0 = y.mean()
    for a, b in GroupKFold(n_splits=5).split(values, y, groups):
        stats = {}
        for v, t in zip(values[a], y[a]):
            s = stats.setdefault(v, [0, 0])
            s[0] += t
            s[1] += 1
        out[b] = [(stats.get(v, [0, 0])[0] + k * p0) / (stats.get(v, [0, 0])[1] + k) for v in values[b]]
    return out


def fit_eval(X, y, tr, te):
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

    m = HistGradientBoostingClassifier(random_state=SEED).fit(X[tr], y[tr])
    p = m.predict_proba(X[te])[:, 1]
    return {"accuracy": round(float(accuracy_score(y[te], p >= 0.5)), 4),
            "roc_auc": round(float(roc_auc_score(y[te], p)), 4),
            "f1": round(float(f1_score(y[te], p >= 0.5)), 4), "test_rows": int(len(te))}


def main() -> int:
    import numpy as np
    from sklearn.model_selection import GroupShuffleSplit, ShuffleSplit

    t0 = time.time()
    df = load_phiusiil()
    y = df["y"].to_numpy()
    groups = df["group"].to_numpy()
    numeric = [c for c in df.columns if c not in TEXT_COLUMNS | {"label", "y", "host", "group"}]
    print(f"{len(df)} rows, {len(numeric)} numeric columns ({time.time() - t0:.0f}s)")

    # 1-2. single-feature AUC + availability
    cols = []
    for c in numeric:
        cols.append({"column": c, "auc": round(auc(y, df[c].to_numpy(dtype=float)), 4), "kind": kind(c)})
    cols.append({"column": "TLD (target-encoded, out of fold)", "kind": "host",
                 "auc": round(auc(y, oof_target_encode(df["TLD"].astype(str).str.lower().to_numpy(), y, groups)), 4)})
    probes = {
        "URL starts with https://www.": df["URL"].str.lower().str.startswith("https://www.").to_numpy(dtype=float),
        "host has a www. label": df["Domain"].str.lower().str.startswith("www.").to_numpy(dtype=float),
        "host is punycode (xn--)": df["Domain"].str.contains("xn--", regex=False).to_numpy(dtype=float),
    }
    artifacts = []
    for name, x in probes.items():
        artifacts.append({"probe": name, "auc": round(auc(y, x), 4),
                          "share_legitimate": round(float(x[y == 0].mean()), 4),
                          "share_phishing": round(float(x[y == 1].mean()), 4)})
    for c in cols:
        c["leaky"] = c["auc"] > LEAK_AUC
        c["bare_domain"] = False    # host columns carry the www artifact; the shipped model recomputes them
    cols.sort(key=lambda c: -c["auc"])
    leaky = [c["column"] for c in cols if c["leaky"]]
    print("leaky:", leaky)

    # 3. ablation
    rnd_tr, rnd_te = next(ShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(df))
    g_tr, g_te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(df, y, groups))
    no_leak = [c for c in numeric if c not in leaky]
    no_page = [c for c in no_leak if c not in PAGE]
    host_cols = [c for c in no_page if c in HOST]
    rows = [
        ("All 50 columns, random row split (as published)", numeric, rnd_tr, rnd_te),
        ("All 50 columns, split by registrable domain", numeric, g_tr, g_te),
        (f"Leaky columns dropped (single-feature AUC > {LEAK_AUC})", no_leak, g_tr, g_te),
        ("…and page (HTML) columns dropped", no_page, g_tr, g_te),
        ("…and URL + dataset-derived columns dropped (PhiUSIIL's host columns only, www included)", host_cols, g_tr, g_te),
    ]
    ablation = []
    for name, use, tr, te in rows:
        X = df[use].to_numpy(dtype=float)
        res = {"setting": name, "columns": len(use), **fit_eval(X, y, tr, te)}
        ablation.append(res)
        print(f"{res['accuracy']:.4f} acc  {res['roc_auc']:.4f} AUC  {name}")

    report = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "seed": SEED,
              "rows": int(len(df)), "phishing_share": round(float(y.mean()), 4), "leak_auc_threshold": LEAK_AUC,
              "model": "HistGradientBoostingClassifier (scikit-learn defaults)", "kinds": WHY,
              "columns": cols, "leaky": leaky, "artifacts": artifacts, "ablation": ablation,
              "host_columns_used": host_cols, "seconds": round(time.time() - t0, 1)}
    OUT.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO_ROOT)} in {time.time() - t0:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
