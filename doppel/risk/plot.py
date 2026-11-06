"""The P7 chart: reliability on the held-out split, and where each population's scores fall (distribution shift).

Needs the `bench` extra (matplotlib). Colours: the validated default categorical palette (slots 1-4, light
surface); every line is also direct-labelled and the eval doc carries the same numbers as tables.
"""

from __future__ import annotations

SURFACE, INK, MUTED, GRID = "#fcfcfb", "#1f1f1e", "#6b6a64", "#e4e3de"
BLUE, ORANGE, AQUA, YELLOW = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"


def _ecdf(ax, values, color, label, style):
    import numpy as np

    v = np.sort(np.asarray(values))
    share_above = 1.0 - np.arange(1, len(v) + 1) / len(v)          # share of names scoring above x
    ax.plot(v, share_above, color=color, lw=2, ls=style, label=f"{label} (n={len(v):,})")
    return v, share_above


def plot_reliability(report, yte, p_te, nrd_p, p3, out_png) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    plt.rcParams.update({"font.size": 10, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED,
                         "ytick.color": MUTED, "text.color": INK, "axes.titleweight": "bold",
                         "axes.titlesize": 11, "axes.titlelocation": "left"})
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 5.2), dpi=150, facecolor=SURFACE)
    for ax in (a1, a2):
        ax.set_facecolor(SURFACE)
        ax.grid(color=GRID, lw=0.8)
        ax.set_axisbelow(True)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)

    # left: reliability
    a1.plot([0, 1], [0, 1], color=MUTED, lw=1, ls=(0, (4, 3)))
    a1.text(0.62, 0.55, "perfectly calibrated", color=MUTED, rotation=38, fontsize=8.5)
    for key, color, style, label in (("phiusiil_test", BLUE, "-", "PhiUSIIL held-out hosts"),
                                     ("p3_test", YELLOW, "--", "P3 held-out pairs (look-alike vs not)")):
        bins = report["reliability"][key]
        x = [b["mean_p"] for b in bins]
        y = [b["observed"] for b in bins]
        a1.plot(x, y, color=color, lw=2, ls=style, marker="o", ms=5, label=label,
                markeredgecolor=SURFACE, markeredgewidth=1.5)
    a1.set_xlabel("Predicted probability (bin mean)")
    a1.set_ylabel("Observed share that is phishing / a look-alike")
    a1.set_title("Reliability: calibrated in-distribution, not under shift")
    a1.legend(loc="upper left", frameon=False, fontsize=8.5)

    # right: survival curves of the score
    yte = np.asarray(yte)
    p_te = np.asarray(p_te)
    look = [p for k, v in p3.items() if k.startswith("lookalike") for p in v]
    series = [(p_te[yte == 0], BLUE, "-", "PhiUSIIL legitimate (held-out)"),
              (p_te[yte == 1], ORANGE, "-", "PhiUSIIL phishing (held-out)"),
              (nrd_p, AQUA, "--", "NRD new domains (sample, unlabelled)"),
              (look, YELLOW, ":", "P3 brand look-alikes (held-out)")]
    for values, color, style, label in series:
        if len(values):
            _ecdf(a2, values, color, label, style)
            share = float((np.asarray(values) >= 0.5).mean())
            a2.annotate(f"{share:.0%}", (0.5, share), xytext=(6, 3), textcoords="offset points",
                        fontsize=8.5, color=INK)
    a2.axvline(0.5, color=MUTED, lw=1, ls=(0, (4, 3)))
    a2.set_xlabel("ML risk (calibrated probability)")
    a2.set_ylabel("Share of names scoring at least this")
    a2.set_title("Who scores high: new domains look like PhiUSIIL phishing")
    a2.legend(loc="upper right", frameon=False, fontsize=8.5)

    fig.text(0.01, 0.01, "Risk Model (P7): logistic regression on host-only features, trained on PhiUSIIL split by "
             "registrable domain. Labels at x = 0.5 give the share flagged at the 0.5 threshold.",
             fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(out_png, facecolor=SURFACE)
    plt.close(fig)
