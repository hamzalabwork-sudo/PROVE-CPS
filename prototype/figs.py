"""Paper figures (IEEE column width, print). Palette: reference categorical slots 1-4 in fixed order, validated
light-mode (adjacent CVD dE >= 9.1); slots 3-4 are < 3:1 on the surface, so every series is direct-labelled and
carries a distinct marker/linestyle (survives grayscale print).

Usage: python figs.py   -> paper/figs/*.pdf
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "paper/figs"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]   # slots 1-4, fixed order
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({
    "font.family": "serif", "font.size": 7.5, "axes.labelsize": 7.5, "xtick.labelsize": 7, "ytick.labelsize": 7,
    "axes.edgecolor": INK2, "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
    "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.6,
    "pdf.fonttype": 42, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
})


def pareto():
    d = json.loads((ROOT / "experiments/results/pareto.json").read_text())
    rows = [r for r in d["rows"] if r["split"] == "test2"]  # the longer trace (64 h); test1 is within a few %
    tau = [r["tau_full"] for r in rows]
    g = lambda k: [r["gas_per_h"][k] / 1e6 for r in rows]  # noqa: E731
    series = [  # (label, values, color, marker, linestyle)
        ("PROVE-CPS (deadline stabbing, committed policy)", g("provecps"), SERIES[0], "o", "-"),
        ("B3/B5 Merkle batching, fixed interval", g("B3_fixed"), SERIES[1], "s", "--"),
        ("B2 per-event hash", g("B2"), SERIES[2], None, "-."),
        ("B1 full on-chain log", g("B1"), SERIES[3], None, ":"),
    ]
    fig, ax = plt.subplots(figsize=(3.45, 2.0))
    ax.grid(True, which="major", color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    for label, ys, c, m, ls in series:
        ax.plot(tau, ys, color=c, linewidth=2 if m else 1.6, linestyle=ls, marker=m, markersize=3.6,
                markeredgecolor="white", markeredgewidth=0.6)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xticks([5, 10, 30, 60, 120, 300])
    ax.set_xticklabels(["5", "10", "30", "60", "120", "300"])
    ax.set_xlabel(r"Anchoring deadline for FULL events, $\tau_{\mathrm{full}}$ (s)")
    ax.set_ylabel("On-chain gas per hour (M)")
    ax.set_ylim(0.3, 2e4)
    # direct labels in text ink, next to each line (relief rule)
    ax.text(4.6, g("B1")[0] * 1.35, "B1 full on-chain log", color=INK, ha="left", va="bottom")
    ax.text(4.6, g("B2")[0] * 0.70, "B2 per-event hash", color=INK, ha="left", va="top")
    ax.text(11, g("B3_fixed")[1] * 2.0, "B3/B5 fixed-interval Merkle batching", color=INK, ha="left", va="bottom")
    ax.text(5, g("provecps")[0] * 0.42, "PROVE-CPS", color=INK, ha="left", va="top", fontweight="bold")
    i30 = tau.index(30)
    lo, hi = g("provecps")[i30], g("B3_fixed")[i30]
    ax.annotate("", xy=(30, lo * 1.12), xytext=(30, hi * 0.88),
                arrowprops=dict(arrowstyle="<->", color=INK2, linewidth=0.6, shrinkA=0, shrinkB=0))
    ax.text(28, (lo * hi) ** 0.5 * 1.25, f"{100 * (1 - lo / hi):.0f}% less gas", color=INK2,
            fontsize=6.3, ha="right", va="center")
    fig.savefig(OUT / "pareto.pdf")
    fig.savefig(OUT / "pareto.png", dpi=220)
    print("wrote", OUT / "pareto.pdf")


def frame():
    """Non-frameability phase transition: share of honest-gateway trials with a (false) conviction vs the
    partition length O, for two response windows. Two series -> slots 1-2, plus marker/linestyle encoding."""
    from collections import defaultdict
    g = defaultdict(list)
    for line in open(ROOT / "experiments/results/frame_sweep.jsonl"):
        r = json.loads(line)
        if "error" not in r:
            g[(r["params"]["W"], r["params"]["O"])].append(r["gateway_convicted"])
    fig, ax = plt.subplots(figsize=(3.45, 1.75))
    ax.grid(True, color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    # The two curves coincide (the transition depends on O - W only); draw the first thick and solid under a
    # thin dashed second so both stay visible, and say so in the legend.
    for (W, c, m, ls, lw, ms) in ((120, SERIES[0], "o", "-", 3.2, 5.2), (300, SERIES[1], "s", "--", 1.4, 3.0)):
        pts = sorted((O - W, 100 * sum(v) / len(v)) for (w, O), v in g.items() if w == W)
        ax.plot([p[0] for p in pts], [p[1] for p in pts], color=c, linewidth=lw, linestyle=ls, marker=m,
                markersize=ms, markeredgecolor="white", markeredgewidth=0.6,
                label=rf"$W_{{\mathrm{{resp}}}}$ = {W} s")
    ax.axvspan(-200, -2.555, color=GRID, alpha=0.6, linewidth=0)
    ax.text(-185, 55, "Theorem 3 condition holds\n" r"($W_{\mathrm{resp}} > O + \Delta_L$)", color=INK2, fontsize=6.3,
            ha="left", va="center")
    leg = ax.legend(loc="center right", frameon=False, fontsize=6.5, title="curves coincide", title_fontsize=6.3)
    for t in leg.get_texts():
        t.set_color(INK)
    ax.set_xlim(-200, 190)
    ax.set_ylim(-5, 105)
    ax.set_xlabel(r"Partition length minus response window, $O - W_{\mathrm{resp}}$ (s)")
    ax.set_ylabel("Honest trials convicted (%)")
    fig.savefig(OUT / "frame.pdf")
    fig.savefig(OUT / "frame.png", dpi=220)
    print("wrote", OUT / "frame.pdf")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    pareto()
    frame()
