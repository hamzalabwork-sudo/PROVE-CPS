"""Evaluation figures (IEEE column width, print). Palette: reference categorical slots 1-4 in fixed order, validated
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
    fig, ax = plt.subplots(figsize=(3.45, 1.45))
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
    ax.text(32, hi * 1.25, f"{100 * (1 - lo / hi):.0f}% less gas", color=INK2,
            fontsize=6.3, ha="left", va="bottom")
    fig.savefig(OUT / "pareto.pdf")
    fig.savefig(OUT / "pareto.png", dpi=220)
    print("wrote", OUT / "pareto.pdf")


def frame():
    """Non-frameability phase transition on the predicted-boundary axis. An honest gateway cut off for O seconds
    from A0 can answer only after A0 + O, while the first challenge opened at T_c must be answered by T_c + W.
    x = (A0 + O) - (T_c + W): the analysis predicts a conviction iff x + Delta_L > 0. Each point is one (W, O)
    variant (14 windows, x averaged; per-window x spans < 7 s); two series -> slots 1-2, plus marker/linestyle."""
    from collections import defaultdict
    g = defaultdict(list)
    agree = n = 0
    for line in open(ROOT / "experiments/results/frame_sweep_v2.jsonl"):
        r = json.loads(line)
        if "error" in r:
            continue
        P = r["params"]
        x = P["O"] - r["first_challenge_rel"] - P["W"]
        g[(P["W"], P["O"])].append((x, r["gateway_convicted"]))
        n += 1
        agree += (x > 0) == bool(r["gateway_convicted"])
    fig, ax = plt.subplots(figsize=(3.45, 1.28))
    ax.grid(True, color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    for (W, c, m, ls, lw, ms) in ((120, SERIES[0], "o", "-", 3.2, 5.2), (300, SERIES[1], "s", "--", 1.4, 3.0)):
        pts = sorted((sum(x for x, _ in v) / len(v), 100 * sum(bool(k) for _, k in v) / len(v))
                     for (w, O), v in g.items() if w == W)
        ax.plot([p[0] for p in pts], [p[1] for p in pts], color=c, linewidth=lw, linestyle=ls, marker=m,
                markersize=ms, markeredgecolor="white", markeredgewidth=0.6,
                label=rf"$W_{{\mathrm{{resp}}}}$ = {W} s")
    ax.axvspan(-260, 0, color=GRID, alpha=0.6, linewidth=0)
    ax.axvline(0, color=INK2, linewidth=0.7, linestyle=":")
    ax.text(-250, 55, "predicted safe:\nanswer lands before\nthe challenge deadline", color=INK2, fontsize=6.3,
            ha="left", va="center")
    ax.text(14, 55, f"predicted = observed\nin {agree}/{n} trials", color=INK, fontsize=6.3, ha="left",
            va="center")
    leg = ax.legend(loc="lower right", frameon=False, fontsize=6.5)
    for t in leg.get_texts():
        t.set_color(INK)
    ax.set_xlim(-260, 170)
    ax.set_ylim(-5, 105)
    ax.set_xlabel(r"Outage end minus challenge deadline, $(A_0{+}O)-(T_c{+}W_{\mathrm{resp}})$ (s)")
    ax.set_ylabel("Honest trials convicted (%)")
    fig.savefig(OUT / "frame.pdf")
    fig.savefig(OUT / "frame.png", dpi=220)
    print("wrote", OUT / "frame.pdf", agree, n)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    pareto()
    frame()
