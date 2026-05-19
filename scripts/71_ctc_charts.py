#!/usr/bin/env python3
"""
71_ctc_charts.py — CTC Explainability Evaluation Charts

Generates:
  1. Grouped bar chart: 3 methods × 3 CTC dimensions
  2. Radar chart: 3 methods CTC comparison
  3. Wilcoxon signed-rank test: DmAVID vs LLM-only, DmAVID vs Slither

Output: charts/ctc_*.png
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from scipy import stats

BASE         = Path(__file__).parent.parent
SUMMARY_PATH = BASE / "experiments/explainability/ctc_eval_summary.json"
CKPT_PATH    = BASE / "experiments/explainability/ctc_checkpoint.json"
CHARTS_DIR   = BASE / "charts"

METHODS      = ["dmavid", "llm", "slither"]
METHOD_LABEL = {"dmavid": "DmAVID", "llm": "LLM-only", "slither": "Slither"}
DIMS         = ["correctness", "thoroughness", "clarity"]
DIM_LABEL    = {"correctness": "Correctness", "thoroughness": "Thoroughness", "clarity": "Clarity"}
COLORS       = {"dmavid": "#2196F3", "llm": "#FF9800", "slither": "#4CAF50"}


def load_summary():
    if not SUMMARY_PATH.exists():
        print(f"Summary not found: {SUMMARY_PATH}")
        sys.exit(1)
    return json.load(open(SUMMARY_PATH))


def load_per_sample():
    """Load per-sample scores from checkpoint for significance tests."""
    if not CKPT_PATH.exists():
        print(f"Checkpoint not found: {CKPT_PATH}")
        sys.exit(1)
    ckpt = json.load(open(CKPT_PATH))
    # Group by contract_id → method → scores
    by_contract: dict = defaultdict(dict)
    for rec in ckpt.values():
        cid = rec["contract_id"]
        m   = rec["method"]
        c   = rec.get("correctness")
        t   = rec.get("thoroughness")
        cl  = rec.get("clarity")
        if all(v is not None for v in [c, t, cl]):
            by_contract[cid][m] = {"correctness": c, "thoroughness": t, "clarity": cl,
                                    "ctc_avg": round(c * 0.6 + t * 0.3 + cl * 0.1, 3)}
    return by_contract


# ── Chart 1: Grouped Bar Chart ────────────────────────────────────────────────
def chart_grouped_bar(summary):
    pm = summary["per_method"]
    methods = [m for m in METHODS if m in pm]
    dims    = DIMS

    n_dims    = len(dims)
    n_methods = len(methods)
    x         = np.arange(n_dims)
    width     = 0.25

    fig, ax = plt.subplots(figsize=(9, 5))
    for i, m in enumerate(methods):
        vals   = [pm[m].get(d, 0) for d in dims]
        offset = (i - n_methods / 2 + 0.5) * width
        bars   = ax.bar(x + offset, vals, width, label=METHOD_LABEL[m],
                        color=COLORS[m], alpha=0.85, edgecolor="white")
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.03,
                    f"{v:.2f}", ha="center", va="bottom", fontsize=8)

    ax.set_xlabel("CTC Dimension", fontsize=12)
    ax.set_ylabel("Score (1–10)", fontsize=12)
    ax.set_title("CTC Explainability Evaluation\n(Li et al., Smart-LLaMA-DPO, ISSTA 2025)",
                 fontsize=12, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels([DIM_LABEL[d] for d in dims], fontsize=11)
    ax.set_ylim(0, 11.5)
    ax.axhline(y=5, color="gray", linestyle="--", linewidth=0.8, alpha=0.5, label="Average (5)")
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    path = CHARTS_DIR / "ctc_grouped_bar.png"
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Saved: {path}")
    return path


# ── Chart 2: Radar Chart ─────────────────────────────────────────────────────
def chart_radar(summary):
    pm      = summary["per_method"]
    methods = [m for m in METHODS if m in pm]
    labels  = [DIM_LABEL[d] for d in DIMS]
    N       = len(DIMS)

    angles  = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]  # close the polygon

    fig, ax = plt.subplots(figsize=(6, 6), subplot_kw={"polar": True})
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylim(0, 10)
    ax.set_yticks([2, 4, 6, 8, 10])
    ax.set_yticklabels(["2", "4", "6", "8", "10"], fontsize=8)
    ax.yaxis.grid(True, alpha=0.3)

    for m in methods:
        vals  = [pm[m].get(d, 0) for d in DIMS]
        vals += vals[:1]
        ax.plot(angles, vals, "o-", linewidth=2, color=COLORS[m], label=METHOD_LABEL[m])
        ax.fill(angles, vals, alpha=0.1, color=COLORS[m])

    ax.set_title("CTC Radar Chart", size=13, fontweight="bold", pad=20)
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1), fontsize=10)

    path = CHARTS_DIR / "ctc_radar.png"
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Saved: {path}")
    return path


# ── Chart 3: Wilcoxon Significance Test ──────────────────────────────────────
def chart_wilcoxon(by_contract):
    """Pairwise Wilcoxon signed-rank test on matched contract-level CTC averages."""
    pairs = [("dmavid", "llm"), ("dmavid", "slither")]
    results = []

    for m1, m2 in pairs:
        shared = [cid for cid, ms in by_contract.items() if m1 in ms and m2 in ms]
        if len(shared) < 10:
            print(f"  Too few shared samples for {m1} vs {m2}: {len(shared)}")
            continue
        a1 = [by_contract[cid][m1]["ctc_avg"] for cid in shared]
        a2 = [by_contract[cid][m2]["ctc_avg"] for cid in shared]
        stat, p = stats.wilcoxon(a1, a2, alternative="greater")
        mean1, mean2 = np.mean(a1), np.mean(a2)
        results.append({
            "comparison": f"{METHOD_LABEL[m1]} vs {METHOD_LABEL[m2]}",
            "n": len(shared),
            "mean_a": round(mean1, 3),
            "mean_b": round(mean2, 3),
            "statistic": round(stat, 3),
            "p_value": round(p, 4),
            "significant": bool(p < 0.05),
        })
        print(f"  {METHOD_LABEL[m1]} ({mean1:.3f}) vs {METHOD_LABEL[m2]} ({mean2:.3f}): "
              f"W={stat:.1f}, p={p:.4f} {'*' if p < 0.05 else 'ns'}")

    if not results:
        print("No Wilcoxon results to plot.")
        return None

    # Save significance results as JSON
    sig_path = CHARTS_DIR / "ctc_wilcoxon.json"
    json.dump(results, open(sig_path, "w"), indent=2)
    print(f"Saved: {sig_path}")

    # Bar plot of CTC averages with significance annotation
    fig, ax = plt.subplots(figsize=(7, 5))
    x = np.arange(len(results))
    width = 0.35

    mean_a = [r["mean_a"] for r in results]
    mean_b = [r["mean_b"] for r in results]
    labels_a = ["DmAVID"] * len(results)
    labels_b = [r["comparison"].split(" vs ")[1] for r in results]

    bars_a = ax.bar(x - width / 2, mean_a, width, color="#2196F3", alpha=0.85, label="DmAVID")
    bars_b = ax.bar(x + width / 2, mean_b, width, color=["#FF9800", "#4CAF50"][:len(results)],
                    alpha=0.85)

    for i, r in enumerate(results):
        ax.text(i - width / 2, r["mean_a"] + 0.05, f"{r['mean_a']:.3f}", ha="center", fontsize=9)
        ax.text(i + width / 2, r["mean_b"] + 0.05, f"{r['mean_b']:.3f}", ha="center", fontsize=9)
        sig_label = f"p={r['p_value']:.4f}{'*' if r['significant'] else ''}"
        ymax = max(r["mean_a"], r["mean_b"]) + 0.3
        ax.annotate("", xy=(i + width / 2, ymax), xytext=(i - width / 2, ymax),
                    arrowprops={"arrowstyle": "-", "color": "black"})
        ax.text(i, ymax + 0.05, sig_label, ha="center", fontsize=9,
                color="red" if r["significant"] else "gray")

    patches = [mpatches.Patch(color="#FF9800", label="LLM-only"),
               mpatches.Patch(color="#4CAF50", label="Slither")]
    ax.legend(handles=[mpatches.Patch(color="#2196F3", label="DmAVID")] + patches, fontsize=10)
    ax.set_xticks(x)
    ax.set_xticklabels([r["comparison"] for r in results], fontsize=10)
    ax.set_ylabel("Mean CTC Score (1–10)", fontsize=11)
    ax.set_ylim(0, 12)
    ax.set_title("Wilcoxon Signed-Rank Test\n(DmAVID vs Baselines, one-tailed p<0.05)",
                 fontsize=11, fontweight="bold")
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    path = CHARTS_DIR / "ctc_wilcoxon.png"
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Saved: {path}")
    return path


def main():
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading CTC summary...")
    summary = load_summary()

    print("\n── Per-Method CTC Results ──")
    for m, s in summary["per_method"].items():
        print(f"  {METHOD_LABEL.get(m, m):12s}  C={s['correctness']}  "
              f"T={s['thoroughness']}  CL={s['clarity']}  CTC={s['ctc_avg']}")

    print("\n[Chart 1] Grouped bar chart...")
    chart_grouped_bar(summary)

    print("[Chart 2] Radar chart...")
    chart_radar(summary)

    print("[Chart 3] Wilcoxon significance test...")
    by_contract = load_per_sample()
    chart_wilcoxon(by_contract)

    print(f"\nAll charts saved to {CHARTS_DIR}/")


if __name__ == "__main__":
    main()
