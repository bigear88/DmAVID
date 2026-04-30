#!/usr/bin/env python3
"""
Sprint 6: Explainability charts (3 PNGs)

Reads experiments/explainability/exi_deep_results.json and renders:
  charts/sprint6_exi_radar.png   — 5 軸雷達圖（4 指標 + EXI 總分）
  charts/sprint6_exi_bar.png     — EXI 總分 bar chart
  charts/sprint6_per_metric.png  — 4 子圖各指標方法對比

老花友善：base fontsize ≥14。

Author: Curtis Chang (張宏睿), 2026
"""
import os
import json
from pathlib import Path

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import rcParams

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "experiments" / "explainability" / "exi_deep_results.json"
CHART_DIR = ROOT / "charts"
CHART_DIR.mkdir(parents=True, exist_ok=True)

METHOD_COLORS = {"DmAVID": "#C0392B", "Slither": "#2980B9", "CodeBERT": "#7F8C8D"}
METHOD_ORDER = ["DmAVID", "Slither", "CodeBERT"]

# 老花友善
rcParams.update({
    "font.size": 14,
    "axes.titlesize": 16,
    "axes.labelsize": 14,
    "xtick.labelsize": 13,
    "ytick.labelsize": 13,
    "legend.fontsize": 13,
    "figure.titlesize": 17,
})


def load_data():
    d = json.loads(SRC.read_text(encoding="utf-8"))
    table = {}
    for m in METHOD_ORDER:
        key = m.lower()
        e = d[key]
        rq_norm = e["repair_quality_avg_1to5"] / 5.0
        table[m] = {
            "Pattern\nCoverage": e["pattern_coverage"],
            "Root Cause\nAccuracy": e["root_cause"],
            "Attack Path\nCoverage": e["attack_path"],
            "Repair\nQuality": rq_norm,
            "EXI": e["exi"] / 100.0,
            "_exi_raw": e["exi"],
        }
    return d, table


def chart_radar(table):
    metrics = ["Pattern\nCoverage", "Root Cause\nAccuracy",
               "Attack Path\nCoverage", "Repair\nQuality", "EXI"]
    angles = np.linspace(0, 2 * np.pi, len(metrics), endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(10, 9), subplot_kw=dict(polar=True))
    for method in METHOD_ORDER:
        vals = [table[method][m] for m in metrics]
        vals += vals[:1]
        ax.plot(angles, vals, marker="o", markersize=10, linewidth=2.5,
                color=METHOD_COLORS[method], label=method)
        ax.fill(angles, vals, alpha=0.15, color=METHOD_COLORS[method])

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(metrics, fontsize=14)
    ax.set_ylim(0, 1.0)
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(["0.2", "0.4", "0.6", "0.8", "1.0"], fontsize=12)
    ax.grid(alpha=0.4)
    ax.set_title("Explainability Profile — DmAVID vs Slither vs CodeBERT\n"
                 "(Each axis normalized to 0–1)", pad=22)
    ax.legend(loc="upper right", bbox_to_anchor=(1.18, 1.10))

    out = CHART_DIR / "sprint6_exi_radar.png"
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"→ {out}")


def chart_bar(table):
    fig, ax = plt.subplots(figsize=(10, 6))
    methods = METHOD_ORDER
    exi_vals = [table[m]["_exi_raw"] for m in methods]
    colors = [METHOD_COLORS[m] for m in methods]

    bars = ax.bar(methods, exi_vals, color=colors, edgecolor="black", linewidth=1.5, width=0.55)
    for bar, v in zip(bars, exi_vals):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 1.5,
                f"{v:.1f}", ha="center", fontsize=16, fontweight="bold")

    ax.set_ylabel("Composite Explainability Index (EXI, 0–100)")
    ax.set_title("EXI Composite Score — DmAVID vs Slither vs CodeBERT")
    ax.set_ylim(0, max(exi_vals) * 1.15 + 5)
    ax.axhline(50, color="gray", linestyle="--", alpha=0.5, linewidth=1)
    ax.text(2.45, 51, "EXI=50 reference", fontsize=11, color="gray")
    ax.grid(axis="y", alpha=0.3, linestyle="--")

    out = CHART_DIR / "sprint6_exi_bar.png"
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"→ {out}")


def chart_per_metric(table):
    metrics = ["Pattern\nCoverage", "Root Cause\nAccuracy",
               "Attack Path\nCoverage", "Repair\nQuality"]
    weights = [25, 30, 25, 20]
    fig, axes = plt.subplots(2, 2, figsize=(13, 10))
    axes = axes.flatten()

    for i, m in enumerate(metrics):
        ax = axes[i]
        vals = [table[meth][m] for meth in METHOD_ORDER]
        colors = [METHOD_COLORS[meth] for meth in METHOD_ORDER]
        bars = ax.bar(METHOD_ORDER, vals, color=colors,
                      edgecolor="black", linewidth=1.2, width=0.55)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, v + 0.025,
                    f"{v:.3f}", ha="center", fontsize=14, fontweight="bold")
        title = m.replace("\n", " ") + f"  (weight {weights[i]}%)"
        ax.set_title(title)
        ax.set_ylabel("Score (0–1)")
        ax.set_ylim(0, 1.15)
        ax.grid(axis="y", alpha=0.3, linestyle="--")

    fig.suptitle("Per-Metric Comparison — DmAVID vs Slither vs CodeBERT", y=0.995)
    out = CHART_DIR / "sprint6_per_metric.png"
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"→ {out}")


def main():
    print("=" * 70)
    print("Sprint 6 — Explainability Charts")
    print("=" * 70)
    if not SRC.exists():
        print(f"✗ {SRC} 不存在，先跑 41")
        return
    _, table = load_data()
    print("\nEXI scores:")
    for m in METHOD_ORDER:
        print(f"  {m:<10}: {table[m]['_exi_raw']:.2f}")
    print()
    chart_radar(table)
    chart_bar(table)
    chart_per_metric(table)
    print("\nDone.")


if __name__ == "__main__":
    main()
