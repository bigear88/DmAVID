#!/usr/bin/env python3
"""
Generate comparison charts for DeFi vulnerability detection experiments.
Uses existing result JSON files to produce publication-quality figures.
"""

import json
import os
import sys
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec

# ── Paths ──────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
CHARTS_DIR = os.path.join(BASE_DIR, "results", "charts")
os.makedirs(CHARTS_DIR, exist_ok=True)

RESULT_FILES = {
    "Slither":   "experiments/slither/slither_results.json",
    "Mythril":   "experiments/mythril/mythril_results.json",
    "LLM Base":  "experiments/llm_base/llm_base_results.json",
    "LLM+RAG":   "experiments/llm_rag/llm_rag_results.json",
    "Hybrid":    "experiments/hybrid/hybrid_results.json",
}

COLORS = {
    "Slither":  "#4C72B0",
    "Mythril":  "#DD8452",
    "LLM Base": "#55A868",
    "LLM+RAG":  "#C44E52",
    "Hybrid":   "#8172B2",
}

# Thesis reference values (Table 4-2)
THESIS = {
    "Slither":  {"precision": 0.610, "recall": 0.951, "f1_score": 0.743, "fpr": 0.870},
    "Mythril":  {"precision": 1.000, "recall": 0.450, "f1_score": 0.621, "fpr": 0.000},
    "LLM Base": {"precision": 0.592, "recall": 0.993, "f1_score": 0.742, "fpr": 0.980},
    "LLM+RAG":  {"precision": 0.809, "recall": 0.979, "f1_score": 0.886, "fpr": 0.330},
    "Hybrid":   {"precision": 0.723, "recall": 0.986, "f1_score": 0.834, "fpr": 0.540},
}


def load_results():
    data = {}
    for name, rel_path in RESULT_FILES.items():
        path = os.path.join(BASE_DIR, rel_path)
        if os.path.exists(path):
            with open(path) as f:
                d = json.load(f)
            m = d.get("metrics", {})
            data[name] = {
                "precision":  m.get("precision", 0),
                "recall":     m.get("recall", 0),
                "f1_score":   m.get("f1_score", m.get("f1", 0)),
                "fpr":        m.get("fpr", 0),
                "accuracy":   m.get("accuracy", 0),
                "avg_time":   m.get("avg_total_time", m.get("avg_time", 0)),
                "tp": m.get("tp", 0), "fn": m.get("fn", 0),
                "fp": m.get("fp", 0), "tn": m.get("tn", 0),
            }
            print(f"  Loaded {name}: F1={data[name]['f1_score']:.4f}")
        else:
            print(f"  MISSING {name}: {path}")
    return data


def chart1_bar_comparison(data):
    """Grouped bar chart: F1 / Precision / Recall / FPR"""
    methods = list(data.keys())
    metrics = ["f1_score", "precision", "recall", "fpr"]
    labels  = ["F1 Score", "Precision", "Recall", "FPR"]

    x = np.arange(len(methods))
    width = 0.2
    offsets = [-1.5, -0.5, 0.5, 1.5]

    metric_colors = ["#2196F3", "#4CAF50", "#FF9800", "#F44336"]

    fig, ax = plt.subplots(figsize=(12, 6))
    for i, (metric, label, color) in enumerate(zip(metrics, labels, metric_colors)):
        vals = [data[m][metric] for m in methods]
        bars = ax.bar(x + offsets[i] * width, vals, width, label=label, color=color, alpha=0.85)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.01,
                    f'{val:.3f}', ha='center', va='bottom', fontsize=7, rotation=45)

    ax.set_xlabel("Detection Method", fontsize=12)
    ax.set_ylabel("Score", fontsize=12)
    ax.set_title("DeFi Smart Contract Vulnerability Detection\nPerformance Comparison", fontsize=13, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(methods, fontsize=11)
    ax.set_ylim(0, 1.18)
    ax.legend(loc='upper right', fontsize=10)
    ax.axhline(y=0.8, color='gray', linestyle='--', alpha=0.4, linewidth=0.8)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    out = os.path.join(CHARTS_DIR, "01_performance_comparison.png")
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {out}")


def chart2_f1_highlight(data):
    """F1 score comparison with thesis annotations"""
    methods = list(data.keys())
    f1s  = [data[m]["f1_score"] for m in methods]
    cols = [COLORS[m] for m in methods]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(methods, f1s, color=cols, alpha=0.85, edgecolor='white', linewidth=1.2)

    # Thesis reference line
    thesis_f1s = [THESIS[m]["f1_score"] for m in methods]
    ax.scatter(methods, thesis_f1s, marker='D', color='black', zorder=5,
               s=50, label='Thesis target')

    for bar, val in zip(bars, f1s):
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.005,
                f'{val:.4f}', ha='center', va='bottom', fontsize=10, fontweight='bold')

    ax.set_ylim(0, 1.05)
    ax.set_ylabel("F1 Score", fontsize=12)
    ax.set_title("F1 Score by Detection Method\n(diamonds = thesis target values)", fontsize=12, fontweight='bold')
    ax.legend(fontsize=10)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    out = os.path.join(CHARTS_DIR, "02_f1_comparison.png")
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {out}")


def chart3_precision_recall(data):
    """Precision-Recall scatter with F1 iso-curves"""
    fig, ax = plt.subplots(figsize=(8, 7))

    # F1 iso-curves
    p = np.linspace(0.01, 1.0, 300)
    for f1_target in [0.6, 0.7, 0.8, 0.9]:
        r = (f1_target * p) / (2 * p - f1_target)
        r = np.where((r >= 0) & (r <= 1), r, np.nan)
        ax.plot(r, p, '--', color='gray', alpha=0.4, linewidth=0.8)
        idx = np.nanargmin(np.abs(r - 0.5))
        if not np.isnan(r[idx]):
            ax.text(r[idx], p[idx], f'F1={f1_target}', fontsize=8, color='gray', alpha=0.7)

    for method, vals in data.items():
        prec = vals["precision"]
        rec  = vals["recall"]
        ax.scatter(rec, prec, s=200, color=COLORS[method], zorder=5, edgecolors='black', linewidths=0.8)
        ax.annotate(method, (rec, prec), textcoords="offset points",
                    xytext=(8, 5), fontsize=10, fontweight='bold', color=COLORS[method])

    ax.set_xlim(0, 1.05)
    ax.set_ylim(0, 1.05)
    ax.set_xlabel("Recall", fontsize=12)
    ax.set_ylabel("Precision", fontsize=12)
    ax.set_title("Precision-Recall Trade-off\n(with F1 iso-curves)", fontsize=12, fontweight='bold')
    ax.grid(alpha=0.3)

    plt.tight_layout()
    out = os.path.join(CHARTS_DIR, "03_precision_recall.png")
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {out}")


def chart4_confusion_matrices(data):
    """2x3 grid of confusion matrices"""
    fig, axes = plt.subplots(2, 3, figsize=(14, 9))
    axes = axes.flatten()

    methods = list(data.keys())
    for i, method in enumerate(methods):
        ax = axes[i]
        m = data[method]
        cm = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
        total = cm.sum()
        cm_pct = cm / total * 100

        im = ax.imshow(cm, cmap='Blues', aspect='auto')
        ax.set_xticks([0, 1]); ax.set_xticklabels(["Pred Safe", "Pred Vuln"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["True Safe", "True Vuln"])
        ax.set_title(f"{method}\nF1={m['f1_score']:.3f} | Prec={m['precision']:.3f} | Rec={m['recall']:.3f}",
                     fontsize=9, fontweight='bold')

        for r in range(2):
            for c in range(2):
                ax.text(c, r, f'{cm[r,c]}\n({cm_pct[r,c]:.1f}%)',
                        ha='center', va='center', fontsize=11,
                        color='white' if cm[r,c] > cm.max()*0.6 else 'black')

    axes[5].set_visible(False)
    fig.suptitle("Confusion Matrices — All Detection Methods", fontsize=13, fontweight='bold', y=1.01)
    plt.tight_layout()
    out = os.path.join(CHARTS_DIR, "04_confusion_matrices.png")
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {out}")


def chart5_radar(data):
    """Radar chart for multi-dimensional comparison"""
    categories = ['F1 Score', 'Precision', 'Recall', '1-FPR', 'Accuracy']
    N = len(categories)
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

    for method, vals in data.items():
        values = [
            vals["f1_score"],
            vals["precision"],
            vals["recall"],
            1.0 - vals["fpr"],
            vals["accuracy"],
        ]
        values += values[:1]
        ax.plot(angles, values, 'o-', linewidth=2, label=method, color=COLORS[method])
        ax.fill(angles, values, alpha=0.1, color=COLORS[method])

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=11)
    ax.set_ylim(0, 1)
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(['0.2', '0.4', '0.6', '0.8', '1.0'], fontsize=8)
    ax.set_title("Multi-Dimensional Performance Radar", fontsize=13, fontweight='bold', pad=20)
    ax.legend(loc='upper right', bbox_to_anchor=(1.35, 1.15), fontsize=10)
    ax.grid(alpha=0.3)

    plt.tight_layout()
    out = os.path.join(CHARTS_DIR, "05_radar_chart.png")
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {out}")


def chart6_thesis_vs_actual(data):
    """Side-by-side: thesis values vs actual experiment results"""
    methods = list(data.keys())
    metrics = ["f1_score", "precision", "recall", "fpr"]
    labels  = ["F1", "Precision", "Recall", "FPR"]
    metric_colors = ["#2196F3", "#4CAF50", "#FF9800", "#F44336"]

    fig, axes = plt.subplots(1, 4, figsize=(16, 5))
    for ax, metric, label, color in zip(axes, metrics, labels, metric_colors):
        actual = [data[m][metric] for m in methods]
        thesis = [THESIS[m][metric] for m in methods]

        x = np.arange(len(methods))
        w = 0.35
        ax.bar(x - w/2, actual, w, label='Actual', color=color, alpha=0.85)
        ax.bar(x + w/2, thesis, w, label='Thesis', color=color, alpha=0.4, hatch='//')

        for xi, (a, t) in enumerate(zip(actual, thesis)):
            diff = a - t
            ax.text(xi, max(a, t) + 0.03, f'{diff:+.3f}',
                    ha='center', va='bottom', fontsize=7,
                    color='green' if diff >= -0.01 else 'red')

        ax.set_title(label, fontsize=12, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels([m.replace(' ', '\n') for m in methods], fontsize=8)
        ax.set_ylim(0, 1.2)
        ax.legend(fontsize=8, loc='upper right')
        ax.grid(axis='y', alpha=0.3)

    fig.suptitle("Actual Results vs. Thesis Target Values", fontsize=13, fontweight='bold')
    plt.tight_layout()
    out = os.path.join(CHARTS_DIR, "06_thesis_vs_actual.png")
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {out}")


def main():
    print("=" * 55)
    print(" DeFi Vulnerability Detection — Chart Generator")
    print("=" * 55)
    print(f"\nLoading experiment results...")
    data = load_results()

    if not data:
        print("ERROR: No result files found.")
        sys.exit(1)

    print(f"\nGenerating charts to: {CHARTS_DIR}")
    chart1_bar_comparison(data)
    chart2_f1_highlight(data)
    chart3_precision_recall(data)
    chart4_confusion_matrices(data)
    chart5_radar(data)
    chart6_thesis_vs_actual(data)

    print(f"\nAll charts saved to {CHARTS_DIR}/")
    print("\nSummary Table:")
    print(f"{'Method':<12} {'F1':>7} {'Prec':>7} {'Recall':>7} {'FPR':>7} {'Acc':>7}")
    print("-" * 52)
    for method, vals in data.items():
        print(f"{method:<12} {vals['f1_score']:>7.4f} {vals['precision']:>7.4f} "
              f"{vals['recall']:>7.4f} {vals['fpr']:>7.4f} {vals['accuracy']:>7.4f}")


if __name__ == "__main__":
    main()
