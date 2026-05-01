#!/usr/bin/env python3
"""Sprint 8 — 4 PNG"""
import json
from collections import Counter
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import rcParams

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "experiments/bytecode_ml"
CHARTS = ROOT / "charts"
CHARTS.mkdir(parents=True, exist_ok=True)

rcParams.update({
    "font.size": 14, "axes.titlesize": 16, "axes.labelsize": 14,
    "xtick.labelsize": 12, "ytick.labelsize": 13, "legend.fontsize": 13,
    "figure.titlesize": 17,
})


def chart_f1_comparison():
    res = json.loads((OUT_DIR / "results.json").read_text(encoding="utf-8"))
    settings = res["settings"]
    names = sorted(settings.keys())
    f1s = [settings[k]["f1"] for k in names]
    cis = [(settings[k]["ci_low"], settings[k]["ci_high"]) for k in names]
    err_low = [f - lo for f, (lo, _) in zip(f1s, cis)]
    err_high = [hi - f for f, (_, hi) in zip(f1s, cis)]

    feat_color = {"F1": "#2980B9", "F2": "#E67E22", "F3": "#27AE60"}
    colors = [feat_color[k.split("_")[0]] for k in names]

    dm_f1 = res["comparison_with_dmavid_on_test_subset"]["dmavid_metrics_on_test"]["f1"]
    dm_ci_lo = res["comparison_with_dmavid_on_test_subset"]["dmavid_metrics_on_test"]["ci_low"]
    dm_ci_hi = res["comparison_with_dmavid_on_test_subset"]["dmavid_metrics_on_test"]["ci_high"]

    fig, ax = plt.subplots(figsize=(13, 6.5))
    x = np.arange(len(names))
    bars = ax.bar(x, f1s, color=colors, edgecolor="black", linewidth=1.2,
                  yerr=[err_low, err_high], capsize=5, ecolor="black", width=0.65)
    for bar, f, (lo, hi) in zip(bars, f1s, cis):
        ax.text(bar.get_x() + bar.get_width() / 2, hi + 0.01,
                f"{f:.3f}", ha="center", fontsize=12, fontweight="bold")
    ax.axhline(dm_f1, color="red", linestyle="--", linewidth=2,
               label=f"DmAVID Hybrid F1={dm_f1:.4f} (on same test set)")
    ax.axhspan(dm_ci_lo, dm_ci_hi, color="red", alpha=0.10)
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20, ha="right")
    ax.set_ylabel("F1 (with 95% bootstrap CI)")
    ax.set_title("Sprint 8  Pre-compile vs Post-compile — 9 ML settings vs DmAVID")
    ax.set_ylim(0, max(max(f1s) + 0.10, dm_ci_hi + 0.05))
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    ax.legend(loc="lower right")
    plt.tight_layout()
    out = CHARTS / "sprint8_f1_comparison.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"→ {out}")


def chart_exi_4way():
    exi_data = json.loads((OUT_DIR / "exi_bytecode_ml.json").read_text(encoding="utf-8"))
    rank = exi_data["comparison"]["ranking"]
    methods = [r["method"] for r in rank]
    exis = [r["exi"] for r in rank]
    color_map = {"DmAVID": "#C0392B", "Slither": "#2980B9", "CodeBERT": "#7F8C8D", "bytecode_ml": "#8E44AD"}
    colors = [color_map[m] for m in methods]

    fig, ax = plt.subplots(figsize=(11, 6))
    bars = ax.bar(methods, exis, color=colors, edgecolor="black", linewidth=1.3, width=0.55)
    for bar, v in zip(bars, exis):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 1.5,
                f"{v:.1f}", ha="center", fontsize=15, fontweight="bold")
    ax.axhline(50, color="gray", linestyle="--", alpha=0.5, linewidth=1)
    ax.set_ylabel("Composite Explainability Index (EXI, 0–100)")
    ax.set_title("Sprint 8  EXI 4-way comparison\n(DmAVID / Slither / CodeBERT / bytecode-ML)")
    ax.set_ylim(0, max(exis) * 1.18 + 5)
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    plt.tight_layout()
    out = CHARTS / "sprint8_exi_4way.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"→ {out}")


def chart_compile_status():
    d = json.loads((OUT_DIR / "compile_results.json").read_text(encoding="utf-8"))
    n_succ = d["compiled_success"]
    fail_bd = d.get("fail_breakdown", {})
    labels = [f"Success ({n_succ})"] + [f"{k} ({v})" for k, v in fail_bd.items()]
    sizes = [n_succ] + list(fail_bd.values())
    colors = ["#27AE60", "#E74C3C", "#E67E22", "#F39C12", "#9B59B6", "#34495E"][:len(sizes)]

    fig, ax = plt.subplots(figsize=(10, 8))
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct="%1.1f%%",
                                       colors=colors, startangle=90, textprops={"fontsize": 13})
    for at in autotexts:
        at.set_fontweight("bold")
        at.set_color("white")
    ax.set_title(f"Sprint 8  SmartBugs 243 Compile Status (success={n_succ}/243 = {n_succ/243*100:.1f}%)")
    plt.tight_layout()
    out = CHARTS / "sprint8_compile_status.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"→ {out}")


def chart_paired_bootstrap():
    d = json.loads((OUT_DIR / "paired_bootstrap.json").read_text(encoding="utf-8"))
    bs = d["paired_bootstrap_diff"]
    # 重新採 1000 paired diff
    import numpy as np
    rng = np.random.default_rng(42)
    y = np.array(d["test_y_true"])
    a = np.array(d["test_yhat_dmavid"])
    b = np.array(d["test_yhat_bytecode"])
    from sklearn.metrics import f1_score
    diffs = []
    n = len(y)
    for _ in range(1000):
        idx = rng.integers(0, n, size=n)
        diffs.append(f1_score(y[idx], a[idx], zero_division=0)
                     - f1_score(y[idx], b[idx], zero_division=0))
    diffs = np.array(diffs)
    mean = diffs.mean()
    lo, hi = np.percentile(diffs, [2.5, 97.5])

    fig, ax = plt.subplots(figsize=(11, 6))
    ax.hist(diffs, bins=40, color="#5B7FA8", edgecolor="black", alpha=0.85)
    ax.axvline(0, color="red", linestyle="--", linewidth=2, label="Δ = 0 (equal)")
    ax.axvline(mean, color="black", linewidth=2, label=f"mean Δ = {mean:.4f}")
    ax.axvspan(lo, hi, alpha=0.15, color="green", label=f"95% CI [{lo:.4f}, {hi:.4f}]")
    ax.set_xlabel("F1(DmAVID) − F1(bytecode-ML best)  on same test set")
    ax.set_ylabel("Frequency (1000 paired bootstrap iterations)")
    ax.set_title(f"Sprint 8  Paired bootstrap — DmAVID vs {d['best_bytecode_setting']}\n"
                 f"P(DmAVID > bytecode-ML) = {bs['p_diff_gt_0']:.3f}")
    ax.legend()
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    plt.tight_layout()
    out = CHARTS / "sprint8_paired_bootstrap.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"→ {out}")


def main():
    print("=" * 70)
    print("Sprint 8 — Charts")
    print("=" * 70)
    chart_f1_comparison()
    chart_exi_4way()
    chart_compile_status()
    chart_paired_bootstrap()
    print("Done.")


if __name__ == "__main__":
    main()
