#!/usr/bin/env python3
"""
Sprint 7: 兩張視覺化 PNG

charts/sprint7_agent_contribution.png — 每個 Agent 邊際貢獻 bar chart
                                        + reference line 於 full DmAVID F1
charts/sprint7_leaveoneout_f1.png      — 拿掉每個 Agent 後 F1 橫向 bar
                                        從低到高排序

老花友善：base fontsize ≥ 14。
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import rcParams

ROOT = Path(__file__).resolve().parent.parent
SUMMARY = ROOT / "experiments/coordinator_ablation/leaveoneout_summary.json"
CHART_DIR = ROOT / "charts"
CHART_DIR.mkdir(parents=True, exist_ok=True)

AGENT_ORDER = ["coordinator", "teacher", "student", "red_team", "blue_team"]
AGENT_LABEL = {
    "coordinator": "Coordinator",
    "teacher": "Teacher (RAG)",
    "student": "Student (LLM core)",
    "red_team": "Red Team",
    "blue_team": "Blue Team",
}
AGENT_COLOR = {
    "coordinator": "#8E44AD",
    "teacher":     "#27AE60",
    "student":     "#C0392B",
    "red_team":    "#E67E22",
    "blue_team":   "#2980B9",
}

rcParams.update({
    "font.size": 14,
    "axes.titlesize": 16,
    "axes.labelsize": 14,
    "xtick.labelsize": 13,
    "ytick.labelsize": 13,
    "legend.fontsize": 13,
    "figure.titlesize": 17,
})


def load():
    return json.loads(SUMMARY.read_text(encoding="utf-8"))


def chart_contribution(d):
    full_f1 = d["full_dmavid_f1"]
    agents = AGENT_ORDER
    contribs = [d["leave_one_out"][a]["marginal_contribution"] for a in agents]
    labels = [AGENT_LABEL[a] for a in agents]
    colors = [AGENT_COLOR[a] for a in agents]

    fig, ax = plt.subplots(figsize=(11, 6.5))
    bars = ax.bar(labels, contribs, color=colors,
                  edgecolor="black", linewidth=1.3, width=0.6)
    for bar, c in zip(bars, contribs):
        if c is None:
            continue
        ax.text(bar.get_x() + bar.get_width() / 2, c + 0.015,
                f"+{c:.4f}", ha="center", fontsize=14, fontweight="bold")

    # removable threshold line
    ax.axhline(0.005, color="gray", linestyle=":", alpha=0.7,
               label="removable threshold (Δ<0.005)")
    ax.axhline(0, color="black", linewidth=1)
    ax.set_ylabel("Marginal Contribution to F1\n(full DmAVID − leave-out)")
    ax.set_title(
        f"Sprint 7  Agent Leave-One-Out Marginal Contribution\n"
        f"(reference: full DmAVID F1 = {full_f1:.4f})"
    )
    ymax = max([c for c in contribs if c is not None]) + 0.08
    ax.set_ylim(-0.02, ymax)
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    ax.legend(loc="upper right")
    plt.xticks(rotation=12, ha="right")

    out = CHART_DIR / "sprint7_agent_contribution.png"
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"→ {out}")


def chart_leaveout_f1(d):
    """橫向 bar chart：拿掉某 Agent 後 F1，從低到高"""
    rows = []
    for a in AGENT_ORDER:
        f1 = d["leave_one_out"][a]["f1"]
        if f1 is None:
            f1 = 0.0
        rows.append((a, f1))
    rows.sort(key=lambda x: x[1])
    agents = [r[0] for r in rows]
    f1s = [r[1] for r in rows]
    labels = [AGENT_LABEL[a] for a in agents]
    colors = [AGENT_COLOR[a] for a in agents]
    full_f1 = d["full_dmavid_f1"]

    fig, ax = plt.subplots(figsize=(11, 6))
    bars = ax.barh(labels, f1s, color=colors, edgecolor="black", linewidth=1.3, height=0.6)
    for bar, v in zip(bars, f1s):
        ax.text(v + 0.012, bar.get_y() + bar.get_height() / 2,
                f"{v:.4f}", va="center", fontsize=14, fontweight="bold")

    ax.axvline(full_f1, color="gray", linestyle="--", linewidth=1.4,
               label=f"full DmAVID F1 = {full_f1:.4f}")
    ax.set_xlabel("F1 score after removing the agent")
    ax.set_title("Sprint 7  Leave-One-Out F1 (sorted, lower = more critical agent)")
    ax.set_xlim(0, max(f1s + [full_f1]) * 1.10)
    ax.grid(axis="x", alpha=0.3, linestyle="--")
    ax.legend(loc="lower right")

    out = CHART_DIR / "sprint7_leaveoneout_f1.png"
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"→ {out}")


def main():
    print("=" * 70)
    print("Sprint 7 — Charts")
    print("=" * 70)
    d = load()
    print(f"full DmAVID F1 = {d['full_dmavid_f1']}")
    for a in AGENT_ORDER:
        info = d["leave_one_out"][a]
        print(f"  {a:<12} F1={info['f1']}  contrib={info['marginal_contribution']}  removable={info['removable']}")
    chart_contribution(d)
    chart_leaveout_f1(d)
    print("Done.")


if __name__ == "__main__":
    main()
