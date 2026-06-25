#!/usr/bin/env python3
"""
72_literature_comparison_chart.py — 圖4-1 DmAVID vs External Literature Methods
Cross-dataset comparison (for reference only). Author attributions and the
iterative DmAVID value are kept consistent with Table 4-1 and the canonical
ChromaDB autonomous run (iterative F1=0.9158).
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

CH = Path(__file__).parent.parent / "charts"
CH.mkdir(exist_ok=True)

# (label, Precision, Recall, F1)  — None = not reported in source
methods = [
    ("GPTScan\n(Sun 2024)",            0.90, 0.71, 0.80),
    ("AuditGPT\n(Xia et al., 2024)",   0.80, 0.83, 0.81),
    ("LLM-SmartAudit\n(Wei et al., 2025a)", 0.91, 0.86, 0.88),
    ("DmAVID\n+Self-Verify",           0.8537, 0.979, 0.9121),
    ("DmAVID\n+Iteration",             0.8831, 0.9510, 0.9158),
]
labels = [m[0] for m in methods]
prec = [m[1] for m in methods]
rec  = [m[2] for m in methods]
f1   = [m[3] for m in methods]

x = np.arange(len(methods)); w = 0.26
fig, ax = plt.subplots(figsize=(13, 7))
ax.bar(x - w, prec, w, label="Precision", color="#2196F3", edgecolor="white")
ax.bar(x,     rec,  w, label="Recall",    color="#FF9800", edgecolor="white")
b3 = ax.bar(x + w, f1, w, label="F1",      color="#4CAF50", edgecolor="white")
for r, v in zip(b3, f1):
    ax.text(r.get_x() + r.get_width()/2, v + 0.006, f"{v:.4f}", ha="center", fontsize=11, fontweight="bold")

ax.axvline(2.5, ls=":", color="#bbb")
ax.text(1.0, 0.585, "Literature Methods", color="#9aa", fontsize=11, ha="center")
ax.text(3.5, 0.585, "DmAVID (SmartBugs 243)", color="#5a9bd4", fontsize=11, ha="center")

ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=11)
ax.set_ylabel("Score"); ax.set_ylim(0.55, 1.06)
ax.set_title("DmAVID vs External Literature Methods\n(Cross-dataset comparison, for reference only)", fontsize=15)
ax.legend(loc="lower right", fontsize=11)
ax.grid(axis="y", alpha=0.25)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
fig.tight_layout()
out = CH / "fig4_1_literature_comparison.png"
fig.savefig(out, dpi=150); plt.close(fig)
print("Saved:", out)
