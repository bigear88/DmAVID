# -*- coding: utf-8 -*-
"""English vector version of the DmAVID information-processing flow figure
(for English journal submission). Outputs PDF (vector) + PNG."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.family"] = "DejaVu Sans"
plt.rcParams["axes.unicode_minus"] = False

OUT_PNG = "/home/curtis/DmAVID/supplementary_results/appendix_dmavid_flow_en.png"
OUT_PDF = "/home/curtis/DmAVID/supplementary_results/appendix_dmavid_flow_en.pdf"

fig, ax = plt.subplots(figsize=(11.0, 8.6))
ax.set_xlim(0, 100); ax.set_ylim(24, 100); ax.axis("off")

C_IN = "#E8EEF7"; C_DM = "#DCEBDC"; C_ML = "#F6E5D8"; C_OUT = "#F3E1EE"
EDGE = "#3A3A3A"


def box(cx, cy, w, h, text, fc, fs=10, bold=False):
    x, y = cx - w / 2, cy - h / 2
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.6,rounding_size=1.4",
                                linewidth=1.3, edgecolor=EDGE, facecolor=fc, zorder=2))
    ax.text(cx, cy, text, ha="center", va="center", fontsize=fs, zorder=3,
            fontweight="bold" if bold else "normal", linespacing=1.4)


def arrow(x1, y1, x2, y2):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=18,
                                 linewidth=1.4, color=EDGE, zorder=1, shrinkA=2, shrinkB=2))


box(50, 95, 76, 6.5,
    "Input: full smart-contract source code (.sol, uncompiled, untruncated)\n"
    "Example ETH_FUND:  L44 if(msg.sender.call.value(_am)())  →  L46 balances[msg.sender]-=_am;  (external call precedes state update)",
    C_IN, fs=9.5, bold=True)

arrow(38, 91.7, 27, 87.5)
arrow(62, 91.7, 76, 87.5)
ax.text(27, 88.8, "DmAVID (this work)", ha="center", fontsize=11, fontweight="bold", color="#245A24")
ax.text(76, 88.8, "Traditional ML (baseline)", ha="center", fontsize=11, fontweight="bold", color="#8A4A22")

# DmAVID lane
box(27, 82, 40, 8,
    "Stage 1: LLM + RAG Detection\n"
    "Retrieve relevant patterns from the ChromaDB\nvulnerability KB; LLM reasons at source level",
    C_DM, fs=9.5)
arrow(27, 77.8, 27, 73.2)
box(27, 69, 40, 8,
    "Stage 2: Self-Verify / Re-evaluation\n"
    "Gate α=0.75 (triggered iff stage1_safe ∧\nslither_high_med>0 ∧ conf<0.75); adds Slither evidence",
    C_DM, fs=9.5)
arrow(27, 64.8, 27, 60.2)
box(27, 55, 40, 9.5,
    "Stage 3: Multi-Agent Adversarial Iteration\n"
    "Coordinator → Student → Red Team variants\n"
    "→ Foundry(solc) compile-check → Blue Team patterns\n"
    "→ ChromaDB feedback loop; stop: ΔF1<0.01 or ≤3 rounds",
    C_DM, fs=9.0)

arrow(27, 50.0, 16, 44.5)
arrow(27, 50.0, 40, 44.5)
box(15.5, 37.5, 27, 12,
    "Output A: Binary label → F1\n"
    "Aggregate confusion (243 contracts)\n"
    "TP=136   FP=18\nFN=7    TN=82\n"
    "P=0.8831   R=0.9510\nF1=0.9158",
    C_OUT, fs=9.0)
box(41.5, 37.5, 30, 12,
    "Output B: Structured explanation report\n"
    "predicted_vulnerable=true\ntypes=[reentrancy]  severity=High\nconfidence=0.90\n"
    "reasoning (root cause + lines L44/L46\n+ missing mitigation)\nrepair (recommend CEI / ReentrancyGuard)\n→ CTC Correctness=8.881",
    C_OUT, fs=8.4)

# Traditional ML lane
box(76, 82, 38, 8,
    "Feature Extraction\n"
    "Treat source as text:\nTF-IDF (500) + 19 structural features\n(#functions, #external calls, code length...)",
    C_ML, fs=9.5)
arrow(76, 77.6, 76, 73.2)
box(76, 69, 38, 7,
    "Classifier\n"
    "Random Forest / Gradient Boosting /\nLogistic Regression / SVM",
    C_ML, fs=9.5)
arrow(76, 65.2, 76, 60.2)
box(76, 54, 38, 11,
    "Binary label → Confusion matrix → F1\n"
    "Random Forest (5-fold CV):\nP≈1.00  R≈0.986  F1≈0.993\n"
    "Note: high score = overfit to SmartBugs\nsurface statistics (shortcut features),\nnot semantics; collapses OOD (EVMbench)",
    C_ML, fs=8.8)

ax.text(50, 27,
        "Figure A-1. DmAVID information-processing flow: from .sol source input to F1 score and\n"
        "vulnerability explanation report (traditional ML shown for contrast).",
        ha="center", fontsize=11, fontweight="bold", linespacing=1.3)

plt.tight_layout()
fig.savefig(OUT_PNG, dpi=300, bbox_inches="tight", facecolor="white")
fig.savefig(OUT_PDF, bbox_inches="tight", facecolor="white")
print("saved", OUT_PNG)
print("saved", OUT_PDF)
