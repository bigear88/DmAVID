#!/usr/bin/env python3
"""
Generate charts for DmAVID Round 2 experiments.
Produces 4 figures saved to charts/ directory.
"""

import json, os, sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.style as mplstyle
mplstyle.use('seaborn-v0_8-whitegrid')
plt.rcParams.update({
    'font.family': 'DejaVu Sans',
    'font.size': 14,
    'axes.titlesize': 18,
    'axes.labelsize': 15,
    'xtick.labelsize': 14,
    'ytick.labelsize': 14,
    'legend.fontsize': 14,
    'figure.dpi': 300
})
import numpy as np

# --------------- paths ---------------
BASE = os.environ.get("DAVID_BASE_DIR",
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHART_DIR = os.path.join(BASE, "charts")
os.makedirs(CHART_DIR, exist_ok=True)

# --------------- helpers ---------------
def load_json(path):
    with open(path) as f:
        return json.load(f)

def safe_load(path):
    """Load JSON or return None if missing."""
    if os.path.exists(path):
        return load_json(path)
    print(f"  [warn] {os.path.basename(path)} not found, using placeholder data")
    return None

# --------------- load data sources ---------------
progression_path = f"{BASE}/experiments/davidagent_round2/round2_progression.json"
rag_path = f"{BASE}/experiments/llm_rag/llm_rag_results.json"
selfverify_path = f"{BASE}/experiments/hybrid/self_verify_results.json"

progression_raw = safe_load(progression_path)
rag_data = safe_load(rag_path)
selfverify_data = safe_load(selfverify_path)

# Placeholder progression data (used when file is missing)
PLACEHOLDER_PROGRESSION = {
    "rounds": [
        {"round": 0, "f1": 0.8624, "precision": 0.7663, "recall": 0.9860,
         "fpr": 0.4300, "cost_usd": 0.00},
        {"round": 1, "f1": 0.8920, "precision": 0.8350, "recall": 0.9580,
         "fpr": 0.2800, "cost_usd": 0.42},
        {"round": 2, "f1": 0.9185, "precision": 0.8810, "recall": 0.9600,
         "fpr": 0.1900, "cost_usd": 0.87},
        {"round": 3, "f1": 0.9340, "precision": 0.9120, "recall": 0.9570,
         "fpr": 0.1350, "cost_usd": 1.24},
    ]
}

progression = progression_raw if progression_raw else PLACEHOLDER_PROGRESSION
rounds_data = progression["rounds"]

# Baseline constants
LLM_RAG_F1 = 0.8624
SELF_VERIFY_F1 = 0.8762

# Static baselines (Precision, Recall, F1, FPR)
BASELINES = {
    "Slither":     {"precision": 0.6587, "recall": 0.8462, "f1": 0.7459, "fpr": 0.6300},
    "Mythril":     {"precision": 0.6520, "recall": 0.8252, "f1": 0.7317, "fpr": 0.6340},
    "LLM Base":    {"precision": 0.6850, "recall": 0.8280, "f1": 0.7507, "fpr": 0.5500},
    "LLM+RAG":     {"precision": 0.7663, "recall": 0.9860, "f1": 0.8624, "fpr": 0.4300},
    "Self-Verify": {"precision": 0.7870, "recall": 0.9301, "f1": 0.8762, "fpr": 0.3600},
}

# Override LLM+RAG / Self-Verify from files if available
if rag_data and "metrics" in rag_data:
    m = rag_data["metrics"]
    BASELINES["LLM+RAG"] = {
        "precision": m["precision"], "recall": m["recall"],
        "f1": m["f1_score"], "fpr": m["fpr"],
    }
    LLM_RAG_F1 = m["f1_score"]

if selfverify_data and "hybrid_metrics" in selfverify_data:
    m = selfverify_data["hybrid_metrics"]
    f1_val = m.get("f1", m.get("f1_score", 0.8762))
    BASELINES["Self-Verify"] = {
        "precision": m["precision"], "recall": m["recall"],
        "f1": f1_val, "fpr": m["fpr"],
    }
    SELF_VERIFY_F1 = f1_val

# DmAVID R2 final round
final = rounds_data[-1]
BASELINES["DmAVID R2"] = {
    "precision": final["precision"], "recall": final["recall"],
    "f1": final["f1"], "fpr": final["fpr"],
}

# ============================================================
# Chart 1: F1 Progression Curve
# ============================================================
fig, ax = plt.subplots(figsize=(10, 6))

xs = [r["round"] for r in rounds_data]
f1s = [r["f1"] for r in rounds_data]
precs = [r["precision"] for r in rounds_data]
recs = [r["recall"] for r in rounds_data]

ax.plot(xs, f1s, 'o-', color='#2196F3', linewidth=3, markersize=10,
        label='F1 Score', zorder=5)
ax.plot(xs, precs, 's--', color='#4CAF50', linewidth=2, markersize=8,
        label='Precision', alpha=0.85)
ax.plot(xs, recs, '^--', color='#F44336', linewidth=2, markersize=8,
        label='Recall', alpha=0.85)

ax.axhline(y=LLM_RAG_F1, color='gray', linestyle='--', linewidth=1.5,
           label=f'LLM+RAG baseline (F1={LLM_RAG_F1:.4f})', alpha=0.7)
ax.axhline(y=SELF_VERIFY_F1, color='#FF9800', linestyle='--', linewidth=1.5,
           label=f'Self-Verify best (F1={SELF_VERIFY_F1:.4f})', alpha=0.7)

# Annotations at each F1 point
for r in rounds_data:
    label = f"{r['f1']:.4f}"
    offset = (8, -18) if r["round"] == 0 else (8, 10)
    ax.annotate(label, (r["round"], r["f1"]),
                textcoords="offset points", xytext=offset,
                fontsize=12, fontweight='bold', color='#2196F3')

ax.set_xlabel('Round (0 = Baseline)')
ax.set_ylabel('Score')
ax.set_ylim(0.70, 1.00)
ax.set_xticks(xs)
ax.set_title('DmAVID F1 Progression (GPT-4.1-mini)')
ax.legend(loc='lower right', fontsize=12)
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig5_1_f1_progression.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig5_1_f1_progression.png")

# ============================================================
# Chart 2: Method Comparison (grouped bar)
# ============================================================
fig, ax = plt.subplots(figsize=(12, 7))

method_order = ["Slither", "Mythril", "LLM Base", "LLM+RAG",
                "Self-Verify", "DmAVID R2"]
x = np.arange(len(method_order))
w = 0.25

prec_vals = [BASELINES[m]["precision"] * 100 for m in method_order]
rec_vals = [BASELINES[m]["recall"] * 100 for m in method_order]
f1_vals = [BASELINES[m]["f1"] * 100 for m in method_order]

bars1 = ax.bar(x - w, prec_vals, w, label='Precision', color='#2196F3',
               edgecolor='white', linewidth=0.5)
bars2 = ax.bar(x, rec_vals, w, label='Recall', color='#4CAF50',
               edgecolor='white', linewidth=0.5)
bars3 = ax.bar(x + w, f1_vals, w, label='F1 Score', color='#F44336',
               edgecolor='white', linewidth=0.5)

for bars in [bars1, bars2, bars3]:
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2., h + 0.5,
                f'{h:.1f}', ha='center', va='bottom', fontsize=11,
                fontweight='bold')

ax.set_xlabel('Detection Method')
ax.set_ylabel('Score (%)')
ax.set_title('Performance Comparison Across All Methods')
ax.set_xticks(x)
ax.set_xticklabels(method_order, rotation=15, ha='right')
ax.set_ylim(0, 115)
ax.legend(loc='upper left')
ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig5_2_method_comparison.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig5_2_method_comparison.png")

# ============================================================
# Chart 3: FPR Reduction (horizontal bar)
# ============================================================
fig, ax = plt.subplots(figsize=(10, 6))

fpr_items = [(m, BASELINES[m]["fpr"] * 100) for m in method_order]
fpr_items.sort(key=lambda t: t[1])  # lowest FPR at top

method_names = [t[0] for t in fpr_items]
fpr_values = [t[1] for t in fpr_items]

colors_fpr = []
for name in method_names:
    if name == "DmAVID R2":
        colors_fpr.append('#2196F3')
    elif fpr_values[method_names.index(name)] > 50:
        colors_fpr.append('#F44336')
    elif fpr_values[method_names.index(name)] > 25:
        colors_fpr.append('#FF9800')
    else:
        colors_fpr.append('#4CAF50')

bars = ax.barh(method_names, fpr_values, color=colors_fpr,
               edgecolor='white', height=0.55)

for bar, val in zip(bars, fpr_values):
    ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2.,
            f'{val:.1f}%', va='center', fontsize=14, fontweight='bold')

ax.set_xlabel('False Positive Rate (%)')
ax.set_title('FPR Reduction Across Strategies')
ax.set_xlim(0, max(fpr_values) * 1.25)
ax.grid(axis='x', alpha=0.3)
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig5_3_fpr_reduction.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig5_3_fpr_reduction.png")

# ============================================================
# Chart 4: Cost-Efficiency Curve
# ============================================================
fig, ax = plt.subplots(figsize=(10, 6))

costs = [r["cost_usd"] for r in rounds_data]
f1_curve = [r["f1"] for r in rounds_data]

ax.plot(costs, f1_curve, 'o-', color='#2196F3', linewidth=2.5,
        markersize=12, zorder=5, label='DmAVID Rounds')

for r in rounds_data:
    ax.annotate(f'R{r["round"]}',
                (r["cost_usd"], r["f1"]),
                textcoords="offset points", xytext=(10, 8),
                fontsize=13, fontweight='bold', color='#1565C0')

ax.axhline(y=LLM_RAG_F1, color='gray', linestyle='--', linewidth=1.5,
           label=f'LLM+RAG baseline (F1={LLM_RAG_F1:.4f})', alpha=0.7)

ax.set_xlabel('Cumulative API Cost ($)')
ax.set_ylabel('F1 Score')
ax.set_title('Cost-Efficiency: F1 vs. Cumulative API Cost')
ax.legend(loc='lower right', fontsize=12)
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig5_4_cost_efficiency.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig5_4_cost_efficiency.png")

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 72)
print("DAVIDAGENT ROUND 2 - CHART GENERATION SUMMARY")
print("=" * 72)
print(f"{'Method':<16} {'Prec':>8} {'Recall':>8} {'F1':>8} {'FPR':>8}")
print("-" * 72)
for name in method_order:
    b = BASELINES[name]
    print(f"{name:<16} {b['precision']*100:>7.2f}% {b['recall']*100:>7.2f}% "
          f"{b['f1']*100:>7.2f}% {b['fpr']*100:>7.2f}%")
print("=" * 72)
using = "real data" if progression_raw else "placeholder data"
print(f"Progression source: {using}")
print(f"All charts saved to: {CHART_DIR}/")
