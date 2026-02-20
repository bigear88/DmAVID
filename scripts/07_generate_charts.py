#!/usr/bin/env python3
"""
Generate all experiment charts from real experiment data.
"""

import json, os
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
    'xtick.labelsize': 12,
    'ytick.labelsize': 12,
    'legend.fontsize': 12,
    'figure.dpi': 300
})
import numpy as np

BASE = "/home/ubuntu/defi-vuln-detection"
CHART_DIR = os.path.join(BASE, "charts")
os.makedirs(CHART_DIR, exist_ok=True)

# Load all results
def load_json(path):
    with open(path) as f:
        return json.load(f)

slither = load_json(f"{BASE}/experiments/slither/slither_results.json")
mythril = load_json(f"{BASE}/experiments/mythril/mythril_results.json")
llm_base = load_json(f"{BASE}/experiments/llm_base/llm_base_results.json")
llm_rag = load_json(f"{BASE}/experiments/llm_rag/llm_rag_results.json")
hybrid = load_json(f"{BASE}/experiments/hybrid/hybrid_results.json")

methods = ["Slither", "Mythril", "LLM Base", "LLM+RAG", "Hybrid"]
metrics_all = [slither["metrics"], mythril["metrics"], llm_base["metrics"], llm_rag["metrics"], hybrid["metrics"]]

# ============================================================
# Fig 1: Theoretical Comparison (Precision, Recall, F1)
# ============================================================
fig, ax = plt.subplots(figsize=(12, 7))
x = np.arange(len(methods))
w = 0.25
prec = [m["precision"]*100 for m in metrics_all]
rec = [m["recall"]*100 for m in metrics_all]
f1 = [m["f1_score"]*100 for m in metrics_all]

bars1 = ax.bar(x - w, prec, w, label='Precision', color='#2196F3', edgecolor='white', linewidth=0.5)
bars2 = ax.bar(x, rec, w, label='Recall', color='#4CAF50', edgecolor='white', linewidth=0.5)
bars3 = ax.bar(x + w, f1, w, label='F1 Score', color='#FF9800', edgecolor='white', linewidth=0.5)

for bars in [bars1, bars2, bars3]:
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 0.5, f'{h:.1f}', ha='center', va='bottom', fontsize=10, fontweight='bold')

ax.set_xlabel('Detection Method')
ax.set_ylabel('Score (%)')
ax.set_title('Performance Comparison Across Detection Methods')
ax.set_xticks(x)
ax.set_xticklabels(methods)
ax.set_ylim(0, 115)
ax.legend(loc='upper right')
ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig4_1_performance_comparison.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig4_1_performance_comparison.png")

# ============================================================
# Fig 2: Empirical Comparison (Accuracy, Specificity, FPR)
# ============================================================
fig, ax = plt.subplots(figsize=(12, 7))
acc = [m["accuracy"]*100 for m in metrics_all]
spec = [m["specificity"]*100 for m in metrics_all]
fpr = [m["fpr"]*100 for m in metrics_all]

bars1 = ax.bar(x - w, acc, w, label='Accuracy', color='#3F51B5', edgecolor='white')
bars2 = ax.bar(x, spec, w, label='Specificity', color='#009688', edgecolor='white')
bars3 = ax.bar(x + w, fpr, w, label='FPR', color='#F44336', edgecolor='white')

for bars in [bars1, bars2, bars3]:
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 0.5, f'{h:.1f}', ha='center', va='bottom', fontsize=10, fontweight='bold')

ax.set_xlabel('Detection Method')
ax.set_ylabel('Rate (%)')
ax.set_title('Accuracy, Specificity and False Positive Rate Comparison')
ax.set_xticks(x)
ax.set_xticklabels(methods)
ax.set_ylim(0, 115)
ax.legend(loc='upper right')
ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig4_2_empirical_comparison.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig4_2_empirical_comparison.png")

# ============================================================
# Fig 3: FPR Comparison (dedicated chart)
# ============================================================
fig, ax = plt.subplots(figsize=(10, 6))
colors = ['#F44336' if f > 50 else '#FF9800' if f > 20 else '#4CAF50' for f in fpr]
bars = ax.barh(methods, fpr, color=colors, edgecolor='white', height=0.5)
for bar, val in zip(bars, fpr):
    ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2., f'{val:.1f}%', va='center', fontsize=13, fontweight='bold')
ax.set_xlabel('False Positive Rate (%)')
ax.set_title('False Positive Rate Comparison')
ax.set_xlim(0, 110)
ax.grid(axis='x', alpha=0.3)
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig4_3_fpr_comparison.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig4_3_fpr_comparison.png")

# ============================================================
# Fig 4: Time vs F1 Trade-off
# ============================================================
fig, ax = plt.subplots(figsize=(10, 7))
times = [m.get("avg_time_seconds", m.get("avg_total_time", 0)) for m in metrics_all]
f1_scores = [m["f1_score"]*100 for m in metrics_all]
colors_scatter = ['#2196F3', '#9C27B0', '#FF9800', '#4CAF50', '#F44336']
sizes = [200, 200, 200, 300, 250]

for i, method in enumerate(methods):
    ax.scatter(times[i], f1_scores[i], s=sizes[i], c=colors_scatter[i], label=method, zorder=5, edgecolors='white', linewidth=2)
    ax.annotate(method, (times[i], f1_scores[i]), textcoords="offset points", xytext=(10, 10), fontsize=12, fontweight='bold')

ax.set_xlabel('Average Time per Contract (seconds)')
ax.set_ylabel('F1 Score (%)')
ax.set_title('Detection Time vs. F1 Score Trade-off')
ax.grid(True, alpha=0.3)
ax.legend(loc='lower right')
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig4_4_time_f1_tradeoff.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig4_4_time_f1_tradeoff.png")

# ============================================================
# Fig 5: Ablation Study (LLM Base -> +RAG -> +Slither)
# ============================================================
fig, ax = plt.subplots(figsize=(10, 7))
ablation_methods = ['LLM Base', 'LLM + RAG', 'Hybrid\n(Slither+LLM+RAG)']
ablation_f1 = [llm_base["metrics"]["f1_score"]*100, llm_rag["metrics"]["f1_score"]*100, hybrid["metrics"]["f1_score"]*100]
ablation_fpr = [llm_base["metrics"]["fpr"]*100, llm_rag["metrics"]["fpr"]*100, hybrid["metrics"]["fpr"]*100]
ablation_prec = [llm_base["metrics"]["precision"]*100, llm_rag["metrics"]["precision"]*100, hybrid["metrics"]["precision"]*100]

x_ab = np.arange(len(ablation_methods))
w_ab = 0.25
bars1 = ax.bar(x_ab - w_ab, ablation_f1, w_ab, label='F1 Score', color='#FF9800', edgecolor='white')
bars2 = ax.bar(x_ab, ablation_prec, w_ab, label='Precision', color='#2196F3', edgecolor='white')
bars3 = ax.bar(x_ab + w_ab, ablation_fpr, w_ab, label='FPR', color='#F44336', edgecolor='white')

for bars in [bars1, bars2, bars3]:
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 0.5, f'{h:.1f}', ha='center', va='bottom', fontsize=11, fontweight='bold')

ax.set_ylabel('Score (%)')
ax.set_title('Ablation Study: Component Contribution Analysis')
ax.set_xticks(x_ab)
ax.set_xticklabels(ablation_methods)
ax.set_ylim(0, 115)
ax.legend()
ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig4_5_ablation_study.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig4_5_ablation_study.png")

# ============================================================
# Fig 6: Improvement from RAG
# ============================================================
fig, ax = plt.subplots(figsize=(10, 7))
metrics_names = ['Accuracy', 'Precision', 'Recall', 'F1 Score', 'Specificity']
base_vals = [llm_base["metrics"]["accuracy"]*100, llm_base["metrics"]["precision"]*100, 
             llm_base["metrics"]["recall"]*100, llm_base["metrics"]["f1_score"]*100, llm_base["metrics"]["specificity"]*100]
rag_vals = [llm_rag["metrics"]["accuracy"]*100, llm_rag["metrics"]["precision"]*100,
            llm_rag["metrics"]["recall"]*100, llm_rag["metrics"]["f1_score"]*100, llm_rag["metrics"]["specificity"]*100]
improvements = [r - b for r, b in zip(rag_vals, base_vals)]

x_imp = np.arange(len(metrics_names))
colors_imp = ['#4CAF50' if v > 0 else '#F44336' for v in improvements]
bars = ax.bar(x_imp, improvements, color=colors_imp, edgecolor='white', width=0.5)
for bar, val in zip(bars, improvements):
    h = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., h + (0.5 if h > 0 else -2), f'{val:+.1f}%', ha='center', va='bottom' if h > 0 else 'top', fontsize=13, fontweight='bold')

ax.set_ylabel('Improvement (%)')
ax.set_title('RAG Enhancement: Improvement over Base LLM')
ax.set_xticks(x_imp)
ax.set_xticklabels(metrics_names)
ax.axhline(y=0, color='black', linewidth=0.5)
ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig4_6_rag_improvement.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig4_6_rag_improvement.png")

# ============================================================
# Fig 7: Vulnerability Type Heatmap (LLM+RAG per-category)
# ============================================================
fig, ax = plt.subplots(figsize=(12, 7))
rag_results = llm_rag["results"]
categories = sorted(set(r["category"] for r in rag_results if r["ground_truth"] == "vulnerable"))

cat_metrics = {}
for cat in categories:
    cat_r = [r for r in rag_results if r["category"] == cat and r["ground_truth"] == "vulnerable"]
    tp = sum(1 for r in cat_r if r["predicted_vulnerable"])
    fn = len(cat_r) - tp
    recall = tp / len(cat_r) if len(cat_r) > 0 else 0
    cat_metrics[cat] = {"tp": tp, "fn": fn, "total": len(cat_r), "recall": recall}

cat_names = list(cat_metrics.keys())
recalls = [cat_metrics[c]["recall"]*100 for c in cat_names]
totals = [cat_metrics[c]["total"] for c in cat_names]

colors_heat = ['#4CAF50' if r >= 95 else '#FF9800' if r >= 80 else '#F44336' for r in recalls]
bars = ax.barh(cat_names, recalls, color=colors_heat, edgecolor='white', height=0.6)
for bar, val, total in zip(bars, recalls, totals):
    ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2., 
            f'{val:.1f}% (n={total})', va='center', fontsize=12, fontweight='bold')

ax.set_xlabel('Recall (%)')
ax.set_title('LLM+RAG Detection Recall by Vulnerability Category')
ax.set_xlim(0, 115)
ax.grid(axis='x', alpha=0.3)
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig4_7_category_recall.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig4_7_category_recall.png")

# ============================================================
# Fig 8: Radar Chart (multi-dimensional comparison)
# ============================================================
fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(polar=True))
radar_metrics = ['Precision', 'Recall', 'F1 Score', 'Specificity', 'Speed']
# Normalize speed: inverse of time, scaled to 0-1
max_time = max(m.get("avg_time_seconds", m.get("avg_total_time", 1)) for m in metrics_all)
speed_scores = [1 - (m.get("avg_time_seconds", m.get("avg_total_time", 0))/max_time) for m in metrics_all]

radar_data = []
for i, m in enumerate(metrics_all):
    radar_data.append([m["precision"], m["recall"], m["f1_score"], m["specificity"], speed_scores[i]])

angles = np.linspace(0, 2*np.pi, len(radar_metrics), endpoint=False).tolist()
angles += angles[:1]

colors_radar = ['#2196F3', '#9C27B0', '#FF9800', '#4CAF50', '#F44336']
for i, (data, method) in enumerate(zip(radar_data, methods)):
    values = data + data[:1]
    ax.plot(angles, values, 'o-', linewidth=2, label=method, color=colors_radar[i])
    ax.fill(angles, values, alpha=0.1, color=colors_radar[i])

ax.set_xticks(angles[:-1])
ax.set_xticklabels(radar_metrics, fontsize=13)
ax.set_ylim(0, 1.1)
ax.set_title('Multi-dimensional Performance Radar Chart', pad=20, fontsize=16)
ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1))
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig4_8_radar_chart.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig4_8_radar_chart.png")

# ============================================================
# Fig 9: ROC-like curve (Recall vs FPR)
# ============================================================
fig, ax = plt.subplots(figsize=(9, 8))
fpr_vals = [m["fpr"] for m in metrics_all]
rec_vals = [m["recall"] for m in metrics_all]

for i, method in enumerate(methods):
    ax.scatter(fpr_vals[i], rec_vals[i], s=250, c=colors_scatter[i], label=method, zorder=5, edgecolors='white', linewidth=2)
    offset = (10, 10) if method != "LLM Base" else (10, -15)
    ax.annotate(method, (fpr_vals[i], rec_vals[i]), textcoords="offset points", xytext=offset, fontsize=12, fontweight='bold')

ax.plot([0, 1], [0, 1], 'k--', alpha=0.3, label='Random Classifier')
ax.set_xlabel('False Positive Rate')
ax.set_ylabel('True Positive Rate (Recall)')
ax.set_title('ROC Space: Detection Methods Comparison')
ax.set_xlim(-0.05, 1.05)
ax.set_ylim(-0.05, 1.05)
ax.legend(loc='lower right')
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig4_9_roc_space.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig4_9_roc_space.png")

# ============================================================
# Fig 10: Confusion Matrix for LLM+RAG (best method)
# ============================================================
fig, ax = plt.subplots(figsize=(8, 7))
m = llm_rag["metrics"]
cm = np.array([[m["tp"], m["fn"]], [m["fp"], m["tn"]]])
im = ax.imshow(cm, interpolation='nearest', cmap='Blues')
ax.set_xticks([0, 1])
ax.set_yticks([0, 1])
ax.set_xticklabels(['Predicted\nVulnerable', 'Predicted\nSafe'], fontsize=13)
ax.set_yticklabels(['Actually\nVulnerable', 'Actually\nSafe'], fontsize=13)
ax.set_title('Confusion Matrix: LLM+RAG Method', fontsize=16)

for i in range(2):
    for j in range(2):
        color = 'white' if cm[i, j] > cm.max()/2 else 'black'
        ax.text(j, i, str(cm[i, j]), ha='center', va='center', fontsize=28, fontweight='bold', color=color)

fig.colorbar(im, ax=ax, shrink=0.8)
plt.tight_layout()
plt.savefig(f"{CHART_DIR}/fig4_10_confusion_matrix.png", dpi=300, bbox_inches='tight')
plt.close()
print("Generated: fig4_10_confusion_matrix.png")

# ============================================================
# Summary table
# ============================================================
print("\n" + "=" * 80)
print("COMPLETE EXPERIMENT RESULTS SUMMARY")
print("=" * 80)
print(f"{'Method':<15} {'Acc':>8} {'Prec':>8} {'Recall':>8} {'F1':>8} {'FPR':>8} {'Spec':>8} {'Time':>8}")
print("-" * 80)
for method, m in zip(methods, metrics_all):
    t = m.get("avg_time_seconds", m.get("avg_total_time", 0))
    print(f"{method:<15} {m['accuracy']*100:>7.2f}% {m['precision']*100:>7.2f}% {m['recall']*100:>7.2f}% "
          f"{m['f1_score']*100:>7.2f}% {m['fpr']*100:>7.2f}% {m['specificity']*100:>7.2f}% {t:>7.3f}s")
print("=" * 80)
print(f"\nAll charts saved to: {CHART_DIR}/")
print(f"Total charts generated: {len(os.listdir(CHART_DIR))}")
