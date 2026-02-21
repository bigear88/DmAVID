#!/usr/bin/env python3
"""生成補充分析圖表：混淆矩陣熱力圖、McNemar 檢驗、成本敏感分析"""

import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import LinearSegmentedColormap

# 設定全域字體
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['font.size'] = 14

OUTPUT_DIR = "/home/ubuntu/defi-vuln-detection/charts"

# ============================================================
# 1. 混淆矩陣熱力圖（所有方法並排）
# ============================================================
print("生成混淆矩陣熱力圖...")

with open("/home/ubuntu/defi-vuln-detection/supplementary_results/confusion_matrices.json") as f:
    cm_data = json.load(f)

methods = ['slither', 'mythril', 'llm_base', 'llm_rag', 'hybrid']
method_labels = ['Slither', 'Mythril', 'LLM Base', 'LLM+RAG', 'Hybrid']

fig, axes = plt.subplots(1, 5, figsize=(24, 5.5))
fig.suptitle('Confusion Matrices for All Detection Methods', fontsize=20, fontweight='bold', y=1.02)

for idx, (method, label) in enumerate(zip(methods, method_labels)):
    ax = axes[idx]
    cm = cm_data[method]['confusion_matrix']
    matrix = np.array([[cm['TP'], cm['FN']], 
                       [cm['FP'], cm['TN']]])
    
    total = matrix.sum()
    
    # 使用藍色系
    cmap = LinearSegmentedColormap.from_list('custom', ['#f0f4ff', '#1a56db'], N=256)
    im = ax.imshow(matrix, cmap=cmap, aspect='auto')
    
    # 標註數值和百分比
    for i in range(2):
        for j in range(2):
            val = matrix[i, j]
            pct = val / total * 100
            color = 'white' if val > total * 0.3 else 'black'
            ax.text(j, i, f'{val}\n({pct:.1f}%)', ha='center', va='center',
                   fontsize=13, fontweight='bold', color=color)
    
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(['Positive', 'Negative'], fontsize=12)
    ax.set_yticklabels(['Positive', 'Negative'], fontsize=12)
    ax.set_xlabel('Predicted', fontsize=13, fontweight='bold')
    if idx == 0:
        ax.set_ylabel('Actual', fontsize=13, fontweight='bold')
    
    # 標題包含 F1 分數
    f1 = cm_data[method]['metrics']['F1']
    ax.set_title(f'{label}\nF1={f1:.3f}', fontsize=14, fontweight='bold', pad=10)

plt.tight_layout()
plt.savefig(f'{OUTPUT_DIR}/fig4_sup1_confusion_matrices.png', dpi=300, bbox_inches='tight',
            facecolor='white', edgecolor='none')
plt.close()
print(f"  ✓ 混淆矩陣熱力圖已保存")

# ============================================================
# 2. McNemar 檢驗結果圖
# ============================================================
print("生成 McNemar 檢驗結果圖...")

with open("/home/ubuntu/defi-vuln-detection/supplementary_results/mcnemar_tests.json") as f:
    mcnemar_data = json.load(f)

fig, ax = plt.subplots(figsize=(14, 7))

# 準備數據
comparisons = []
chi2_values = []
p_values = []
significances = []

for test in mcnemar_data:
    label = f"{test['method_a']}\nvs\n{test['method_b']}"
    comparisons.append(label)
    chi2_values.append(test['chi2_statistic'])
    p_values.append(test['p_value'])
    sig = '***' if test['significant_at_001'] else ('*' if test['significant_at_005'] else 'n.s.')
    significances.append(sig)

x = np.arange(len(comparisons))
colors = ['#dc2626' if s != 'n.s.' else '#9ca3af' for s in significances]

bars = ax.bar(x, chi2_values, color=colors, width=0.6, edgecolor='white', linewidth=1.5)

# 添加顯著性標記和 p 值
for i, (bar, sig, pv) in enumerate(zip(bars, significances, p_values)):
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height + 0.5,
            f'{sig}\np={pv:.4f}' if pv > 0 else f'{sig}\np<0.001',
            ha='center', va='bottom', fontsize=12, fontweight='bold')

# 添加顯著性閾值線
ax.axhline(y=3.841, color='#f59e0b', linestyle='--', linewidth=2, label='α=0.05 (χ²=3.841)')
ax.axhline(y=6.635, color='#dc2626', linestyle='--', linewidth=2, label='α=0.01 (χ²=6.635)')

ax.set_xticks(x)
ax.set_xticklabels(comparisons, fontsize=11)
ax.set_ylabel('McNemar χ² Statistic', fontsize=14, fontweight='bold')
ax.set_title('McNemar Test Results: Pairwise Method Comparisons', fontsize=18, fontweight='bold', pad=15)
ax.legend(fontsize=12, loc='upper right')
ax.set_ylim(0, max(chi2_values) * 1.3)
ax.grid(axis='y', alpha=0.3)

# 圖例
sig_patch = mpatches.Patch(color='#dc2626', label='Significant (p<0.05)')
ns_patch = mpatches.Patch(color='#9ca3af', label='Not Significant')
ax.legend(handles=[sig_patch, ns_patch, 
                   plt.Line2D([0], [0], color='#f59e0b', linestyle='--', linewidth=2, label='α=0.05'),
                   plt.Line2D([0], [0], color='#dc2626', linestyle='--', linewidth=2, label='α=0.01')],
         fontsize=11, loc='upper right')

plt.tight_layout()
plt.savefig(f'{OUTPUT_DIR}/fig4_sup2_mcnemar_tests.png', dpi=300, bbox_inches='tight',
            facecolor='white', edgecolor='none')
plt.close()
print(f"  ✓ McNemar 檢驗結果圖已保存")

# ============================================================
# 3. 成本敏感分析圖
# ============================================================
print("生成成本敏感分析圖...")

with open("/home/ubuntu/defi-vuln-detection/supplementary_results/cost_sensitive_analysis.json") as f:
    cost_data = json.load(f)

fig, ax = plt.subplots(figsize=(12, 7))

ratios = [d['fn_fp_cost_ratio'] for d in cost_data]
methods_cost = ['slither', 'llm_base', 'llm_rag', 'hybrid']
method_labels_cost = ['Slither', 'LLM Base', 'LLM+RAG', 'Hybrid']
colors_cost = ['#3b82f6', '#f59e0b', '#10b981', '#8b5cf6']
markers = ['o', 's', 'D', '^']

for method, label, color, marker in zip(methods_cost, method_labels_cost, colors_cost, markers):
    costs = [d['all_costs'][method] for d in cost_data]
    ax.plot(ratios, costs, color=color, marker=marker, linewidth=2.5, markersize=10,
            label=label, markeredgecolor='white', markeredgewidth=1.5)

ax.set_xlabel('FN/FP Cost Ratio (Higher = More Penalty for Missing Vulnerabilities)', 
              fontsize=13, fontweight='bold')
ax.set_ylabel('Total Misclassification Cost', fontsize=13, fontweight='bold')
ax.set_title('Cost-Sensitive Analysis: Method Comparison\nAcross Different FN/FP Cost Ratios', 
             fontsize=16, fontweight='bold', pad=15)
ax.legend(fontsize=13, loc='upper left', framealpha=0.9)
ax.grid(True, alpha=0.3)
ax.set_xticks(ratios)

# 標記最佳方法區域
ax.fill_between(ratios, 
                [d['all_costs']['llm_rag'] for d in cost_data],
                alpha=0.1, color='#10b981')
ax.annotate('LLM+RAG: Best across\nall cost ratios', 
            xy=(5, cost_data[2]['all_costs']['llm_rag']),
            xytext=(7, cost_data[2]['all_costs']['llm_rag'] + 30),
            fontsize=12, fontweight='bold', color='#10b981',
            arrowprops=dict(arrowstyle='->', color='#10b981', lw=2))

plt.tight_layout()
plt.savefig(f'{OUTPUT_DIR}/fig4_sup3_cost_sensitive.png', dpi=300, bbox_inches='tight',
            facecolor='white', edgecolor='none')
plt.close()
print(f"  ✓ 成本敏感分析圖已保存")

# ============================================================
# 4. 漏洞類型檢測比較圖
# ============================================================
print("生成漏洞類型檢測比較圖...")

with open("/home/ubuntu/defi-vuln-detection/supplementary_results/vulnerability_type_comparison.json") as f:
    vuln_type_data = json.load(f)

fig, ax = plt.subplots(figsize=(14, 7))

categories = list(vuln_type_data.keys())
methods_vt = ['slither', 'llm_base', 'llm_rag', 'hybrid']
method_labels_vt = ['Slither', 'LLM Base', 'LLM+RAG', 'Hybrid']
colors_vt = ['#3b82f6', '#f59e0b', '#10b981', '#8b5cf6']

x = np.arange(len(categories))
width = 0.2

for i, (method, label, color) in enumerate(zip(methods_vt, method_labels_vt, colors_vt)):
    recalls = []
    for cat in categories:
        cat_data = vuln_type_data[cat]
        if method in cat_data:
            recalls.append(cat_data[method].get('recall', 0))
        else:
            recalls.append(0)
    
    bars = ax.bar(x + i * width, recalls, width, label=label, color=color, 
                  edgecolor='white', linewidth=1)
    
    # 標註數值
    for bar, val in zip(bars, recalls):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.01,
                   f'{val:.0%}', ha='center', va='bottom', fontsize=9, fontweight='bold')

ax.set_xlabel('Vulnerability Type', fontsize=14, fontweight='bold')
ax.set_ylabel('Recall', fontsize=14, fontweight='bold')
ax.set_title('Detection Recall by Vulnerability Type', fontsize=18, fontweight='bold', pad=15)
ax.set_xticks(x + width * 1.5)
ax.set_xticklabels([c.replace('_', '\n') for c in categories], fontsize=11)
ax.legend(fontsize=12, loc='lower right')
ax.set_ylim(0, 1.15)
ax.grid(axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig(f'{OUTPUT_DIR}/fig4_sup4_vuln_type_recall.png', dpi=300, bbox_inches='tight',
            facecolor='white', edgecolor='none')
plt.close()
print(f"  ✓ 漏洞類型檢測比較圖已保存")

print("\n=== 所有補充圖表生成完成 ===")
print(f"輸出目錄: {OUTPUT_DIR}")
