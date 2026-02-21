#!/usr/bin/env python3
"""
補充實驗分析腳本
- 混淆矩陣（所有方法）
- McNemar 統計檢驗
- DeFi 漏洞基線比較（Slither vs 本框架）
- 原始預測結果 CSV
- 成本敏感分析
"""

import json
import os
import csv
import numpy as np
from collections import defaultdict

BASE_DIR = "/home/ubuntu/defi-vuln-detection"
EXP_DIR = os.path.join(BASE_DIR, "experiments")
OUTPUT_DIR = os.path.join(BASE_DIR, "supplementary_results")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_results(method):
    """載入實驗結果"""
    method_dir = os.path.join(EXP_DIR, method)
    json_files = [f for f in os.listdir(method_dir) if f.endswith('.json')]
    if not json_files:
        return None
    with open(os.path.join(method_dir, json_files[0])) as f:
        return json.load(f)

def compute_confusion_matrix(results):
    """計算混淆矩陣"""
    tp = tn = fp = fn = 0
    for r in results:
        gt = r['ground_truth']  # 'vulnerable' or 'safe'
        pred = r.get('predicted_vulnerable', False)
        
        if gt == 'vulnerable' and pred:
            tp += 1
        elif gt == 'safe' and not pred:
            tn += 1
        elif gt == 'safe' and pred:
            fp += 1
        elif gt == 'vulnerable' and not pred:
            fn += 1
    
    return {'TP': tp, 'TN': tn, 'FP': fp, 'FN': fn}

def compute_metrics(cm):
    """從混淆矩陣計算所有指標"""
    tp, tn, fp, fn = cm['TP'], cm['TN'], cm['FP'], cm['FN']
    total = tp + tn + fp + fn
    
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    return {
        'Accuracy': round(accuracy, 4),
        'Precision': round(precision, 4),
        'Recall': round(recall, 4),
        'F1': round(f1, 4),
        'Specificity': round(specificity, 4),
        'FPR': round(fpr, 4),
        'Total': total
    }

def mcnemar_test(results_a, results_b, method_a_name, method_b_name):
    """McNemar 檢驗：比較兩個方法的預測差異"""
    # 建立合約ID到預測結果的映射
    pred_a = {}
    pred_b = {}
    
    for r in results_a:
        cid = r['contract_id']
        gt = r['ground_truth']
        pred = r.get('predicted_vulnerable', False)
        correct = (gt == 'vulnerable' and pred) or (gt == 'safe' and not pred)
        pred_a[cid] = correct
    
    for r in results_b:
        cid = r['contract_id']
        gt = r['ground_truth']
        pred = r.get('predicted_vulnerable', False)
        correct = (gt == 'vulnerable' and pred) or (gt == 'safe' and not pred)
        pred_b[cid] = correct
    
    # 找共同的合約
    common_ids = set(pred_a.keys()) & set(pred_b.keys())
    
    # 建立 2x2 列聯表
    # b: A正確 B錯誤
    # c: A錯誤 B正確
    b = sum(1 for cid in common_ids if pred_a[cid] and not pred_b[cid])
    c = sum(1 for cid in common_ids if not pred_a[cid] and pred_b[cid])
    a = sum(1 for cid in common_ids if pred_a[cid] and pred_b[cid])
    d = sum(1 for cid in common_ids if not pred_a[cid] and not pred_b[cid])
    
    # McNemar 檢驗統計量（帶連續性校正）
    if (b + c) == 0:
        chi2 = 0
        p_value = 1.0
    else:
        chi2 = (abs(b - c) - 1) ** 2 / (b + c)
        # 使用 chi-squared 分布 df=1 計算 p-value
        from scipy import stats
        p_value = 1 - stats.chi2.cdf(chi2, df=1)
    
    return {
        'method_a': method_a_name,
        'method_b': method_b_name,
        'common_contracts': len(common_ids),
        'both_correct': a,
        'a_correct_b_wrong': b,
        'a_wrong_b_correct': c,
        'both_wrong': d,
        'chi2_statistic': round(chi2, 4),
        'p_value': round(p_value, 6),
        'significant_at_005': bool(p_value < 0.05),
        'significant_at_001': bool(p_value < 0.01)
    }

def generate_prediction_csv(all_results, output_path):
    """生成每合約預測標籤 CSV"""
    rows = []
    
    for method, data in all_results.items():
        for r in data['results']:
            row = {
                'contract_id': r['contract_id'],
                'filename': r.get('filename', ''),
                'category': r.get('category', ''),
                'lines': r.get('lines', 0),
                'ground_truth': r['ground_truth'],
                'method': method,
                'predicted_vulnerable': r.get('predicted_vulnerable', False),
                'confidence': r.get('confidence', None),
                'time_seconds': r.get('time_seconds', r.get('total_time', 0)),
            }
            rows.append(row)
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'contract_id', 'filename', 'category', 'lines',
            'ground_truth', 'method', 'predicted_vulnerable',
            'confidence', 'time_seconds'
        ])
        writer.writeheader()
        writer.writerows(rows)
    
    return len(rows)

def defi_vulnerability_baseline(slither_results):
    """分析 Slither 在不同漏洞類型上的表現（作為 DeFi 基線）"""
    category_stats = defaultdict(lambda: {'tp': 0, 'fn': 0, 'total': 0})
    
    for r in slither_results:
        if r['ground_truth'] == 'vulnerable':
            cat = r.get('category', 'unknown')
            category_stats[cat]['total'] += 1
            if r.get('predicted_vulnerable', False):
                category_stats[cat]['tp'] += 1
            else:
                category_stats[cat]['fn'] += 1
    
    results = {}
    for cat, stats in category_stats.items():
        recall = stats['tp'] / stats['total'] if stats['total'] > 0 else 0
        results[cat] = {
            'total': stats['total'],
            'detected': stats['tp'],
            'missed': stats['fn'],
            'recall': round(recall, 4)
        }
    
    return results

def cost_sensitive_analysis(all_cms):
    """成本敏感分析：不同誤報/漏報成本比率下的最佳方法"""
    # 假設漏報成本是誤報成本的 N 倍
    cost_ratios = [1, 2, 5, 10, 20, 50]
    analysis = []
    
    for ratio in cost_ratios:
        best_method = None
        best_cost = float('inf')
        
        for method, cm in all_cms.items():
            # 總成本 = FP * 1 + FN * ratio
            cost = cm['FP'] * 1 + cm['FN'] * ratio
            if cost < best_cost:
                best_cost = cost
                best_method = method
        
        method_costs = {m: cm['FP'] * 1 + cm['FN'] * ratio 
                       for m, cm in all_cms.items()}
        
        analysis.append({
            'fn_fp_cost_ratio': ratio,
            'best_method': best_method,
            'best_cost': best_cost,
            'all_costs': method_costs
        })
    
    return analysis

# ===== 主程式 =====
print("=" * 60)
print("補充實驗分析")
print("=" * 60)

# 載入所有實驗結果
methods = ['slither', 'mythril', 'llm_base', 'llm_rag', 'hybrid']
method_names = {
    'slither': 'Slither',
    'mythril': 'Mythril', 
    'llm_base': 'LLM Base (GPT-4.1-mini)',
    'llm_rag': 'LLM + RAG',
    'hybrid': 'Hybrid (Slither + LLM + RAG)'
}

all_data = {}
for m in methods:
    data = load_results(m)
    if data:
        all_data[m] = data
        print(f"✓ 載入 {method_names[m]}: {len(data['results'])} 合約")

# ===== 1. 混淆矩陣 =====
print("\n" + "=" * 60)
print("1. 混淆矩陣")
print("=" * 60)

all_cms = {}
all_metrics = {}

for m, data in all_data.items():
    cm = compute_confusion_matrix(data['results'])
    metrics = compute_metrics(cm)
    all_cms[m] = cm
    all_metrics[m] = metrics
    
    print(f"\n--- {method_names[m]} ({metrics['Total']} 合約) ---")
    print(f"  TP={cm['TP']:4d}  FP={cm['FP']:4d}")
    print(f"  FN={cm['FN']:4d}  TN={cm['TN']:4d}")
    print(f"  Accuracy={metrics['Accuracy']:.4f}  Precision={metrics['Precision']:.4f}")
    print(f"  Recall={metrics['Recall']:.4f}  F1={metrics['F1']:.4f}")
    print(f"  Specificity={metrics['Specificity']:.4f}  FPR={metrics['FPR']:.4f}")

# 保存混淆矩陣
cm_output = {m: {'confusion_matrix': all_cms[m], 'metrics': all_metrics[m]} 
             for m in all_data}
with open(os.path.join(OUTPUT_DIR, 'confusion_matrices.json'), 'w') as f:
    json.dump(cm_output, f, indent=2)
print("\n✓ 混淆矩陣已保存至 confusion_matrices.json")

# ===== 2. McNemar 統計檢驗 =====
print("\n" + "=" * 60)
print("2. McNemar 統計檢驗")
print("=" * 60)

try:
    from scipy import stats
    
    # 比較本框架（LLM+RAG 和 Hybrid）與各基線
    comparisons = [
        ('llm_rag', 'slither'),
        ('llm_rag', 'llm_base'),
        ('hybrid', 'slither'),
        ('hybrid', 'llm_base'),
        ('llm_rag', 'hybrid'),
    ]
    
    mcnemar_results = []
    for m_a, m_b in comparisons:
        if m_a in all_data and m_b in all_data:
            result = mcnemar_test(
                all_data[m_a]['results'], 
                all_data[m_b]['results'],
                method_names[m_a],
                method_names[m_b]
            )
            mcnemar_results.append(result)
            
            sig = "***" if result['significant_at_001'] else ("**" if result['significant_at_005'] else "n.s.")
            print(f"\n{method_names[m_a]} vs {method_names[m_b]}:")
            print(f"  共同合約: {result['common_contracts']}")
            print(f"  χ² = {result['chi2_statistic']:.4f}, p = {result['p_value']:.6f} {sig}")
            print(f"  A正確B錯: {result['a_correct_b_wrong']}, A錯B正確: {result['a_wrong_b_correct']}")
    
    with open(os.path.join(OUTPUT_DIR, 'mcnemar_tests.json'), 'w') as f:
        json.dump(mcnemar_results, f, indent=2)
    print("\n✓ McNemar 檢驗結果已保存至 mcnemar_tests.json")

except ImportError:
    print("⚠ scipy 未安裝，跳過 McNemar 檢驗")

# ===== 3. 各漏洞類型的檢測表現（DeFi 基線比較）=====
print("\n" + "=" * 60)
print("3. 各漏洞類型的檢測表現比較")
print("=" * 60)

vuln_type_comparison = {}
for m in ['slither', 'llm_base', 'llm_rag', 'hybrid']:
    if m in all_data:
        vuln_type_comparison[m] = defi_vulnerability_baseline(all_data[m]['results'])

# 打印比較表
all_categories = set()
for m_data in vuln_type_comparison.values():
    all_categories.update(m_data.keys())

print(f"\n{'漏洞類型':<25} {'Slither':>10} {'LLM Base':>10} {'LLM+RAG':>10} {'Hybrid':>10}")
print("-" * 70)
for cat in sorted(all_categories):
    row = f"{cat:<25}"
    for m in ['slither', 'llm_base', 'llm_rag', 'hybrid']:
        if m in vuln_type_comparison and cat in vuln_type_comparison[m]:
            data = vuln_type_comparison[m][cat]
            row += f" {data['detected']}/{data['total']}({data['recall']:.0%})"
        else:
            row += f" {'N/A':>10}"
    print(row)

with open(os.path.join(OUTPUT_DIR, 'vulnerability_type_comparison.json'), 'w') as f:
    json.dump(vuln_type_comparison, f, indent=2)
print("\n✓ 漏洞類型比較已保存至 vulnerability_type_comparison.json")

# ===== 4. 原始預測結果 CSV =====
print("\n" + "=" * 60)
print("4. 原始預測結果 CSV")
print("=" * 60)

csv_path = os.path.join(OUTPUT_DIR, 'all_predictions.csv')
num_rows = generate_prediction_csv(all_data, csv_path)
print(f"✓ 已生成 {num_rows} 行預測結果 CSV: {csv_path}")

# 也生成每個方法的獨立 CSV
for m, data in all_data.items():
    method_csv_path = os.path.join(OUTPUT_DIR, f'{m}_predictions.csv')
    with open(method_csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'contract_id', 'filename', 'category', 'lines',
            'ground_truth', 'predicted_vulnerable', 'confidence', 'time_seconds'
        ])
        writer.writeheader()
        for r in data['results']:
            writer.writerow({
                'contract_id': r['contract_id'],
                'filename': r.get('filename', ''),
                'category': r.get('category', ''),
                'lines': r.get('lines', 0),
                'ground_truth': r['ground_truth'],
                'predicted_vulnerable': r.get('predicted_vulnerable', False),
                'confidence': r.get('confidence', None),
                'time_seconds': r.get('time_seconds', r.get('total_time', 0)),
            })
    print(f"  ✓ {method_names[m]}: {method_csv_path}")

# ===== 5. 成本敏感分析 =====
print("\n" + "=" * 60)
print("5. 成本敏感分析")
print("=" * 60)

# 只用 243 合約的方法比較
cms_243 = {m: cm for m, cm in all_cms.items() if m != 'mythril'}
cost_analysis = cost_sensitive_analysis(cms_243)

print(f"\n{'FN/FP成本比':>12} {'最佳方法':<30} {'總成本':>8}")
print("-" * 55)
for ca in cost_analysis:
    print(f"{ca['fn_fp_cost_ratio']:>12}x  {method_names[ca['best_method']]:<30} {ca['best_cost']:>8}")
    for m, cost in ca['all_costs'].items():
        print(f"{'':>15} {method_names[m]:<28} {cost:>8}")

with open(os.path.join(OUTPUT_DIR, 'cost_sensitive_analysis.json'), 'w') as f:
    json.dump(cost_analysis, f, indent=2, default=str)
print("\n✓ 成本敏感分析已保存至 cost_sensitive_analysis.json")

# ===== 6. 總結報告 =====
print("\n" + "=" * 60)
print("6. 總結")
print("=" * 60)

print("\n所有補充分析已完成：")
print(f"  1. 混淆矩陣: {OUTPUT_DIR}/confusion_matrices.json")
print(f"  2. McNemar 檢驗: {OUTPUT_DIR}/mcnemar_tests.json")
print(f"  3. 漏洞類型比較: {OUTPUT_DIR}/vulnerability_type_comparison.json")
print(f"  4. 預測結果 CSV: {OUTPUT_DIR}/all_predictions.csv")
print(f"  5. 成本敏感分析: {OUTPUT_DIR}/cost_sensitive_analysis.json")
