#!/usr/bin/env python3
"""Generate EVMbench experiment charts for presentation slides."""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import os

# Apply style first, then set fonts
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['Noto Sans CJK SC', 'Noto Sans CJK HK', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['figure.dpi'] = 200
plt.rcParams['savefig.dpi'] = 200

OUTPUT_DIR = '/home/ubuntu/evmbench_charts'
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Color palette
COLORS = {
    'primary': '#2563EB',
    'secondary': '#7C3AED',
    'success': '#10B981',
    'warning': '#F59E0B',
    'danger': '#EF4444',
    'gray': '#6B7280',
    'light_blue': '#DBEAFE',
    'light_purple': '#EDE9FE',
    'light_green': '#D1FAE5',
    'dark': '#1F2937',
}

# ============================================================
# Chart 1: Per-audit detect score bar chart
# ============================================================
def chart_per_audit_scores():
    audits = [
        '2024-01-curves', '2024-03-taiko', '2024-05-olas',
        '2024-07-basin', '2024-01-renft', '2024-06-size',
        '2024-08-phi', '2024-12-secondswap', '2025-04-forte',
        '2026-01-tempo'
    ]
    scores = [25.0, 0.0, 0.0, 0.0, 0.0, 0.0, 16.67, 0.0, 0.0, 33.33]
    gold_vulns = [4, 5, 2, 2, 6, 4, 6, 3, 5, 3]
    detected = [1, 0, 0, 0, 0, 0, 1, 0, 0, 1]

    fig, ax = plt.subplots(figsize=(14, 6))
    
    bar_colors = [COLORS['success'] if s > 0 else COLORS['gray'] for s in scores]
    bars = ax.bar(range(len(audits)), scores, color=bar_colors, width=0.6, edgecolor='white', linewidth=1.5)
    
    # Add labels on bars
    for i, (bar, score, d, g) in enumerate(zip(bars, scores, detected, gold_vulns)):
        if score > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    f'{d}/{g}', ha='center', va='bottom', fontsize=11, fontweight='bold', color=COLORS['dark'])
        else:
            ax.text(bar.get_x() + bar.get_width()/2, 1,
                    f'0/{g}', ha='center', va='bottom', fontsize=10, color=COLORS['gray'])
    
    # Average line
    avg = 7.50
    ax.axhline(y=avg, color=COLORS['danger'], linestyle='--', linewidth=2, alpha=0.8)
    ax.text(len(audits)-0.5, avg + 1.5, f'平均: {avg}%', ha='right', fontsize=11,
            color=COLORS['danger'], fontweight='bold')
    
    ax.set_xticks(range(len(audits)))
    ax.set_xticklabels(audits, rotation=35, ha='right', fontsize=9)
    ax.set_ylabel('Detect Score (%)', fontsize=12)
    ax.set_title('EVMbench 逐審計偵測分數', fontsize=14, fontweight='bold', pad=15)
    ax.set_ylim(0, 42)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'evmbench_per_audit_scores.png'), bbox_inches='tight', facecolor='white')
    plt.close()
    print("✓ Chart 1: Per-audit scores")

# ============================================================
# Chart 2: Comparison - SmartBugs vs EVMbench
# ============================================================
def chart_comparison():
    fig, ax = plt.subplots(figsize=(10, 6))
    
    categories = ['SmartBugs\n(LLM+RAG)', 'EVMbench\n(LLM+RAG)', 'EVMbench\n(Codex Agent)*']
    values = [88.61, 7.50, 70.0]
    colors = [COLORS['primary'], COLORS['secondary'], COLORS['warning']]
    
    bars = ax.bar(range(len(categories)), values, color=colors, width=0.5, edgecolor='white', linewidth=2)
    
    for bar, val in zip(bars, values):
        label = f'{val:.1f}%' if val != 70.0 else f'~{val:.0f}%*'
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1.5,
                label, ha='center', va='bottom', fontsize=13, fontweight='bold', color=COLORS['dark'])
    
    ax.set_xticks(range(len(categories)))
    ax.set_xticklabels(categories, fontsize=11)
    ax.set_ylabel('偵測效能 (%)', fontsize=12)
    ax.set_title('跨基準測試偵測效能比較', fontsize=14, fontweight='bold', pad=15)
    ax.set_ylim(0, 100)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    ax.text(0.98, 0.02, '*Codex Agent 數據引用自 Paradigm EVMbench 報告 (2026/02)',
            transform=ax.transAxes, fontsize=8, ha='right', va='bottom', color=COLORS['gray'])
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'evmbench_comparison.png'), bbox_inches='tight', facecolor='white')
    plt.close()
    print("✓ Chart 2: Comparison")

# ============================================================
# Chart 3: Vulnerability detection breakdown (stacked)
# ============================================================
def chart_vuln_breakdown():
    audits = [
        'curves', 'taiko', 'olas', 'basin', 'renft',
        'size', 'phi', 'secondswap', 'forte', 'tempo'
    ]
    gold = [4, 5, 2, 2, 6, 4, 6, 3, 5, 3]
    detected = [1, 0, 0, 0, 0, 0, 1, 0, 0, 1]
    missed = [g - d for g, d in zip(gold, detected)]
    
    fig, ax = plt.subplots(figsize=(12, 5))
    
    x = np.arange(len(audits))
    width = 0.5
    
    bars1 = ax.bar(x, detected, width, label='偵測成功', color=COLORS['success'], edgecolor='white')
    bars2 = ax.bar(x, missed, width, bottom=detected, label='未偵測到', color='#FCA5A5', edgecolor='white')
    
    for i, (d, g) in enumerate(zip(detected, gold)):
        ax.text(i, g + 0.15, str(g), ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    ax.set_xticks(x)
    ax.set_xticklabels(audits, rotation=30, ha='right', fontsize=9)
    ax.set_ylabel('漏洞數量', fontsize=12)
    ax.set_title('各審計漏洞偵測分佈', fontsize=14, fontweight='bold', pad=15)
    ax.legend(loc='upper right', fontsize=10)
    ax.set_ylim(0, 8)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'evmbench_vuln_breakdown.png'), bbox_inches='tight', facecolor='white')
    plt.close()
    print("✓ Chart 3: Vulnerability breakdown")

# ============================================================
# Chart 4: Capability gap visualization
# ============================================================
def chart_capability_gap():
    fig, ax = plt.subplots(figsize=(10, 6))
    
    capabilities = [
        '靜態程式碼分析',
        '語義理解',
        '跨合約追蹤',
        '動態執行模擬',
        '多步驟推理',
        '工具整合能力'
    ]
    
    llm_rag = [7, 8, 3, 1, 2, 1]
    agent = [8, 9, 8, 9, 9, 10]
    
    x = np.arange(len(capabilities))
    width = 0.35
    
    bars1 = ax.barh(x - width/2, llm_rag, width, label='LLM+RAG (本研究)', color=COLORS['primary'], edgecolor='white')
    bars2 = ax.barh(x + width/2, agent, width, label='AI Agent (EVMbench)', color=COLORS['warning'], edgecolor='white')
    
    for bar, val in zip(bars1, llm_rag):
        ax.text(val + 0.2, bar.get_y() + bar.get_height()/2, str(val), va='center', fontsize=10)
    for bar, val in zip(bars2, agent):
        ax.text(val + 0.2, bar.get_y() + bar.get_height()/2, str(val), va='center', fontsize=10)
    
    ax.set_yticks(x)
    ax.set_yticklabels(capabilities, fontsize=11)
    ax.set_xlabel('能力評分 (1-10)', fontsize=12)
    ax.set_title('LLM+RAG vs AI Agent 能力差距分析', fontsize=14, fontweight='bold', pad=15)
    ax.legend(loc='lower right', fontsize=10)
    ax.set_xlim(0, 12)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'evmbench_capability_gap.png'), bbox_inches='tight', facecolor='white')
    plt.close()
    print("✓ Chart 4: Capability gap")

# ============================================================
# Chart 5: Timeline positioning
# ============================================================
def chart_timeline():
    fig, ax = plt.subplots(figsize=(14, 5))
    
    # Timeline events
    events = [
        (2020, 'Slither/Mythril\n靜態分析工具', COLORS['gray']),
        (2023, 'GPT-4 + RAG\nLLM 輔助偵測', COLORS['primary']),
        (2025, '本研究\nLLM+RAG Pipeline', COLORS['success']),
        (2026, 'EVMbench\nAI Agent 基準', COLORS['warning']),
        (2027, '未來\n自主審計 Agent', COLORS['secondary']),
    ]
    
    # Draw timeline
    ax.plot([2019, 2028], [0, 0], color=COLORS['gray'], linewidth=3, alpha=0.3)
    
    for i, (year, label, color) in enumerate(events):
        y_offset = 0.4 if i % 2 == 0 else -0.4
        ax.scatter(year, 0, s=200, color=color, zorder=5, edgecolors='white', linewidths=2)
        ax.annotate(label, (year, 0), xytext=(0, 50 * (1 if y_offset > 0 else -1)),
                    textcoords='offset points', ha='center', va='center',
                    fontsize=10, fontweight='bold',
                    bbox=dict(boxstyle='round,pad=0.5', facecolor=color, alpha=0.15, edgecolor=color),
                    arrowprops=dict(arrowstyle='->', color=color, lw=1.5))
        ax.text(year, -0.08 if y_offset > 0 else 0.08, str(year), ha='center', va='center',
                fontsize=11, fontweight='bold', color=COLORS['dark'])
    
    # Highlight "Pre-Agent Era"
    ax.axvspan(2019.5, 2025.5, alpha=0.05, color=COLORS['primary'])
    ax.text(2022.5, 0.7, 'Pre-Agent Era', fontsize=12, ha='center',
            color=COLORS['primary'], fontstyle='italic', fontweight='bold')
    
    ax.axvspan(2025.5, 2028, alpha=0.05, color=COLORS['warning'])
    ax.text(2026.75, 0.7, 'Agent Era', fontsize=12, ha='center',
            color=COLORS['warning'], fontstyle='italic', fontweight='bold')
    
    ax.set_xlim(2019, 2028)
    ax.set_ylim(-1, 1)
    ax.set_title('智能合約安全偵測技術演進時間線', fontsize=14, fontweight='bold', pad=15)
    ax.axis('off')
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'evmbench_timeline.png'), bbox_inches='tight', facecolor='white')
    plt.close()
    print("✓ Chart 5: Timeline")

# ============================================================
# Chart 6: Detected vulnerabilities detail
# ============================================================
def chart_detected_detail():
    fig, ax = plt.subplots(figsize=(12, 5))
    
    vulns = [
        ('curves H-02\n(Fee Claiming)', '存取控制缺陷', 25.0),
        ('phi H-01\n(Signature Replay)', '簽章驗證缺陷', 16.67),
        ('tempo H-01\n(Price Manipulation)', '價格操縱', 33.33),
    ]
    
    names = [v[0] for v in vulns]
    types = [v[1] for v in vulns]
    scores = [v[2] for v in vulns]
    
    colors_list = [COLORS['success'], COLORS['primary'], COLORS['secondary']]
    
    bars = ax.barh(range(len(names)), scores, color=colors_list, height=0.5, edgecolor='white', linewidth=2)
    
    for i, (bar, vtype, score) in enumerate(zip(bars, types, scores)):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                f'{score:.1f}% — {vtype}', va='center', fontsize=11, fontweight='bold')
    
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=11)
    ax.set_xlabel('該審計 Detect Score (%)', fontsize=12)
    ax.set_title('成功偵測的 3 個漏洞詳情', fontsize=14, fontweight='bold', pad=15)
    ax.set_xlim(0, 55)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'evmbench_detected_detail.png'), bbox_inches='tight', facecolor='white')
    plt.close()
    print("✓ Chart 6: Detected detail")

# Run all
if __name__ == '__main__':
    chart_per_audit_scores()
    chart_comparison()
    chart_vuln_breakdown()
    chart_capability_gap()
    chart_timeline()
    chart_detected_detail()
    print(f"\nAll charts saved to: {OUTPUT_DIR}")
    print(f"Files: {os.listdir(OUTPUT_DIR)}")
