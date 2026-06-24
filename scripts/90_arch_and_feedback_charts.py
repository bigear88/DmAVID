#!/usr/bin/env python3
"""Generate (1) the DmAVID architecture diagram with the knowledge-feedback loop,
and (2) the iteration trend chart, both mapped to the actual project experiment
(experiments/dmavid_autonomous/autonomous_progression.json).

Reproducible replacement for the externally-drawn 架構設計圖.png.
"""
import os, json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib.font_manager import FontProperties

BASE = "/home/curtis/DmAVID"
OUT  = os.path.join(BASE, "charts")
CJK  = FontProperties(fname="/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc")

# ── palette ────────────────────────────────────────────────────────────────
C_DATA="#FFE8C2"; C_STAGE="#FAFAFA"; C_S1="#D6E4FF"; C_S2="#E8DAFF"
C_S3="#FFD9E1"; C_AGENT_T="#D6E4FF"; C_AGENT_S="#CFE8FF"; C_AGENT_R="#FFD9D9"
C_AGENT_B="#D7F5DD"; C_COORD="#FFE8B0"; C_LOOP="#FFE0B2"; C_KB="#D7F5DD"
C_SIDE="#EFEFEF"; C_GREEN="#CDEBD3"; C_FB="#D32F2F"
EDGE="#9AA0A6"


def box(ax, x, y, w, h, text, fc, fs=11, bold=False, sub=None, ec=EDGE, tc="#1a1a1a"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.02",
                                fc=fc, ec=ec, lw=1.3, zorder=2))
    if sub:
        ax.text(x+w/2, y+h*0.62, text, ha="center", va="center", fontproperties=CJK,
                fontsize=fs, fontweight="bold" if bold else "normal", color=tc, zorder=3)
        ax.text(x+w/2, y+h*0.27, sub, ha="center", va="center", fontproperties=CJK,
                fontsize=fs-2.5, color="#555", zorder=3)
    else:
        ax.text(x+w/2, y+h/2, text, ha="center", va="center", fontproperties=CJK,
                fontsize=fs, fontweight="bold" if bold else "normal", color=tc, zorder=3)


def stage_frame(ax, x, y, w, h, label):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.01,rounding_size=0.02",
                                fc="none", ec="#B0B0B0", lw=1.1, ls=(0,(6,4)), zorder=1))
    ax.text(x+0.12, y+h-0.16, label, ha="left", va="center", fontproperties=CJK,
            fontsize=11.5, fontweight="bold", color="#333", zorder=3)


def arrow(ax, x1, y1, x2, y2, color="#5f6368", lw=1.6, style="-|>", ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=16,
                                 color=color, lw=lw, ls=ls, zorder=4,
                                 connectionstyle="arc3,rad=0"))


def build_architecture():
    fig, ax = plt.subplots(figsize=(12.5, 15))
    ax.set_xlim(0, 12); ax.set_ylim(0, 18); ax.axis("off")

    # Dataset
    box(ax, 3.2, 17.0, 5.6, 0.7, "智能合約資料集", C_DATA, 12, True,
        sub="SmartBugs Curated + Wild (243)  /  EVMbench (39, post-cutoff)")
    arrow(ax, 6, 17.0, 6, 16.55)

    # Stage 1
    stage_frame(ax, 0.5, 15.0, 11, 1.5, "第一階段：靜態分析 Static Analysis")
    box(ax, 4.0, 15.25, 4.0, 0.75, "Slither v0.11.5", C_S1, 11.5, True, sub="AST 解析 + 80+ detectors")
    arrow(ax, 6, 15.0, 6, 14.7)

    # Stage 2
    stage_frame(ax, 0.5, 12.7, 11, 2.0, "第二階段：LLM + RAG 智慧研判")
    box(ax, 0.9, 13.05, 3.3, 0.95, "SWC 漏洞知識庫", C_S2, 10.5, True, sub="漏洞類型索引 · 字典結構")
    box(ax, 4.35, 13.05, 3.3, 0.95, "Top-3 關鍵字比對式檢索", C_S2, 10.5, True, sub="漏洞類型知識注入 prompt")
    box(ax, 7.8, 13.05, 3.3, 0.95, "GPT-4.1-mini", C_S2, 10.5, True, sub="V4 Plan-and-Solve + CoT")
    arrow(ax, 6, 12.7, 6, 12.4)

    # Stage 3
    stage_frame(ax, 0.5, 10.4, 11, 2.0, "第三階段：Self-Verify 三類自我驗證 (three-class, conf-agnostic)")
    box(ax, 0.9, 10.75, 3.3, 0.95, "對所有 vuln 預測執行", C_S3, 10.5, True, sub="conf-agnostic · no gating")
    box(ax, 4.35, 10.75, 3.3, 0.95, "批判性再驗證", C_S3, 10.5, True, sub="安全審計師視角檢視緩解")
    box(ax, 7.8, 10.75, 3.3, 0.95, "Three-class Verdict", C_S3, 10.5, True, sub="VULNERABLE / SAFE / UNCERTAIN")
    arrow(ax, 6, 10.4, 6, 10.1)

    # Stage 4
    stage_frame(ax, 0.5, 4.6, 11, 5.5, "第四階段：DmAVID 多代理對抗式迭代增強 (Multi-Agent Adversarial)")
    box(ax, 3.8, 9.25, 4.4, 0.7, "Coordinator Agent", C_COORD, 11, True, sub="任務調度 · 判定整合(投票) · 收斂控制")
    # agents row
    box(ax, 0.8, 8.0, 2.5, 0.95, "Teacher Agent", C_AGENT_T, 10, True, sub="SWC 知識庫 / RAG 檢索")
    box(ax, 3.55, 8.0, 2.5, 0.95, "Student Agent", C_AGENT_S, 10, True, sub="三階段管線偵測")
    box(ax, 6.3, 8.0, 2.5, 0.95, "Red Team Agent", C_AGENT_R, 10, True, sub="3 結構突變策略")
    box(ax, 9.05, 8.0, 2.1, 0.95, "Blue Team Agent", C_AGENT_B, 10, True, sub="FN 分析 / 合成補丁")
    arrow(ax, 6, 8.0, 6, 7.55)
    box(ax, 3.3, 6.75, 5.4, 0.75, "雙層迭代迴圈", C_LOOP, 11, True, sub="外層漏洞類型輪詢 + 內層 S1–S6 對抗自強化")
    arrow(ax, 6, 6.75, 6, 6.35)
    # S5 / S6 (knowledge synthesis + update)
    box(ax, 0.8, 5.35, 5.0, 0.85, "S5：Blue Team 知識合成", C_KB, 10, True,
        sub="向量化寫入 ChromaDB（迭代層儲存）")
    box(ax, 6.2, 5.35, 4.95, 0.85, "S6：知識庫更新", C_KB, 10, True,
        sub="Blue Team → vulnerability_knowledge.json")

    # ── Knowledge feedback loop (the NEW closed loop) ──────────────────────
    # red dashed path: S6 → left margin → up → Student RAG (Stage 2 keyword KB)
    fb = C_FB
    ax.add_patch(FancyArrowPatch((6.2, 5.6), (0.3, 5.6), arrowstyle="-", mutation_scale=14,
                                 color=fb, lw=2.0, ls=(0,(5,3)), zorder=5))
    ax.add_patch(FancyArrowPatch((0.3, 5.6), (0.3, 13.5), arrowstyle="-", mutation_scale=14,
                                 color=fb, lw=2.0, ls=(0,(5,3)), zorder=5))
    ax.add_patch(FancyArrowPatch((0.3, 13.5), (0.9, 13.5), arrowstyle="-|>", mutation_scale=16,
                                 color=fb, lw=2.0, ls=(0,(5,3)), zorder=5))
    ax.text(0.45, 9.6, "知識回饋閉環\nreload_dynamic_kb()\n+ 漏洞模式關鍵字注入",
            ha="left", va="center", fontproperties=CJK, fontsize=9.5, color=fb,
            fontweight="bold", rotation=90, zorder=6)

    arrow(ax, 6, 4.6, 6, 4.25)

    # Side branches
    stage_frame(ax, 0.5, 2.3, 5.3, 1.9, "EVM Foundry 驗證（旁支）")
    box(ax, 0.9, 3.25, 4.5, 0.7, "solc 編譯", C_SIDE, 10, True, sub="變體語法正確性確認")
    box(ax, 0.9, 2.45, 4.5, 0.7, "forge test 攻擊重放", C_SIDE, 10, True, sub="PoC 重放 / Exploit 可重現性")
    stage_frame(ax, 6.2, 2.3, 5.3, 1.9, "模型評估 Model Evaluation（旁支）")
    box(ax, 6.6, 3.25, 4.5, 0.7, "最終預測", C_GREEN, 10, True, sub="vulnerable / safe")
    box(ax, 6.6, 2.45, 4.5, 0.7, "多維效能指標", C_GREEN, 10, True, sub="Accuracy·Precision·Recall·F1·FPR (+CTC)")
    arrow(ax, 4.0, 4.6, 3.15, 4.2, ls="-")
    arrow(ax, 8.0, 4.6, 8.85, 4.2, ls="-")

    # Note
    ax.text(6, 1.75,
            "註：五代理底層模型統一為 GPT-4.1-mini（T=0.1, seed=42）。主管線採關鍵字比對式檢索；ChromaDB 向量庫僅用於第四階段 S6 迭代儲存。",
            ha="center", va="center", fontproperties=CJK, fontsize=9, color="#444")
    ax.text(6, 1.42,
            "紅色虛線為知識回饋閉環：每輪 Blue Team 合成之漏洞模式經 reload 後，於下一輪以關鍵字注入 Student 的 RAG 脈絡，形成閉環學習。",
            ha="center", va="center", fontproperties=CJK, fontsize=9, color=C_FB, fontweight="bold")

    plt.tight_layout()
    p = os.path.join(OUT, "fig3_2_architecture_feedback.png")
    plt.savefig(p, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close()
    print("saved:", p)


def build_trend():
    prog = json.load(open(os.path.join(BASE, "experiments/dmavid_autonomous/autonomous_progression.json")))
    rounds = prog["rounds"]
    xs = [r["round"] for r in rounds]
    f1  = [r["student_post_verify"]["f1"] for r in rounds]
    rec = [r["student_post_verify"]["recall"] for r in rounds]
    fpr = [r["student_post_verify"]["fpr"] for r in rounds]
    fn  = [r["student_post_verify"]["fn"] for r in rounds]
    # KB-retained learned patterns VISIBLE to the Student at the start of each round,
    # taken from the run's [FEEDBACK] log (per-category cap of 5 drops some synthesised
    # patches, so this is below the raw cumulative synthesis count).
    patches = [0, 11, 16][:len(rounds)]
    base = prog["config"]["baseline_f1"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    ax1.axhline(base, ls="--", color="#999", lw=1.3, label=f"Baseline F1={base:.4f}")
    ax1.plot(xs, f1, "o-", color="#1565C0", lw=2.4, ms=9, label="F1 (post-verify)")
    ax1.plot(xs, rec, "s-", color="#2E7D32", lw=2.2, ms=8, label="Recall")
    ax1.plot(xs, fpr, "^-", color="#C62828", lw=2.2, ms=8, label="FPR")
    for x, y in zip(xs, f1):
        ax1.annotate(f"{y:.4f}", (x, y), textcoords="offset points", xytext=(0, 10),
                     ha="center", fontsize=10, fontweight="bold", color="#1565C0")
    ax1.set_xticks(xs); ax1.set_xlabel("Iteration Round", fontsize=12)
    ax1.set_ylabel("Score", fontsize=12)
    ax1.set_title("DmAVID Knowledge-Feedback Iteration Trend", fontsize=13, fontweight="bold")
    ax1.set_ylim(0.10, 1.0); ax1.legend(loc="center right", fontsize=10); ax1.grid(alpha=0.3)

    ax2b = ax2.twinx()
    bars = ax2.bar([x-0.0 for x in xs], fn, width=0.45, color="#EF6C00", alpha=0.85,
                   label="False Negatives (FN)")
    ax2b.plot(xs, patches, "D--", color="#6A1B9A", lw=2.2, ms=9, label="Learned patches visible")
    for x, y in zip(xs, fn):
        ax2.annotate(f"{y}", (x, y), textcoords="offset points", xytext=(0, 5),
                     ha="center", fontsize=11, fontweight="bold", color="#E65100")
    for x, y in zip(xs, patches):
        ax2b.annotate(f"{y}", (x, y), textcoords="offset points", xytext=(0, 8),
                      ha="center", fontsize=10, fontweight="bold", color="#6A1B9A")
    ax2.set_xticks(xs); ax2.set_xlabel("Iteration Round", fontsize=12)
    ax2.set_ylabel("False Negatives", fontsize=12, color="#E65100")
    ax2b.set_ylabel("Cumulative learned patches in KB", fontsize=12, color="#6A1B9A")
    ax2.set_title("Closed-Loop Feedback: FN Reduction vs Learned Patches", fontsize=13, fontweight="bold")
    ax2.grid(alpha=0.25)
    l1, lab1 = ax2.get_legend_handles_labels(); l2, lab2 = ax2b.get_legend_handles_labels()
    ax2.legend(l1+l2, lab1+lab2, loc="upper right", fontsize=10)

    plt.tight_layout()
    p = os.path.join(OUT, "fig4_iteration_feedback_trend.png")
    plt.savefig(p, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close()
    print("saved:", p)
    print("trend:", list(zip(xs, [round(x,4) for x in f1], [round(x,4) for x in rec], fn, patches)))


if __name__ == "__main__":
    build_architecture()
    build_trend()
