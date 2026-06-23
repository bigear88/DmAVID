#!/usr/bin/env python3
"""Redesign 圖3-2 / 圖3-3 / 圖3-4 / 圖3-5 to match the ACTUAL canonical pipeline.

對齊真實程式（scripts/20_coordinator_autonomous.py 為主，19_coordinator_round2.py 對照）：
  * 主偵測管線（05_run_llm_rag.py）不讀 Slither 輸出；Slither 為獨立預篩/基線。
  * 第二階段檢索＝對「合約原始碼關鍵字」比對 SWC 知識庫（非向量、非 Slither）。
  * 第四階段為「輪次迭代（上限 3 輪）× 單輪多代理管線」，
    由 Coordinator 每輪 decide_round_strategy（focus_vuln_types / sv_threshold）自適應聚焦，
    每輪皆對「完整 243 子集」評估；收斂由 decide_early_stop 判定
    （F1 提升 ≤ 0.002 連續 2 輪 且 FN 穩定，或達輪數上限）。
  * Blue Team 補丁同步寫入 vulnerability_knowledge.json 與 ChromaDB
    （chroma_rag.write_blue_team_to_chroma，collection=dmavid_blue_team_iter），
    下一輪經 reload_dynamic_kb() 以關鍵字注入 Student 的 RAG 脈絡，形成知識回饋閉環。
  * Red Team 三結構突變：control_flow_flattening / dead_code_insertion / cross_contract_delegation。
  * 數據（experiments/dmavid_autonomous/autonomous_progression.json）：
    baseline 0.9061 → R1 0.9103 → R2 0.9153 → R3 0.9158。
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle
from matplotlib.font_manager import FontProperties

BASE = "/home/curtis/DmAVID"
OUT  = os.path.join(BASE, "charts")
CJK   = FontProperties(fname="/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc")
CJK_B = FontProperties(fname="/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc")

# ── palette ──────────────────────────────────────────────────────────────────
C_DATA="#FFE8C2"; C_S1="#D6E4FF"; C_S2="#E8DAFF"; C_S3="#FFD9E1"
C_AGENT_T="#D6E4FF"; C_AGENT_S="#CFE8FF"; C_AGENT_R="#FFD9D9"; C_AGENT_B="#D7F5DD"
C_COORD="#FFE8B0"; C_LOOP="#FFE0B2"; C_KB="#D7F5DD"; C_SIDE="#EFEFEF"
C_GREEN="#CDEBD3"; C_FB="#D32F2F"; C_ROUND="#EAF2FF"; C_CONV="#FCEFC7"
EDGE="#9AA0A6"; INK="#1A1A1A"; ARROW="#5F6368"


def box(ax, x, y, w, h, text, fc, fs=11, bold=False, sub=None, ec=EDGE, tc=INK, sub_c="#555"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.02",
                                fc=fc, ec=ec, lw=1.3, zorder=2))
    fp = CJK_B if bold else CJK
    if sub:
        ax.text(x+w/2, y+h*0.64, text, ha="center", va="center", fontproperties=fp,
                fontsize=fs, color=tc, zorder=3)
        ax.text(x+w/2, y+h*0.28, sub, ha="center", va="center", fontproperties=CJK,
                fontsize=fs-2.5, color=sub_c, zorder=3)
    else:
        ax.text(x+w/2, y+h/2, text, ha="center", va="center", fontproperties=fp,
                fontsize=fs, color=tc, zorder=3)


def frame(ax, x, y, w, h, label, ec="#B0B0B0", tc="#333"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.01,rounding_size=0.02",
                                fc="none", ec=ec, lw=1.2, ls=(0,(6,4)), zorder=1))
    ax.text(x+0.14, y+h-0.18, label, ha="left", va="center", fontproperties=CJK_B,
            fontsize=11.5, color=tc, zorder=3)


def arrow(ax, x1, y1, x2, y2, color=ARROW, lw=1.6, style="-|>", ls="-", rad=0.0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=16,
                                 color=color, lw=lw, ls=ls, zorder=4,
                                 connectionstyle=f"arc3,rad={rad}"))


# ═════════════════════════════════════════════════════════════════════════════
# 圖 3-2　DmAVID 四階段管線系統架構
# ═════════════════════════════════════════════════════════════════════════════
def build_fig32():
    fig, ax = plt.subplots(figsize=(12.8, 15)); ax.set_xlim(0, 12); ax.set_ylim(0, 18); ax.axis("off")
    ax.text(6, 17.6, "圖 3-2　DmAVID 四階段管線系統架構", ha="center", va="center",
            fontproperties=CJK_B, fontsize=15, color=INK)

    # Dataset
    box(ax, 3.0, 16.7, 6.0, 0.72, "智能合約資料集", C_DATA, 12, True,
        sub="SmartBugs Curated 143 + Wild 100 = 243　/　EVMbench 39（post-cutoff）")
    # 主資料流：原始碼 → Stage 2（非 Slither）
    arrow(ax, 6, 16.7, 6, 14.75, lw=2.0)
    ax.text(6.15, 15.7, "合約原始碼\n（已剝除漏洞標註）", ha="left", va="center",
            fontproperties=CJK, fontsize=9, color="#444")

    # Stage 1 — Slither 獨立基線（分支，不注入 LLM）
    frame(ax, 0.4, 15.0, 4.4, 1.45, "第一階段：靜態分析（獨立預篩／基線）")
    box(ax, 0.75, 15.2, 3.7, 0.72, "Slither v0.10.4", C_S1, 11, True, sub="AST + 80+ detectors")
    arrow(ax, 3.0, 16.55, 2.6, 16.45, ls="-")  # dataset → slither
    ax.add_patch(FancyArrowPatch((2.6, 16.62), (2.6, 15.95), arrowstyle="-|>", mutation_scale=14,
                                 color=ARROW, lw=1.4, zorder=4))
    ax.text(4.95, 15.55, "（原始發現不注入 LLM 提示）\n→ 僅供效率對照／稽核／可解釋性",
            ha="left", va="center", fontproperties=CJK, fontsize=8.8, color=C_FB)

    # Stage 2
    frame(ax, 0.5, 12.55, 11, 2.05, "第二階段：LLM + RAG 智慧研判（核心推論引擎）")
    box(ax, 0.9, 12.95, 3.3, 0.92, "SWC 漏洞知識庫", C_S2, 10.5, True, sub="漏洞類型索引・字典結構")
    box(ax, 4.35, 12.95, 3.3, 0.92, "關鍵字比對式檢索", C_S2, 10.5, True, sub="原始碼關鍵字 → 注入 prompt")
    box(ax, 7.8, 12.95, 3.3, 0.92, "GPT-4.1-mini", C_S2, 10.5, True, sub="V4 Plan-and-Solve + CoT")
    arrow(ax, 6, 12.55, 6, 12.25, lw=2.0)

    # Stage 3
    frame(ax, 0.5, 10.3, 11, 2.0, "第三階段：Self-Verify 自我驗證（三類判決）")
    box(ax, 0.9, 10.65, 3.3, 0.92, "安全審計師視角", C_S3, 10.5, True, sub="批判性再驗證・檢視緩解")
    box(ax, 4.35, 10.65, 3.3, 0.92, "翻轉條件", C_S3, 10.5, True, sub="SAFE + 具體緩解證據才翻轉")
    box(ax, 7.8, 10.65, 3.3, 0.92, "Three-class Verdict", C_S3, 10.5, True, sub="VULNERABLE / SAFE / UNCERTAIN")
    arrow(ax, 6, 10.3, 6, 10.0, lw=2.0)

    # Stage 4
    frame(ax, 0.5, 4.5, 11, 5.45, "第四階段：DmAVID 多代理對抗式迭代增強（Multi-Agent Adversarial）")
    box(ax, 3.7, 9.1, 4.6, 0.7, "Coordinator Agent", C_COORD, 11, True,
        sub="任務調度・判定整合（投票）・收斂控制 decide_early_stop")
    box(ax, 0.8, 7.85, 2.5, 0.92, "Teacher", C_AGENT_T, 10, True, sub="SWC KB / RAG 檢索")
    box(ax, 3.55, 7.85, 2.5, 0.92, "Student", C_AGENT_S, 10, True, sub="前三階段管線偵測")
    box(ax, 6.3, 7.85, 2.5, 0.92, "Red Team", C_AGENT_R, 10, True, sub="3 結構突變策略")
    box(ax, 9.05, 7.85, 2.1, 0.92, "Blue Team", C_AGENT_B, 10, True, sub="FN 分析／合成補丁")
    arrow(ax, 6, 7.85, 6, 7.45)
    box(ax, 2.9, 6.7, 6.2, 0.72, "輪次迭代（上限 3 輪）× 單輪多代理管線", C_LOOP, 11, True,
        sub="Coordinator 每輪自適應 focus；每輪評完整 243（詳見圖 3-4 / 圖 3-5）")
    arrow(ax, 6, 6.7, 6, 6.3)
    box(ax, 0.8, 5.3, 5.0, 0.82, "Blue Team 知識合成", C_KB, 10, True,
        sub="寫入 vulnerability_knowledge.json")
    box(ax, 6.2, 5.3, 4.95, 0.82, "ChromaDB 迭代層儲存", C_KB, 10, True,
        sub="write_blue_team_to_chroma（向量化）")

    # 知識回饋閉環 → Stage 2
    fb = C_FB
    ax.add_patch(FancyArrowPatch((6.2, 5.55), (0.3, 5.55), arrowstyle="-", mutation_scale=14,
                                 color=fb, lw=2.0, ls=(0,(5,3)), zorder=5))
    ax.add_patch(FancyArrowPatch((0.3, 5.55), (0.3, 13.4), arrowstyle="-", mutation_scale=14,
                                 color=fb, lw=2.0, ls=(0,(5,3)), zorder=5))
    ax.add_patch(FancyArrowPatch((0.3, 13.4), (0.9, 13.4), arrowstyle="-|>", mutation_scale=16,
                                 color=fb, lw=2.0, ls=(0,(5,3)), zorder=5))
    ax.text(0.46, 9.5, "知識回饋閉環\nreload_dynamic_kb()\n+ 關鍵字注入", ha="left", va="center",
            fontproperties=CJK_B, fontsize=9.2, color=fb, rotation=90, zorder=6)
    arrow(ax, 6, 4.5, 6, 4.15)

    # Side branches
    frame(ax, 0.5, 2.25, 5.3, 1.85, "EVM Foundry 驗證（Stage 4 子步驟）")
    box(ax, 0.9, 3.15, 4.5, 0.66, "solc 編譯", C_SIDE, 10, True, sub="變體語法正確性確認")
    box(ax, 0.9, 2.38, 4.5, 0.66, "forge test 攻擊重放", C_SIDE, 10, True, sub="PoC 重放 / 可重現性")
    frame(ax, 6.2, 2.25, 5.3, 1.85, "模型評估（旁支）")
    box(ax, 6.6, 3.15, 4.5, 0.66, "最終預測", C_GREEN, 10, True, sub="vulnerable / safe")
    box(ax, 6.6, 2.38, 4.5, 0.66, "多維效能指標", C_GREEN, 10, True, sub="Accuracy・Precision・Recall・F1・FPR")
    arrow(ax, 4.0, 4.5, 3.15, 4.1, ls="-")
    arrow(ax, 8.0, 4.5, 8.85, 4.1, ls="-")

    ax.text(6, 1.75,
            "註：五代理底層模型統一為 GPT-4.1-mini（T=0.1, seed=42）。主管線採關鍵字比對式檢索；"
            "ChromaDB 向量庫僅用於第四階段迭代層儲存。",
            ha="center", va="center", fontproperties=CJK, fontsize=9, color="#444")
    ax.text(6, 1.42,
            "紅色虛線為知識回饋閉環：每輪 Blue Team 合成之漏洞模式經 reload 後，下一輪以關鍵字注入 Student 的 RAG 脈絡。",
            ha="center", va="center", fontproperties=CJK_B, fontsize=9, color=C_FB)

    plt.subplots_adjust(left=0.01, right=0.99, top=0.99, bottom=0.01)
    p = os.path.join(OUT, "圖3-2_DmAVID四階段管線系統架構.png")
    plt.savefig(p, dpi=200, bbox_inches="tight", facecolor="white"); plt.close(); print("saved:", p)


# ═════════════════════════════════════════════════════════════════════════════
# 圖 3-3　DmAVID 五代理系統架構
# ═════════════════════════════════════════════════════════════════════════════
def build_fig33():
    fig, ax = plt.subplots(figsize=(13, 8.4)); ax.set_xlim(0, 13); ax.set_ylim(0, 8.4); ax.axis("off")
    ax.text(6.5, 8.05, "圖 3-3　DmAVID 五代理系統架構", ha="center", va="center",
            fontproperties=CJK_B, fontsize=15, color=INK)

    # Coordinator
    box(ax, 3.7, 6.7, 5.6, 0.95, "Coordinator Agent", C_COORD, 13, True,
        sub="任務調度・判定整合（投票）・收斂控制 decide_early_stop・自適應 focus 策略")

    # four agents
    cards = [
        (0.4, C_AGENT_T, "Teacher Agent", ["管理 SWC 知識庫", "RAG / ChromaDB 檢索", "生成課程式挑戰"]),
        (3.55, C_AGENT_S, "Student Agent", ["執行前三階段管線", "Slither→LLM+RAG→Self-Verify", "對 243 子集偵測"]),
        (6.7, C_AGENT_R, "Red Team Agent", ["對 FN 生成對抗變體", "control_flow_flattening", "dead_code / cross_contract"]),
        (9.85, C_AGENT_B, "Blue Team Agent", ["FN 漏報防禦分析", "合成防禦補丁知識", "寫 KB(JSON)+ChromaDB"]),
    ]
    for x, c, title, bullets in cards:
        box(ax, x, 4.55, 2.75, 1.55, "", c)
        ax.text(x+1.375, 5.85, title, ha="center", va="center", fontproperties=CJK_B, fontsize=11, color=INK)
        ty=5.5
        for b in bullets:
            ax.text(x+0.16, ty, "• "+b, ha="left", va="top", fontproperties=CJK, fontsize=8.3, color="#333")
            ty-=0.34
        # coordinator ↔ agent
        arrow(ax, x+1.375, 6.7, x+1.375, 6.12, color="#8a8a8a", lw=1.4, style="<|-|>")

    # interaction band
    frame(ax, 0.4, 2.0, 12.2, 2.0, "代理間互動（輪次迭代 × 多代理管線）")
    flow = [("Teacher", C_AGENT_T), ("Student", C_AGENT_S), ("收集 FN", "#FFFFFF"),
            ("Red Team", C_AGENT_R), ("Foundry", C_SIDE), ("Blue Team", C_AGENT_B), ("Self-Verify", C_S3)]
    fw, fg = 1.5, 0.22; fx = 0.7
    for i,(t,c) in enumerate(flow):
        box(ax, fx, 2.55, fw, 0.7, t, c, 9.5, True)
        if i < len(flow)-1:
            arrow(ax, fx+fw, 2.9, fx+fw+fg, 2.9, color=C_LOOP if False else "#C98A50", lw=1.6)
        fx += fw+fg
    # feedback arc Blue→Teacher (KB)
    ax.add_patch(FancyArrowPatch((0.7+5*(fw+fg)+fw/2, 2.55), (0.7+fw/2, 2.55),
                 arrowstyle="-|>", mutation_scale=14, color=C_FB, lw=1.7, ls=(0,(5,3)),
                 connectionstyle="arc3,rad=0.30", zorder=5))
    ax.text(6.4, 2.18, "Blue Team 補丁 → KB → 下一輪 Student RAG（知識回饋閉環）",
            ha="center", va="center", fontproperties=CJK, fontsize=8.6, color=C_FB)

    # shared memory
    box(ax, 0.4, 0.7, 12.2, 0.95, "Shared Memory（共享記憶體 / SharedState）", C_KB, 11.5, True,
        sub="ChromaDB 向量知識庫・Blue Team 防禦補丁・逐輪 metrics・Coordinator 決策軌跡")
    arrow(ax, 6.5, 2.0, 6.5, 1.67, color="#8a8a8a", lw=1.4, style="<|-|>")

    ax.text(6.5, 0.32, "註：五代理底層模型統一為 GPT-4.1-mini（T=0.1, seed=42）。",
            ha="center", va="center", fontproperties=CJK, fontsize=9, color="#444")

    plt.subplots_adjust(left=0.01, right=0.99, top=0.99, bottom=0.01)
    p = os.path.join(OUT, "圖3-3_DmAVID五代理系統架構.png")
    plt.savefig(p, dpi=200, bbox_inches="tight", facecolor="white"); plt.close(); print("saved:", p)


# ═════════════════════════════════════════════════════════════════════════════
# 圖 3-4　DmAVID 輪次迭代機制與收斂（取代舊「雙層迴圈」）
# ═════════════════════════════════════════════════════════════════════════════
def build_fig34():
    fig, ax = plt.subplots(figsize=(13, 7.6)); ax.set_xlim(0, 13); ax.set_ylim(0, 7.6); ax.axis("off")
    ax.text(6.5, 7.25, "圖 3-4　DmAVID 雙層迭代迴圈—外層迭代輪次與收斂控制", ha="center", va="center",
            fontproperties=CJK_B, fontsize=14.5, color=INK)

    f1 = [("baseline","0.9061"), ("R1","0.9103"), ("R2","0.9153"), ("R3","0.9158")]
    # three round cards
    rounds = ["Round 1", "Round 2", "Round 3（上限）"]
    rw, rg = 3.5, 0.55; rx0 = 0.7; ry = 4.2; rh = 2.2
    for i, rn in enumerate(rounds):
        x = rx0 + i*(rw+rg)
        ax.add_patch(FancyBboxPatch((x, ry), rw, rh, boxstyle="round,pad=0.02,rounding_size=0.04",
                                    fc=C_ROUND, ec="#2E5AAC", lw=1.6, zorder=2))
        ax.text(x+rw/2, ry+rh-0.28, rn, ha="center", va="center", fontproperties=CJK_B,
                fontsize=12, color="#2E5AAC")
        steps = ["① Coordinator 自適應策略", "    （focus_vuln_types, sv_threshold）",
                 "② 多代理管線 → 完整 243（圖 3-5）", "③ 評估 metrics", "④ decide_early_stop 收斂判定"]
        ty = ry+rh-0.65
        for s in steps:
            ax.text(x+0.2, ty, s, ha="left", va="top", fontproperties=CJK, fontsize=8.8, color="#333")
            ty -= 0.34
        if i < len(rounds)-1:
            arrow(ax, x+rw, ry+rh/2, x+rw+rg, ry+rh/2, color="#2E5AAC", lw=2.2)
            ax.text(x+rw+rg/2, ry+rh/2+0.5, "知識\n回饋", ha="center", va="center",
                    fontproperties=CJK, fontsize=8, color=C_FB)

    # feedback band under rounds
    ax.add_patch(FancyArrowPatch((rx0+2*(rw+rg)+rw/2, ry), (rx0+rw/2, ry),
                 arrowstyle="-|>", mutation_scale=16, color=C_FB, lw=2.0, ls=(0,(6,4)),
                 connectionstyle="arc3,rad=0.18", zorder=5))
    ax.text(6.5, 3.35, "跨輪知識回饋：Blue Team 補丁 → vulnerability_knowledge.json + ChromaDB "
                       "→ reload_dynamic_kb() → 下一輪 Student RAG",
            ha="center", va="center", fontproperties=CJK_B, fontsize=9.5, color=C_FB)

    # convergence panel
    ax.add_patch(FancyBboxPatch((0.7, 1.45), 11.6, 1.5, boxstyle="round,pad=0.02,rounding_size=0.03",
                                fc=C_CONV, ec="#D8B24A", lw=1.4, zorder=2))
    ax.text(1.0, 2.65, "收斂條件（decide_early_stop）", ha="left", va="center",
            fontproperties=CJK_B, fontsize=11.5, color="#6b5410")
    ax.text(1.0, 2.22, "• F1 提升 ≤ 0.002 連續 2 輪　且　FN 數穩定　→ 提早停止", ha="left", va="center",
            fontproperties=CJK, fontsize=10, color="#5a4a10")
    ax.text(1.0, 1.85, "• 或達輪數上限（3 輪）", ha="left", va="center",
            fontproperties=CJK, fontsize=10, color="#5a4a10")

    # F1 progression chips
    ax.text(7.3, 2.65, "F1 漸進（243 平衡子集）：", ha="left", va="center",
            fontproperties=CJK_B, fontsize=10, color="#6b5410")
    cx = 7.3
    for i,(lab,val) in enumerate(f1):
        ax.add_patch(FancyBboxPatch((cx, 1.7), 1.05, 0.55, boxstyle="round,pad=0.01,rounding_size=0.05",
                                    fc="white", ec="#2E5AAC", lw=1.2, zorder=3))
        ax.text(cx+0.525, 2.03, val, ha="center", va="center", fontproperties=CJK_B, fontsize=9.5, color="#1565C0")
        ax.text(cx+0.525, 1.55, lab, ha="center", va="top", fontproperties=CJK, fontsize=8, color="#555")
        if i < 3:
            ax.text(cx+1.13, 1.97, "→", ha="center", va="center", fontproperties=CJK, fontsize=11, color="#888")
        cx += 1.22

    ax.text(6.5, 0.85, "註：外層為「迭代輪次」（上限 3 輪），每輪皆對完整 243 子集評估，"
                       "由 Coordinator 自適應決定本輪聚焦之漏洞類型與 Self-Verify 閾值；不採固定「漏洞類型輪詢」之外層迴圈。",
            ha="center", va="center", fontproperties=CJK, fontsize=8.8, color="#444")

    plt.subplots_adjust(left=0.01, right=0.99, top=0.99, bottom=0.01)
    p = os.path.join(OUT, "圖3-4_DmAVID輪次迭代機制與收斂.png")
    plt.savefig(p, dpi=200, bbox_inches="tight", facecolor="white"); plt.close(); print("saved:", p)


# ═════════════════════════════════════════════════════════════════════════════
# 圖 3-5　單輪多代理對抗式管線流程（取代舊「內層六步驟」）
# ═════════════════════════════════════════════════════════════════════════════
def build_fig35():
    fig, ax = plt.subplots(figsize=(12.5, 8.6)); ax.set_xlim(0, 12.5); ax.set_ylim(0, 8.6); ax.axis("off")
    ax.text(6.25, 8.3, "圖 3-5　內層對抗式自強化單輪管線（S1–S6）", ha="center", va="center",
            fontproperties=CJK_B, fontsize=15, color=INK)

    steps = [
        ("S1", "Student 偵測（完整 243）", "Student", C_AGENT_S,
         "reload_dynamic_kb() → LLM+RAG + Self-Verify；計 F1/P/R/FPR、標記 FN"),
        ("S2", "結果收集與收斂判定", "Coordinator", C_COORD,
         "彙整 TP/FP/TN/FN；連兩輪 ΔF1<0.01 或達輪數上限 → 收斂則輸出，否則續 S3"),
        ("S3", "Red Team 攻擊", "Red Team", C_AGENT_R,
         "對 FN 施 3 結構突變：control_flow_flattening / dead_code_insertion / cross_contract_delegation；保語義等價"),
        ("S4", "Foundry 驗證", "Coordinator", C_SIDE,
         "solc 編譯確認語法；forge test 重放 PoC；僅雙重驗證通過之變體進入知識合成"),
        ("S5", "Blue Team 知識合成", "Blue Team", C_AGENT_B,
         "根因分析→防禦補丁；寫 ChromaDB（dmavid_blue_team_iter）+ vulnerability_knowledge.json"),
        ("S6", "RAG 知識庫更新", "Coordinator", C_KB,
         "reload_dynamic_kb() 關鍵字注入 → 返回 S1，形成閉環學習（closed-loop feedback）"),
    ]
    y0 = 7.7; h = 0.92; gap = 0.22; x = 0.6; w = 10.7; pitch = h+gap
    y = y0
    for num, title, agent, c, desc in steps:
        ax.add_patch(FancyBboxPatch((x, y-h), w, h, boxstyle="round,pad=0.012,rounding_size=0.03",
                                    fc=c, ec=EDGE, lw=1.3, zorder=2))
        ax.add_patch(Circle((x+0.5, y-h/2), 0.32, fc="#2E5AAC", ec="white", lw=1.4, zorder=4))
        ax.text(x+0.5, y-h/2, num, ha="center", va="center", fontproperties=CJK_B, fontsize=11, color="white", zorder=5)
        ax.text(x+1.05, y-0.30, title, ha="left", va="center", fontproperties=CJK_B, fontsize=11.5, color=INK)
        if agent and agent != "—":
            ax.text(x+w-0.15, y-0.30, f"[{agent}]", ha="right", va="center", fontproperties=CJK,
                    fontsize=9, color="#2E5AAC")
        ax.text(x+1.05, y-0.64, desc, ha="left", va="center", fontproperties=CJK, fontsize=8.7, color="#444")
        if num != "S6":
            ax.add_patch(FancyArrowPatch((x+0.5, y-h), (x+0.5, y-h-gap), arrowstyle="-|>",
                         mutation_scale=13, color=ARROW, lw=1.6, zorder=4))
        y -= pitch

    # S2 收斂分支（輸出）
    s2_mid = y0 - 1*pitch - h/2
    ax.add_patch(FancyArrowPatch((x+w, s2_mid), (x+w+0.85, s2_mid), arrowstyle="-|>",
                 mutation_scale=13, color="#2E7D32", lw=1.6, zorder=4))
    ax.text(x+w+0.92, s2_mid, "收斂\n→輸出", ha="left", va="center",
            fontproperties=CJK_B, fontsize=8.3, color="#2E7D32")

    # loop-back arrow S6 → S1（右側外緣）
    xr = x + w + 0.42
    s1_mid = y0 - h/2
    s6_mid = y0 - 5*pitch - h/2
    ax.add_patch(FancyArrowPatch((xr, s6_mid), (xr, s1_mid), arrowstyle="-|>", mutation_scale=16,
                 color=C_FB, lw=1.9, ls=(0,(6,4)), connectionstyle="arc3,rad=0.0", zorder=3))
    ax.text(xr+0.24, (s1_mid+s6_mid)/2, "知識回饋閉環（S6 → S1）", ha="left", va="center",
            fontproperties=CJK_B, fontsize=8.6, color=C_FB, rotation=90)

    ax.text(6.25, 0.45,
            "註：內層 S1–S6 為每一迭代輪次之單輪管線（scripts/20_coordinator_autonomous.py）；"
            "外層迭代輪次與收斂控制見圖 3-4。",
            ha="center", va="center", fontproperties=CJK, fontsize=8.8, color="#444")

    plt.subplots_adjust(left=0.01, right=0.99, top=0.99, bottom=0.01)
    p = os.path.join(OUT, "圖3-5_內層對抗式自強化單輪管線.png")
    plt.savefig(p, dpi=200, bbox_inches="tight", facecolor="white"); plt.close(); print("saved:", p)


if __name__ == "__main__":
    build_fig32()
    build_fig33()
    build_fig34()
    build_fig35()
