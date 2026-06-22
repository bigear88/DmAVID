#!/usr/bin/env python3
"""Regenerate 圖3-1 DSR 五階段研究流程圖, aligned to the ACTUAL project experiment.

Layout modelled on the original 圖3-1_DSR五階段研究流程圖.png:
  (a) top row   — DSRM 五階段流程卡片 (Peffers 等)
  (b) mid band  — DmAVID 對抗式迭代迴圈 (階段 3-4 的核心), 七步驟
  (c) bottom    — Hevner 七項 DSR 準則

Content verified against the repo:
  - pipeline (scripts/05/.. + 90_arch_and_feedback_charts.py): Slither → LLM+RAG →
    Self-Verify 三類 → 多代理對抗式迭代
  - convergence (scripts/20_coordinator_autonomous.py decide_early_stop):
    F1 連續兩輪提升 ≤ 0.002 且 FN 數穩定, 或達 3 輪上限
  - autonomous config (experiments/dmavid_autonomous/autonomous_progression.json):
    243 平衡子集, baseline F1 0.9061, R3 F1 0.9158
  - CTC explainability (experiments/explainability/ctc_eval_summary.json):
    Correctness/Thoroughness/Clarity 三維度
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
C_STAGE   = "#EAF2FF"   # 一般階段卡片底
C_STAGE_H = "#FFF3D6"   # 設計與開發 (核心階段) 底
C_BADGE   = "#2E5AAC"   # 階段編號圓徽
C_BADGE_H = "#E8A317"   # 核心階段編號圓徽
C_LOOPBG  = "#FFF6EC"   # 迭代迴圈底
C_LOOPED  = "#D9772B"   # 迭代迴圈邊框
C_STEP    = "#FFFFFF"   # 迴圈步驟方塊
C_STEP_HL = "#FDE7CF"   # 迴圈關鍵步驟 (Red/Blue) 方塊
C_GUIDE   = "#FCEFC7"   # 準則 chip 底
C_GUIDE_E = "#D8B24A"   # 準則 chip 邊
EDGE      = "#9AA0A6"
INK       = "#1A1A1A"
ARROW     = "#5F6368"


def stage_card(ax, x, y, w, h, num, title, bullets, highlight=False):
    fc   = C_STAGE_H if highlight else C_STAGE
    bcol = C_BADGE_H if highlight else C_BADGE
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06",
                                fc=fc, ec=EDGE, lw=1.3, zorder=2))
    # 編號圓徽
    r = 0.22
    ax.add_patch(Circle((x + r + 0.12, y + h - r - 0.12), r, fc=bcol, ec="white", lw=1.5, zorder=4))
    ax.text(x + r + 0.12, y + h - r - 0.12, str(num), ha="center", va="center",
            fontproperties=CJK_B, fontsize=12.5, color="white", zorder=5)
    # 標題
    ax.text(x + r + 0.42, y + h - 0.30, title, ha="left", va="center",
            fontproperties=CJK_B, fontsize=11, color=INK, zorder=4)
    # 條列
    ty = y + h - 0.68
    for b in bullets:
        ax.text(x + 0.18, ty, "• " + b, ha="left", va="top", fontproperties=CJK,
                fontsize=8.6, color="#333", zorder=4, wrap=True)
        ty -= 0.42


def loop_step(ax, x, y, w, h, title, sub, hl=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.014,rounding_size=0.04",
                                fc=C_STEP_HL if hl else C_STEP, ec="#C98A50", lw=1.2, zorder=3))
    ax.text(x + w / 2, y + h * 0.66, title, ha="center", va="center",
            fontproperties=CJK_B, fontsize=9.2, color="#7A3E12", zorder=4)
    ax.text(x + w / 2, y + h * 0.28, sub, ha="center", va="center",
            fontproperties=CJK, fontsize=7.4, color="#5b5b5b", zorder=4)


def arrow(ax, x1, y1, x2, y2, color=ARROW, lw=1.7, style="-|>"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=15,
                                 color=color, lw=lw, zorder=4,
                                 connectionstyle="arc3,rad=0"))


def build():
    fig, ax = plt.subplots(figsize=(14.5, 8.6))
    ax.set_xlim(0, 14.5); ax.set_ylim(0, 8.6); ax.axis("off")

    ax.text(7.25, 8.32, "圖 3-1　DmAVID 之 DSR 五階段研究流程", ha="center", va="center",
            fontproperties=CJK_B, fontsize=15, color=INK)

    # ── (a) 五階段流程卡片 ────────────────────────────────────────────────────
    stages = [
        ("1", "問題識別與動機", [
            "DeFi 智能合約安全威脅嚴峻",
            "靜態工具高誤報、LLM 單次推論召回受限",
            "後截止點泛化與資料洩漏疑慮"]),
        ("2", "目標定義", [
            "設計四階段混合偵測管線",
            "引入多代理對抗式迭代增強",
            "兼顧偵測效能與可解釋性"]),
        ("3", "設計與開發", [
            "DmAVID 框架（Coordinator 協調）",
            "Teacher／Student／Red／Blue 多代理",
            "雙層迭代迴圈＋知識回饋閉環"]),
        ("4", "展示與示範", [
            "SmartBugs 1000 筆基準偵測",
            "243 平衡子集對抗迭代增強",
            "EVMbench 後截止點跨資料集驗證"]),
        ("5", "評估", [
            "Accuracy／Precision／Recall／F1／FPR",
            "EVMbench 跨資料集偵測率",
            "CTC 可解釋性（正確·完整·清晰）"]),
    ]
    n = len(stages)
    x0, gap, w, h, y = 0.30, 0.28, 2.55, 2.05, 5.85
    for i, (num, title, bullets) in enumerate(stages):
        x = x0 + i * (w + gap)
        stage_card(ax, x, y, w, h, num, title, bullets, highlight=(num == "3"))
        if i < n - 1:
            ax.add_patch(FancyArrowPatch((x + w + 0.02, y + h / 2), (x + w + gap - 0.02, y + h / 2),
                         arrowstyle="-|>", mutation_scale=17, color=C_BADGE, lw=2.2, zorder=5))

    # 由 階段3、4 指向迭代迴圈
    cx3 = x0 + 2 * (w + gap) + w / 2
    cx4 = x0 + 3 * (w + gap) + w / 2
    for cx in (cx3, cx4):
        arrow(ax, cx, y - 0.02, cx, 5.18, color=C_LOOPED, lw=1.8)

    # ── (b) 對抗式迭代迴圈 band ───────────────────────────────────────────────
    bx, by, bw, bh = 0.30, 2.55, 13.90, 2.60
    ax.add_patch(FancyBboxPatch((bx, by), bw, bh, boxstyle="round,pad=0.02,rounding_size=0.05",
                                fc=C_LOOPBG, ec=C_LOOPED, lw=2.0, ls=(0, (7, 4)), zorder=1))
    ax.text(bx + 0.30, by + bh - 0.27, "DmAVID 對抗式迭代迴圈（階段 3–4 的核心，循環增強）",
            ha="left", va="center", fontproperties=CJK_B, fontsize=11.5, color=C_LOOPED, zorder=4)

    steps = [
        ("Teacher", "SWC 知識庫／RAG 檢索", False),
        ("Student", "三階段管線偵測", False),
        ("收集結果", "標記 FN／FP 案例", False),
        ("Red Team", "3 結構突變生成變體", True),
        ("Blue Team", "FN 分析→合成補丁知識", True),
        ("Foundry 驗證", "solc 編譯＋forge 重放", False),
        ("更新 RAG", "知識回饋閉環 reload", False),
    ]
    sn = len(steps)
    sw, sgap, sh = 1.78, 0.13, 1.10
    sx0 = bx + (bw - (sn * sw + (sn - 1) * sgap)) / 2
    sy = by + 0.78
    for i, (t, s, hl) in enumerate(steps):
        sx = sx0 + i * (sw + sgap)
        loop_step(ax, sx, sy, sw, sh, t, s, hl=hl)
        if i < sn - 1:
            ax.add_patch(FancyArrowPatch((sx + sw + 0.005, sy + sh / 2),
                         (sx + sw + sgap - 0.005, sy + sh / 2), arrowstyle="-|>",
                         mutation_scale=13, color=C_LOOPED, lw=1.8, zorder=5))
    # 回饋弧線：更新 RAG → Teacher
    last_x = sx0 + (sn - 1) * (sw + sgap)
    ax.add_patch(FancyArrowPatch((last_x + sw / 2, sy), (sx0 + sw / 2, sy),
                 arrowstyle="-|>", mutation_scale=15, color=C_LOOPED, lw=1.8, ls=(0, (5, 3)),
                 connectionstyle="arc3,rad=0.32", zorder=5))

    ax.text(bx + bw / 2, by + 0.34,
            "收斂條件：F1 連續兩輪提升 ≤ 0.002 且 FN 數穩定，或達 3 輪上限　"
            "（243 平衡子集：baseline F1 0.9061 → R1 0.9103 → R2 0.9153 → R3 0.9158）",
            ha="center", va="center", fontproperties=CJK, fontsize=8.7, color="#7A3E12", zorder=4)

    # ── (c) Hevner 七項 DSR 準則 ──────────────────────────────────────────────
    ax.text(0.30, 2.18, "對應 Hevner 等 DSR 七項準則：", ha="left", va="center",
            fontproperties=CJK_B, fontsize=10, color="#6b5410")
    guides = ["1 問題相關性", "2 設計即產物", "3 設計評估", "4 研究貢獻",
              "5 研究嚴謹性", "6 設計搜尋", "7 研究溝通"]
    gn = len(guides)
    gw, ggap, gh, gy = 1.86, 0.16, 0.62, 0.55
    gx0 = (14.5 - (gn * gw + (gn - 1) * ggap)) / 2
    for i, g in enumerate(guides):
        gx = gx0 + i * (gw + ggap)
        ax.add_patch(FancyBboxPatch((gx, gy), gw, gh, boxstyle="round,pad=0.014,rounding_size=0.06",
                                    fc=C_GUIDE, ec=C_GUIDE_E, lw=1.2, zorder=2))
        ax.text(gx + gw / 2, gy + gh / 2, "準則 " + g, ha="center", va="center",
                fontproperties=CJK_B, fontsize=9, color="#6b5410", zorder=3)

    plt.subplots_adjust(left=0.01, right=0.99, top=0.99, bottom=0.01)
    p = os.path.join(OUT, "圖3-1_DSR五階段研究流程圖.png")
    plt.savefig(p, dpi=200, facecolor="white", bbox_inches="tight")
    plt.close()
    print("saved:", p)


if __name__ == "__main__":
    build()
