# -*- coding: utf-8 -*-
"""Generate the DmAVID information-processing flow figure for the appendix.
Input (.sol) -> [DmAVID 4-stage pipeline] -> {F1 score, explanation report},
with a parallel traditional-ML lane for contrast. Outputs PNG (embed) + PDF (vector)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib import font_manager as fm

FONT = "/usr/share/fonts/opentype/noto/NotoSerifCJK-Regular.ttc"
fp = fm.FontProperties(fname=FONT)
plt.rcParams["axes.unicode_minus"] = False

OUT_PNG = "/home/curtis/DmAVID/supplementary_results/appendix_dmavid_flow.png"
OUT_PDF = "/home/curtis/DmAVID/supplementary_results/appendix_dmavid_flow.pdf"

fig, ax = plt.subplots(figsize=(11.0, 8.6))
ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")

C_IN = "#E8EEF7"; C_DM = "#DCEBDC"; C_ML = "#F6E5D8"; C_OUT = "#F3E1EE"
EDGE = "#3A3A3A"


def box(cx, cy, w, h, text, fc, fs=11, bold=False):
    x, y = cx - w / 2, cy - h / 2
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.6,rounding_size=1.4",
                                linewidth=1.3, edgecolor=EDGE, facecolor=fc, zorder=2))
    ax.text(cx, cy, text, ha="center", va="center", fontproperties=fp,
            fontsize=fs, zorder=3, fontweight="bold" if bold else "normal", linespacing=1.4)


def arrow(x1, y1, x2, y2, text=None):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=18,
                                 linewidth=1.4, color=EDGE, zorder=1,
                                 shrinkA=2, shrinkB=2))
    if text:
        ax.text((x1 + x2) / 2 + 2.5, (y1 + y2) / 2, text, ha="left", va="center",
                fontproperties=fp, fontsize=8.5, color="#7A2E2E")


# ---------- shared input ----------
box(50, 95, 74, 6.5,
    "輸入 Input：智能合約完整原始碼（.sol 全文，未經編譯或裁切）\n"
    "範例 ETH_FUND：L44  if(msg.sender.call.value(_am)())  →  L46  balances[msg.sender]-=_am;（外部呼叫先於狀態更新）",
    C_IN, fs=10, bold=True)

# split arrows
arrow(38, 91.7, 27, 87.5)
arrow(62, 91.7, 76, 87.5)
ax.text(27, 88.8, "DmAVID（本研究）", ha="center", fontproperties=fp, fontsize=11, fontweight="bold", color="#245A24")
ax.text(76, 88.8, "傳統機器學習（對照）", ha="center", fontproperties=fp, fontsize=11, fontweight="bold", color="#8A4A22")

# ---------- DmAVID lane (left, cx=27) ----------
box(27, 82, 40, 8,
    "階段一 Stage 1：LLM + RAG 偵測\n"
    "自 ChromaDB 漏洞知識庫檢索相關樣式，\nLLM 於原始碼層次語意推理",
    C_DM, fs=9.5)
arrow(27, 77.8, 27, 73.2)
box(27, 69, 40, 8,
    "階段二 Stage 2：自我驗證 / 重新評估\n"
    "閘控 α=0.75（stage1_safe ∧ slither_high_med>0\n∧ conf<0.75 才觸發），納入 Slither 靜態證據",
    C_DM, fs=9.5)
arrow(27, 64.8, 27, 60.2)
box(27, 55, 40, 9.5,
    "階段三 Stage 3：多代理對抗式迭代\n"
    "Coordinator 出題 → Student 偵測 → Red Team 對抗變體\n"
    "→ Foundry(solc) 編譯驗證 → Blue Team 萃取防禦樣式\n"
    "→ ChromaDB 回饋閉環；停止：ΔF1<0.01 或 ≤3 輪",
    C_DM, fs=9.0)

# DmAVID split to two outputs
arrow(27, 50.0, 16, 44.5)
arrow(27, 50.0, 40, 44.5)
box(15.5, 37.5, 27, 12,
    "輸出 A：二元標籤 → F1\n"
    "全 243 份合約彙總混淆矩陣\n"
    "TP=136  FP=18\nFN=7   TN=82\n"
    "P=0.8831  R=0.9510\nF1=0.9158",
    C_OUT, fs=9.0, bold=False)
box(41.5, 37.5, 30, 12,
    "輸出 B：結構化漏洞解釋報告\n"
    "predicted_vulnerable=true\ntypes=[reentrancy]  severity=High\nconfidence=0.90\n"
    "reasoning（根因+行號 L44/L46+缺失緩解）\nrepair（建議 CEI/ReentrancyGuard）\n→ CTC Correctness=8.881",
    C_OUT, fs=8.6)

# ---------- Traditional ML lane (right, cx=76) ----------
box(76, 82, 38, 8,
    "特徵抽取 Feature Extraction\n"
    "將原始碼視為文字：\nTF-IDF（500 維）+ 19 項結構特徵\n（函式數、外部呼叫數、程式長度…）",
    C_ML, fs=9.5)
arrow(76, 77.6, 76, 73.2)
box(76, 69, 38, 7,
    "分類器 Classifier\n"
    "Random Forest / Gradient Boosting /\nLogistic Regression / SVM",
    C_ML, fs=9.5)
arrow(76, 65.2, 76, 60.2)
box(76, 54, 38, 11,
    "二元標籤 → 混淆矩陣 → F1\n"
    "以 Random Forest 為例（5-fold CV）：\nP≈1.00  R≈0.986  F1≈0.993\n"
    "※ 高分源自 SmartBugs 表面統計\n（shortcut 特徵）過擬合，非語意理解；\n分佈外（EVMbench）泛化崩跌",
    C_ML, fs=8.8)

ax.text(50, 27, "圖 A-1　DmAVID 資訊處理流程：從 .sol 原始碼輸入，至 F1 分數與漏洞解釋報告輸出（並列傳統 ML 對照）",
        ha="center", fontproperties=fp, fontsize=11, fontweight="bold")
ax.set_ylim(24, 100)
plt.tight_layout()
fig.savefig(OUT_PNG, dpi=300, bbox_inches="tight", facecolor="white")
fig.savefig(OUT_PDF, bbox_inches="tight", facecolor="white")
print("saved", OUT_PNG)
print("saved", OUT_PDF)
