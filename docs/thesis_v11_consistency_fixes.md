# 論文 v11 一致性修正紀錄（對齊 CANONICAL_TRUTH.md）

> 對象檔案：`DmAVID_20260622_v11.docx`
> 修正日期：2026-06-24
> 真實來源：`CANONICAL_TRUTH.md` ＋ `experiments/exp15/`、`scripts/19_coordinator_round2.py`
> 結論：README 已對齊 canonical（無誤）；v11 docx 為較舊版本，本次將其逐項對齊 canonical。

審查報告共列 10 項一致性問題，逐項處置如下（數值一律以 canonical 為準）。

| # | 位置 | 問題 | 處置 | 依據 |
|---|---|---|---|---|
| 1 | 表 3-4 vs 正文 | 收斂閾值：表用 <0.01、正文用 ≤0.002 | 正文 0.002 → **<0.01**（4 處） | `19_coordinator_round2.py` `--convergence-threshold default=0.01`、`--convergence-patience default=2` |
| 2 | 圖目錄 圖 3-5 | 標題「六步驟（S1-S6）」與正文「七步驟（S1-S7）」不符 | 圖目錄改為 **七步驟（S1-S7）** | 正文與內文圖說皆為 S1-S7 |
| 3 | 表 4-1 AuditGPT | 表中 Precision/F1 為「—」，正文三處給 0.80/0.81 | 表格**填回 0.80/0.81**；備註 `Chen et al., 2024` → **`Xia et al., 2024`** | 正文 P390/P394/P540 一致；參考文獻為 Xia et al. (2024) AuditGPT |
| 4 | 表 4-2 正文 | 「FPR 逐步降至 0.24」但最終 R2 FPR=0.26 | 改述為前三階段降至 Self-Verify 最低 **0.24**，迭代後因 Recall→0.993 回升至 **0.26** | canonical A/H |
| 5 | 表 4-7 vs 表 4-8 | FP 合約數(24) 與 類型歸因加總(46) 不符 | 補註：表 4-7 = 偽陽性**合約數**，表 4-8 = 幻覺**類型歸因次數**（可重複計），比值＝「平均每 FP 類型數」 | 24×1.96≈46、95×2.42≈227 |
| 6 | 表 4-11 access_control | Pre-iter F1 表中 1.0000、正文 0.9714 | 表格 Pre-iter **1.0000 → 0.9714**、提升 **0.0000 → +0.029**（正文正確） | canonical H：access_control 0.9714→1.0000 (+0.029) |
| 7 | 正文 Coordinator CTC | 一處「0.163」、一處「1.63（0–10 制）」 | 統一為 **1.63（0–10 制，滿分 16.3%）**（P537/P554） | ΔCTC = 8.06→6.43 = −1.63 |
| 8 | 第伍章 Recall | 「0.9650 → 0.9930」中 0.9650 來源疑義 | **不改**：0.9650 = exp15 迭代前 Recall（canonical H），與 F1 0.8961 同屬迭代管線基線，正確 | canonical H |
| 9 | 第伍章 限制 | 標籤雜訊 6–16% 無估算依據 | 補述：GPT-4.1-mini 複核野生「安全」合約，雜訊上界約 16%、人工確認約 7% | `project_safe_label_noise` v52 |
| 10 | 表 4-12 Token | 三配置 Token 逐步下降未說明 | 補述：合約展平與介面解析移除冗餘相依與重複介面，精簡有效輸入，故偵測率升而 Token 降 | canonical D／§九 智能預處理 |

## 驗證

修正後對 v11 docx 全文掃描，確認已無 deprecated 數值殘留：
`0.8917`、`0.8924`、`0.8467/0.8468`、`8/39`、`20.5%`、`≤0.002`、`六步驟/S1-S6`、`下降 0.163`、`Chen et al., 2024` 皆為 0 次命中。

備份：`DmAVID_20260622_v11.bak_before_review_fix.docx`。
