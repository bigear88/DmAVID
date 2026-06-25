# CTC 可解釋性評估改以 gpt-4.1-mini 重跑（canonical 更新紀錄）

> 日期：2026-06-25
> 觸發：審查報告3 指出 CTC 圖表（圖4-16）與表4-18 數據衝突，且評估模型名實不符。
> 真實來源：`experiments/explainability/ctc_eval_summary.json`（`scripts/70_ctc_explainability_eval.py --judge openai --judge-model gpt-4.1-mini`）

## 背景

論文先前之 CTC 分數存在三方名實不符：
- 正文敘述 CTC 評審模型為 **GPT-4.1-mini**；
- 圖 4-15/4-16 標示為 **GPT-4o-mini**；
- 而產生 7.777 / 1.876 / 7.209 之 canonical 資料檔 `ctc_eval_summary.json` 實際記錄 `"model": "gpt-5.4"`。

依「不得造假、數據須與實驗一致」原則，改以論文宣稱之主模型 **gpt-4.1-mini** 重新執行 CTC 評估（143 份 ground-truth 漏洞合約 × 3 方法＝429 次 judge 呼叫），取得名實相符且可重現之分數。

## 新 canonical（gpt-4.1-mini judge，n=143）

| 方法 | Correctness | Thoroughness | Clarity | CTC 綜合 |
|---|---|---|---|---|
| DmAVID | 8.881 | 8.014 | 8.035 | **8.536** |
| LLM-only (GPT-4.1-mini) | 8.587 | 6.867 | 7.692 | **7.981** |
| Slither | 3.266 | 2.112 | 3.301 | **2.923** |

- DmAVID CTC 8.536 > LLM 7.981 > Slither 2.923；DmAVID/Slither ≈ **2.92 倍**（舊 gpt-5.4 為 4.1 倍）。
- Wilcoxon 單尾檢定：DmAVID vs LLM、DmAVID vs Slither 皆 **p<0.0001**（W=7211.5、10296.0）。
- 加權：CTC = 0.6×C + 0.3×T + 0.1×CL（同 Smart-LLaMA-DPO, ISSTA 2025）。

### 逐類別（DmAVID，CTC）
重入 8.661 / 整數溢位 8.073 / 阻斷服務 8.667 / 時間操縱 8.680 / 未檢查 8.456 / 存取控制 8.794 / 搶先交易 8.625 / 隨機性 8.550。

## 舊資料保存

- `ctc_eval_summary_gpt5.4_backup.json`（gpt-5.4：7.777/1.876/7.209，已棄用）
- `ctc_eval_summary_gpt4omini_backup.json`（gpt-4o-mini：4.455/3.704/4.294，舊圖4-16 誤用來源）

## 連動更新（論文 v11）

- 表 4-18（三方對比）、表 4-19（逐類別）全面換為新值。
- 正文 §4.x（P520/521/522/534/546/551/554）：7.777→8.536、1.876→2.923、7.209→7.981、4.1 倍→2.9 倍、三維度子分數同步。
- 圖 4-14（雷達）、圖 4-15（維度對比）、圖 4-16（綜合分數）重繪，judge 標籤統一為 **GPT-4.1-mini**。
- 圖 4-2 / 4-3：四階段管線末點由 0.9132（舊 exp15）更正為 **0.9158**（ChromaDB R3）、FPR 末點 0.18、標籤 R3。

> 自此 CTC canonical 為 gpt-4.1-mini 之 8.536 / 7.981 / 2.923；勿再引用 7.777 / 1.876 / 7.209（gpt-5.4）或 4.455 / 3.704 / 4.294（gpt-4o-mini）。
