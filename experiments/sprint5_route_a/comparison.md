# Sprint 5 路線 A — Out-of-Distribution Generalization 對比

_Generated: 2026-04-28T04:41:12.501226_

**訓練資料**：SmartBugs（ML 用 Stage 2 length-matched 286；CodeBERT 用 Sprint 3 配置 243）
**測試資料**：EVMbench post-cutoff 8 個 audits（2025+ / 2026+），每 audit 之 `patch/*.sol` 合併為單一輸入

## 三軌總覽

| 方法 | In-Domain F1（5-fold CV） | OOD Audit-level Recall | OOD Vuln-level Recall |
|---|---:|---:|---:|
| Random Forest | 0.8886±0.0316 | 0/8 = 0.00% | ✘ N/A |
| Logistic Regression | 0.8282±0.0348 | 1/8 = 12.50% | ✘ N/A |
| Gradient Boosting | 0.9064±0.0315 | 0/8 = 0.00% | ✘ N/A |
| SVM (RBF) | 0.6448±0.0625 | 7/8 = 87.50% | ✘ N/A |
| CodeBERT (微調) | — | 2/8 = 25.00% | ✘ N/A |
| **DmAVID Hybrid (canonical)** | — | **2/8 = 25.00%** | **2/17 = 11.76%** |

## 逐 audit 預測（1=vulnerable, 0=safe）

| audit_id | Random Forest | Logistic Regression | Gradient Boosting | SVM (RBF) | CodeBERT | DmAVID_audit | DmAVID_vulns |
|---|---|---|---|---|---|---|---|
| 2025-01-liquid-ron | 0 | 0 | 0 | 1 | 0 | 0 | 0/1 |
| 2025-04-forte | 0 | 1 | 0 | 1 | 0 | 0 | 0/5 |
| 2025-04-virtuals | 0 | 0 | 0 | 1 | 0 | 0 | 0/4 |
| 2025-05-blackhole | 0 | 0 | 0 | 0 | 0 | 0 | 0/1 |
| 2025-06-panoptic | 0 | 0 | 0 | 1 | 0 | 0 | 0/2 |
| 2026-01-tempo-feeamm | 0 | 0 | 0 | 1 | 0 | 1 | 1/1 |
| 2026-01-tempo-mpp-streams | 0 | 0 | 0 | 1 | 1 | 0 | 0/1 |
| 2026-01-tempo-stablecoin-dex | 0 | 0 | 0 | 1 | 1 | 1 | 1/2 |

## ⚠ 評估限制與退化基準警告

**8 個 audits 皆為 vulnerable（無 safe 對照）**，故只能算 audit-level **Recall**，無法計算 Precision/FP。
退化基準：**「全部預測 vulnerable」可獲得 8/8 = 100%**，這是無意義上限。

- **SVM (RBF) 的 7/8 不是真正的勝利**：其 in-domain CV F1=0.6448 已遠低於其它 ML（0.83~0.91），決策邊界嚴重偏向 vulnerable class，等同退化基準。論文應排除其 OOD 數值或標註為「退化模型參考值」。
- **RF/GB 0/8 雖然極端但反映真實**：兩者 in-domain F1=0.89~0.91 看似強，OOD 完全失效，這才是泛化失敗的明確訊號。

## 解讀

- **In-Domain vs OOD 落差**：RF/GB 從 SmartBugs CV F1≈0.90 退到 OOD 0%，CodeBERT 從 Sprint 3 ID F1=0.9180 退到 OOD 25%。傳統 ML 與 PLM 微調都吃 SmartBugs 樣本偏差。
- **CodeBERT 與 DmAVID Hybrid audit-level 並列 25%（2/8），但偵測的 audit 不同**：
  - DmAVID 命中：`2026-01-tempo-feeamm`、`2026-01-tempo-stablecoin-dex`
  - CodeBERT 命中：`2026-01-tempo-mpp-streams`、`2026-01-tempo-stablecoin-dex`
  - 唯一重疊：`tempo-stablecoin-dex`。兩種方法**歸納偏好不同**，潛在 ensemble 上限為 3/8 = 37.5%。
- **DmAVID Hybrid 唯一支援 vuln-level**：傳統 ML 與 PLM 微調為 contract-level binary classifier，無法逐一指出 17 個 gold vulns 中的哪些被偵測。DmAVID 的 11.76% 雖數值看似低，但提供的是定位資訊而非「contract is buggy」這種粗粒度判斷。
- **OOD 是研究價值所在**：post-cutoff（2025+/2026+）8 audits 確保不在 SmartBugs / CodeBERT 預訓練 / DmAVID RAG 語料中，這是真實佈署條件下唯一公平的對比場景。
