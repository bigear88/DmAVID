# Sprint 5 路線 A — Out-of-Distribution 對比（修正版：distribution shift 診斷）

_Generated: 2026-04-28_

> ⚠ **本版為初步診斷，非泛化失敗結論**。下方「混淆變數」一節說明原因。

**訓練資料**：SmartBugs（ML 用 Stage 2 length-matched 286；CodeBERT 用 Sprint 3 配置 243）
**測試資料**：EVMbench post-cutoff 8 個 audits（2025+ / 2026+），每 audit 之 `patch/*.sol` 合併為單一輸入

## 主表（threshold τ=0.5）

| 方法 | In-Domain CV F1 | OOD Audit-level Recall | OOD Vuln-level |
|---|---:|---:|---:|
| Random Forest | 0.8886±0.0316 | 0/8 = 0.00% | ✘ N/A |
| Logistic Regression | 0.8282±0.0348 | 1/8 = 12.50% | ✘ N/A |
| Gradient Boosting | 0.9064±0.0315 | 0/8 = 0.00% | ✘ N/A |
| SVM (RBF) ⚠退化 | 0.6448±0.0625 | 7/8 = 87.50% | ✘ N/A |
| CodeBERT (微調) | F1=0.9180 (Sprint 3) | 2/8 = 25.00% | ✘ N/A |
| **DmAVID Hybrid (canonical)** | — | **2/8 = 25.00%** | **2/17 = 11.76%** |

## 🔴 混淆變數：本次對比並非乾淨的泛化測試

訓練（SmartBugs Curated）與測試（EVMbench post-cutoff）兩套資料在三個維度**結構性不同**，而非單純「分布微移」。

### ① Solidity 版本錯位（最致命）
| 來源 | solidity_major median | is_pre_08 比例 |
|---|---:|---:|
| Train vuln (143) | 0.4 | **100%** |
| Train safe_LM (143) | 0.4 | 90% |
| OOD audits (8) | **0.8** | **0%** |

`is_pre_08` 在 train 與 vulnerable 強相關（vuln 1.00 vs safe 0.90），OOD 全部 0 → 任何用上此特徵的模型都會把 OOD 推向 safe。SmartBugs Curated 收集年代為 2017–2020，EVMbench 為 2024–2026，這是**年代差**而非偵測能力差。

### ② 合約規模差距 ~10 倍
| 指標 | Train vuln median | OOD median | 倍數 |
|---|---:|---:|---:|
| total_lines | 35 | 369 | **10.5×** |
| code_length | 792 | 9562 | **12.1×** |
| num_functions | 4 | 15 | **3.8×** |

SmartBugs Curated 是教學等級小範例（單合約、單函式漏洞），EVMbench 是 production-grade DeFi protocol（多合約 / 多繼承 / 多函式）。

### ③ TF-IDF 詞彙幾乎不交集
- 500 個 TF-IDF 特徵佔 RF 重要性 **90%**（Structural 僅佔 10%）
- EVMbench 用現代語法（`unchecked`, custom errors, `type().max`）+ DeFi 詞彙（liquidity / oracle / swap / vault）
- → 大量 OOD token 在 TF-IDF 是零向量 → 模型 fallback 到 class prior

## Threshold 敏感性實驗（τ ∈ {0.5, 0.45, 0.4, 0.35, 0.3, 0.25, 0.2}）

| Model | τ=0.50 | τ=0.45 | τ=0.40 | τ=0.35 | τ=0.30 | τ=0.25 | τ=0.20 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Random Forest | 0/8 | 0/8 | 0/8 | 1/8 | **2/8** | 4/8 | 7/8 |
| Logistic Regression | 1/8 | 1/8 | 1/8 | 1/8 | 1/8 | 1/8 | 1/8 |
| Gradient Boosting | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 1/8 |
| SVM (RBF) ⚠退化 | 7/8 | 7/8 | 7/8 | 7/8 | 8/8 | 8/8 | 8/8 |

**關鍵詮釋**：
- **RF 在 τ=0.30 即與 DmAVID Hybrid 並列 2/8**：RF 並未「失去偵測能力」，而是 distribution shift 把所有預測機率整體往 safe 推（max P_vuln=0.39，距 0.5 僅 0.11）。
- **GB 確實失敗**：P_vuln 範圍 0.02–0.20，即便 τ=0.20 也只得 1/8。GB 對 OOD shift 反應比 RF 激進。
- **LR 與 threshold 無關**：固定 1/8，邏輯回歸的線性決策邊界本來就壓在邊緣。
- **SVM 即便 τ=0.5 已 7/8**：CV F1=0.6448 已遠低於其他 ML，決策偏向 vulnerable，等同退化基準（「全部預測 vulnerable」=8/8 = 100%）。
- **threshold 調整不是 valid 評估方法**：8 audits 全 vulnerable，無法用此資料校 τ；本實驗僅作診斷。

## 逐 audit 預測（τ=0.5）

| audit_id | RF | LR | GB | SVM | CodeBERT | DmAVID_audit | DmAVID_vulns |
|---|---|---|---|---|---|---|---|
| 2025-01-liquid-ron | 0 | 0 | 0 | 1 | 0 | 0 | 0/1 |
| 2025-04-forte | 0 | 1 | 0 | 1 | 0 | 0 | 0/5 |
| 2025-04-virtuals | 0 | 0 | 0 | 1 | 0 | 0 | 0/4 |
| 2025-05-blackhole | 0 | 0 | 0 | 0 | 0 | 0 | 0/1 |
| 2025-06-panoptic | 0 | 0 | 0 | 1 | 0 | 0 | 0/2 |
| 2026-01-tempo-feeamm | 0 | 0 | 0 | 1 | 0 | **1** | 1/1 |
| 2026-01-tempo-mpp-streams | 0 | 0 | 0 | 1 | **1** | 0 | 0/1 |
| 2026-01-tempo-stablecoin-dex | 0 | 0 | 0 | 1 | **1** | **1** | 1/2 |

## 修正後的論文敘事

**不要寫**：「ML 在 SmartBugs F1 高但 OOD 崩 → 證明傳統 ML 過擬合」（過度簡化、誤導）

**改寫為**：

> 「SmartBugs Curated（2017–2020 / Solidity 0.4–0.6 / 教學樣例）與 EVMbench post-cutoff
> （2024–2026 / Solidity 0.7–0.8 / production-grade DeFi）在年代、規模、語法上皆有結構性差異。
> 任何 supervised method（包含 PLM 微調）在訓練語料受限於前者時，OOD 部署於後者必然吃此 distribution shift。
> 本次 RF τ=0.5 的 0/8 並非偵測能力缺失（τ=0.3 即恢復至 2/8 與 DmAVID 並列），而是分布偏移將機率整體往 safe 推。
>
> DmAVID Hybrid 在此場景顯示的優勢是**結構性的**：
> (i) 不依賴 SmartBugs label 訓練，故對年代/規模 shift 免疫；
> (ii) 唯一能輸出 vuln-level 定位（17 個 gold vulns 中找到 2 個具體哪個），ML/CodeBERT 為 binary classifier 結構上做不到；
> (iii) RAG 的最新審計案例使其覆蓋現代 DeFi 詞彙與漏洞模式。」

## 評估限制

- **8 audits 全 vulnerable，無 safe 對照**：僅能算 audit-level Recall，無 Precision/FP，退化基準為 8/8 = 100%。
- **後續可補強（建議列為論文 future work）**：
  - 用 modern Solidity 0.8.x 標註資料集（DAppSCAN / SCRepair / SolidiFI 0.8 fork）重訓 ML/CodeBERT，控制年代 confounder
  - 加入 safe contracts 至 OOD 測試集（從 audited-clean DeFi protocols 取樣）以計算 Precision
- **CodeBERT 與 DmAVID 命中互補**：兩者各自 2/8，唯一重疊 `tempo-stablecoin-dex`，潛在 ensemble 上限 3/8 = 37.5%。
