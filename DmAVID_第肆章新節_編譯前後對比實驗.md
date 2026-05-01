# 第肆章 第十五節 編譯前 vs 編譯後對比實驗（Sprint 8）

> 對應第貳章第七節缺口 Gz：「DmAVID（編譯前 source-level）與 SoliAudit-style（編譯後 bytecode-level）兩條
> 漏洞偵測路線在文獻中各自報告高 F1，但缺乏 paired comparison。本實驗以同份 SmartBugs 樣本對兩條路線
> 做直接對比，化解第貳章「ML 不適用」與 SoliAudit 89% F1 之表面矛盾。」
>
> 全程**無 API 成本**，純本地 solc 編譯 + sklearn 訓練。

## 4.15.1 研究背景與設計動機

| 路線 | 輸入 | 表徵 | 模型 | 文獻代表 |
|---|---|---|---|---|
| 編譯前（DmAVID） | Solidity source | 自然語言 + RAG context | LLM (gpt-4.1-mini) + Self-Verify | 本研究 |
| 編譯後 (SoliAudit-style) | Solidity source → solc → bytecode | opcode N-gram TF-IDF | RF / GBoost / SVM | Liao et al. 2019 (89% F1) |

文獻中此二路線從未在「同一樣本 / 同一切分 / paired bootstrap」下直接對比。本節補上這一缺口。

## 4.15.2 編譯結果（圖 4-21 / 表 4-35）

對 SmartBugs Curated 143 vuln + Wild safe 100 共 **243** 合約，使用 `solc-select` 切換 25 個 Solidity 版本（0.4.11 到 0.8.20）做編譯：

- **編譯成功：223 / 243 = 91.8%**
- **失敗類型分布**：
  - `compile_error`: 16
  - `import_not_found`: 1
  - `pragma_not_found_or_no_solc_version`: 3

**圖 4-21**　SmartBugs 243 編譯狀態 pie chart（charts/sprint8_compile_status.png）

solc 版本使用分布（每個合約對應到最匹配的 installed 版本）：
  - 0.4.18: 1
  - 0.4.19: 2
  - 0.4.21: 1
  - 0.4.24: 6
  - 0.4.25: 2
  - 0.4.26: 224
  - 0.5.17: 3
  - 0.8.20: 1

## 4.15.3 9 組 bytecode-ML 對照（表 4-36）

特徵設定（experiments/bytecode_ml/features_meta.json）：
- **F1**（baseline）: 1-gram opcode + TF-IDF（vocab=77）
- **F2**（SoliAudit-like）: 1+2+3-gram + TF-IDF（vocab=2069, max_features=10000）
- **F3**（enhanced）: F2 + opcode 序列長度 + JUMP/JUMPI/JUMPDEST/LOG/CALL ratio

切分：80/20 stratified, seed=42（對齊 Sprint 3 CodeBERT）；hyperparameter 5-fold CV grid search。
測試集 n = 45；F1 95% CI = 1000 次 bootstrap on test set。

**表 4-36**　9 組 bytecode-ML F1 + CI + 訓練/推論時間

| 設定 | F1 | 95% CI | Precision | Recall | FPR | Train (s) | Infer (s/contract) |
|---|---:|---|---:|---:|---:|---:|---:|
| F1_GBoost | **0.8421** | [0.7308, 0.9333] | 0.8276 | 0.8571 | 0.2941 | 1.74 | 1.3e-05 |
| F1_RF | **0.8571** | [0.7499, 0.9455] | 0.8571 | 0.8571 | 0.2353 | 2.29 | 0.000806 |
| F1_SVM | **0.9057** | [0.8075, 0.9804] | 0.9600 | 0.8571 | 0.0588 | 0.03 | 1.2e-05 |
| F2_GBoost | **0.9057** | [0.8, 0.9787] | 0.9600 | 0.8571 | 0.0588 | 1.92 | 1.9e-05 |
| F2_RF | **0.8846** | [0.7755, 0.9643] | 0.9583 | 0.8214 | 0.0588 | 1.42 | 0.001341 |
| F2_SVM | **0.9057** | [0.8085, 0.9787] | 0.9600 | 0.8571 | 0.0588 | 0.15 | 0.000196 |
| F3_GBoost | **0.9057** | [0.8, 0.9787] | 0.9600 | 0.8571 | 0.0588 | 4.51 | 1.8e-05 |
| F3_RF | **0.8846** | [0.7755, 0.9643] | 0.9583 | 0.8214 | 0.0588 | 1.36 | 0.00128 |
| F3_SVM | **0.8679** | [0.7586, 0.9546] | 0.9200 | 0.8214 | 0.1176 | 0.11 | 0.000154 |

**最佳設定**：`F1_SVM`，F1 = 0.9057

**圖 4-22**　9 組 bytecode-ML F1 + DmAVID Hybrid reference（charts/sprint8_f1_comparison.png）

## 4.15.4 DmAVID vs 最佳 bytecode-ML — paired comparison（表 4-37）

於同一份 test set（n = 45）：

**表 4-37**　DmAVID Hybrid vs 最佳 bytecode-ML

| 方法 | F1 | 95% CI | Precision | Recall | FPR |
|---|---:|---|---:|---:|---:|
| **DmAVID Hybrid** (canonical, predictions from `ablation_v5_clean_self-verify_details.json`) | **0.9455** | [0.875, 1.0] | 0.9630 | 0.9286 | 0.0588 |
| **bytecode-ML best (F1_SVM)** | **0.9057** | [0.8075, 0.9804] | 0.9600 | 0.8571 | 0.0588 |

**Paired bootstrap (1000 次)**：
- 平均 F1 差值（DmAVID − bytecode-ML）= 0.0408
- 95% CI = [-0.0312, 0.1252]
- P(DmAVID > bytecode-ML) = 0.8640

**McNemar test**：
- DmAVID 答對 / bytecode-ML 答錯：b = 3
- DmAVID 答錯 / bytecode-ML 答對：c = 1
- p-value = 0.625

**CI overlap**：是 → 統計上不顯著差異

**圖 4-23**　Paired bootstrap F1 差值分布（charts/sprint8_paired_bootstrap.png）

## 4.15.5 EXI 4-way 對比（表 4-38）

對 bytecode-ML 套相同 EXI 評估流程（Sprint 6 定義），實際掃描其輸出欄位：

| 方法 | Pattern Coverage | Root Cause Acc | Attack Path Cov | Repair Quality (1-5) | **EXI (0-100)** |
|---|---:|---:|---:|---:|---:|
| **DmAVID** (LLM+RAG+Self-Verify) | 100.00% | 95.00% | 64.10% | 2.91 | **81.15** |
| Slither | 57.78% | 40.00% | 0.00% | 0.00 | 26.44 |
| CodeBERT | 0.00% | 0.00% | 0.00% | 0.00 | 0.00 |
| **bytecode-ML** (F1_SVM) | 0.00% | 0.00% | 0.00% | 0.00 | 0.00 |

bytecode-ML 與 CodeBERT 同為黑盒分類器（無 reasoning / vulnerability_type / attack path / repair 輸出），
EXI 為 0；非 hard-code，而是 EXI 流程實際掃描其輸出欄位皆為空。

**圖 4-24**　EXI 4-way bar chart（charts/sprint8_exi_4way.png）

## 4.15.6 結論

**情境 B 偏 A — F1 微幅領先**：DmAVID F1 = 0.9455 略高於 bytecode-ML F1_SVM F1 = 0.9057，差距 0.0398，CI 重疊 = True。統計上不顯著，但 EXI 維度 DmAVID 大幅領先（81.15 vs 0），結論為「F1 等價、可解釋性懸殊」。

**化解第貳章「ML 不適用」vs SoliAudit 89% F1」之表面矛盾**：
- SoliAudit 在 17,392 大規模 dataset 達 89%；本實驗在 SmartBugs 243（小規模、年代偏舊、編譯成功率 91.8%）
  上得到 bytecode-ML F1 = 0.9057，與 DmAVID F1 = 0.9455 比對。
- 兩路線於 in-distribution F1 維度上「DmAVID 微幅領先」，
  EXI 維度則 DmAVID（81.15）vs bytecode-ML（0.00）懸殊。
- 因此「ML 不適用」之原文獻論述應修正為「**bytecode-level ML 在 in-distribution F1 與 LLM-based 方法可比，但結構性
  缺乏可解釋性、zero-shot 部署彈性與修復建議**」。

## 4.15.7 評估限制

- **編譯失敗率 8.2%**（透明標註）：僅對成功編譯之 223 合約做 ML 訓練；
  未編譯成功的 20 個合約於 bytecode-ML 路線上等同 systematically excluded。
- **SmartBugs Curated 規模限制**（243 vs SoliAudit 17,392）：bytecode-ML 在小樣本上仍能達到此 F1
  顯示其 generalize 能力，但無法直接外推到大規模情境。
- **bytecode-ML 僅 single seed 80/20 split**：未做 5-fold CV 完整重複（hyperparameter 已用 5-fold CV grid search 選擇）。
- **跨資料集（EVMbench post-cutoff）未涵蓋**：現代 DeFi protocol 之 bytecode-ML 表現留待 future work。

---
_資料來源：experiments/bytecode_ml/{compile_results, results, exi_bytecode_ml, paired_bootstrap}.json_
_API 成本：$0_
_生成時間：2026-05-01T15:08:31.856590_
