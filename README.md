# DmAVID：DeFi 多智能體迭代漏洞檢測框架

**DmAVID: DeFi Multi-Agentic Vulnerability Iterative Detection**

> 臺北市立大學 資訊科學系碩士在職專班碩士論文  
> 指導教授：壽大衛 博士 ｜ 研究生：張宏睿

---

## 研究摘要

DmAVID 是一個針對以太坊 DeFi 智能合約的**多代理對抗式迭代漏洞偵測框架**，整合四階段偵測管線與五代理協作機制：

```
Stage 1: 靜態分析 (Slither)        → 模式匹配基線
Stage 2: LLM+RAG (GPT-4.1-mini)   → 語義推論 + 知識增強
Stage 3: Self-Verify               → Exploit Path 後處理驗證
Stage 4: DmAVID 多代理迭代         → Teacher/Student/Red Team/Blue Team 對抗自強化
```

### 核心成果

**SmartBugs 243 合約（Curated 143 漏洞 + Wild 100 安全）**

| 方法 | F1 | Precision | Recall | FPR |
|------|-----|-----------|--------|-----|
| Slither（靜態基線） | 0.7459 | 61.6% | 94.4% | 84.0% |
| LLM Base（無 RAG） | 0.7474 | 59.9% | 99.3% | 95.0% |
| **LLM+RAG（官方基線）** | **0.9061** | **84.3%** | **97.9%** | **26.0%** |
| **+Self-Verify（單通道 FINAL · 穩健最佳）** | **0.9121** | **85.4%** | **97.9%** | **24.0%** |
| **DmAVID 迭代 R3（ChromaDB · compile-only 閘門 · 單調 · FINAL）** | **0.9158** | **88.3%** | **95.1%** | **18.0%** |

**EVMbench 真實審計泛化（39 漏洞 / 10 審計）**

| 階段 | 偵測率 | 偵測數 |
|------|--------|--------|
| LLM+RAG（detect-only） | 7.69% | 3 / 39 |
| **RAG + Smart Preprocess（FINAL）** | **64.10%** | **25 / 39** |
| Post-cutoff 泛化（8 審計，2025–2026） | 58.82% | 10 / 17 |

> 數字鎖定於 `CANONICAL_TRUTH.md §H` / `CANONICAL_STATE.md`。**單通道穩健最佳 = +Self-Verify（F1=0.9121）**；**正式迭代管線（canonical）= 自主型 Coordinator（autonomous、ChromaDB 知識回饋閉環、compile-only 把關、T=0.1/seed=42、3 輪）**，三輪 F1 **單調遞增 0.9103→0.9153→0.9158**（Recall 0.9231→0.9510、FN 11→7、26 補丁；> 單通道 0.9121），支持 FN 課程學習設計理念。**採用此版本之缺點（誠實揭露）**：(1) 補丁僅 solc 編譯通過、未經 forge test PoC 攻擊重放驗證 → 0.9158 宜視為效能上界；(2) 改嚴格 forge test PoC 把關則該對照雖生成 30 變體（10/輪）、PoC 通過 17（7/4/6），但實際入庫補丁僅 1/輪=3（patterns_added 1/1/1，對比 compile-only 26），學習訊號驟稀 → 退為非單調 0.9164→0.9060→0.9128、僅與單通道相當（`experiments/dmavid_autonomous/`）；(3) multi-seed（42/7/123）+ placebo 顯示單調增益對 seed 敏感（placebo R3 0.9201 ≥ treatment 0.9149）、未達統計顯著。詳見 `experiments/dmavid_autonomous_BAK_precompile_20260626/`（**主，compile-only，F1=0.9158**）、`experiments/dmavid_autonomous/`（真 PoC 嚴格閘門對照，F1=0.9128）、`experiments/seed_placebo/`。

---

## 專案結構

```
DmAVID/
├── README.md
├── scripts/                          # 實驗腳本
│   ├── 01_prepare_dataset.py         # 資料集建構 (243 合約)
│   ├── 02_run_slither.py             # Stage 1: Slither 靜態分析
│   ├── 03_run_mythril.py             # Stage 1: Mythril 符號執行
│   ├── 04_run_llm_base.py            # Stage 2: LLM 基線偵測
│   ├── 05_run_llm_rag.py             # Stage 2: LLM+RAG 增強偵測 (Student Agent)
│   ├── 06_run_hybrid.py              # Stage 3: 多策略 Hybrid 融合
│   ├── postprocess_self_verify.py    # Stage 3: Self-Verify 後處理
│   ├── 11_teacher_challenge.py       # Stage 4: Teacher Agent
│   ├── 12_red_team_generate.py       # Stage 4: Red Team Agent
│   ├── 13_foundry_validate.py        # (DEPRECATED) 假驗證 assertTrue(true)；僅 exp12~15 用過，已停用、執行即中止
│   ├── 13b_foundry_poc.py            # Stage 4: Foundry 真實驗證 (solc 編譯 + forge test PoC + 自我修復)
│   ├── 18_blue_team_defense.py       # Stage 4: Blue Team Agent
│   ├── 20_coordinator_autonomous.py  # Stage 4: Coordinator 自主編排 (canonical, --seed/--placebo/--gate)
│   ├── 21_error_analysis.py          # 錯誤分析 + KB 更新
│   ├── 22_evmbench_enhanced.py       # EVMbench 增強偵測
│   ├── 23_traditional_ml_baseline.py # 傳統 ML 基線 (RF/LR/GB/SVM)
│   ├── 24_defi_real_world_test.py    # DeFiHackLabs 真實場景測試
│   ├── 25_style_balanced_test.py     # 風格平衡消融實驗
│   ├── 26_explainability_metrics.py  # 可解釋性量化指標
│   ├── _model_compat.py              # GPT-4.1-mini 相容層
│   └── build_knowledge_base.py       # ChromaDB RAG 知識庫建構
├── data/
│   ├── dataset_1000.json             # 主資料集 (143 vuln + 857 safe)
│   ├── smartbugs_curated_repo/       # SmartBugs Curated 漏洞合約
│   ├── smartbugs_wild_repo/          # SmartBugs Wild 安全合約
│   ├── chroma_kb/                    # ChromaDB 向量知識庫
│   └── DeFiHackLabs/                 # 真實 DeFi 攻擊 PoC
├── experiments/                       # 實驗結果
│   ├── slither/                      # Slither 基線結果
│   ├── llm_base/                     # LLM 基線結果
│   ├── llm_rag/                      # LLM+RAG 結果 (F1=0.9061)
│   ├── hybrid/                       # Self-Verify 結果 (F1=0.9121)
│   ├── dmavid_autonomous_BAK_precompile_20260626/  # DmAVID 迭代 canonical 主結果 (compile-only 閘門, ChromaDB, 單調 0.9103→0.9153→0.9158)
│   ├── dmavid_autonomous/      # 迭代嚴格 PoC 閘門對照 (真 forge test PoC, 非單調 0.9164→0.9060→0.9128)
│   ├── exp15/                  # (deprecated) JSON-only 迭代 F1=0.9132，已被 dmavid_autonomous 取代
│   ├── dmavid_round2/            # DmAVID 迭代過程輸出
│   ├── evmbench_postcutoff/         # EVMbench 知識截止後泛化 (58.82%, 10/17)
│   ├── evmbench_enhanced/            # (DEPRECATED) hint/gold-injected 30.77%，因洩漏已自乾淨兩段軌跡移除
│   ├── evmbench_smart/               # EVMbench 智能預處理 (64.10%, 25/39, FINAL)
│   ├── traditional_ml/              # 傳統 ML 基線 (RF/LR/GB/SVM)
│   ├── defi_real_world/             # DeFiHackLabs 測試
│   ├── style_balanced/              # 風格平衡消融
│   ├── explainability/              # 可解釋性指標
│   └── agentic/                     # 錯誤分析 + KB 更新
├── docs/
│   └── cross_validation_report.md    # 論文 vs GitHub 交叉驗證
└── charts/                           # 實驗圖表
```

---

## 五代理架構

```
┌─────────────────────────────────────────────────┐
│              Coordinator Agent                   │
│         (迭代編排、資源管理、停止決策)            │
└────────┬──────────┬──────────┬──────────┬───────┘
         │          │          │          │
    ┌────▼───┐ ┌────▼───┐ ┌───▼────┐ ┌───▼────┐
    │Teacher │ │Student │ │Red Team│ │Blue Team│
    │ Agent  │ │ Agent  │ │ Agent  │ │ Agent  │
    │        │ │        │ │        │ │        │
    │出題挑戰│ │混合偵測│ │對抗變體│ │防禦合成│
    │(SWC分類)│ │(4階段) │ │(FN攻擊)│ │(KB更新)│
    └────────┘ └────────┘ └────────┘ └────────┘
```

### 自適應迭代迴圈

每一輪由 Coordinator 自適應決策、對完整 243 合約評估，形成閉環自強化：

- **單一自適應迴圈**：Coordinator 依上一輪 F1／FN 分布決定本輪重點漏洞類型與攻防策略（取代固定輪詢的雙層設計）
- **每輪流程**：Student 偵測 (LLM+RAG+Self-Verify) → FN 收集 → Red Team 對抗變體 → Foundry 編譯/PoC 驗證 → Blue Team 防禦合成 → 知識庫更新 → 重新評估
- **ChromaDB 知識回饋閉環**：Blue Team 合成之防禦補丁經 `write_blue_team_to_chroma()` 向量化寫入 ChromaDB（`text-embedding-3-small`），並同步更新 `vulnerability_knowledge.json`；經 `reload_dynamic_kb()` 注入下一輪 Student 之 RAG 脈絡
- **FN 課程學習**：上一輪偽陰性以 `extra_context` hints 注入下一輪 Student 逐輪修正。compile-only 閘門（canonical）下三輪 F1 單調 0.9103→0.9153→0.9158（每輪 11/8/7、共 26 筆補丁，Recall 0.9231→0.9510）；缺點：改嚴格 forge test PoC 閘門則每輪有效補丁僅 ~1、退為非單調 0.9164→0.9060→0.9128（補丁未經漏洞利用驗證，0.9158 為效能上界）

### 收斂條件

1. F1 收斂：連續 patience=2 輪 ΔF1 < 0.01
2. 無新發現：連續 2 輪 Red Team 無有效變體
3. 最大輪次：3 輪上限（--rounds 3 預設）
4. 預算輔助：USD 上限作為安全邊界

---

## 資料集

| 資料集 | 規模 | 用途 |
|--------|------|------|
| SmartBugs Curated | 143 漏洞合約 (10 類) | 主測試集 |
| SmartBugs Wild | 100 安全合約 (隨機抽樣) | 主測試集 |
| EVMbench | 10 審計專案 / 39 漏洞 | 泛化驗證 |
| DeFiHackLabs | 682 攻擊 PoC | 風格洩漏分析 |

### 漏洞類型分布

| 類型 | 數量 | 典型漏洞 |
|------|------|----------|
| Unchecked Low-Level Calls | 52 | `.call()` 無返回值檢查 |
| Reentrancy | 31 | 外部呼叫在狀態更新之前 |
| Access Control | 18 | 缺少 onlyOwner 檢查 |
| Arithmetic | 15 | Solidity <0.8 整數溢位 |
| Bad Randomness | 8 | block.timestamp 偽隨機 |
| Denial of Service | 6 | 迴圈中外部呼叫 |
| Time Manipulation | 5 | 依賴 block.timestamp |
| Front Running | 4 | mempool 參數可見 |
| Short Addresses | 1 | 地址長度未驗證 |
| Other | 3 | 未初始化 storage pointer |

---

## 關鍵實驗發現

### 1. 傳統 ML 的風格洩漏

傳統 ML（RF test F1=1.0，cv F1=0.9949，leakage-fixed）學到的是**資料集風格差異**，而非漏洞語意：
- Top TF-IDF 特徵：totalSupply, allowance, indexed (ERC20 特徵)
- 移除標注後 RF 仍達 0.955
- EVMbench 真實場景：傳統工具 0%，DmAVID detect-only 7.69% (3/39) → **64.10% (25/39, Smart Preprocess FINAL)**

### 2. 分階段消融

| 配置 | F1 | 增量 |
|------|-----|------|
| Slither only | 0.7459 | 基線 |
| +LLM+RAG | 0.9061 | **+21.5%** |
| +Self-Verify | 0.9121 | **+0.7%** |
| +DmAVID 迭代（ChromaDB，3 輪，compile-only 閘門） | **0.9158** | **+0.4%** |

### 3. 可解釋性（自動化量化）

| 指標 | DmAVID | Slither | 傳統 ML |
|------|--------|---------|---------|
| 模式覆蓋率 | 90% | ~70% | 0% (黑箱) |
| 解釋深度 | 65 詞/合約 | ~15 詞 | 0 詞 |
| 修復建議率 | 52.5% | ~20% | 0% |

---

## 環境需求

```bash
# Python 3.12+
pip install openai transformers scikit-learn pandas matplotlib seaborn chromadb

# Solidity 工具
pip install slither-analyzer
pip install solc-select && solc-select install all

# Foundry (Stage 4 驗證)
curl -L https://foundry.paradigm.xyz | bash && foundryup
```

### 環境變數

```bash
export OPENAI_API_KEY="your-key"
export DMAVID_MODEL="gpt-4.1-mini"
export DMAVID_BASE_DIR="/path/to/DmAVID"
```

---

## 快速開始

```bash
# 1. Baseline 實驗
python scripts/02_run_slither.py          # Stage 1
python scripts/05_run_llm_rag.py          # Stage 2
python scripts/postprocess_self_verify.py --conf-threshold 0.95  # Stage 3

# 2. DmAVID 迭代
python scripts/19_coordinator_round2.py --rounds 3 --budget 50

# 3. 傳統 ML 基線
python scripts/23_traditional_ml_baseline.py

# 4. 可解釋性指標
python scripts/26_explainability_metrics.py

# 5. EVMbench 泛化測試
python scripts/30_evmbench_smart_preprocess.py  # Smart preprocess FINAL (64.10%, 25/39)
python scripts/31_postcutoff_validation.py      # Post-cutoff 8 audits (58.82%, 10/17)
```

---

## 研究方法論

本研究採用**設計科學研究（DSR）**方法論（Hevner et al., 2004）：

1. **問題識別**：DeFi 安全事件損失超百億美元，現有工具缺乏自我改進機制
2. **目標定義**：多代理對抗式迭代 → 持續改進偵測能力
3. **設計開發**：四階段管線 + 五代理架構
4. **展示驗證**：SmartBugs 243 + EVMbench 39
5. **評估分析**：F1/Recall/FPR + McNemar 檢驗 + 消融實驗

---



---

## 實驗資料來源對照

| 論文表格 | 說明 | 來源 JSON |
|---------|------|-----------|
| 表 3-2（傳統 ML SmartBugs） | RF/LR/GB/SVM test F1，leakage-fixed 70/30 split | `experiments/traditional_ml/ml_baseline_results_fixed.json` |
| 表 3-2（傳統 ML DeFi Real） | DeFiHackLabs 100+100 合約測試集 | `experiments/defi_real_world/defi_results_fixed.json` |
| 表 3-2（Style Balanced） | 143+143 平衡集消融 | `experiments/style_balanced/balanced_results_fixed.json` |
| 表 3-1（Self-Verify 門檻掃描 T=1/2/3） | v4 門檻敏感度掃描（F1=0.8797/0.9030/0.9007） | `experiments/tool_augmented/threshold_sensitivity.json` |
| 漏洞類型分布（143 合約） | 依 SmartBugs GitHub 原始標籤統計 | `data/dataset_1000.json（category 欄位）` |
| 消融實驗管線 F1 | v5_clean 官方基準（LLM+RAG→Self-Verify） | `experiments/ablation/OFFICIAL_RESULTS_v5.md` |
| autonomous BAK 迭代 canonical F1=0.9158 | compile-only 閘門，3 輪單調最終值 | `experiments/dmavid_autonomous_BAK_precompile_20260626/round_3_results.json` |
| 真 PoC 嚴格閘門對照 F1=0.9128（非單調） | forge test PoC：30 變體（10/輪）/ PoC 通過 17（7/4/6）/ 實際入庫補丁僅 3（1/輪，patterns_added 1/1/1）（採此版本之缺點佐證） | `experiments/dmavid_autonomous/autonomous_progression.json` |

> **舊檔並存說明**：`experiments/traditional_ml/ml_baseline_results.json`（cv_f1=0.993）與 `experiments/defi_real_world/defi_results.json` 為 TF-IDF **未 Pipeline 化**之舊版實驗，已被 `*_fixed.json` 取代。論文所引用之所有數字均來自 `*_fixed.json`（leakage-fixed，70/30 stratified split）。

> **漏洞類別計數差異**：本研究 `data/dataset_1000.json` 所記載之 access_control=18、arithmetic=15、unchecked_low_level_calls=52，依 SmartBugs Curated GitHub 實際原始碼標籤統計。SmartBugs Durieux 2020 論文所列數字（access_control=17、arithmetic=22、unchecked=42）來自論文版本，兩者總數均為 143 漏洞合約，分類依據略有差異，本研究以 GitHub 實際標籤為準。

## 引用

```bibtex
@mastersthesis{chang2026dmavid,
  title     = {DmAVID: DeFi Multi-Agentic Vulnerability Iterative Detection},
  author    = {Chang, Hung-Jui},
  school    = {University of Taipei, Department of Computer Science},
  year      = {2026},
  note      = {Advisor: Prof. David Shou}
}
```

---

## 授權

MIT License

## 作者

**張宏睿 (bigear88)** — 臺北市立大學資訊科學系碩士在職專班
