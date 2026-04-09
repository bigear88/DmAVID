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

| 方法 | F1 | Precision | Recall | FPR | 資料集 |
|------|-----|-----------|--------|-----|--------|
| Slither | 0.7459 | 61.6% | 94.4% | 84.0% | SmartBugs 243 |
| LLM Base | 0.7474 | 59.9% | 99.3% | 95.0% | SmartBugs 243 |
| **LLM+RAG** | **0.9061** | **84.3%** | **97.9%** | **26.0%** | SmartBugs 243 |
| **+Self-Verify** | **0.9121** | **85.4%** | **97.9%** | **24.0%** | SmartBugs 243 |
| DmAVID Enhanced | 20.51% detect | 100% | 20.5% | 0% | EVMbench 39 |

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
│   ├── 13_foundry_validate.py        # Stage 4: Foundry 編譯驗證
│   ├── 18_blue_team_defense.py       # Stage 4: Blue Team Agent
│   ├── 19_coordinator_round2.py      # Stage 4: Coordinator 編排
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
│   ├── dmavid_round2/            # DmAVID 迭代結果
│   ├── evmbench_enhanced/            # EVMbench 增強偵測 (20.51%)
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

### 雙層迭代迴圈

- **外層**：Teacher 輪詢漏洞類型 (reentrancy → overflow → access control → ...)
- **內層**：Student 偵測 → FN 收集 → Red Team 變體 → Foundry 驗證 → Blue Team 合成 → RAG 更新 → 重新評估

### 收斂條件

1. F1 收斂：連續兩輪 ΔF1 < 0.5%
2. 無新發現：連續三輪 Red Team 無有效變體
3. 最大輪次：10 輪上限
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

傳統 ML (RF F1=0.993) 學到的是**資料集風格差異**，而非漏洞語意：
- Top TF-IDF 特徵：totalSupply, allowance, indexed (ERC20 特徵)
- 移除標注後 RF 仍達 0.955
- EVMbench 真實場景：傳統工具 0%，DmAVID 20.51%

### 2. 分階段消融

| 配置 | F1 | 增量 |
|------|-----|------|
| Slither only | 0.7459 | 基線 |
| +LLM+RAG | 0.8468 | **+12.8%** |
| +Self-Verify | 0.8896 | **+5.1%** |
| +DmAVID 迭代 | 0.8924 | +0.3% |

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
python scripts/22_evmbench_enhanced.py
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
