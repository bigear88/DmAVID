# EVMbench 延伸實驗 — CLI 執行指南

## 概述

本指南用於在 WSL ext4 環境中執行 EVMbench 延伸實驗。
實驗包含 2 個部分：
1. **LLM+RAG 偵測** (`09_run_evmbench_detect.py`) — 純 LLM+RAG 在 EVMbench 上的偵測效能
2. **混合式框架** (`10_run_evmbench_hybrid.py`) — 改良後的 Hybrid Verification (Two-Stage Fusion)

## 前置條件

- WSL ext4 檔案系統（不要在 NTFS 上跑）
- Python 3.10+ with venv
- OPENAI_API_KEY
- Git（用來 clone EVMbench audit repos）

## 已完成的準備工作（由 Cowork 完成）

1. ✅ 3 支 EVMbench 腳本已重寫（ChromaDB RAG、GPTScan 預過濾、Two-Stage Fusion）
2. ✅ 修正 RAG 嵌入維度不匹配 bug（query 改用 OpenAI embedding）
3. ✅ 修正 Judge 載入漏洞詳細描述（從 findings/H-xx.md）
4. ✅ EVMbench 資料集已放到 `data/evmbench/audits/`（46 個 audits，含 10 個 sample）
5. ✅ Runner 腳本 `scripts/run_evmbench_all.sh`
6. ✅ `.env` 模板

## 執行步驟

### Step 1: 複製專案到 WSL ext4

```bash
# 如果專案還在 NTFS，先複製到 ext4
cp -r /mnt/c/.../DmAVID ~/DmAVID
cd ~/DmAVID
```

如果專案已在 ext4 (`~/DmAVID`)，直接 cd 進去即可。

### Step 2: 設定環境

```bash
# 設定 API Key
export OPENAI_API_KEY="sk-proj-你的金鑰"

# 啟動 venv
source venv/bin/activate

# 確認套件（如果缺少就安裝）
pip install openai chromadb python-dotenv pyyaml
```

### Step 3: 建立 ChromaDB 知識庫

```bash
cd scripts
python build_knowledge_base.py --reset
```

預期輸出：
- 載入 42 筆知識條目
- 計算 OpenAI embeddings (text-embedding-3-small)
- 儲存到 `data/chroma_kb/`
- 驗證查詢測試通過

### Step 4: 執行 LLM+RAG 偵測

```bash
python 09_run_evmbench_detect.py
```

這個腳本會：
1. 逐一處理 10 個 sample audits
2. 解析 Dockerfile 取得 GitHub repo URL
3. Clone repo（到 `data/evmbench_repos/`）
4. 提取 Solidity 原始碼
5. 用 LLM+RAG 偵測漏洞
6. 用 LLM Judge 比對 gold standard

預期耗時：約 10-15 分鐘
結果檔案：`experiments/evmbench/evmbench_detect_results.json`

### Step 5: 執行混合式框架偵測

```bash
python 10_run_evmbench_hybrid.py
```

這個腳本會：
1. 對每個 audit 跑 Slither 靜態分析
2. GPTScan 預過濾去除 Slither 誤報
3. Stage 1: 獨立 LLM+RAG 分析
4. Stage 2: 條件式 Slither 引導重新評估
5. LLM Judge 比對 gold standard

前提：需要 Slither + solc-select 已安裝
預期耗時：約 15-25 分鐘
結果檔案：`experiments/evmbench/evmbench_hybrid_results.json`

### 或者一鍵全部執行

```bash
bash run_evmbench_all.sh
```

## 10 個 Sample Audits

| Audit ID | 漏洞數 | 類型 |
|----------|--------|------|
| 2024-01-curves | 4 | DeFi Curves |
| 2024-03-taiko | 5 | L2 |
| 2024-05-olas | 2 | Tokenomics |
| 2024-07-basin | 2 | DeFi |
| 2024-01-renft | 6 | NFT Rental |
| 2024-06-size | 4 | Lending |
| 2024-08-phi | 6 | Social |
| 2024-12-secondswap | 3 | DEX |
| 2025-04-forte | 5 | DeFi |
| 2026-01-tempo-stablecoin-dex | 2 | Stablecoin DEX |
| **合計** | **39** | |

## 先前基線結果（供比對）

| 方法 | 偵測數/總數 | 偵測率 |
|------|------------|--------|
| Slither | 0/40 | 0% |
| Mythril | 0/40 | 0% |
| LLM+RAG | 3/40 | 7.50% |
| Hybrid(Verify) | 4/40 | 10.00% |

注意：先前基線用 40 個漏洞（tempo=3），目前 frontier-evals 最新版 tempo=2（共 39 個）。

## 結果檔案位置

```
experiments/evmbench/
├── evmbench_detect_results.json      # LLM+RAG 偵測結果
├── evmbench_detect_per_audit.csv     # 逐 audit CSV
├── evmbench_hybrid_results.json      # Hybrid 偵測結果
└── logs/
    ├── detect_YYYYMMDD_HHMMSS.log    # 偵測日誌
    └── hybrid_YYYYMMDD_HHMMSS.log    # Hybrid 日誌
```

## 故障排除

- **ModuleNotFoundError: openai**: `pip install openai`
- **ChromaDB not found**: 先跑 `python build_knowledge_base.py --reset`
- **Clone timeout**: 網路問題，重跑即可（已 clone 的 repo 會跳過）
- **Slither not found**: `pip install slither-analyzer && solc-select install 0.8.0 && solc-select use 0.8.0`
- **NTFS 太慢**: 確認專案在 ext4 (`~/` 開頭)，不是 `/mnt/c/`
