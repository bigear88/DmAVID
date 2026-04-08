# EVMbench 延伸實驗執行指南

## 已完成的準備工作

### 1. 腳本重寫 (3 支)
- `scripts/09_run_evmbench_detect.py` — LLM+RAG 偵測 (ChromaDB RAG, Dockerfile 解析, 結構化日誌)
- `scripts/10_run_evmbench_hybrid.py` — 混合驗證模式 (Two-Stage Fusion, GPTScan 預過濾)
- `scripts/10_run_evmbench_hybrid_3modes.py` — 三模式比較 (Original/Verification/Context)

### 2. 修正的重要 Bug
- **RAG 嵌入維度不匹配**: 原本 `query_texts` 用 ChromaDB 預設模型 (384-dim) 查詢 OpenAI 嵌入 (1536-dim)，已改為用 OpenAI `text-embedding-3-small` 計算查詢嵌入
- **Judge 缺少漏洞描述**: 原本 judge 只用 `title`，已改為從 `findings/{H-xx}.md` 載入詳細描述
- **Tempo 漏洞數量**: frontier-evals 最新版 tempo 只有 2 個漏洞 (H-02, H-04)，已更新註解

### 3. EVMbench 資料集
- 資料來源: `openai/frontier-evals` (GitHub 公開 repo)
- 已設定 symlink: `data/evmbench/audits/` → frontier-evals 的 audit 目錄
- 10 個 sampled audits, 共 39 個 high-severity 漏洞

### 4. 新增輔助檔案
- `.env` — 環境變數設定 (需填入 OPENAI_API_KEY)
- `scripts/run_evmbench_all.sh` — 一鍵執行全部實驗

---

## 在 WSL 上執行實驗

### 前置準備

```bash
cd ~/DmAVID  # 或你的專案目錄

# 1. 設定 API Key
export OPENAI_API_KEY="sk-proj-..."
# 或寫入 .env 檔案:
echo 'OPENAI_API_KEY=sk-proj-...' > .env

# 2. 安裝套件 (如未安裝)
source venv/bin/activate
pip install openai chromadb python-dotenv pyyaml

# 3. 取得 EVMbench 資料集 (如未取得)
git clone --depth 1 https://github.com/openai/frontier-evals.git /tmp/frontier-evals
mkdir -p data/evmbench
cp -r /tmp/frontier-evals/project/evmbench/audits data/evmbench/
rm -rf /tmp/frontier-evals
```

### 執行

#### 方法一: 一鍵執行

```bash
cd scripts
bash run_evmbench_all.sh
```

#### 方法二: 逐步執行

```bash
cd scripts
source ../venv/bin/activate

# Step 1: 建立 ChromaDB 知識庫
python build_knowledge_base.py --reset

# Step 2: LLM+RAG 偵測
python 09_run_evmbench_detect.py

# Step 3: 混合驗證
python 10_run_evmbench_hybrid.py

# Step 4: 三模式比較
python 10_run_evmbench_hybrid_3modes.py
```

### 預期結果

結果會存到 `experiments/evmbench/`:
- `evmbench_detect_results.json` — LLM+RAG 偵測結果
- `evmbench_hybrid_results.json` — 混合驗證結果
- `evmbench_hybrid_3modes_results.json` — 三模式比較結果
- `logs/` — 詳細日誌

### 先前的基線結果

| 方法 | 偵測數 | 總數 | 偵測率 |
|------|--------|------|--------|
| Slither | 0 | 40 | 0% |
| Mythril | 0 | 40 | 0% |
| LLM+RAG | 3 | 40 | 7.50% |
| Hybrid(Original) | 2 | 40 | 5.00% |
| Hybrid(Verify) | 4 | 40 | 10.00% |
| Hybrid(Context) | 2 | 40 | 5.00% |

注意: 先前基線是 40 個漏洞 (tempo=3), 目前 frontier-evals 最新版 tempo 只有 2 個 (共 39 個)。
