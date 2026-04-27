# Sprint 3：CodeBERT 深度學習基線 — Claude Code CLI 執行腳本

> 在 WSL 終端執行：`cd /home/curtis/DmAVID && claude`
> 然後把下方 **【貼給 Claude Code 的指令】** 完整貼進去。

---

## 【貼給 Claude Code 的指令】（從這條線以下複製）

────────────────────────────────────────────────────────────────

我要執行 DmAVID Sprint 3 的 **CodeBERT 深度學習基線實驗**。目的是補齊論文「為何不跟深度學習方法比較」的口試委員提問空白。微調 microsoft/codebert-base 於 SmartBugs 243，作為 DmAVID Hybrid (F1=0.9121) 與 V4 Prompt (F1=0.7889) 的深度學習對照基線。

### 工作目錄
`/home/curtis/DmAVID`

### 執行步驟（請依序完成，每步先報告結果再進下一步）

**Step 1 — 環境健康檢查 (含 GPU 偵測)**

```bash
cd /home/curtis/DmAVID

# 1.1 確認新腳本存在
ls -lh scripts/34_codebert_baseline.py

# 1.2 確認資料集
ls -lh data/dataset_1000.json

# 1.3 確認 Python 環境
python3 --version
which python3

# 1.4 GPU 偵測 (關鍵：CPU 模式預估 4-8 小時，GPU 模式 30-60 分鐘)
python3 -c "
import torch
print(f'PyTorch version: {torch.__version__}')
print(f'CUDA available: {torch.cuda.is_available()}')
if torch.cuda.is_available():
    print(f'CUDA device   : {torch.cuda.get_device_name(0)}')
    print(f'CUDA version  : {torch.version.cuda}')
    print(f'GPU memory    : {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB')
else:
    print('⚠ NO CUDA — 必須跑 CPU 模式 (預估 4-8 小時)')
"

# 1.5 確認相依套件
python3 -c "
import importlib
needed = ['transformers', 'datasets', 'sklearn', 'torch', 'numpy']
for pkg in needed:
    try:
        m = importlib.import_module(pkg)
        v = getattr(m, '__version__', 'unknown')
        print(f'  ✓ {pkg} {v}')
    except ImportError:
        print(f'  ✗ {pkg} (NOT INSTALLED)')
"
```

回報以下結果給我：
1. 是否有 GPU（若沒有，要決定是換 CPU 慢跑還是借 colab）
2. GPU 記憶體大小（< 6GB 可能要降 batch_size）
3. 哪些套件未安裝

---

**Step 2 — 安裝缺失套件 (若需要)**

如果 Step 1.5 顯示有套件未安裝：

```bash
# 用 conda env 還是 system Python？看 Step 1.3 的 which python3 結果
# 如果是 conda：
pip install transformers datasets scikit-learn

# 如果是 system Python (Curtis 你之前用 python3 system 版)：
pip install transformers datasets scikit-learn --break-system-packages
```

注意：transformers 會自動拉 ~2GB 的 model weights (microsoft/codebert-base)，需要等。

---

**Step 3 — 煙霧測試 (1 epoch + 50 樣本)**

確認 model 載入、tokenize、訓練流程都通：

```bash
cd /home/curtis/DmAVID
python3 scripts/34_codebert_baseline.py --smoke-test 2>&1 | tee /tmp/sprint3_smoke.log
```

預期：
- GPU 模式：3-5 分鐘
- CPU 模式：20-40 分鐘
- 末尾應印出 `CodeBERT Baseline Results` 區塊

如果跑成功 → 進 Step 4。
如果失敗 → 把完整錯誤訊息貼給我（特別注意 OOM、tokenizer 載入失敗、CUDA mismatch 這幾種）。

---

**Step 4 — 全量訓練 (3 epochs, 全 243 樣本)**

```bash
cd /home/curtis/DmAVID
mkdir -p experiments/codebert_baseline
nohup python3 scripts/34_codebert_baseline.py \
  > experiments/codebert_baseline/run.log 2>&1 &
echo "Started, PID=$!"
```

監控進度：

```bash
tail -30 /home/curtis/DmAVID/experiments/codebert_baseline/run.log
ps -p <PID> && echo "still running" || echo "finished"
```

預估時間：
- GPU (RTX 3060+)：30-60 分鐘
- GPU (T4 or 2080)：60-90 分鐘
- CPU：4-8 小時（不建議）

---

**Step 5 — 跑完後驗收**

```bash
cd /home/curtis/DmAVID

# 5.1 確認所有結果檔產出
ls -lh experiments/codebert_baseline/

# 5.2 看 metrics summary CSV (含對照組)
cat experiments/codebert_baseline/metrics_summary.csv | column -t -s,

# 5.3 看 log 末段（含三向對照與結論）
tail -40 experiments/codebert_baseline/run.log

# 5.4 抽樣檢查 per-sample 預測（看分類錯誤的合約類型）
python3 -c "
import json
with open('experiments/codebert_baseline/metrics.json') as f:
    d = json.load(f)
errors = [r for r in d['results'] if not r['correct']]
print(f'Total errors: {len(errors)} / {len(d[\"results\"])}')
print('\nFirst 5 errors by category:')
for r in errors[:5]:
    print(f'  {r[\"category\"]:<25} GT={r[\"ground_truth\"]:<10} Pred={r[\"predicted\"]:<10} {r[\"name\"][:40]}')
"
```

把以下回報給我：
1. `metrics_summary.csv` 完整內容（含對照組三向比較）
2. `run.log` 末段 40 行（含腳本印出的最終結論）
3. 錯誤抽樣 5 筆（看 CodeBERT 主要失誤在哪些類型）

我會根據這些產出：
- **(a)** 第肆章「五、CodeBERT 深度學習基線對照」小節 markdown 草稿
- **(b)** 三向對照圖 PNG（CodeBERT vs V4 Prompt vs DmAVID Hybrid 並排）
- **(c)** 表 4-26 三向 F1 對照 + 表 4-27 CodeBERT per-category 失誤分析

---

**Step 6 — 失敗排除指引**

| 症狀 | 處置 |
|---|---|
| `OutOfMemoryError` (CUDA) | 改 `--batch-size 4` 或 `--max-seq-len 256` |
| `tokenizer download failed` | `export HF_HOME=/some/large/disk; huggingface-cli login` 或用 mirror |
| GPU 沒被偵測到 (但 nvidia-smi 看得到) | 重裝 torch with cuda：`pip install torch --index-url https://download.pytorch.org/whl/cu121` |
| F1 < 0.50 (異常低) | 可能 dataset code 載入失敗 (skipped 太多)。檢查 log 第 [1/5] 步顯示樣本數是否=243 |
| 訓練 loss 不降 | 改 `--lr 5e-5` 或 `--epochs 5` 重跑 |
| Slither / RAG 相關錯誤 | 不該發生 — 34 號腳本完全不需 Slither/RAG，只用 transformers |

---

**重要約束**：
1. 不要修改 `04_run_llm_base.py` / `32_prompt_variants_ablation.py` (它們是已用論文結果的來源)
2. 結果輸出獨立到 `experiments/codebert_baseline/`，不污染既有實驗
3. 跑完 Step 5 後請先**不要**動 commit & push，等我寫完論文段落再一起 commit
4. 80/20 train/test split 與 seed=42 已寫死在腳本，**不要動**（reproducibility 前提）

────────────────────────────────────────────────────────────────

## 【貼給 Claude Code 的指令到此結束】

---

## 給 Curtis 自己的備忘（不要貼進 Claude Code）

- **預估成本**：$0（本地計算，無 API call）
- **預估時間**：GPU 30-90 分鐘 / CPU 4-8 小時
- **跑完之後**：把 `metrics_summary.csv` + `run.log` 末段 + 錯誤抽樣貼回 Cowork
- **三種預期結果與論文敘事**：
  - F1 ≥ 0.85 → 「CodeBERT 表現接近 DmAVID Hybrid，DmAVID 真正優勢在 FP 控制與多代理迭代，而非單純偵測能力」（最謙遜版本，但仍突顯獨立貢獻）
  - F1 介於 0.75-0.85 → 「CodeBERT 介於 V4 Prompt 與 Hybrid 之間，DmAVID Hybrid 相對深度學習仍具明顯優勢」（最理想版本）
  - F1 < 0.75 → 「DmAVID 全面領先深度學習基線，混合架構優於單一 DL 模型」（最強版本）
- **無論結果如何都能寫進論文**，這是 Sprint 3 的價值
- **GPU 沒得用怎麼辦**：(a) Google Colab 免費 T4，把 dataset_1000.json 上傳跑；(b) 借 lab 機器；(c) 改用 CodeBERT 較小變體 (`microsoft/codebert-base-mlm` 或 `huggingface/CodeBERTa-small-v1`) 在 CPU 跑

---

## 跟 Sprint 1/2 的差異

| 項目 | Sprint 1 | Sprint 2 | Sprint 3 |
|---|---|---|---|
| 計算類型 | API call (OpenAI) | API call (OpenAI) | 本地 GPU 訓練 |
| 預估時間 | 42 分 | 1 分 36 秒 | 30-90 分 (GPU) |
| 預估成本 | $0.84 | $0.04 | $0 (本地) |
| 主要技術風險 | API rate limit | git clone 失敗 | GPU OOM / CUDA 環境 |
| 失敗成本 | 浪費 $1 | 浪費 1 分鐘 | 浪費 1 小時 GPU 時間 |

Sprint 3 失敗成本最高（時間長），請務必 Step 1 GPU 偵測後再決定是否繼續。
