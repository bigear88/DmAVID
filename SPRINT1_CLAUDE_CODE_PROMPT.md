# Sprint 1：Prompt 變體消融實驗 — Claude Code CLI 執行腳本

> 在 WSL 終端機執行：`cd /home/curtis/DmAVID && claude`
> 然後把下方 **【貼給 Claude Code 的指令】** 完整貼進去。

---

## 【貼給 Claude Code 的指令】（從這條線以下複製）

────────────────────────────────────────────────────────────────

我要執行 DmAVID Sprint 1 的 **Prompt 變體消融實驗**，目的是對照高科大 Tsai (2023) 碩論的 prompt engineering 結果，量化 4 種 prompt 變體在 SmartBugs 子集上的表現差異，作為論文第肆章的補強材料。

### 工作目錄
`/home/curtis/DmAVID`

### 執行步驟（請依序完成，每步先報告結果再進下一步，不要連跑）

**Step 1 — 環境健康檢查**

請依序執行並回報結果：

```bash
cd /home/curtis/DmAVID

# 1.1 確認資料集存在
ls -lh data/dataset_1000.json

# 1.2 確認 baseline 結果存在（如果不在，後面要先補跑 04）
ls -lh experiments/llm_base/llm_base_results.json 2>/dev/null || echo "[!] 04 baseline 未跑過，需先跑"

# 1.3 確認 OpenAI key 已載入（只印前 8 碼避免外洩）
echo "OPENAI_API_KEY prefix: ${OPENAI_API_KEY:0:8}..."

# 1.4 確認模型名稱
echo "DMAVID_MODEL: ${DMAVID_MODEL:-gpt-4.1-mini (default)}"

# 1.5 確認新腳本存在
ls -lh scripts/32_prompt_variants_ablation.py

# 1.6 確認相依模組
python -c "from openai import OpenAI; import sys; sys.path.insert(0, 'scripts'); from _model_compat import token_param; print('imports OK')"
```

如果 1.5 顯示「No such file」，請先告訴我，我會把腳本內容貼給你建立。

---

**Step 2 — 煙霧測試（5 個合約 × 1 個變體）**

確認沒有 import error、API call 沒卡住：

```bash
cd /home/curtis/DmAVID
python scripts/32_prompt_variants_ablation.py --variants V1_baseline --limit 5
```

預期輸出：應該在 1 分鐘內結束，看到 5 行 `[ X/ 5] xxx GT=xxx Pred=xxx ✓/✗`，最後印出 metrics。

如果跑成功 → 進 Step 3。
如果跑失敗 → 把完整錯誤訊息貼給我，先別動下一步。

---

**Step 3 — 全量執行（4 變體 × 全樣本）**

```bash
cd /home/curtis/DmAVID

# 在背景執行並寫 log，避免 SSH 斷線中斷實驗
nohup python scripts/32_prompt_variants_ablation.py \
  > experiments/prompt_ablation/run.log 2>&1 &
echo "PID: $!"
```

**注意**：這個指令會在執行前等使用者按 Enter 確認成本估算。為了讓 nohup 模式能跑，請改用以下版本（自動跳過確認）：

```bash
cd /home/curtis/DmAVID
mkdir -p experiments/prompt_ablation
yes "" | nohup python scripts/32_prompt_variants_ablation.py \
  > experiments/prompt_ablation/run.log 2>&1 &
echo "Started, PID=$!"
```

跑起來後，每 5 分鐘監控進度：

```bash
tail -20 /home/curtis/DmAVID/experiments/prompt_ablation/run.log
ps -p <剛才的PID> && echo "still running" || echo "finished or crashed"
```

預估時間：約 30–60 分鐘（972 calls × 平均 2-3 秒/call）。

---

**Step 4 — 跑完後驗收**

```bash
cd /home/curtis/DmAVID

# 4.1 確認所有結果檔產出
ls -lh experiments/prompt_ablation/

# 4.2 看 summary CSV
cat experiments/prompt_ablation/metrics_summary.csv | column -t -s,

# 4.3 看每個變體的最終 metrics 比較（從 log 末段抓）
tail -30 experiments/prompt_ablation/run.log

# 4.4 抽樣檢查任一變體的逐筆結果（看 reasoning 欄位是否真的顯示推理過程）
python -c "
import json
with open('experiments/prompt_ablation/V2_cot_results.json') as f:
    d = json.load(f)
print('First 3 reasoning samples (V2 CoT):')
for r in d['results'][:3]:
    print(f\"  [{r['ground_truth']}] {r['name'][:40]}: {r['prediction']['reasoning'][:200]}\")
"
```

把以下內容回報給我：
1. `metrics_summary.csv` 的完整內容
2. `run.log` 最後 30 行
3. V2_cot 的前 3 筆 reasoning 樣本

我會根據這些產出：
- **(a)** 第肆章對照表 4-X 的 markdown 草稿
- **(b)** F1 排名圖（PNG）
- **(c)** 與 Tsai (2023) 結果的對比論述（中文學術段落，~150 字）

---

**Step 5 — 失敗排除指引**（出問題才看）

| 症狀 | 處置 |
|---|---|
| `ImportError: No module named openai` | `pip install openai` |
| `RateLimitError` | 在腳本第 35 行調整 `client = OpenAI()`，加入 `max_retries=5`，或在 main 迴圈中加 `time.sleep(0.5)` |
| `json_parse_error` 出現 > 5% | 把該樣本的 `raw_content_head` 貼給我，調整 prompt |
| 跑到一半 OOM | 不應該發生（這是 API call，本機只用少量記憶體）；若發生則檢查 chromadb 是否被其他程序佔用 |
| 成本超出預期 | 立刻 `kill <PID>`，回報已累積的 token 數 |

---

**重要約束**：
1. 所有變體必須使用 `seed=42`、`temperature=0.1`、相同 dataset，這是消融實驗的有效性前提，**不要改**。
2. 不要修改 `04_run_llm_base.py`（它是論文已記錄的 baseline）；32 號腳本是獨立的對照實驗。
3. 結果檔產出後**不要覆蓋舊的 `llm_base_results.json`**（它是論文表 4-7 的來源）。
4. 跑完 Step 4 後請先**不要**動下一個 Sprint，等我寫完論文段落再說。

────────────────────────────────────────────────────────────────

## 【貼給 Claude Code 的指令到此結束】

---

## 給 Curtis 自己的備忘（不要貼進 Claude Code）

- **預估成本**：~$2-4 USD（972 calls × 平均 ~3000 input + 200 output tokens）
- **預估時間**：30-60 分鐘
- **可中斷重跑**：是。腳本以 variant 為單位輸出 JSON，跑壞某一個變體可以單獨重跑：
  `python scripts/32_prompt_variants_ablation.py --variants V3_plan_solve`
- **檔案位置**：
  - 腳本：`scripts/32_prompt_variants_ablation.py`
  - 結果：`experiments/prompt_ablation/V{1-4}_results.json`
  - 摘要：`experiments/prompt_ablation/metrics_summary.csv`
  - Log：`experiments/prompt_ablation/run.log`
- **跑完之後**：把 `metrics_summary.csv` + `run.log` 末段貼回給我（在 Cowork 裡），我會接續第肆章寫作。
