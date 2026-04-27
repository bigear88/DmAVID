# Sprint 2：預訓練資料洩漏量化驗證 — Claude Code CLI 執行腳本

> 在 WSL 終端執行：`cd /home/curtis/DmAVID && claude`
> 然後把下方 **【貼給 Claude Code 的指令】** 完整貼進去。

---

## 【貼給 Claude Code 的指令】（從這條線以下複製）

────────────────────────────────────────────────────────────────

我要執行 DmAVID Sprint 2 的 **預訓練資料洩漏量化驗證實驗**。目的是把 DmAVID Hybrid 管線跑在 gpt-4.1-mini cutoff (2024-10) 之後才公開的 8 個 EVMbench audit packs 上，量化「真實泛化能力」與「預訓練語料記憶」之比例。

### 工作目錄
`/home/curtis/DmAVID`

### 執行步驟（請依序完成，每步先報告結果再進下一步）

**Step 1 — 環境健康檢查**

```bash
cd /home/curtis/DmAVID

# 1.1 確認新腳本存在
ls -lh scripts/33_pretraining_leakage_test.py

# 1.2 確認 8 個 post-cutoff audit 資料夾都存在
for a in 2025-01-liquid-ron 2025-04-forte 2025-04-virtuals 2025-05-blackhole 2025-06-panoptic 2026-01-tempo-feeamm 2026-01-tempo-mpp-streams 2026-01-tempo-stablecoin-dex; do
  if [ -d "data/evmbench/audits/$a" ]; then
    echo "  ✓ $a"
  else
    echo "  ✗ $a (MISSING)"
  fi
done

# 1.3 確認 chromadb RAG 知識庫存在
ls -d data/chroma_kb/

# 1.4 確認 10 號既有 evmbench 結果存在 (作為 B 組對照)
ls experiments/evmbench/evmbench_hybrid_results.json 2>/dev/null && echo "✓ 10 號既有結果可作為 B 組對照"

# 1.5 確認 OpenAI key
echo "OPENAI_API_KEY prefix: ${OPENAI_API_KEY:0:8}..."
```

如果 1.2 有任何 audit MISSING，請告訴我，我們要決定是 (a) 跳過該 audit 或 (b) 從 evmbench upstream 補拉。如果 1.4 不存在，B 組對照數據要用論文表 4-14 (30.77%) 為準，沒問題。

---

**Step 2 — 煙霧測試 (1 個 audit)**

```bash
cd /home/curtis/DmAVID
python3 scripts/33_pretraining_leakage_test.py --first-only 2>&1 | tee /tmp/sprint2_smoke.log
```

預期：3-5 分鐘內完成 `2025-01-liquid-ron` 1 個 audit。看到：
- `Detection rate=X/Y (Z%)`
- 結果寫入 `experiments/leakage_test/`

如果跑成功 → 進 Step 3。
如果失敗 → 把完整錯誤訊息貼給我，先別動下一步。

---

**Step 3 — 全量執行 (8 個 audits 背景跑)**

```bash
cd /home/curtis/DmAVID
mkdir -p experiments/leakage_test
nohup python3 scripts/33_pretraining_leakage_test.py \
  > experiments/leakage_test/run.log 2>&1 &
echo "Started, PID=$!"
```

監控進度（每 5-10 分鐘）：

```bash
tail -30 /home/curtis/DmAVID/experiments/leakage_test/run.log
ps -p <PID> && echo "still running" || echo "finished or crashed"
```

預估時間：30-50 分鐘（8 audits × 平均 5 分鐘 + git clone 開銷）。
預估成本：~$1-2 USD。

---

**Step 4 — 跑完後驗收**

```bash
cd /home/curtis/DmAVID

# 4.1 確認所有結果檔產出
ls -lh experiments/leakage_test/

# 4.2 看三向對照 summary CSV
cat experiments/leakage_test/leakage_test_summary.csv | column -t -s,

# 4.3 看 per-audit 偵測率
cat experiments/leakage_test/evmbench_hybrid_per_audit.csv | column -t -s,

# 4.4 看 log 末段（含關鍵結論）
tail -40 experiments/leakage_test/run.log
```

把以下內容回報給我：
1. `leakage_test_summary.csv` 完整內容
2. `evmbench_hybrid_per_audit.csv` 完整內容
3. `run.log` 末段 40 行（含腳本印出的「關鍵結論」段落）

我會根據這些產出：
- **(a)** 第肆章「五、預訓練資料洩漏驗證」小節 markdown 草稿（**不對比 Tsai，純自我陳述**）
- **(b)** 三向對照圖 PNG（A=SmartBugs / B=2024 / C=2025+ 三個長條）
- **(c)** 表 4-24 三向對照 + 表 4-25 per-audit 偵測明細

---

**Step 5 — 失敗排除指引**

| 症狀 | 處置 |
|---|---|
| `git clone` 失敗某個 audit repo | 在 `audit_id` 跳過該 audit，繼續其餘。回報跳過的 audit |
| `solc-select` 找不到對應版本 | 該 audit 個別失敗不會中斷整體；繼續看其他結果 |
| `RateLimitError` | 在 33 號腳本最末加 `time.sleep(2)`，或縮減 `--audits` 為 4 個分批 |
| 整體 detection rate < 10% | **這就是論文要的洩漏證據**，別當失敗，原樣回報 |
| 整體 detection rate > 80% | **這是 DmAVID 真泛化能力的強證據**，別意外，原樣回報 |

---

**重要約束**：
1. 不要修改 `10_run_evmbench_hybrid.py`，33 號是 wrapper 不該污染既有腳本
2. 不要覆蓋 `experiments/evmbench/` 的既有結果（33 號輸出獨立到 `experiments/leakage_test/`）
3. 跑完 Step 4 後請先**不要**動 commit & push，等我寫完論文段落再一起 commit

────────────────────────────────────────────────────────────────

## 【貼給 Claude Code 的指令到此結束】

---

## 給 Curtis 自己的備忘（不要貼進 Claude Code）

- **預估成本**：~$1-2 USD
- **預估時間**：30-50 分鐘
- **跑完之後**：把 `leakage_test_summary.csv` + per-audit CSV + log 末段貼回 Cowork
- **三種預期結果與論文敘事**：
  - 偵測率 ≥ 50% → 「DmAVID 在 post-cutoff 合約上仍維持高偵測率，證明 SmartBugs F1=0.9121 主要來自架構能力而非預訓練記憶」
  - 偵測率 ≈ 30% (≈ EVMbench 2024) → 「跨 cutoff 一致，cutoff 影響可控；未來工作可探索 post-cutoff 微調」
  - 偵測率 < 20% → 「**透明承認** SmartBugs 高分含記憶成分；DmAVID 主要貢獻在於降低 FP 而非泛化偵測；未來工作應建構動態知識庫」
- **無論結果如何都能寫進論文**，這是 Sprint 2 的價值
