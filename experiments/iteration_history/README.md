# ⚠️ Scaffold 測試產出 — 非論文實驗數據

本目錄下的檔案（`history_*.json`、`f1_progression_*.json`，皆為 2026-03-12 產生）
為早期原型腳本 `scripts/14_adversarial_loop.py` 的輸出。

**請勿引用為論文數據。** 原因：

- `14_adversarial_loop.py` 在 non-dry-run 模式下，precision / recall / FPR /
  fn_count / fp_count 皆以 `np.random.uniform/randint` 模擬產生，並非真實計算。
- 其 F1 僅在 Teacher 合成 challenge 上評估，不在 243 平衡子集上評估。

論文第肆章對抗式迭代之正式數據來源為：

| 來源腳本 | 輸出目錄 | 說明 |
|---|---|---|
| `scripts/19_coordinator_round2.py` | `experiments/dmavid_round2/` | Round 2 完整管線（full 243、真實 metrics、patience 收斂、Blue Team 整合） |
| `scripts/20_coordinator_autonomous.py` | `experiments/dmavid_autonomous/` | 自主協調器（自適應 focus、decide_early_stop、Blue Team→ChromaDB） |

本目錄僅保留為流程開發之歷史軌跡。
