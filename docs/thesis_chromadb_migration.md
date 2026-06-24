# 迭代管線改採 ChromaDB 向量資料庫（canonical 遷移紀錄）

> 日期：2026-06-25
> 真實來源：`experiments/dmavid_autonomous/`（`scripts/20_coordinator_autonomous.py`，ChromaDB 啟用）
> 對齊：`charts/圖3-2_DmAVID四階段管線系統架構.png`（Blue Team 知識合成 → ChromaDB 向量化寫存）

## 背景

論文先前之正式迭代結果採 `exp15`（`19_coordinator_round2.py`，2 輪、JSON-only 知識庫、回饋路徑未經 ChromaDB），F1=0.9132。經確認，該路徑與架構圖不符（架構圖第四階段明列 Blue Team → `write_blue_team_to_chroma`）。依使用者要求，改採已實際完成、且真正使用 ChromaDB 向量化知識回饋閉環之 autonomous run 為新 canonical。

## 新 canonical（autonomous，ChromaDB，3 輪）

基線（LLM+RAG Stage 2，無迭代）F1=0.9061、FPR=0.26。

| Round | TP | FP | FN | TN | P | R | F1 | FPR | 可見補丁 |
|---|---|---|---|---|---|---|---|---|---|
| R1 | 132 | 15 | 11 | 85 | 0.8980 | 0.9231 | 0.9103 | 0.15 | 0 |
| R2 | 135 | 17 | 8 | 83 | 0.8882 | 0.9441 | 0.9153 | 0.17 | 11 |
| **R3 (FINAL)** | **136** | **18** | **7** | **82** | **0.8831** | **0.9510** | **0.9158** | **0.18** | 16 |

- 三輪 F1 單調遞增 0.9103→0.9153→0.9158；Recall 0.9231→0.9510；FN 11→7。
- 迭代式 F1=0.9158 > 單通道 Self-Verify 0.9121。
- 邊際效益遞減（R1→R2 +0.50% ≫ R2→R3 +0.05%），與自主早停一致。
- 代價：FPR 0.15→0.18（召回提升之代價，淨效益為正）。
- 成本：約 2,388K tokens、$23.88（預算 $50）；Red Team 26 個對抗變體（11/8/7）全數 Foundry 編譯。

### 逐類別（R1→R3）
| 類別 | n | R1 F1 | R3 F1 | Δ |
|---|---|---|---|---|
| arithmetic | 15 | 0.8889 | 0.9286 | +0.040 |
| bad_randomness | 8 | 0.9333 | 0.9333 | +0.000 |
| access_control | 18 | 0.9412 | 0.9714 | +0.030 |
| unchecked_low_level_calls | 52 | 0.9600 | 0.9903 | +0.030 |
| time_manipulation | 5 | 0.8889 | 1.0000 | +0.111 |
| none/safe (FPR) | 100 | 0.1500 | 0.1800 | +0.030 |

## 機制

Blue Team 每輪合成防禦補丁（11/8/7），經 per-category 上限（每類別 ≤5）篩選後累積保留 **16 筆**於 `vulnerability_knowledge.json`，並以 `write_blue_team_to_chroma()` 向量化寫入 ChromaDB（`text-embedding-3-small`，`data/chroma_kb/`）；每輪以 `reload_dynamic_kb()` 注入下一輪 Student 之 RAG 脈絡。主管線 LLM+RAG 階段檢索仍採關鍵字比對。

## 版本號更正（依實驗環境）

- Slither：`0.10.4` → **`0.11.5`**（環境實測；結果檔未記版本，以可重現環境為準）。
- Mythril：架構列為候選之符號執行工具，但單合約平均逾 27 秒、成本過高，**未納入第肆章正式評估**（僅 40 份子集前導測試，F1=0.7317）。

## 連動更新

- `CANONICAL_TRUTH.md` §H（重寫為 autonomous/ChromaDB；標記 exp15 為 deprecated）。
- `README.md`（迭代式 FINAL 0.9132→0.9158、3 輪、ChromaDB 閉環、experiments 結構）。
- `DmAVID_20260622_v11.docx`：表 4-1、表 4-2、表 4-11、§4.x 正文、第伍章結論、實驗環境（Slither/Mythril）全面對齊。

> exp15（0.9132，JSON-only）自此 **deprecated**，勿再引用 0.9132 / 0.8961 / 0.9650 / 0.9930（迭代）/「39→51 條」。Recall=0.9930 僅對 LLM Base 與 prompt 消融 V1–V4 有效。
