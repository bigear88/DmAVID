# 資料集來源與還原說明（Dataset Provenance）

本目錄的 1000 筆評測資料集索引檔 `dataset_1000.json` 已納入 Git；但**原始 Solidity 合約源檔（`.sol`）並未上傳至本 repo**，而是引用自兩個 SmartBugs 公開上游 repo。原因：`smartbugs-wild` 含 47,398 份合約（>140 MB），全數納入會使 repo 體積過大，故在 `.gitignore`（`data/smartbugs_wild_repo/`、`data/smartbugs_curated_repo/`）排除，改以「索引 + 可重現還原」方式管理。

> 口委 / 重現者若要找「原始合約檔」，請依下表還原；本 repo 內的 `dataset_1000.json` 即為對應索引（含 `filename` / `filepath` / `label` / `category`）。

## 1. 資料集組成（dataset_1000.json）

- 建立時間：2026-03-07，亂數種子 `seed=42`
- 總數 `total=1000`：`vulnerable=143`（全部來自 curated）、`safe=857`（全部來自 wild）
- 漏洞類別分布（143 vulnerable）：unchecked_low_level_calls 52、reentrancy 31、access_control 18、arithmetic 15、bad_randomness 8、denial_of_service 6、time_manipulation 5、front_running 4、other 3、short_addresses 1
- 每筆記錄欄位：`id`、`filename`、`filepath`（本機絕對路徑）、`label`、`category`、`source`、`lines`、`code_length`

### 1.1 實驗實際使用之子集（重要：243 平衡子集）

`dataset_1000.json` 是「抽樣池」；**論文主要實驗（表 4-2、表 4-9 等）實際使用的是 143 + 100 = 243 份平衡子集**，並非全部 1000 筆：

| 角色 | 來源 | 實驗使用筆數 | 池中總數 |
|---|---|---|---|
| vulnerable（正類） | SmartBugs **Curated** | 143（全用） | 143 |
| safe（負類） | SmartBugs **Wild** | **100** | 857 |
| 合計 | — | **243** | 1000 |

- 程式碼依據：`scripts/05_run_llm_rag.py:487`（`sample = vuln + safe[:100]`）、`scripts/20_coordinator_autonomous.py:703`（`dataset = vuln_c + safe_c[:100]`）。兩支主腳本皆載入 `data/dataset_1000.json`，僅取前 100 筆 wild safe，其餘 757 筆 wild safe 未進入實驗。
- **SmartBugs Wild 並非備用資料**：它提供實驗中「全部」的 safe（負類）樣本（243 子集中的 100 筆）。Curated 提供全部 vulnerable（正類）樣本。論文表 3-2 與第肆章對此數字一致（143 vuln + 100 safe = 243）。
- EVMbench（10 專案 / 39 漏洞）僅作外部跨資料集驗證，不計入 243。

## 2. 源檔在哪（上游 repo + 釘選 commit）

| source | 標籤 | 筆數 | 上游 GitHub repo | 釘選 commit | 源檔相對路徑規則 |
|---|---|---|---|---|---|
| `smartbugs_curated` | vulnerable | 143 | https://github.com/smartbugs/smartbugs-curated | `230e649123477eff332742a59a1c7cc6dc286cab` | `dataset/<category>/<filename>` |
| `smartbugs_wild` | safe | 857 | https://github.com/smartbugs/smartbugs-wild | `91ec17573d3e0f42cc7d4a6d2883b941901c26e5` | `contracts/<filename>` |

### 對應範例
- curated（漏洞）：`id = curated_reentrancy_0xaae1...b0b8.sol`
  → 上游路徑 `dataset/reentrancy/0xaae1f51cf3339f18b6d3f3bdc75a5facd744b0b8.sol`
  → 線上檢視 https://github.com/smartbugs/smartbugs-curated/blob/230e649123477eff332742a59a1c7cc6dc286cab/dataset/reentrancy/0xaae1f51cf3339f18b6d3f3bdc75a5facd744b0b8.sol
- wild（安全）：`filename = 0xe91054f2d28a9c4f013c5313f070ce5aba9009c6.sol`
  → 上游路徑 `contracts/0xe91054f2d28a9c4f013c5313f070ce5aba9009c6.sol`
  → 線上檢視 https://github.com/smartbugs/smartbugs-wild/blob/91ec17573d3e0f42cc7d4a6d2883b941901c26e5/contracts/0xe91054f2d28a9c4f013c5313f070ce5aba9009c6.sol

> `dataset_1000.json` 內 `filepath` 為本機絕對路徑；移除前綴 `…/data/smartbugs_curated_repo/` 或 `…/data/smartbugs_wild_repo/` 後，即為上述上游相對路徑。

## 3. 一鍵還原源檔

```bash
cd data
# 安全樣本來源（857 筆 safe 取自此）
git clone https://github.com/smartbugs/smartbugs-wild.git smartbugs_wild_repo
git -C smartbugs_wild_repo checkout 91ec17573d3e0f42cc7d4a6d2883b941901c26e5

# 漏洞樣本來源（143 筆 vulnerable 取自此）
git clone https://github.com/smartbugs/smartbugs-curated.git smartbugs_curated_repo
git -C smartbugs_curated_repo checkout 230e649123477eff332742a59a1c7cc6dc286cab
```

還原後，`dataset_1000.json` 的 `filepath`（將前綴改為自己的本機路徑）即可逐筆對應到 `.sol` 源檔。

## 4. 已隨本 repo 提供的其他源檔

- `data/evmbench/audits/**`：跨資料集驗證用的真實審計案例（patch / test 的 `.sol`）已直接納入本 repo（共 92 個 `.sol`），見 `data/evmbench/audits/README.md`。

## 5. 授權

SmartBugs curated / wild 各自授權見其上游 repo 的 `LICENSE`（已隨本機 clone 一併取得）。本資料集索引（`dataset_1000.json`）僅為抽樣引用，未重新散布上游源碼。
