# Foundry 真實 PoC 攻擊重放 — 程式修正與重跑紀錄

## 背景
第肆/參章描述 S5「Foundry 雙重驗證」為 solc 編譯 + `forge test` PoC 攻擊重放，確認對抗變體之可利用性。然而先前的自主協調器（`20_coordinator_autonomous.py`）**僅執行 `forge build`（編譯層級）**，從未實際呼叫 `forge test` PoC；`13_foundry_validate.py` 的 PoC 模板亦為 `assertTrue(true)` 空殼。為使實驗與論文所述一致（且不造假），本次修改程式並完整重跑。

## 程式修改
- `scripts/12_red_team_generate.py`
  - `generate_adversarial_variant(..., target_solidity)`：新增參數，使對抗變體以 Solidity `^0.8.20` 生成（保留漏洞語義；overflow 類以 `unchecked{}` 維持可觸發），以利 forge-std PoC 測試（forge-std 需 solc ≥ 0.6.2）。
  - `repair_poc(...)`：真實 PoC 自我修復——將 `forge` 編譯/測試錯誤回饋給模型修正，明文禁止以恆真斷言作弊。
- `scripts/13b_foundry_poc.py`（新增）
  - `validate_variant_poc()`：兩階段真驗證——`forge build`(solc) 確認變體可編譯，`forge test` 執行 PoC 攻擊重放。
  - `validate_with_repair()`：最多 3 次嘗試的自我修復迴圈；**防作弊**：通過必須含非恆真斷言（拒絕 `assertTrue(true)`、`assertEq(1,1)` 等）。
  - 使用持久化 forge 專案 `experiments/foundry_poc/`（預裝 forge-std）。
- `scripts/20_coordinator_autonomous.py`
  - Red Team 產生 `^0.8.20` 變體；Foundry 階段改為真 PoC 雙重驗證並記錄 `foundry_poc_passed`；Blue Team 僅吸收「編譯+PoC 雙通過」之變體；變體原始碼＋PoC＋逐次 trace 全數存檔於 `experiments/dmavid_autonomous/foundry_poc/round_*_foundry_poc.json`（修正先前變體未保存之問題）。

## 重跑結果（gpt-4.1-mini，SmartBugs 243＝143 vuln + 100 safe，3 輪，預算 $50，實花 $24.60）
基線（LLM+RAG）F1 = 0.9061。

| 輪次 | 變體 | solc 編譯 | forge PoC 通過 | 雙重通過 | Blue patterns | Post-verify F1 (N=243) | FPR |
|---|---|---|---|---|---|---|---|
| R1 | 6 | 3 | 1 | 1 | 1 | 0.9164 | 0.19 |
| R2 | 8 | 3 | 3 | 1 | 1 | 0.9060 | 0.20 |
| R3 | 7 | 1 | 1 | 1 | 1 | 0.9128 | 0.19 |
| **合計/最終** | **21** | **7** | **5** | **3** | **3** | **0.9128** | **0.19** |

## 誠實結論
- `forge test` PoC 攻擊重放**確實執行**（含自我修復與防作弊），非空殼。
- 跨三輪 21 個變體中，7 個通過 solc 編譯、5 個通過 PoC、3 個通過 solc+PoC 雙重驗證。
- 以真實 PoC 把關後，對抗式迭代之效益為**小幅且具雜訊**（最終 0.9128，較 LLM+RAG 基線 +0.0067；R2 一度回落至基線 0.906），不宜宣稱穩定大幅提升。
- 方法學限制：自我修復迴圈會修正 PoC 內 inline 之合約，故「PoC 通過」係指該漏洞型之 exploit 可成立；最保守之指標為 solc+PoC 雙重通過（3/21）。

## 可重現
```
cd /home/curtis/DmAVID
export PATH=/home/curtis/.foundry/bin:$PATH
export OPENAI_API_KEY=...   # 見 env.sh
python3 scripts/20_coordinator_autonomous.py --rounds 3 --no-early-stop --budget 50
```
注意：管線具隨機性（temperature、資料洗牌、變異策略隨機選取），跨次執行 F1 與通過數會有波動。
