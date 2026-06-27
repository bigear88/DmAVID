# DmAVID — CANONICAL STATE（單一權威記錄）

> 目的：止血「每次問結果都不一樣」的 drift 問題。本檔為**唯一權威來源**。
> 所有數字皆從 `experiments/` 結果檔讀出，非記憶。最後更新：2026-06-27。
> 回答任何 DmAVID 問題前，**先讀本檔**，不要重新推導。

---

## 1. 資料集（對應圖3-2「智能資料集」）

| 用途 | 內容 | 來源腳本 | 檔案 |
|---|---|---|---|
| 主資料集 | SmartBugs Curated 143 (vuln) + Wild 100 (safe) = **243** | `01_prepare_dataset.py` | `data/dataset_1000.json`（取 143+100=243） |
| 泛化集 | EVMbench 39（post-cutoff） | `01_prepare_dataset.py` | `data/evmbench*` |

---

## 2. 四階段主管線 — 階段 × 腳本 × F1（CANONICAL）

| 圖3-2 階段 | 主腳本 | 輔助腳本 | F1 | P / R | 狀態 |
|---|---|---|---|---|---|
| 第一階段 解構分析（Slither v0.10.4） | `02_run_slither.py` | `03_run_mythril*.py`(備用) | **0.7458** | 0.6164 / 0.9441 | ✅ 真跑 |
| (基線) LLM Base 無 RAG | `04_run_llm_base.py` | — | **0.7474** | 0.5992 / 0.993 | ✅ |
| (基線) Hybrid Slither+LLM | `06_run_hybrid.py` | `06_run_hybrid_optimized.py` | **0.8428** | 0.732 / 0.993 | ✅ |
| 第二階段 LLM+RAG | `05_run_llm_rag.py` | `build_knowledge_base.py`, `chroma_rag.py` | **0.9061** | 0.8434 / 0.979 | ✅ |
| 第三階段 Self-Verify 三類判決 | `postprocess_self_verify.py` | `31_ablation_study_v5_clean.py`(驗證), `58_sv_threshold_audit.py` | **0.9121** | 0.8537 / 0.979 | ✅ |
| 第四階段 DmAVID 多代理對抗式迭代 | `20_coordinator_autonomous.py` | `11_teacher_challenge.py`, `12_red_team_generate.py`, `18_blue_team_defense.py`, `chroma_rag.py` | **R1 0.9164 / R2 0.9060 / R3 0.9128** | — | ✅ 真實重跑 |
| └ EVM Foundry 驗證（Stage4 子步驟） | `13b_foundry_poc.py`（真實） | — | PoC pass: R1 1/6, R2 3/8, R3 1/7 | — | ✅ 已改真實 |
| 模型評估（旁支） | `07_run_ablation.py` | `35_per_category_breakdown.py`, `72/73_*chart.py` | Acc/P/R/F1/FPR | — | ✅ |

**權威結論**：
- 單通道最佳 = +Self-Verify **0.9121**。
- 迭代最終 R3 **0.9128**（vs SV 0.9121 = +0.0007，雜訊內，統計平手；非單調，R2 跌至 0.9060）。
- 「迭代越來越好」**未成立**。

---

## 3. 「只編譯、未真實驗證」腳本稽核

| 腳本 | 行為 | 判定 |
|---|---|---|
| ⚠️ `13_foundry_validate.py` | 跑 `forge test`，但 PoC 測試體是 `// Placeholder ... assertTrue(true);`（line 263-266）= 編譯過即假通過 | **假驗證**（exp12~exp15 用的是這版） |
| ✅ `13b_foundry_poc.py` | `forge build` + `forge test` 真 PoC + 自我修復 + anti-cheat（拒 assertTrue(true)） | **真實驗證**（已取代之） |
| ○ `50_compile_to_bytecode.py` / `51_extract_opcodes.py` / `52_bytecode_ml_features.py` | 只編譯→取 bytecode/opcode 做 ML 特徵 | 合法（編譯本就是其用途，非漏洞驗證，不算假） |

---

## 4. 迭代實驗歷程（更正版）

| 實驗 | Foundry 閘門 | 早停 | 輪數 | 結果 | 備註 |
|---|---|---|---|---|---|
| exp14 | compile-only(stub) | 含設計 | 跑滿 3 | R3 崩 **0.8831** | compile-only 跑滿會崩 |
| exp15 | compile-only(stub) | **早停 `decide_early_stop`（ΔF1≤0.002×2輪）於第2輪觸發** | 停在 2 | **0.9132** | **非人為截斷，是早停機制；後來早停被移除** |
| dmavid_autonomous | **真實 PoC** | 無（跑滿） | 3 | R1 0.9164 / R2 0.9060 / R3 0.9128 | 當前 canonical |

---

## 5. PoC 定位（已與使用者確認）

- PoC = 泛化／可利用性實驗，**可從 SmartBugs 迭代迴圈解耦**。
- 解耦後 PoC 不影響 SmartBugs 迭代數字 ✅。
- 但解耦**不能**讓「迭代越來越好」成立——compile-only 跑滿三輪一樣崩（exp14 R3=0.8831），與 PoC 無關。

---

## 6. 迭代顯著性檢定（multi-seed + placebo）— 已完成 2026-06-27

3 seed (42/7/123) × {treatment, placebo} × 3 輪，compile 閘門，每 run 前重置 clean_baseline KB 隔離。

| 條件 | R3 mean±std | band |
|---|---|---|
| treatment（注入知識） | **0.9149 ± 0.0109** | [0.9040, 0.9258] |
| placebo（不注入） | **0.9201 ± 0.0072** | [0.9129, 0.9273] |

**定論：兩帶子重疊、placebo 平均還更高 → 對抗式迭代在 SmartBugs 上無顯著 F1 增益（雜訊）。** 噪音地板（std ~0.008–0.011）> 任何迭代效益。直接證據：treatment vs placebo 同 seed42 的 R1（同 KB、同 seed）差 0.0102 → OpenAI seed 非決定性。
- 圖：`charts/fig_seed_placebo_errorbar.png`
- 腳本：`scripts/aggregate_seed_placebo.py`、`scripts/plot_seed_placebo.py`、`run_seed_placebo.sh`
- 機制（FN 學習軌跡 treatment_seed42 R1→R3）：11 漏報學會 7，但新增 5 FP、弄丟 3 → 蹺蹺板抵銷（`scripts/trace_fn_learning.py`）。

## 7. EVMbench 泛化（兩段乾淨軌跡）— 2026-06-27 定稿

論文 §4.3「六、EVMbench 基準線偵測」與「九、智能預處理」已改為**乾淨兩配置**（移除洩漏的 Enhanced）。

| 配置 | 偵測率 | Token | 腳本 / 來源 |
|---|---|---|---|
| LLM+RAG（detect-only） | **3/39 = 7.69%** | 124,812 | `09_run_evmbench_detect.py` / `evmbench/evmbench_detect_results.json` |
| RAG + Smart Preprocess（FINAL） | **25/39 = 64.10%** | 62,858 | `30_evmbench_smart_preprocess.py` / `evmbench_smart/smart_preprocess_results.json` |

- **Smart Preprocess 真實技術**＝擷取全部介面定義（函式簽章/事件/修飾子）＋安全關鍵模組深度分析（存取控制/資金流/外部呼叫）＋匯入/繼承關係摘要，**取代 60K 字元粗暴截斷**。**不是**「合約展平/相依性注入」。偵測 prompt 只放 RAG KB + 預處理碼，**不含 gold → 無洩漏** ✅。
- **❌ 已移除：Enhanced（hint/gold-injected）30.77%（12/39, token 95,377）**＝`22_evmbench_enhanced.py` 的 `targeted_search(gold_vuln,...)` 把 **gold 漏洞餵給 LLM**（leakage），非 RAG、非真實 hint 增強。論文/HTML/圖 4-13 皆已剔除。
- **時序分層（表 4-16/圖 4-13）**：pre-cutoff SmartBugs F1 0.9121 → EVMbench 2024 邊界（smart preprocess）64.10% → post-cutoff 2025+ 58.82%（10/17），平緩衰退 −5.28pp，無「矛盾」。圖 4-13 已重畫（`scripts/regen_fig413.py`，英文標籤，已內嵌 docx image23.png）。舊圖誤用 0.3077→0.1176，已棄。
- **真正 hint-enhanced（讀 EVMbench `*_hints.md` 逐級注入）= 從未跑過**；若未來要做漸進式增強軸需另跑。

## 8. 仍待辦
- [ ] 路徑 B：把迭代搬到有 headroom 的難集（EVMbench/post-cutoff）驗證 held-out 類推
- [ ] （選）Student 評估端 temperature 0.1→0 進一步降噪
- [ ] （選）真正的 hint-enhanced 漸進式增強實驗（讀 `*_hints.md`，名實相符、非洩漏）
