# 論文表格數據可追溯性矩陣 (Table 4-1 ~ 4-19)

稽核日期：2026-06-28
稽核方式：逐表逐欄將論文數字與 `experiments/` 下實驗產出檔 (Output Log) exact match 比對。
結論：**19 張表全部可追溯至真實實驗產出檔，無任何「編寫」(捏造) 數據，無需補做實驗。**

| 表 | 內容 | 來源產出檔 | 判定 |
|---|---|---|---|
| 4-1 | 近期 LLM 工具效能對照 | 前 3 列(GPTScan/AuditGPT/LLM-SmartAudit)=**引用他人論文(文獻外部)**；DmAVID 列=`ablation/ablation_v5_clean_results.json`(+self-verify)；DmAVID+迭代列=`dmavid_autonomous_BAK_precompile_20260626/round_3_results.json` | MATCH |
| 4-2 | 四階段管線 | Slither=`slither/slither_results.json`；LLM Base=`llm_base/llm_base_results.json`；LLM+RAG=`ablation/ablation_v5_clean_results.json`(baseline)；+Self-Verify=同檔(+self-verify)；+對抗迭代R3=`dmavid_autonomous_BAK.../round_3_results.json` | MATCH |
| 4-3 | Prompt 變體混淆矩陣 | `prompt_ablation/{V1_baseline,V2_cot,V3_plan_solve,V4_plan_solve_user}_results.json` | MATCH |
| 4-4 | Prompt 變體效能(含 95% CI) | 同上(`f1_ci_low`/`f1_ci_high` 欄位，bootstrap 已落檔) | MATCH |
| 4-5 | McNemar 配對檢定 | `baseline_gpt41mini/supplementary_results/mcnemar_tests.json`(腳本 `scripts/08_supplementary_analysis.py`) | MATCH |
| 4-6 | 五代理 Leave-One-Out | `coordinator_ablation/leaveoneout_summary.json` | MATCH |
| 4-7 | 三方法偽陽性概況 | `per_category/fp_type_full.json` (=`fp_type_pivot.csv`) | MATCH |
| 4-8 | 三方法 FP 類型歸因 | `per_category/fp_type_full.json` (表僅列前 8 大類型，建議表註說明) | MATCH |
| 4-9 | 工具增強五臂(Arm A-E) | `tool_augmented/ablation_results.json` | MATCH |
| 4-10 | 門檻敏感度 | `tool_augmented/threshold_sensitivity.json` | MATCH |
| 4-11 | 五大漏洞類型對抗迭代 F1 | `dmavid_autonomous_BAK.../round_1_results.json` + `round_3_results.json`(per-category 實算) | MATCH |
| 4-12 | EVMbench 兩配置 | `evmbench/evmbench_detect_results.json` + `evmbench_smart/smart_preprocess_results.json` | MATCH |
| 4-13 | 傳統 ML 跨資料集 | `traditional_ml/ml_baseline_results_fixed.json` + `defi_real_world/defi_results_fixed.json` | MATCH |
| 4-14 | LLM+RAG 跨域 DeFi Real | `defi_real_world/defi_results.json`(llm_rag 區塊) | MATCH |
| 4-15 | EVMbench Smart 逐審計 | `evmbench_smart/smart_preprocess_results.json`(per_audit) | MATCH |
| 4-16 | 時序分層 | `evmbench_smart/smart_preprocess_results.json` + `evmbench_postcutoff/postcutoff_results.json` | MATCH |
| 4-17 | Post-cutoff 逐審計 | `evmbench_postcutoff/postcutoff_results.json`(per_audit) | MATCH |
| 4-18 | CTC 三方對照 | `explainability/ctc_eval_summary.json`(底層 `ctc_checkpoint.json`，429 筆逐合約 LLM-as-judge 評分) | MATCH |
| 4-19 | DmAVID CTC 各漏洞類型 | `explainability/ctc_eval_summary.json` per_category(同上 checkpoint) | MATCH |

## 稽核備註(非錯誤，僅建議於論文表註釐清)

1. **表 4-2 LLM+RAG 列**：採用 `ablation_v5_clean_results.json` 的 `baseline` config(tp140/fp26/fn3/tn74, F1=0.9061)，與 `+self-verify` 列同出一次標準消融跑，內部一致。另存在較早的獨立 `llm_rag/llm_rag_results.json`(tp137/fp27/fn6/tn73, F1=0.8925)數字略異——管線表採用同一次消融跑的 baseline 為正確選擇。

2. **表 4-8**：來源檔實有 13 個 FP 類型，論文表僅呈現前 8 大主要類型，建議表註說明「僅列前 8 大類型」。

3. **表 4-14**：來源 `defi_results.json` 內部標記 deprecated(ML 部分由 `_fixed` 版取代)，但其 **llm_rag 區塊**數值仍與論文表一致，可於表註標明資料版本。

4. **表 4-16**：「Pre-cutoff(2024) 10 審計」標籤中，smart 檔的 10 審計含 2 件實為 post-cutoff(`2025-04-forte`、`2026-01-tempo-stablecoin-dex`)；數字與 smart 檔總計完全相符，但建議文字釐清時序標籤(實際 2024 審計為 8 件)。

5. **CTC(表 4-18/4-19)**：經重算驗證，分數來自真實逐合約 LLM-as-judge 產出(429 筆，每筆含 correctness/thoroughness/clarity 整數分與 judge reason)，CTC=0.6·C+0.3·T+0.1·Cl 加權驗算通過，**非手寫**。
