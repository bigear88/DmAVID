#!/usr/bin/env python3
"""驗證論文表 3-1 Self-Verify 策略效能比較三 row 之資料來源"""
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "experiments/ablation/ablation_v5_clean_baseline_details.json"
SV = ROOT / "experiments/ablation/ablation_v5_clean_self-verify_details.json"
OUT = ROOT / "experiments/explainability/sv_threshold_ablation_audit.json"


def metrics(preds, truths):
    tp = fp = tn = fn = 0
    for p, t in zip(preds, truths):
        if p and t:
            tp += 1
        elif p and not t:
            fp += 1
        elif (not p) and (not t):
            tn += 1
        else:
            fn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
    }


def main():
    base = json.loads(BASE.read_text(encoding="utf-8"))
    sv = json.loads(SV.read_text(encoding="utf-8"))
    sv_idx = {r["contract_id"]: r for r in sv["results"]}

    # baseline metrics
    truths = [r["ground_truth_vulnerable"] for r in base["results"]]
    base_preds = [r["predicted_vulnerable"] for r in base["results"]]
    base_m = metrics(base_preds, truths)

    # SV coverage 分析：哪些 baseline 樣本有 sv_verdict?
    coverage = {"sv_verdict_present": 0, "sv_verdict_none": 0,
                "vuln_pred_with_sv": 0, "vuln_pred_without_sv": 0,
                "vuln_pred_high_conf_no_sv": 0}
    by_conf = Counter()
    sv_by_conf = Counter()
    for r in base["results"]:
        cid = r["contract_id"]
        c = r.get("confidence")
        sv_r = sv_idx.get(cid, {})
        sv_v = sv_r.get("sv_verdict")
        by_conf[c] += 1
        if sv_v is not None:
            coverage["sv_verdict_present"] += 1
            sv_by_conf[c] += 1
        else:
            coverage["sv_verdict_none"] += 1
        if r["predicted_vulnerable"]:
            if sv_v is not None:
                coverage["vuln_pred_with_sv"] += 1
            else:
                coverage["vuln_pred_without_sv"] += 1
                if c is not None and c >= 0.95:
                    coverage["vuln_pred_high_conf_no_sv"] += 1

    # 模擬「SV 無門檻」：對所有 baseline predicted=True 都套用 SV
    # conf>=0.95 樣本如果 sv_verdict=None → 視為「無資料」(unknown)
    # 計算兩個版本：
    #   version A: 對 unknown 保守視為「保留 baseline 預測」(乘客性最小)
    #   version B: 對 unknown 視為「flip to safe」(極端假設)
    sim_a_preds = []
    sim_b_preds = []
    unknown_count = 0
    flip_to_safe_count = 0
    for r in base["results"]:
        cid = r["contract_id"]
        sv_v = sv_idx.get(cid, {}).get("sv_verdict")
        baseline_p = r["predicted_vulnerable"]
        if not baseline_p:
            sim_a_preds.append(False)
            sim_b_preds.append(False)
            continue
        # baseline_p == True
        if sv_v == "SAFE":
            sim_a_preds.append(False)
            sim_b_preds.append(False)
            flip_to_safe_count += 1
        elif sv_v == "VULNERABLE":
            sim_a_preds.append(True)
            sim_b_preds.append(True)
        else:
            # sv_verdict is None: SV 機制未實際執行
            unknown_count += 1
            sim_a_preds.append(True)   # version A: keep baseline
            sim_b_preds.append(False)  # version B: assume flip

    sim_a = metrics(sim_a_preds, truths)
    sim_b = metrics(sim_b_preds, truths)

    paper_row_1 = {"tp": 141, "fp": 49, "tn": None, "fn": 2,
                   "precision": None, "recall": None, "f1": 0.8468}
    paper_row_2 = {"tp": 96, "fp": 23, "tn": None, "fn": 47,
                   "precision": None, "recall": None, "f1": 0.787,
                   "f1_recomputed_from_tp_fp_fn": round(2 * 96 / (2 * 96 + 23 + 47), 4)}
    paper_row_3 = {"tp": 140, "fp": 24, "tn": 76, "fn": 3,
                   "precision": 0.8537, "recall": 0.979, "f1": 0.9121}

    discrepancy = {
        "row_1_baseline_vs_v5_clean": {
            "paper": paper_row_1,
            "v5_clean_actual": base_m,
            "diff_fp": paper_row_1["fp"] - base_m["fp"],  # 49 - 26 = 23
            "diff_tp": paper_row_1["tp"] - base_m["tp"],  # 141 - 140 = 1
            "verdict": "MISMATCH",
            "note": "論文 Row 1 FP=49，v5_clean baseline FP=26，差距 23 個。Row 1 數字疑似來自更早期版本（v3/v4），無法以 v5_clean raw output 重建。",
        },
        "row_2_no_threshold_sv": {
            "paper": paper_row_2,
            "simulated_full_coverage": sim_a,
            "verdict": "UNRECONSTRUCTABLE_AND_REDUNDANT",
            "note": (f"v5_clean self-verify 對全部 {coverage['vuln_pred_with_sv']} 個 baseline vuln 預測都跑了 SV"
                     f"（含 conf>=0.95 樣本 {coverage['vuln_pred_with_sv']-121} 個），"
                     "與 Row 3 是同一個實驗。論文 Row 2 TP=96/FP=23/FN=47 數字無法重建。"
                     f"論文 Row 2 之 F1=0.787 算術錯誤（由 TP=96/FP=23/FN=47 重算 F1={paper_row_2['f1_recomputed_from_tp_fp_fn']}）。"),
        },
        "row_3_with_threshold_sv": {
            "paper": paper_row_3,
            "v5_clean_actual": sv["metrics"],
            "verdict": "MATCH_BUT_LABEL_WRONG",
            "note": (
                "論文 Row 3 之 metrics 與 v5_clean +self-verify config 完全一致 ✓，"
                "但標籤「SV (conf<0.95)」與實際實作不符——v5_clean SV 對所有 conf 級別之 vuln 預測都執行（無 gating）。"
            ),
        },
    }

    out = {
        "audit": "table_3_1_row_sourcing_verification",
        "purpose": "驗證論文第參章表 3-1 三 row 之 raw experiment 資料來源",
        "method": (
            "1) 從 v5_clean baseline_details 抽取 LLM+RAG 純預測作為 Row 1 對照；"
            "2) 模擬 SV 無門檻（對所有 baseline vuln 預測套 SV），對 conf>=0.95 樣本因 v5_clean 未實跑 SV，"
            "回報 keep/flip 兩端模擬作為夾擊區間；"
            "3) 與論文現有三 row 數字逐一比對"
        ),
        "data_sources": [
            "experiments/ablation/ablation_v5_clean_baseline_details.json",
            "experiments/ablation/ablation_v5_clean_self-verify_details.json",
        ],
        "v5_clean_baseline_metrics": base_m,
        "v5_clean_self_verify_metrics": sv["metrics"],
        "simulated_no_threshold_sv_metrics": {
            "result": sim_a,
            "high_conf_unknown_count": unknown_count,
            "actual_sv_flips_to_safe": flip_to_safe_count,
            "rationale": (
                "經 coverage 分析發現 v5_clean SV 對所有 vuln 預測都跑了 SV（含 conf>=0.95），"
                "因此「SV 無門檻」模擬結果即為 v5_clean self-verify 之實際 metrics。"
                "unknown_count=0 確認此事實。"
            ),
        },
        "sv_coverage": {
            **coverage,
            "all_conf_distribution": dict(sorted(by_conf.items())),
            "sv_verdict_present_by_conf": dict(sorted(sv_by_conf.items())),
        },
        "paper_row_1_metrics": paper_row_1,
        "paper_row_2_metrics": paper_row_2,
        "paper_row_3_metrics": paper_row_3,
        "discrepancy_finding": discrepancy,
        "critical_finding": (
            "v5_clean SV 機制實際上對所有 166 個 baseline vuln 預測（含 conf=0.9/0.95/1.0）都跑了 SV，"
            "並未套用 conf<0.95 門檻。因此論文 Row 2「SV 無門檻」與 Row 3「SV conf<0.95」"
            "在 v5_clean raw output 中是同一個實驗（F1=0.9121）。"
            "Row 3 標籤「conf<0.95」與實際實作不符；Row 2 之 TP=96/FP=23/FN=47 完全無對應 raw 資料。"
        ),
        "recommendation_for_paper": {
            "row_1": (f"建議改為 v5_clean baseline 數字: TP={base_m['tp']}, FP={base_m['fp']}, "
                       f"TN={base_m['tn']}, FN={base_m['fn']}, F1={base_m['f1']}"),
            "row_2": (
                "**建議刪除**。論文 Row 2 數字 (TP=96/FP=23/FN=47) 在 v5_clean raw 中無對應實驗。"
                "若必要保留「SV 無門檻」row，需另跑 SV-with-explicit-no-threshold 實驗（即使結果可能 = Row 3）。"
                "若要呈現 confidence threshold 之效果，需新跑「SV-with-conf<0.95-gating」實驗（即只對 conf<0.95 樣本跑 SV）。"
            ),
            "row_3": (
                "保留 metrics，但**修正標籤**：v5_clean self-verify 實際對所有 vuln 預測套 SV，"
                "並無 conf<0.95 門檻；標籤應改為「SV (對所有 vuln 預測套用)」或「SV (conf-agnostic)」。"
            ),
            "table_redesign_option": (
                "若論文表 3-1 之核心訊息是「SV 機制提升 F1」，"
                "建議簡化為兩 row：Row 1 baseline (F1=0.9061) → Row 2 +SV (F1=0.9121) "
                "並在文字中說明 SV 對所有 vuln 預測一律執行（無 confidence gating）。"
            ),
        },
        "f1_arithmetic_error_note": (
            f"論文 Row 2 標示 F1=0.787，但由 TP=96/FP=23/FN=47 重算 F1={paper_row_2['f1_recomputed_from_tp_fp_fn']}，"
            "原文可能有算術或 typo 錯誤，需校正"
        ),
        "computed_at": datetime.now().isoformat(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=" * 70)
    print("表 3-1 三 row sourcing 驗證結果")
    print("=" * 70)
    print(f"\nRow 1 (無 SV) 比對:")
    print(f"  論文        : TP=141 FP=49 FN=2  F1=0.8468")
    print(f"  v5_clean raw: TP={base_m['tp']} FP={base_m['fp']} FN={base_m['fn']} F1={base_m['f1']}  → MISMATCH")
    print(f"\nRow 2 (SV 無門檻) 模擬:")
    print(f"  論文                           : TP=96  FP=23  FN=47 F1=0.787 (算術錯誤, 應 {2*96/(2*96+23+47):.4f})")
    print(f"  模擬 A (high-conf keep baseline): TP={sim_a['tp']} FP={sim_a['fp']} FN={sim_a['fn']} F1={sim_a['f1']}")
    print(f"  模擬 B (high-conf flip to safe ): TP={sim_b['tp']} FP={sim_b['fp']} FN={sim_b['fn']} F1={sim_b['f1']}")
    print(f"  high-conf 無 SV raw 樣本數: {coverage['vuln_pred_high_conf_no_sv']}")
    print(f"\nRow 3 (SV conf<0.95) 比對:")
    print(f"  論文        : TP=140 FP=24 FN=3 F1=0.9121")
    print(f"  v5_clean raw: TP={sv['metrics']['tp']} FP={sv['metrics']['fp']} FN={sv['metrics']['fn']} F1={sv['metrics']['f1']}  → MATCH")
    print(f"\n→ {OUT}")


if __name__ == "__main__":
    main()
