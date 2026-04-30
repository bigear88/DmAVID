#!/usr/bin/env python3
"""
Sprint 6: Explainability Deepening — 4-Metric EXI Score

新增 4 進階指標 + 合成 EXI（0-100）：
  - Pattern Coverage    25% : reasoning 是否提及已知漏洞 pattern
  - Root Cause Accuracy 30% : 預測 vulnerability_type 是否對齊 ground truth category
  - Attack Path Coverage 25% : EVMbench 上 detected gold findings 比例
  - Repair Quality      20% : 修復建議的 LLM-as-judge 平均分數（1-5 → /5）

EXI = 25 * PC + 30 * RCA + 25 * APC + 20 * (RQ/5)

三方對比：DmAVID vs Slither vs CodeBERT

Inputs:
  experiments/llm_rag/llm_rag_results.json
  experiments/slither/slither_results.json
  experiments/codebert_baseline/per_sample_predictions.json
  experiments/evmbench_smart/smart_preprocess_results.json
  experiments/explainability/repair_quality_judge.json (optional)

Output:
  experiments/explainability/exi_deep_results.json

Idempotent：可重複執行覆寫輸出。Repair Quality 在 judge 結果不存在時用 0 作 placeholder。

Author: Curtis Chang (張宏睿), 2026
"""
import os
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "experiments" / "explainability" / "exi_deep_results.json"
OUT.parent.mkdir(parents=True, exist_ok=True)


# ============================================================
# 漏洞類型關鍵字（fuzzy match，case-insensitive）
# 用於 (1) Pattern Coverage 偵測 reasoning 是否含已知 pattern
# (2) Root Cause Accuracy 把 detector/type 映射回 SmartBugs category
# ============================================================
CATEGORY_KEYWORDS = {
    "reentrancy": ["reentran"],
    "access_control": [
        "access", "tx-origin", "tx_origin", "txorigin",
        "arbitrary-send", "arbitrary_send", "suicidal",
        "delegatecall", "uninitialized", "shadowing", "missing-zero",
        "selfdestruct", "owner",
    ],
    "arithmetic": [
        "overflow", "underflow", "arithmetic",
        "divide", "shift", "multiply",
    ],
    "denial_of_service": ["denial", "dos", "calls-loop", "costly", "msg-value-loop"],
    "time_manipulation": ["timestamp", "time-manipulation", "time_manipulation"],
    "bad_randomness": ["random", "blockhash", "prng"],
    "front_running": ["front", "running"],
    "unchecked_low_level_calls": [
        "unchecked", "low-level", "lowlevel", "low_level", "send",
    ],
    "short_addresses": ["short-address", "short_address"],
    "other": ["other"],
}

# Pattern keyword set for Pattern Coverage（任一 hit 即視為 reasoning 含 pattern）
PATTERN_HIT_KEYWORDS = sorted({kw for kws in CATEGORY_KEYWORDS.values() for kw in kws})


def text_has_category(text, category):
    """判斷 text 是否含 category 對應的關鍵字（fuzzy, case-insensitive）"""
    if not text:
        return False
    t = text.lower()
    for kw in CATEGORY_KEYWORDS.get(category, [category.replace("_", " ")]):
        if kw in t:
            return True
    return False


def text_has_any_pattern(text):
    """Pattern Coverage：reasoning 中是否有任一已知漏洞關鍵字"""
    if not text:
        return False
    t = text.lower()
    return any(kw in t for kw in PATTERN_HIT_KEYWORDS)


# ============================================================
# 指標 (1): Pattern Coverage
# ============================================================
def compute_pattern_coverage_dmavid(results):
    """DmAVID: TP 中 reasoning 包含任一 pattern 的比例"""
    tps = [r for r in results if r.get("ground_truth") == "vulnerable"
           and r.get("predicted_vulnerable") is True]
    if not tps:
        return 0.0, 0, 0
    hits = sum(1 for r in tps if text_has_any_pattern(r.get("reasoning", "")))
    return hits / len(tps), hits, len(tps)


def compute_pattern_coverage_slither(results):
    """Slither: TP 中 vuln_types 至少含一個 high/medium severity detector 的比例
       低嚴重度 / informational 不算實質 pattern hit"""
    tps = [r for r in results if r.get("ground_truth") == "vulnerable"
           and r.get("predicted_vulnerable") is True]
    if not tps:
        return 0.0, 0, 0
    hits = 0
    for r in tps:
        sevs = r.get("severities", [])
        # 至少有一個 High/Medium severity detector，且其 detector 名稱命中 pattern keyword
        types = r.get("vuln_types", [])
        if not types or not sevs:
            continue
        has_meaningful = False
        for t, s in zip(types, sevs):
            if s in ("High", "Medium") and text_has_any_pattern(t):
                has_meaningful = True
                break
        if has_meaningful:
            hits += 1
    return hits / len(tps), hits, len(tps)


def compute_pattern_coverage_codebert(predictions):
    """CodeBERT: 黑箱無 reasoning → 0"""
    tps = [p for p in predictions if p.get("ground_truth") == "vulnerable"
           and p.get("predicted") == "vulnerable"]
    return 0.0, 0, len(tps)


# ============================================================
# 指標 (2): Root Cause Accuracy
# 對 TP 樣本，檢查預測 type 是否能映射到 ground truth category
# ============================================================
def compute_root_cause_dmavid(results):
    tps = [r for r in results if r.get("ground_truth") == "vulnerable"
           and r.get("predicted_vulnerable") is True]
    if not tps:
        return 0.0, 0, 0
    correct = 0
    for r in tps:
        gt_cat = r.get("category", "")
        pred_types = r.get("vulnerability_types", []) or []
        types_text = " ".join(pred_types)
        if text_has_category(types_text, gt_cat):
            correct += 1
    return correct / len(tps), correct, len(tps)


def compute_root_cause_slither(results):
    tps = [r for r in results if r.get("ground_truth") == "vulnerable"
           and r.get("predicted_vulnerable") is True]
    if not tps:
        return 0.0, 0, 0
    correct = 0
    for r in tps:
        gt_cat = r.get("category", "")
        # 只看 High/Medium 嚴重度的 detector（避免 informational noise）
        types = r.get("vuln_types", [])
        sevs = r.get("severities", [])
        relevant = [t for t, s in zip(types, sevs) if s in ("High", "Medium")]
        if relevant and text_has_category(" ".join(relevant), gt_cat):
            correct += 1
    return correct / len(tps), correct, len(tps)


def compute_root_cause_codebert(predictions):
    """無 type 輸出 → 0"""
    tps = [p for p in predictions if p.get("ground_truth") == "vulnerable"
           and p.get("predicted") == "vulnerable"]
    return 0.0, 0, len(tps)


# ============================================================
# 指標 (3): Attack Path Coverage（EVMbench）
# DmAVID：使用 smart_preprocess per_audit['score'] = detected / gold_count
# Slither / CodeBERT：無 EVMbench 結構化 result → 0
# ============================================================
def compute_attack_path_dmavid():
    sp = ROOT / "experiments" / "evmbench_smart" / "smart_preprocess_results.json"
    if not sp.exists():
        return 0.0, 0, 0, []
    d = json.loads(sp.read_text(encoding="utf-8"))
    total_detected = d.get("total_detected", 0)
    total_gold = d.get("total_gold", 0)
    coverage = total_detected / total_gold if total_gold else 0.0
    per_audit = d.get("per_audit", [])
    return coverage, total_detected, total_gold, per_audit


def compute_attack_path_slither_codebert():
    """Slither/CodeBERT 在 EVMbench 上無對應結果結構（既有實驗未跑或結構不同）→ 0
       這是誠實標註，不是占位符。"""
    return 0.0, 0, 0


# ============================================================
# 指標 (4): Repair Quality
# 從 42 寫出的 repair_quality_judge.json 讀取 LLM-as-judge 評分
# 不存在時用 0（placeholder），跑完 42 後重 run 41 即更新
# ============================================================
def load_repair_quality():
    judge_file = ROOT / "experiments" / "explainability" / "repair_quality_judge.json"
    if not judge_file.exists():
        return {
            "available": False,
            "dmavid_avg": 0.0,
            "n_judged": 0,
            "n_total_with_repair": 88,
            "note": "repair_quality_judge.json 尚未產生，等 42 跑完後重 run 41",
        }
    d = json.loads(judge_file.read_text(encoding="utf-8"))
    scores = [r["score"] for r in d.get("results", []) if isinstance(r.get("score"), (int, float))]
    avg = sum(scores) / len(scores) if scores else 0.0
    return {
        "available": True,
        "dmavid_avg": round(avg, 4),
        "n_judged": len(scores),
        "n_total_with_repair": d.get("n_total_with_repair", len(scores)),
        "score_distribution": {
            str(s): scores.count(s) for s in sorted(set(int(x) for x in scores))
        },
    }


# ============================================================
# EXI 合成
# ============================================================
WEIGHTS = {
    "pattern_coverage": 25,
    "root_cause": 30,
    "attack_path": 25,
    "repair_quality": 20,
}


def compute_exi(pc, rca, apc, rq_avg_1to5):
    """所有指標 0-1，repair quality 從 1-5 normalize 到 0-1"""
    rq_norm = (rq_avg_1to5 / 5.0) if rq_avg_1to5 else 0.0
    return round(
        WEIGHTS["pattern_coverage"] * pc
        + WEIGHTS["root_cause"] * rca
        + WEIGHTS["attack_path"] * apc
        + WEIGHTS["repair_quality"] * rq_norm,
        2,
    )


# ============================================================
# Main
# ============================================================
def main():
    print("=" * 70)
    print("Sprint 6 — Explainability Deep Metrics + EXI")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)

    # ---------- 載入 ----------
    print("\n[Load] DmAVID llm_rag_results.json")
    dmavid = json.loads((ROOT / "experiments/llm_rag/llm_rag_results.json").read_text(encoding="utf-8"))
    dmavid_results = dmavid["results"]

    print("[Load] Slither slither_results.json")
    slither = json.loads((ROOT / "experiments/slither/slither_results.json").read_text(encoding="utf-8"))
    slither_results = slither["results"]

    print("[Load] CodeBERT per_sample_predictions.json")
    cb = json.loads((ROOT / "experiments/codebert_baseline/per_sample_predictions.json").read_text(encoding="utf-8"))

    repair = load_repair_quality()

    # ---------- 計算 ----------
    print("\n[Metric 1] Pattern Coverage")
    pc_d, pc_d_h, pc_d_n = compute_pattern_coverage_dmavid(dmavid_results)
    pc_s, pc_s_h, pc_s_n = compute_pattern_coverage_slither(slither_results)
    pc_c, pc_c_h, pc_c_n = compute_pattern_coverage_codebert(cb)
    print(f"  DmAVID:   {pc_d:.4f}  ({pc_d_h}/{pc_d_n})")
    print(f"  Slither:  {pc_s:.4f}  ({pc_s_h}/{pc_s_n})")
    print(f"  CodeBERT: {pc_c:.4f}  ({pc_c_h}/{pc_c_n})  [黑箱無 reasoning]")

    print("\n[Metric 2] Root Cause Accuracy")
    rca_d, rca_d_h, rca_d_n = compute_root_cause_dmavid(dmavid_results)
    rca_s, rca_s_h, rca_s_n = compute_root_cause_slither(slither_results)
    rca_c, rca_c_h, rca_c_n = compute_root_cause_codebert(cb)
    print(f"  DmAVID:   {rca_d:.4f}  ({rca_d_h}/{rca_d_n})")
    print(f"  Slither:  {rca_s:.4f}  ({rca_s_h}/{rca_s_n})")
    print(f"  CodeBERT: {rca_c:.4f}  ({rca_c_h}/{rca_c_n})  [無 type 輸出]")

    print("\n[Metric 3] Attack Path Coverage (EVMbench)")
    apc_d, apc_d_det, apc_d_gold, _per_audit = compute_attack_path_dmavid()
    apc_s, _, _ = compute_attack_path_slither_codebert()
    apc_c, _, _ = compute_attack_path_slither_codebert()
    print(f"  DmAVID:   {apc_d:.4f}  ({apc_d_det}/{apc_d_gold})")
    print(f"  Slither:  {apc_s:.4f}  [既有實驗未涵蓋 EVMbench]")
    print(f"  CodeBERT: {apc_c:.4f}  [既有實驗未涵蓋 EVMbench]")

    print("\n[Metric 4] Repair Quality")
    if repair["available"]:
        print(f"  DmAVID:   {repair['dmavid_avg']:.4f} / 5  (n={repair['n_judged']}/{repair['n_total_with_repair']})")
    else:
        print(f"  DmAVID:   0.0 (placeholder — {repair['note']})")
    print(f"  Slither:  0.0 (Slither 不輸出修復建議；保持誠實 0 分)")
    print(f"  CodeBERT: 0.0 (黑箱無修復建議)")
    rq_d_1to5 = repair["dmavid_avg"]

    # ---------- EXI ----------
    print("\n[EXI Synthesis]  0-100 scale")
    exi_d = compute_exi(pc_d, rca_d, apc_d, rq_d_1to5)
    exi_s = compute_exi(pc_s, rca_s, apc_s, 0.0)
    exi_c = compute_exi(pc_c, rca_c, apc_c, 0.0)
    print(f"  DmAVID  EXI = {exi_d}")
    print(f"  Slither EXI = {exi_s}")
    print(f"  CodeBERT EXI= {exi_c}")

    # ---------- 寫出 ----------
    out = {
        "experiment": "explainability_deep",
        "timestamp": datetime.now().isoformat(),
        "weights": WEIGHTS,
        "exi_formula": "EXI = 25*PC + 30*RCA + 25*APC + 20*(RQ/5)",
        "repair_quality_status": repair,
        "dmavid": {
            "pattern_coverage": round(pc_d, 4),
            "pattern_coverage_breakdown": {"hits": pc_d_h, "tp_total": pc_d_n},
            "root_cause": round(rca_d, 4),
            "root_cause_breakdown": {"correct": rca_d_h, "tp_total": rca_d_n},
            "attack_path": round(apc_d, 4),
            "attack_path_breakdown": {
                "detected": apc_d_det, "total_gold": apc_d_gold,
                "source": "experiments/evmbench_smart/smart_preprocess_results.json",
            },
            "repair_quality_avg_1to5": round(rq_d_1to5, 4),
            "exi": exi_d,
        },
        "slither": {
            "pattern_coverage": round(pc_s, 4),
            "pattern_coverage_breakdown": {"hits": pc_s_h, "tp_total": pc_s_n},
            "root_cause": round(rca_s, 4),
            "root_cause_breakdown": {"correct": rca_s_h, "tp_total": rca_s_n},
            "attack_path": round(apc_s, 4),
            "attack_path_note": "Slither 既有實驗未涵蓋 EVMbench post-cutoff audits",
            "repair_quality_avg_1to5": 0.0,
            "repair_quality_note": "Slither 不輸出可執行修復建議；不送 LLM-judge 以避免 fabricate",
            "exi": exi_s,
        },
        "codebert": {
            "pattern_coverage": round(pc_c, 4),
            "pattern_coverage_note": "CodeBERT 為黑箱二元分類器，無 reasoning 輸出",
            "root_cause": round(rca_c, 4),
            "root_cause_note": "CodeBERT 不輸出漏洞類型",
            "attack_path": round(apc_c, 4),
            "attack_path_note": "CodeBERT 既有實驗未涵蓋 EVMbench post-cutoff audits",
            "repair_quality_avg_1to5": 0.0,
            "repair_quality_note": "CodeBERT 無修復建議輸出",
            "exi": exi_c,
        },
    }
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n→ Saved: {OUT}")

    # Sanity check 預期 DmAVID > Slither > CodeBERT
    print("\n[Sanity] 預期 DmAVID EXI > Slither EXI > CodeBERT EXI")
    if exi_d > exi_s > exi_c:
        print(f"  ✓ {exi_d} > {exi_s} > {exi_c}")
    else:
        print(f"  ⚠ 順序不符預期: D={exi_d} S={exi_s} C={exi_c} — 請覆查 metric 計算")


if __name__ == "__main__":
    main()
