#!/usr/bin/env python3
"""驗證論文第參章第二節三、Self-Verify 之「高信心 FP 約佔 12.4%」宣稱"""
import json
import statistics
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "experiments/ablation/ablation_v5_clean_self-verify_details.json"
OUT = ROOT / "experiments/explainability/high_conf_fp_analysis.json"
TAU = 0.95


def final_verdict(r):
    sv = r.get("sv_verdict")
    if sv == "VULNERABLE":
        return True
    if sv == "SAFE":
        return False
    return r["predicted_vulnerable"]


def stats(xs):
    if not xs:
        return {"n": 0, "mean": None, "median": None, "min": None, "max": None}
    return {
        "n": len(xs),
        "mean": round(statistics.mean(xs), 4),
        "median": round(statistics.median(xs), 4),
        "min": round(min(xs), 4),
        "max": round(max(xs), 4),
    }


def main():
    data = json.loads(SRC.read_text(encoding="utf-8"))
    rows = data["results"]

    fp_conf, tp_conf, tn_conf, fn_conf = [], [], [], []
    for r in rows:
        gt = r["ground_truth_vulnerable"]
        pred = final_verdict(r)
        c = r.get("confidence")
        if c is None:
            continue
        if gt and pred:
            tp_conf.append(c)
        elif (not gt) and pred:
            fp_conf.append(c)
        elif (not gt) and (not pred):
            tn_conf.append(c)
        else:
            fn_conf.append(c)

    total_fp = len(fp_conf)
    high_conf_fp = sum(1 for c in fp_conf if c >= TAU)
    ratio = round(high_conf_fp / total_fp * 100, 2) if total_fp else 0.0

    from collections import Counter
    fp_buckets = dict(sorted(Counter(fp_conf).items()))
    tp_buckets = dict(sorted(Counter(tp_conf).items()))
    tn_buckets = dict(sorted(Counter(tn_conf).items()))
    fn_buckets = dict(sorted(Counter(fn_conf).items()))

    # 多門檻情境：論文實際可宣稱什麼
    multi_tau = {}
    for tau in [0.90, 0.95, 0.99, 1.00]:
        n_hi = sum(1 for c in fp_conf if c >= tau)
        multi_tau[f"tau_{tau:.2f}"] = {
            "high_conf_fp": n_hi,
            "ratio_pct": round(n_hi / total_fp * 100, 2) if total_fp else 0.0,
        }

    out = {
        "total_fp": total_fp,
        "high_conf_fp": high_conf_fp,
        "high_conf_fp_ratio": ratio,
        "threshold_tau": TAU,
        "fp_conf_stats": stats(fp_conf),
        "tp_conf_stats": stats(tp_conf),
        "tn_conf_stats": stats(tn_conf),
        "fn_conf_stats": stats(fn_conf),
        "fp_conf_buckets": fp_buckets,
        "tp_conf_buckets": tp_buckets,
        "tn_conf_buckets": tn_buckets,
        "fn_conf_buckets": fn_buckets,
        "multi_tau_high_conf_fp": multi_tau,
        "confidence_granularity_note": "LLM 自評 confidence 僅輸出離散值 {0.8, 0.9, 0.95, 1.0}，連續門檻細粒度受限",
        "interpretation": "高信心 FP 比例代表 Self-Verify Confidence Threshold 機制無法捕捉之循環依賴邊界",
        "data_source": "ablation_v5_clean_self-verify_details.json",
        "verdict_rule": "sv_verdict 優先；為 None 時 fallback 到 predicted_vulnerable",
        "computed_at": datetime.now().isoformat(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=" * 60)
    print(f"Self-Verify 高信心 FP 分析  τ={TAU}")
    print("=" * 60)
    print(f"total FP             : {total_fp}")
    print(f"high-conf FP (≥{TAU}) : {high_conf_fp}")
    print(f"high-conf FP ratio   : {ratio}%")
    print()
    print(f"FP conf  : {out['fp_conf_stats']}")
    print(f"TP conf  : {out['tp_conf_stats']}")
    print(f"TN conf  : {out['tn_conf_stats']}")
    print(f"FN conf  : {out['fn_conf_stats']}")
    print()
    print(f"→ {OUT}")
    print()
    claim = 12.4
    diff = ratio - claim
    print(f"論文宣稱 : {claim}%")
    print(f"實算結果 : {ratio}%")
    print(f"差距     : {diff:+.2f} pp")
    if abs(diff) < 1.0:
        print("結論     : 與論文宣稱一致（差 <1pp），無需修改。")
    else:
        print("結論     : 與論文宣稱有差距，建議修改論文文字為實算值。")


if __name__ == "__main__":
    main()
