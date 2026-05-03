#!/usr/bin/env python3
"""Safe Label Noise Audit - v52
Quantify SmartBugs Wild safe label noise using existing Slither results.
"""
import json
import os
from collections import Counter
from datetime import datetime

SLITHER_JSON = "/home/curtis/DmAVID/experiments/slither/slither_results.json"
OUT_JSON = "/home/curtis/DmAVID/experiments/audit/safe_label_noise_audit.json"

with open(SLITHER_JSON) as f:
    data = json.load(f)

results = data["results"]
wild_safe = [r for r in results if r["ground_truth"] == "safe"]
assert len(wild_safe) == 100, f"Expected 100 safe, got {len(wild_safe)}"

per_contract = []
n_high_total = n_medium_total = n_low_total = n_info_total = n_opt_total = 0

for r in wild_safe:
    severities = r.get("severities", [])
    vuln_types = r.get("vuln_types", [])
    counts = Counter(s.lower() for s in severities)
    n_high = counts.get("high", 0)
    n_medium = counts.get("medium", 0)
    n_low = counts.get("low", 0)
    n_info = counts.get("informational", 0)
    n_opt = counts.get("optimization", 0)

    top_detector = None
    top_severity = None
    for sev, det in zip(severities, vuln_types):
        if sev.lower() == "high":
            top_detector = det
            top_severity = "high"
            break
    if top_detector is None:
        for sev, det in zip(severities, vuln_types):
            if sev.lower() == "medium":
                top_detector = det
                top_severity = "medium"
                break
    if top_detector is None and vuln_types:
        top_detector = vuln_types[0]
        top_severity = severities[0].lower() if severities else "unknown"

    n_high_total += n_high
    n_medium_total += n_medium
    n_low_total += n_low
    n_info_total += n_info
    n_opt_total += n_opt

    per_contract.append({
        "id": r["contract_id"],
        "filename": r["filename"],
        "slither_pred_strict": "vulnerable" if n_high >= 1 else "safe",
        "slither_pred_lenient": "vulnerable" if (n_high + n_medium) >= 1 else "safe",
        "slither_pred_any": "vulnerable" if r.get("num_detections", 0) >= 1 else "safe",
        "n_high": n_high,
        "n_medium": n_medium,
        "n_low": n_low,
        "n_informational": n_info,
        "n_optimization": n_opt,
        "top_detector": top_detector,
        "top_severity": top_severity,
    })

noise_strict = sum(1 for c in per_contract if c["slither_pred_strict"] == "vulnerable") / 100
noise_lenient = sum(1 for c in per_contract if c["slither_pred_lenient"] == "vulnerable") / 100
noise_any = sum(1 for c in per_contract if c["slither_pred_any"] == "vulnerable") / 100

assert noise_strict <= noise_lenient <= noise_any, "Monotonicity violated!"

flagged = [c for c in per_contract if c["slither_pred_lenient"] == "vulnerable"]
sample_5 = [
    {
        "id": c["id"],
        "filename": c["filename"],
        "top_finding": c["top_detector"],
        "top_severity": c["top_severity"],
        "n_high": c["n_high"],
        "n_medium": c["n_medium"],
    }
    for c in flagged[:5]
]

if noise_strict < 0.05:
    paper_note = (
        f"safe label noise upper bound < 5% (slither high severity = {noise_strict*100:.1f}%)，"
        f"對 F1 估值之影響可忽略"
    )
elif noise_strict < 0.15:
    paper_note = (
        f"safe label noise upper bound ~{noise_strict*100:.0f}%，"
        f"反映 SmartBugs Wild label 之天然偏差，本研究 F1=0.9121 估值含此 noise floor"
    )
else:
    paper_note = (
        f"safe label noise upper bound {noise_strict*100:.1f}%，"
        f"建議考慮重抽樣或補做 manual review"
    )

suggested_disclosure = (
    f"為驗證 safe label 品質，本研究補做事後 Slither 二次掃描，"
    f"發現 100 safe 樣本中 {noise_strict*100:.1f}% 被 Slither 標為有 high severity 發現，"
    f"此為 safe label 之 noise upper bound。"
    f"考量 Slither 本身於 SmartBugs Curated 之 FPR ≈ 0.84，"
    f"實際 mislabel rate 應遠低於此上界。"
)

output = {
    "version": "v52_safe_noise_audit",
    "timestamp": datetime.now().isoformat(),
    "experiment_purpose": "Quantify SmartBugs Wild safe label noise to disclose dataset limitation",
    "n_safe_contracts": 100,
    "slither_results_source": SLITHER_JSON,
    "slither_experiment_timestamp": data.get("timestamp", "unknown"),
    "noise_rates": {
        "strict (high severity >= 1)": round(noise_strict, 4),
        "lenient (high+medium >= 1)": round(noise_lenient, 4),
        "any_finding (informational+)": round(noise_any, 4),
    },
    "severity_breakdown": {
        "n_high": n_high_total,
        "n_medium": n_medium_total,
        "n_low": n_low_total,
        "n_informational": n_info_total,
        "n_optimization": n_opt_total,
    },
    "per_contract": per_contract,
    "sample_5_flagged": sample_5,
    "interpretation": {
        "noise_upper_bound": (
            f"{noise_strict*100:.1f}% safe 合約被 Slither 視為有 high severity 漏洞，"
            f"此為 safe label 之 noise upper bound"
        ),
        "lower_bound_caveat": (
            "Slither FPR ≈ 0.84 on Curated (84 FP / 100 safe)，"
            "實際 mislabel rate 遠低於 noise upper bound"
        ),
        "slither_fpr_on_curated": 0.84,
        "paper_recommendation": paper_note,
    },
    "suggested_paper_disclosure": suggested_disclosure,
    "validation": {
        "monotonicity_ok": True,
        "n_per_contract": len(per_contract),
        "n_sample_5_flagged": len(sample_5),
    },
}

os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
with open(OUT_JSON, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2, ensure_ascii=False)

print("=== Safe Label Noise Audit ===")
print(f"n_safe_contracts: 100")
print(f"noise_strict  (high>=1):        {noise_strict*100:.1f}%  ({int(noise_strict*100)} contracts)")
print(f"noise_lenient (high+med>=1):    {noise_lenient*100:.1f}%  ({int(noise_lenient*100)} contracts)")
print(f"noise_any     (any finding):    {noise_any*100:.1f}%  ({int(noise_any*100)} contracts)")
print(f"\nSeverity totals (100 safe contracts):")
print(f"  High={n_high_total}, Medium={n_medium_total}, Low={n_low_total}, Info={n_info_total}, Opt={n_opt_total}")
print(f"\nSample 5 flagged (lenient):")
for s in sample_5:
    print(f"  {s['filename']}: top={s['top_finding']} ({s['top_severity']}), H={s['n_high']}, M={s['n_medium']}")
print(f"\nPaper note: {paper_note}")
print(f"Output: {OUT_JSON}")
