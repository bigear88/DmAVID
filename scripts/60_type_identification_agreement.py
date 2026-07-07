# -*- coding: utf-8 -*-
"""
Type-identification agreement analysis.

Answers the examiner's question: the detection task is binary
(vulnerable / safe), yet every report also *names* a vulnerability type.
How accurate is that open-ended type identification?

This script does NOT re-run any experiment. It re-uses the existing hybrid
pipeline output (experiments/baseline_gpt41mini/hybrid_results.json), maps the
free-text predicted `vulnerability_types` onto the 10 SmartBugs/DASP curated
categories, and compares them against each contract's ground-truth `category`.

Outputs supplementary_results/type_identification_agreement.json.
"""
import json, collections, statistics, os
from math import comb

ROOT = "/home/curtis/DmAVID"
SRC = os.path.join(ROOT, "experiments/baseline_gpt41mini/hybrid_results.json")
OUT = os.path.join(ROOT, "supplementary_results/type_identification_agreement.json")

CATS = ["reentrancy", "arithmetic", "access_control", "unchecked_low_level_calls",
        "denial_of_service", "bad_randomness", "front_running", "time_manipulation",
        "short_addresses", "other"]


def norm(t):
    """Map a free-text predicted type onto a SmartBugs/DASP category."""
    s = t.lower()
    if "reentran" in s: return "reentrancy"
    if "short address" in s: return "short_addresses"
    if "front" in s or "race condition" in s or "approval race" in s: return "front_running"
    if "randomness" in s or "random" in s: return "bad_randomness"
    if ("timestamp" in s or "time_manipulation" in s or "time manipulation" in s
            or "block.timestamp" in s or "block number" in s): return "time_manipulation"
    if "overflow" in s or "underflow" in s or "arithmetic" in s or "integer" in s: return "arithmetic"
    if ("denial" in s or "dos" in s or "unbounded loop" in s or "revert" in s
            or "blocking payment" in s or "failed external call" in s): return "denial_of_service"
    if ("access control" in s or "access_control" in s or "selfdestruct" in s
            or "ownership" in s or "owner" in s or "tx.origin" in s or "authentication" in s
            or "delegatecall" in s or "constructor init" in s): return "access_control"
    if ("unchecked" in s or "low-level call" in s or "low_level_call" in s
            or "return value" in s or "send()" in s or "unsafe low-level" in s): return "unchecked_low_level_calls"
    return "other"


def main():
    recs = json.load(open(SRC))["results"]
    tp = [r for r in recs
          if r["ground_truth"] == "vulnerable" and r["predicted_vulnerable"] and r["category"] != "none"]

    hit = 0
    permiss = collections.Counter(); pertot = collections.Counter()
    top1hit = 0; misses = []
    setsizes = []
    for r in tp:
        gt = r["category"]
        raw = r.get("vulnerability_types") or []
        preds = set(norm(t) for t in raw)
        setsizes.append(len(preds))
        pertot[gt] += 1
        if gt in preds:
            hit += 1; permiss[gt] += 1
        else:
            misses.append({"contract_id": r["contract_id"], "ground_truth_category": gt,
                           "predicted_raw": raw, "predicted_normalized": sorted(preds)})
        if raw and norm(raw[0]) == gt:
            top1hit += 1

    N = sum(pertot.values())
    avgset = statistics.mean(setsizes)

    def chance_in_set(k, C=9):
        return 1 - comb(C - 1, k) / comb(C, k) if k <= C else 1.0
    k = max(1, round(avgset))
    p0 = chance_in_set(k)
    pval_set = sum(comb(N, i) * p0**i * (1 - p0)**(N - i) for i in range(hit, N + 1))
    p1 = 1 / 9
    pval_top1 = sum(comb(N, i) * p1**i * (1 - p1)**(N - i) for i in range(top1hit, N + 1))

    result = {
        "source": "experiments/baseline_gpt41mini/hybrid_results.json",
        "note": "Type identification is open-ended; predicted free-text types are normalized to SmartBugs/DASP categories, then compared to ground-truth category. No experiment re-run.",
        "n_true_positive_vulnerable": N,
        "set_agreement": {  # GT category is among the predicted type set
            "hits": hit, "total": N, "rate": round(hit / N, 4),
            "null_chance": round(p0, 4), "binomial_p_value_one_sided": pval_set,
        },
        "top1_agreement": {  # first-listed (primary) predicted type == GT category
            "hits": top1hit, "total": N, "rate": round(top1hit / N, 4),
            "null_chance": round(p1, 4), "binomial_p_value_one_sided": pval_top1,
        },
        "avg_distinct_predicted_types": round(avgset, 3),
        "per_category": {c: {"hits": permiss[c], "total": pertot[c],
                             "rate": round(permiss[c] / pertot[c], 4)}
                         for c in CATS if pertot[c]},
        "misses": misses,
    }
    with open(OUT, "w") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print("set agreement : %d/%d = %.4f  (p=%.2e)" % (hit, N, hit / N, pval_set))
    print("top-1 agreement: %d/%d = %.4f  (p=%.2e)" % (top1hit, N, top1hit / N, pval_top1))
    print("saved ->", OUT)


if __name__ == "__main__":
    main()
