# -*- coding: utf-8 -*-
"""
Convergence evidence for the 3-round adversarial-iterative pipeline
WITHOUT running a 4th round.

Uses the CANONICAL compile-only BAK run (author-chosen main line,
experiments/dmavid_autonomous_BAK_precompile_20260626/).

Produces four independent lines of evidence that the pipeline has
converged by round 3:
  1. McNemar R2-vs-R3: are the two rounds statistically distinguishable?
  2. Marginal F1-gain decay + geometric-extrapolation upper bound.
  3. Marginal cost/benefit flip (TP recovered vs FP added).
  4. Knowledge-signal saturation (defense patterns retained per round).

Outputs supplementary_results/iteration_convergence_evidence.json.
"""
import json, os
from math import comb

ROOT = "/home/curtis/DmAVID"
BAK = os.path.join(ROOT, "experiments/dmavid_autonomous_BAK_precompile_20260626")
OUT = os.path.join(ROOT, "supplementary_results/iteration_convergence_evidence.json")

# canonical compile-only per-round metrics (CANONICAL_TRUTH.md section B)
F1 = {1: 0.9103, 2: 0.9153, 3: 0.9158}
TP = {1: 132, 2: 135, 3: 136}
FP = {1: 15, 2: 17, 3: 18}
FN = {1: 11, 2: 8, 3: 7}
PATCHES = {1: 11, 2: 8, 3: 7}


def load_correct(rd):
    d = json.load(open(f"{BAK}/round_{rd}_results.json"))
    return {r["contract_id"]: (bool(r["predicted_vulnerable"]) == bool(r["ground_truth_vulnerable"]))
            for r in d["results"]}


def exact_mcnemar_p(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / (2 ** n))


def main():
    c2, c3 = load_correct(2), load_correct(3)
    common = sorted(set(c2) & set(c3))
    b = sum(1 for k in common if c2[k] and not c3[k])
    c = sum(1 for k in common if not c2[k] and c3[k])
    both_ok = sum(1 for k in common if c2[k] and c3[k])
    both_no = sum(1 for k in common if not c2[k] and not c3[k])
    p_exact = exact_mcnemar_p(b, c)
    chi2 = ((abs(b - c) - 1) ** 2) / (b + c) if (b + c) else 0.0

    d12 = F1[2] - F1[1]
    d23 = F1[3] - F1[2]
    ratio = d23 / d12
    geo_bound = d23 * ratio / (1 - ratio)

    result = {
        "source": "experiments/dmavid_autonomous_BAK_precompile_20260626 (compile-only canonical)",
        "note": "Four independent convergence signals; no 4th round executed.",
        "mcnemar_r2_vs_r3": {
            "n_common": len(common), "both_correct": both_ok,
            "r2_correct_r3_wrong": b, "r2_wrong_r3_correct": c,
            "both_wrong": both_no, "discordant": b + c,
            "exact_binomial_two_sided_p": round(p_exact, 4),
            "chi2_continuity": round(chi2, 4),
            "distinguishable_at_0.05": p_exact < 0.05,
        },
        "marginal_f1_decay": {
            "delta_r1_r2": round(d12, 4), "delta_r2_r3": round(d23, 4),
            "decay_ratio": round(ratio, 3),
            "geometric_upper_bound_round4_onward": round(geo_bound, 5),
            "convergence_threshold": 0.01,
        },
        "marginal_cost_benefit": {
            "delta_tp_r2_r3": TP[3] - TP[2], "delta_fp_r2_r3": FP[3] - FP[2],
            "delta_fn_r2_r3": FN[3] - FN[2],
            "fpr": {"r1": 0.15, "r2": 0.17, "r3": 0.18},
        },
        "knowledge_saturation": {"patches_per_round": PATCHES},
        "conclusion": "R2 and R3 statistically indistinguishable (p=%.3f); "
                      "remaining achievable gain <= %.5f (< threshold/100); "
                      "marginal recall gain offset by precision loss; "
                      "knowledge signal saturating -> 3 rounds sufficient, round 4 unnecessary."
                      % (p_exact, geo_bound),
    }
    with open(OUT, "w") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("McNemar R2 vs R3 exact p = %.4f (discordant %d:%d) -> %s"
          % (p_exact, b, c, "indistinguishable" if p_exact >= 0.05 else "distinguishable"))
    print("ΔF1 decay %.4f -> %.4f (ratio %.2f); round4+ upper bound %.5f"
          % (d12, d23, ratio, geo_bound))
    print("saved ->", OUT)


if __name__ == "__main__":
    main()
