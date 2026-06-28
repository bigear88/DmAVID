#!/usr/bin/env python3
"""Run EVMbench smart-preprocess detection 3x with temperature=0 + fixed seeds
to estimate the variance of the 64.10% headline number (mean +/- std).

Reuses the preprocessing / judging logic from 30_evmbench_smart_preprocess.py
verbatim; only the detection call is reimplemented with temperature=0 and an
explicit OpenAI `seed` per run. Seeds 42/7/123 match the SmartBugs seed_placebo
methodology. Does NOT overwrite the canonical smart_preprocess_results.json.
"""
import os, re, json, importlib.util, statistics

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "smart30", os.path.join(HERE, "30_evmbench_smart_preprocess.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

SEEDS = [42, 7, 123]
OUTPUT_DIR = m.OUTPUT_DIR


def detect_temp0(preprocessed_code, knowledge_base, seed):
    """Same prompt as 30_..., but temperature=0 + explicit seed."""
    prompt = f"""You are an expert DeFi security auditor. Analyze this smart contract project for HIGH severity vulnerabilities.

## DeFi Vulnerability Knowledge Base:
{knowledge_base[:3000]}

## Smart Contract Project (preprocessed: interface summary + security-critical modules):
```solidity
{preprocessed_code}
```

## Task:
1. Identify ALL high-severity vulnerabilities
2. For each, provide: title, severity, root cause, exploit scenario
3. Focus on DeFi-specific issues: flash loan, oracle manipulation, reentrancy, access control, precision loss

Output JSON only:
{{"vulnerabilities": [{{"title": "...", "severity": "high", "summary": "...", "exploit_scenario": "..."}}]}}"""
    try:
        resp = m.client.chat.completions.create(
            model=m.MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            seed=seed,
            **m.token_param(2000),
        )
        content = resp.choices[0].message.content.strip()
        tokens = resp.usage.total_tokens if resp.usage else 0
        match = re.search(r"\{[\s\S]*\}", content)
        if match:
            return json.loads(match.group()).get("vulnerabilities", []), tokens
        return [], tokens
    except Exception as e:
        print(f"    ERROR: {e}")
        return [], 0


def run_one(seed):
    kb = m.load_knowledge_base()
    total_gold = total_detected = total_tokens = 0
    per_audit = []
    for audit_id in m.AUDITS:
        gold = m.load_gold_vulns(audit_id)
        total_gold += len(gold)
        pre = m.smart_preprocess(audit_id)
        if not pre:
            per_audit.append({"audit_id": audit_id, "status": "no_code"})
            continue
        found, tokens = detect_temp0(pre, kb, seed)
        total_tokens += tokens
        detected = m.judge_detection(found, gold)
        total_detected += detected
        per_audit.append({
            "audit_id": audit_id, "gold_count": len(gold),
            "found_count": len(found), "detected": detected,
            "score": round(detected / len(gold), 4) if gold else 0,
            "tokens": tokens,
        })
        print(f"  [{audit_id:<32}] {detected}/{len(gold)}  tok={tokens}")
    rate = total_detected / total_gold if total_gold else 0
    print(f"  seed={seed}: {total_detected}/{total_gold} = {rate:.4f}  tokens={total_tokens:,}")
    return {
        "seed": seed, "temperature": 0,
        "total_gold": total_gold, "total_detected": total_detected,
        "detect_rate": round(rate, 4), "total_tokens": total_tokens,
        "per_audit": per_audit,
    }


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("=" * 64)
    print(f"EVMbench Smart Preprocess  3-RUN  (temp=0, seeds={SEEDS}, model={m.MODEL})")
    print("=" * 64)
    runs = []
    for s in SEEDS:
        print(f"\n--- seed {s} ---")
        r = run_one(s)
        runs.append(r)
        with open(os.path.join(OUTPUT_DIR, f"smart_3run_seed{s}.json"), "w") as f:
            json.dump(r, f, indent=2)

    rates = [r["detect_rate"] for r in runs]
    dets = [r["total_detected"] for r in runs]
    toks = [r["total_tokens"] for r in runs]
    gold = runs[0]["total_gold"]
    mean = statistics.mean(rates)
    std = statistics.pstdev(rates)
    sstd = statistics.stdev(rates) if len(rates) > 1 else 0.0

    # per-audit detection across seeds (stability)
    audit_ids = [a["audit_id"] for a in runs[0]["per_audit"]]
    per_audit_stab = {}
    for aid in audit_ids:
        vals = []
        g = None
        for r in runs:
            a = next((x for x in r["per_audit"] if x["audit_id"] == aid), None)
            if a and a.get("status") != "no_code":
                vals.append(a["detected"]); g = a["gold_count"]
        if vals:
            per_audit_stab[aid] = {"gold": g, "detected_per_seed": vals,
                                   "stable": len(set(vals)) == 1}

    agg = {
        "experiment": "evmbench_smart_preprocess_3run",
        "model": m.MODEL, "temperature": 0, "seeds": SEEDS,
        "total_gold": gold,
        "detected_per_seed": dets,
        "detect_rate_per_seed": rates,
        "detect_rate_mean": round(mean, 4),
        "detect_rate_pstd": round(std, 4),
        "detect_rate_sample_std": round(sstd, 4),
        "detect_rate_min": min(rates), "detect_rate_max": max(rates),
        "tokens_per_seed": toks,
        "canonical_single_run": 0.641,
        "per_audit_stability": per_audit_stab,
    }
    with open(os.path.join(OUTPUT_DIR, "smart_3run_aggregate.json"), "w") as f:
        json.dump(agg, f, indent=2)

    print("\n" + "=" * 64)
    print("AGGREGATE")
    print("=" * 64)
    print(f"  detect_rate per seed : {rates}")
    print(f"  detected per seed    : {dets} / {gold}")
    print(f"  mean +/- pstd        : {mean:.4f} +/- {std:.4f}")
    print(f"  range                : [{min(rates):.4f}, {max(rates):.4f}]")
    print(f"  canonical single-run : 0.6410")
    unstable = [k for k, v in per_audit_stab.items() if not v["stable"]]
    print(f"  unstable audits      : {unstable if unstable else 'none (fully stable)'}")
    print(f"\nSaved: {OUTPUT_DIR}/smart_3run_aggregate.json")


if __name__ == "__main__":
    main()
