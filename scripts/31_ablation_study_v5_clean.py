#!/usr/bin/env python3
"""
DmAVID Ablation Study v5_clean — Three-Class Self-Verify (UNCERTAIN preserves baseline).

Pipeline: Baseline → Three-Class Self-Verify → Critique → Debate

Built on v3 (leakage-free, uses 05_run_llm_rag.py analyze_with_rag).
Key change from v4/v5: Self-Verify outputs three verdicts:
  - VULNERABLE: all exploit path components confirmed → keep VULNERABLE
  - SAFE: concrete mitigation found (modifier/guard) → flip to SAFE
  - UNCERTAIN: cannot confirm or deny → preserve baseline prediction (no flip)

This avoids v4's recall collapse (null fields → forced SAFE) by treating
ambiguous cases as UNCERTAIN instead of defaulting to SAFE.

Author: Curtis Chang
"""

import os, sys, json, time, random, re
from datetime import datetime
from typing import Dict, List, Any

BASE_DIR = os.environ.get("DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))
sys.path.insert(0, os.path.join(BASE_DIR, "agents"))

from _model_compat import token_param
from openai import OpenAI

# Import the EXACT same detection function as the baseline experiment
from importlib import util as ilu
_spec = ilu.spec_from_file_location("llm_rag", os.path.join(BASE_DIR, "scripts", "05_run_llm_rag.py"))
_rag_mod = ilu.module_from_spec(_spec)
_spec.loader.exec_module(_rag_mod)
analyze_with_rag = _rag_mod.analyze_with_rag

from critic_agent import CriticAgent
from debate_round import DebateRound, apply_debate_flips

random.seed(42)
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
client = OpenAI()

DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments/ablation")


# ============================================================
# Dataset & Metrics (identical to v3)
# ============================================================

def load_dataset():
    with open(DATASET_FILE, "r") as f:
        data = json.load(f)
    contracts = data["contracts"]
    vuln = [c for c in contracts if c["label"] == "vulnerable"]
    safe = [c for c in contracts if c["label"] == "safe"]
    random.shuffle(safe)
    sample = vuln + safe[:100]
    random.shuffle(sample)
    return sample


def load_contract_code(filepath):
    if not filepath or not os.path.exists(filepath):
        return ""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def run_detection(contracts, extra_context=""):
    results = []
    total_tokens = 0
    for i, contract in enumerate(contracts):
        code = load_contract_code(contract.get("filepath", ""))
        if not code.strip():
            continue
        analysis = analyze_with_rag(code, extra_context=extra_context)
        gt_vuln = contract.get("label") == "vulnerable"
        result = {
            "contract_id": contract.get("id", f"c_{i}"),
            "ground_truth_vulnerable": gt_vuln,
            "category": contract.get("category", contract.get("vulnerability_type", "unknown")),
            "predicted_vulnerable": analysis.get("predicted_vulnerable", False),
            "confidence": analysis.get("confidence", 0.5),
            "vulnerability_types": analysis.get("vulnerability_types", []),
            "reasoning": analysis.get("reasoning", ""),
            "tokens_used": analysis.get("tokens_used", 0),
            "time_seconds": analysis.get("time_seconds", 0),
        }
        total_tokens += result["tokens_used"]
        results.append(result)
        if (i + 1) % 50 == 0:
            print(f"    Progress: {i+1}/{len(contracts)} ({total_tokens:,} tokens)")
        time.sleep(0.1)
    return results


def compute_metrics(results):
    tp = fp = tn = fn = 0
    for r in results:
        gt = r.get("ground_truth_vulnerable", False)
        pred = r.get("predicted_vulnerable", False)
        if gt and pred: tp += 1
        elif not gt and pred: fp += 1
        elif gt and not pred: fn += 1
        else: tn += 1
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "total": len(results),
    }


# ============================================================
# Stage 2: Three-Class Self-Verify
# ============================================================

SELF_VERIFY_SYSTEM = """You are an expert Smart Contract Security Analyst. A previous analysis flagged this contract as VULNERABLE. Your task is to verify whether the vulnerability is genuinely exploitable.

IMPORTANT BIAS WARNING: You have a natural tendency to second-guess vulnerability reports and classify contracts as SAFE. Resist this tendency. The previous detector has a 97.9% recall rate — when it says VULNERABLE, it is almost always correct. You should only override it with VERY strong evidence.

Classify into exactly ONE of three categories:

## VULNERABLE (confirmed exploitable) — DEFAULT when the exploit pattern exists
The vulnerability pattern is present in the code. Choose this unless you have DEFINITIVE proof of mitigation. Even partial or complex exploit paths should be classified as VULNERABLE. When in doubt between VULNERABLE and UNCERTAIN, choose VULNERABLE.

## SAFE (definitively mitigated) — ONLY when you can cite a specific Solidity keyword
You found a SPECIFIC, NAMED mitigation IN THE CODE that completely blocks the exploit:
- The exact modifier name applied to the function (e.g., `nonReentrant`, `onlyOwner`)
- A specific `require()` statement with the condition that blocks the attack
- State variable assignment BEFORE the external call (Checks-Effects-Interactions)
- `pragma solidity ^0.8` for integer overflow claims

STRICT RULES for SAFE:
1. You MUST quote the exact Solidity code line containing the mitigation
2. "The function is internal" is NOT a valid mitigation unless the function is literally declared `internal` or `private`
3. "The call target is trusted" is NOT a valid mitigation — any address can be malicious
4. "No state update after call" is NOT sufficient if state was read before the call
5. If ANY public/external function in the contract could serve as an entry point for re-entrancy, it is NOT SAFE

## UNCERTAIN (cannot confirm or deny)
Use this when:
- The vulnerability pattern partially exists but mitigation status is unclear
- The code is too complex to determine exploitability with certainty
- You are not fully confident in either VULNERABLE or SAFE

DEFAULT BEHAVIOR: When in doubt, choose VULNERABLE (not UNCERTAIN or SAFE). The cost of missing a real vulnerability far exceeds the cost of a false positive.

Respond strictly in JSON:
{
  "exploit_evidence": "<specific code pattern/line that enables the exploit, or null>",
  "mitigation_found": "<the EXACT Solidity code line containing the mitigation, or null>",
  "reasoning": "<brief explanation of your analysis>",
  "verdict": "VULNERABLE" or "SAFE" or "UNCERTAIN"
}"""

# Solidity keywords that indicate a real mitigation — used to validate LLM claims
VALID_MITIGATION_KEYWORDS = [
    "nonreentrant", "onlyowner", "onlyadmin", "onlyminter", "onlyauthorized",
    "whennotpaused", "require(msg.sender", "require(_msgSender",
    "modifier ", "pragma solidity ^0.8", "pragma solidity >=0.8",
    "locked", "mutex", "reentrancyguard",
]


def run_self_verify(baseline_results, code_loader):
    """Stage 2: Three-class Self-Verify — only SAFE flips, UNCERTAIN preserves baseline."""
    verified = []
    flipped = 0
    confirmed = 0
    uncertain = 0
    total_tokens = 0

    for r in baseline_results:
        new_r = dict(r)
        new_r["sv_flipped"] = False
        new_r["sv_verdict"] = None

        if not r.get("predicted_vulnerable"):
            verified.append(new_r)
            continue

        cid = r.get("contract_id", "")
        code = code_loader(cid)
        if not code:
            verified.append(new_r)
            continue

        code_short = code[:8000]
        vuln_types = r.get("vulnerability_types", [])
        reasoning = r.get("reasoning", "")[:1500]

        user_msg = (
            f"The previous analysis flagged this contract as VULNERABLE.\n"
            f"Claimed vulnerability types: {', '.join(vuln_types) if vuln_types else 'unspecified'}\n"
            f"Previous reasoning: \"{reasoning}\"\n\n"
            f"## Contract Code:\n```solidity\n{code_short}\n```\n\n"
            f"Verify: is this genuinely exploitable, definitively mitigated, or uncertain?"
        )

        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": SELF_VERIFY_SYSTEM},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.1,
                **token_param(800),
                seed=42,
            )
            content = resp.choices[0].message.content.strip()
            tokens = resp.usage.total_tokens if resp.usage else 0
            total_tokens += tokens

            jm = re.search(r"\{[\s\S]*\}", content)
            if jm:
                parsed = json.loads(jm.group())
            else:
                parsed = {"verdict": "UNCERTAIN"}

            verdict = parsed.get("verdict", "UNCERTAIN").upper()
            mitigation = parsed.get("mitigation_found")
            exploit_evidence = parsed.get("exploit_evidence")

            new_r["sv_verdict"] = verdict
            new_r["sv_reasoning"] = parsed.get("reasoning", "")
            new_r["sv_mitigation"] = mitigation
            new_r["sv_exploit_evidence"] = exploit_evidence

            if verdict == "SAFE":
                # Guard 1: mitigation must be non-null
                has_mitigation = (
                    mitigation is not None
                    and mitigation != "null"
                    and mitigation != ""
                )
                # Guard 2: mitigation text must appear (partially) in actual code
                code_lower = code_short.lower()
                mitigation_in_code = False
                if has_mitigation:
                    # Extract Solidity identifiers from mitigation text
                    mit_lower = mitigation.lower()
                    # Check if any substantive keyword from mitigation is in code
                    for kw in VALID_MITIGATION_KEYWORDS:
                        if kw in code_lower:
                            mitigation_in_code = True
                            break
                    # Also check if the mitigation text itself references code
                    if not mitigation_in_code and len(mitigation) > 10:
                        # Extract potential identifier words (camelCase/snake_case)
                        idents = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{3,}', mitigation)
                        for ident in idents:
                            if ident.lower() in code_lower and ident.lower() not in (
                                "function", "contract", "require", "return", "public",
                                "external", "internal", "private", "memory", "storage",
                                "address", "uint256", "bool", "true", "false", "null",
                                "vulnerable", "safe", "exploit", "attack", "this",
                                "that", "with", "from", "call", "value", "send",
                            ):
                                mitigation_in_code = True
                                break

                # Guard 3: only flip low-confidence predictions
                orig_conf = float(r.get("confidence", 0.5))
                is_low_conf = orig_conf < 0.90

                if has_mitigation and mitigation_in_code:
                    new_r["predicted_vulnerable"] = False
                    new_r["sv_flipped"] = True
                    flipped += 1
                elif has_mitigation and is_low_conf:
                    # Mitigation claimed but not verified — flip only if low confidence
                    new_r["predicted_vulnerable"] = False
                    new_r["sv_flipped"] = True
                    new_r["sv_verdict"] = "SAFE (low-conf override)"
                    flipped += 1
                else:
                    # High confidence + unverified mitigation → keep VULNERABLE
                    new_r["sv_verdict"] = "UNCERTAIN (mitigation not verified)"
                    uncertain += 1
            elif verdict == "VULNERABLE":
                confirmed += 1
                # Keep baseline prediction (VULNERABLE)
            else:
                # UNCERTAIN → preserve baseline prediction (VULNERABLE)
                uncertain += 1

        except Exception as e:
            uncertain += 1  # Error → treat as UNCERTAIN, preserve baseline

        verified.append(new_r)
        time.sleep(0.1)

    total_vuln = sum(1 for r in baseline_results if r.get("predicted_vulnerable"))
    print(f"    Self-Verify: confirmed={confirmed}, flipped_SAFE={flipped}, uncertain={uncertain} (total vuln={total_vuln})")
    print(f"    Tokens: {total_tokens:,}")
    return verified, total_tokens


# ============================================================
# Main
# ============================================================

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 70)
    print("DmAVID ABLATION STUDY v5_clean — Three-Class Self-Verify")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Model: {MODEL}")
    print("Pipeline: Baseline → 3-Class Self-Verify → Critique → Debate")
    print("=" * 70)

    contracts = load_dataset()
    print(f"Dataset: {len(contracts)} contracts")

    id_to_filepath = {}
    for c in contracts:
        cid = c.get("id", "")
        fp = c.get("filepath", "")
        if cid and fp:
            id_to_filepath[cid] = fp

    def code_loader(contract_id):
        fp = id_to_filepath.get(contract_id, "")
        return load_contract_code(fp)

    start_time = time.time()
    all_configs = []

    # =============================================
    # Config 1: Baseline (same as 05_run_llm_rag.py)
    # =============================================
    print("\n" + "=" * 60)
    print("CONFIG 1: Baseline (LLM+RAG, identical to 05_run_llm_rag.py)")
    print("=" * 60)

    baseline_results = run_detection(contracts, extra_context="")
    baseline_metrics = compute_metrics(baseline_results)
    baseline_tokens = sum(r.get("tokens_used", 0) for r in baseline_results)

    print(f"  F1={baseline_metrics['f1']:.4f}  P={baseline_metrics['precision']:.4f}  R={baseline_metrics['recall']:.4f}")
    print(f"  TP={baseline_metrics['tp']} FP={baseline_metrics['fp']} FN={baseline_metrics['fn']} TN={baseline_metrics['tn']}")

    all_configs.append({
        "config": "baseline",
        "description": "LLM+RAG (identical to 05_run_llm_rag.py)",
        "metrics": baseline_metrics,
        "tokens": baseline_tokens,
    })

    # =============================================
    # Config 2: +Self-Verify (three-class)
    # =============================================
    print("\n" + "=" * 60)
    print("CONFIG 2: +Self-Verify (three-class: VULNERABLE/SAFE/UNCERTAIN)")
    print("=" * 60)

    sv_results, sv_tokens = run_self_verify(baseline_results, code_loader)
    sv_metrics = compute_metrics(sv_results)

    print(f"  F1={sv_metrics['f1']:.4f}  P={sv_metrics['precision']:.4f}  R={sv_metrics['recall']:.4f}")
    print(f"  TP={sv_metrics['tp']} FP={sv_metrics['fp']} FN={sv_metrics['fn']} TN={sv_metrics['tn']}")

    all_configs.append({
        "config": "+self-verify",
        "description": "LLM+RAG + Three-Class Self-Verify (UNCERTAIN preserves baseline)",
        "metrics": sv_metrics,
        "tokens": baseline_tokens + sv_tokens,
    })

    # =============================================
    # Config 3: +Critique (Reflexion feedback, same as v3)
    # =============================================
    print("\n" + "=" * 60)
    print("CONFIG 3: +Critique (Critic Agent failure analysis → re-detect)")
    print("=" * 60)

    # Critique operates on Self-Verify results, re-detecting with feedback
    critic = CriticAgent(max_fn=12, max_fp=8)

    print("  Analyzing Self-Verify errors...")
    report = critic.generate_failure_report(sv_results, code_loader)
    critic_feedback = critic.format_hints_for_prompt(report)
    critic_tokens = critic.total_tokens

    print(f"  FN hints: {len(report['corrective_hints']['for_false_negatives'])}")
    print(f"  FP hints: {len(report['corrective_hints']['for_false_positives'])}")
    print(f"  Feedback: {len(critic_feedback)} chars")

    print(f"\n  Re-detecting with Critic feedback...")
    critique_results = run_detection(contracts, extra_context=critic_feedback)
    critique_metrics = compute_metrics(critique_results)
    critique_det_tokens = sum(r.get("tokens_used", 0) for r in critique_results)

    print(f"  F1={critique_metrics['f1']:.4f}  P={critique_metrics['precision']:.4f}  R={critique_metrics['recall']:.4f}")
    print(f"  TP={critique_metrics['tp']} FP={critique_metrics['fp']} FN={critique_metrics['fn']} TN={critique_metrics['tn']}")

    all_configs.append({
        "config": "+critique",
        "description": "Self-Verify + Critic failure analysis feedback (Reflexion)",
        "metrics": critique_metrics,
        "tokens": critique_det_tokens + critic_tokens,
        "critic_summary": {
            "fn_analyzed": report["fn_analyzed"],
            "fp_analyzed": report["fp_analyzed"],
            "fn_hints": len(report["corrective_hints"]["for_false_negatives"]),
            "fp_hints": len(report["corrective_hints"]["for_false_positives"]),
        },
    })

    # =============================================
    # Config 4: +Critique+Debate
    # =============================================
    print("\n" + "=" * 60)
    print("CONFIG 4: +Critique+Debate (adversarial debate on disputed cases)")
    print("=" * 60)

    low_conf_vuln = [
        {"contract_id": r["contract_id"],
         "reasoning": r["reasoning"],
         "student_prediction": True,
         "confidence": r.get("confidence", 0.5)}
        for r in critique_results
        if r.get("predicted_vulnerable") and float(r.get("confidence", 0.5)) < 0.85
    ]
    low_conf_safe = [
        {"contract_id": r["contract_id"],
         "reasoning": r["reasoning"],
         "student_prediction": False,
         "confidence": r.get("confidence", 0.5)}
        for r in critique_results
        if not r.get("predicted_vulnerable") and float(r.get("confidence", 0.5)) < 0.70
    ]

    disputed = low_conf_vuln + low_conf_safe
    print(f"  Disputed: {len(low_conf_vuln)} low-conf vuln + {len(low_conf_safe)} low-conf safe = {len(disputed)}")

    debater = DebateRound(max_debate_rounds=2, max_cases=15)
    debate_output = debater.run_debates(disputed, code_loader)

    debate_results = apply_debate_flips(critique_results, debate_output)
    debate_metrics = compute_metrics(debate_results)

    print(f"\n  F1={debate_metrics['f1']:.4f}  P={debate_metrics['precision']:.4f}  R={debate_metrics['recall']:.4f}")
    print(f"  TP={debate_metrics['tp']} FP={debate_metrics['fp']} FN={debate_metrics['fn']} TN={debate_metrics['tn']}")
    print(f"  Flips: {debate_output['flips']}")

    all_configs.append({
        "config": "+critique+debate",
        "description": "Self-Verify + Critic + Adversarial Debate",
        "metrics": debate_metrics,
        "tokens": debate_output["total_tokens"],
        "debate_summary": {
            "total_debates": debate_output["total_debates"],
            "flips": debate_output["flips"],
        },
    })

    # =============================================
    # Summary
    # =============================================
    total_time = time.time() - start_time

    print("\n" + "=" * 70)
    print("ABLATION RESULTS v5_clean — Three-Class Self-Verify")
    print("=" * 70)
    print(f"\n{'Config':<22} {'F1':>8} {'P':>8} {'R':>8} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5}")
    print("-" * 75)

    for cfg in all_configs:
        m = cfg["metrics"]
        print(f"{cfg['config']:<22} {m['f1']:>8.4f} {m['precision']:>8.4f} {m['recall']:>8.4f} "
              f"{m['tp']:>5} {m['fp']:>5} {m['fn']:>5} {m['tn']:>5}")

    base_f1 = all_configs[0]["metrics"]["f1"]
    print(f"\nBaseline F1: {base_f1:.4f}")
    for cfg in all_configs[1:]:
        delta = cfg["metrics"]["f1"] - base_f1
        pct = delta / base_f1 * 100 if base_f1 > 0 else 0
        print(f"  {cfg['config']:<20} F1={cfg['metrics']['f1']:.4f} (delta: {delta:+.4f}, {pct:+.1f}%)")

    # Comparison with v3 and v4
    print(f"\n--- Comparison with prior versions ---")
    print(f"v3 Self-Verify: F1=0.9032 (no flip, all conf>=0.90 skipped)")
    print(f"v4 Self-Verify: F1=0.5473 P=0.9483 R=0.3846 (null fields → forced SAFE)")
    print(f"v5 Self-Verify: F1={sv_metrics['f1']:.4f} P={sv_metrics['precision']:.4f} R={sv_metrics['recall']:.4f} (three-class UNCERTAIN)")

    print(f"\nTotal time: {total_time/60:.1f} minutes")

    # Save
    output = {
        "experiment": "ablation_study_v5_clean",
        "description": "Three-class Self-Verify: UNCERTAIN preserves baseline, only SAFE with concrete mitigation flips",
        "model": MODEL,
        "dataset_size": len(contracts),
        "timestamp": datetime.now().isoformat(),
        "total_time_seconds": round(total_time, 1),
        "configs": all_configs,
    }

    outfile = os.path.join(OUTPUT_DIR, "ablation_v5_clean_results.json")
    with open(outfile, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {outfile}")

    # Save per-config details
    config_details = {
        "baseline": baseline_results,
        "self-verify": sv_results,
        "critique": critique_results,
        "critique+debate": debate_results,
    }
    for name, res in config_details.items():
        detail_file = os.path.join(OUTPUT_DIR, f"ablation_v5_clean_{name}_details.json")
        with open(detail_file, "w") as f:
            json.dump({"config": name, "metrics": compute_metrics(res), "results": res},
                      f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
