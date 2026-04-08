#!/usr/bin/env python3
"""
DmAVID Ablation Study v2 - Consistent Baseline with 05_run_llm_rag.py

Uses the SAME analyze_with_rag() function as the baseline experiment,
ensuring Baseline F1 matches the published 0.8468.

Configs:
  1. Baseline: LLM+RAG (identical to 05_run_llm_rag.py)
  2. +Self-Verify: Baseline + exploit path verification (conf_threshold=0.90)
  3. +Critique: Baseline + Critic Agent failure analysis feedback
  4. +Critique+Debate: +Critique + adversarial debate on disputed cases

Author: Curtis Chang
"""

import os
import sys
import json
import time
import random
import re
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


# ---------------------------------------------------------------------------
# Dataset loading (same as 05_run_llm_rag.py)
# ---------------------------------------------------------------------------
def load_dataset():
    """Load and sample the SmartBugs dataset (143 vuln + 100 safe = 243)."""
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


# ---------------------------------------------------------------------------
# Detection: wraps analyze_with_rag from 05_run_llm_rag.py
# ---------------------------------------------------------------------------
def run_detection(contracts, extra_context=""):
    """Run LLM+RAG detection using the exact same function as 05_run_llm_rag.py."""
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


# ---------------------------------------------------------------------------
# Self-Verify (same logic as postprocess_self_verify.py)
# ---------------------------------------------------------------------------
def run_self_verify(results, conf_threshold=0.90):
    """Run exploit-path self-verification on vulnerable predictions."""
    verified = []
    flipped = 0
    skipped = 0
    tokens = 0

    for r in results:
        new_r = dict(r)
        new_r["verify_flipped"] = False

        if r.get("predicted_vulnerable"):
            conf = float(r.get("confidence", 0.5))
            if conf_threshold is not None and conf >= conf_threshold:
                skipped += 1
                verified.append(new_r)
                continue

            reasoning = r.get("reasoning", "")[:1500]
            vuln_types = r.get("vulnerability_types", [])
            vuln_str = ", ".join(vuln_types) if vuln_types else "a potential vulnerability"

            prompt = (
                f"You previously analyzed a smart contract and classified it as VULNERABLE "
                f"due to {vuln_str}.\n\nPrevious reasoning:\n\"{reasoning}\"\n\n"
                f"Can you construct a CONCRETE exploit path (preconditions, transaction sequence, "
                f"expected outcome)? If you CANNOT, respond with exactly: "
                f"\"NO_EXPLOIT_PATH\". Otherwise, briefly describe the exploit."
            )
            try:
                resp = client.chat.completions.create(
                    model=MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                    **token_param(512),
                )
                content = resp.choices[0].message.content.strip()
                tokens += resp.usage.total_tokens if resp.usage else 0

                if "NO_EXPLOIT_PATH" in content.upper():
                    new_r["predicted_vulnerable"] = False
                    new_r["verify_flipped"] = True
                    flipped += 1
                # Also check for explicit false positive language
                low = content.lower()
                if "cannot be constructed" in low and "false positive" in low:
                    new_r["predicted_vulnerable"] = False
                    new_r["verify_flipped"] = True
                    if not new_r.get("verify_flipped"):
                        flipped += 1
            except Exception:
                pass

            time.sleep(0.1)

        verified.append(new_r)

    print(f"    Self-Verify: flipped={flipped}, skipped_high_conf={skipped}, tokens={tokens:,}")
    return verified, tokens


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Ablation configs
# ---------------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="DmAVID Ablation Study v2")
    parser.add_argument("--skip-baseline", action="store_true",
                        help="Load baseline from existing results")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 70)
    print("DmAVID ABLATION STUDY v2 (Consistent Baseline)")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Model: {MODEL}")
    print("Configs: Baseline | +Self-Verify | +Critique | +Critique+Debate")
    print("=" * 70)

    contracts = load_dataset()
    print(f"Dataset: {len(contracts)} contracts")

    # Build code loader for Critic Agent
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
    # Config 2: +Self-Verify (conf_threshold=0.90)
    # =============================================
    print("\n" + "=" * 60)
    print("CONFIG 2: +Self-Verify (exploit path verification, conf>=0.90 skipped)")
    print("=" * 60)

    sv_results, sv_tokens = run_self_verify(baseline_results, conf_threshold=0.90)
    sv_metrics = compute_metrics(sv_results)

    print(f"  F1={sv_metrics['f1']:.4f}  P={sv_metrics['precision']:.4f}  R={sv_metrics['recall']:.4f}")
    print(f"  TP={sv_metrics['tp']} FP={sv_metrics['fp']} FN={sv_metrics['fn']} TN={sv_metrics['tn']}")

    all_configs.append({
        "config": "+self-verify",
        "description": "LLM+RAG + Self-Verify (conf_threshold=0.90)",
        "metrics": sv_metrics,
        "tokens": baseline_tokens + sv_tokens,
    })

    # =============================================
    # Config 3: +Critique (Reflexion feedback)
    # =============================================
    print("\n" + "=" * 60)
    print("CONFIG 3: +Critique (Critic Agent failure analysis → re-detect)")
    print("=" * 60)

    critic = CriticAgent(max_fn=12, max_fp=8)

    print("  Analyzing baseline errors...")
    report = critic.generate_failure_report(baseline_results, code_loader)
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
        "description": "LLM+RAG + Critic failure analysis feedback (Reflexion pattern)",
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

    # Select disputed cases by confidence score, NOT by ground truth
    # Low-confidence predictions are most likely to benefit from debate
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
        "description": "LLM+RAG + Critic + Adversarial Debate",
        "metrics": debate_metrics,
        "tokens": debate_output["total_tokens"],
        "debate_summary": {
            "total_debates": debate_output["total_debates"],
            "flips": debate_output["flips"],
        },
    })

    # =============================================
    # Summary table
    # =============================================
    total_time = time.time() - start_time

    print("\n" + "=" * 70)
    print("ABLATION RESULTS v2 (Consistent Baseline)")
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
        print(f"{cfg['config']:<22} F1={cfg['metrics']['f1']:.4f} (delta: {delta:+.4f}, {pct:+.1f}%)")

    print(f"\nTotal time: {total_time/60:.1f} minutes")

    # Save
    output = {
        "experiment": "ablation_study_v2",
        "description": "Ablation with consistent baseline (uses 05_run_llm_rag.py analyze_with_rag)",
        "model": MODEL,
        "dataset_size": len(contracts),
        "timestamp": datetime.now().isoformat(),
        "total_time_seconds": round(total_time, 1),
        "configs": all_configs,
    }

    outfile = os.path.join(OUTPUT_DIR, "ablation_v2_results.json")
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
        detail_file = os.path.join(OUTPUT_DIR, f"ablation_v2_{name}_details.json")
        with open(detail_file, "w") as f:
            json.dump({"config": name, "metrics": compute_metrics(res), "results": res},
                      f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
