#!/usr/bin/env python3
"""
DmAVID Ablation Study - Critic + Debate vs Baselines.

Runs the following configurations and compares:
  1. Baseline: LLM+RAG (single pass, no iteration)
  2. +Critique: LLM+RAG + Critic feedback (2 rounds)
  3. +Debate: LLM+RAG + Critic + Debate (2 rounds + debate on disputed cases)

Uses the same 243-contract SmartBugs dataset for fair comparison.
Results go to experiments/ablation/ for the thesis.

Author: Curtis Chang
"""

import os
import sys
import json
import time
import random
from datetime import datetime
from typing import Dict, List, Any

BASE_DIR = os.environ.get("DMAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))
sys.path.insert(0, os.path.join(BASE_DIR, "agents"))

from _model_compat import token_param
from openai import OpenAI
from critic_agent import CriticAgent
from debate_round import DebateRound, apply_debate_flips

random.seed(42)
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
client = OpenAI()

DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments/ablation")


# Import detection and metric utilities from critic_loop
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from importlib import import_module

# We re-use functions from 30_critic_loop
import importlib.util
spec = importlib.util.spec_from_file_location(
    "critic_loop", os.path.join(BASE_DIR, "scripts", "30_critic_loop.py"))
critic_loop_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(critic_loop_mod)

load_dataset = critic_loop_mod.load_dataset
load_contract_code = critic_loop_mod.load_contract_code
run_student_detection = critic_loop_mod.run_student_detection
compute_metrics = critic_loop_mod.compute_metrics


def run_baseline(contracts, code_loader):
    """Config 1: Single-pass LLM+RAG detection."""
    print("\n" + "=" * 60)
    print("CONFIG 1: Baseline (LLM+RAG, single pass)")
    print("=" * 60)

    results = run_student_detection(contracts, critic_feedback="")
    metrics = compute_metrics(results)
    tokens = sum(r.get("tokens_used", 0) for r in results)

    print(f"  F1={metrics['f1']:.4f}  P={metrics['precision']:.4f}  R={metrics['recall']:.4f}")
    print(f"  TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']} TN={metrics['tn']}")
    print(f"  Tokens: {tokens:,}")

    return {
        "config": "baseline",
        "description": "LLM+RAG single pass",
        "metrics": metrics,
        "tokens": tokens,
        "results": results,
    }


def run_with_critique(contracts, code_loader, baseline_results):
    """Config 2: LLM+RAG + Critic feedback (2 rounds)."""
    print("\n" + "=" * 60)
    print("CONFIG 2: +Critique (LLM+RAG + Critic feedback, 2 rounds)")
    print("=" * 60)

    critic = CriticAgent(max_fn=12, max_fp=8)
    total_tokens = 0

    # Round 1: Use baseline results as the starting point
    print("\n  Round 1: Analyzing baseline errors...")
    report = critic.generate_failure_report(baseline_results, code_loader)
    critic_feedback = critic.format_hints_for_prompt(report)
    total_tokens += critic.total_tokens

    print(f"  Generated {len(report['corrective_hints']['for_false_negatives'])} FN hints, "
          f"{len(report['corrective_hints']['for_false_positives'])} FP hints")

    # Round 2: Re-detect with Critic feedback
    print(f"\n  Round 2: Re-detecting with {len(critic_feedback)} chars of feedback...")
    results_r2 = run_student_detection(contracts, critic_feedback=critic_feedback)
    student_tokens = sum(r.get("tokens_used", 0) for r in results_r2)
    total_tokens += student_tokens

    metrics_r2 = compute_metrics(results_r2)
    print(f"  F1={metrics_r2['f1']:.4f}  P={metrics_r2['precision']:.4f}  R={metrics_r2['recall']:.4f}")
    print(f"  TP={metrics_r2['tp']} FP={metrics_r2['fp']} FN={metrics_r2['fn']} TN={metrics_r2['tn']}")
    print(f"  Total tokens: {total_tokens:,}")

    return {
        "config": "+critique",
        "description": "LLM+RAG + Critic failure analysis feedback (2 rounds)",
        "metrics": metrics_r2,
        "tokens": total_tokens,
        "critic_report_summary": {
            "fn_analyzed": report["fn_analyzed"],
            "fp_analyzed": report["fp_analyzed"],
            "fn_hints": len(report["corrective_hints"]["for_false_negatives"]),
            "fp_hints": len(report["corrective_hints"]["for_false_positives"]),
        },
        "results": results_r2,
    }


def run_with_debate(contracts, code_loader, critique_results):
    """Config 3: LLM+RAG + Critic + Debate on disputed cases."""
    print("\n" + "=" * 60)
    print("CONFIG 3: +Debate (LLM+RAG + Critic + Adversarial Debate)")
    print("=" * 60)

    # Identify disputed cases from critique results
    fn_cases = [
        {"contract_id": r["contract_id"], "category": r["category"],
         "reasoning": r["reasoning"], "is_fn": True}
        for r in critique_results
        if r.get("ground_truth_vulnerable") and not r.get("predicted_vulnerable")
    ]
    fp_cases = [
        {"contract_id": r["contract_id"], "category": r.get("category", "unknown"),
         "reasoning": r["reasoning"], "is_fn": False}
        for r in critique_results
        if not r.get("ground_truth_vulnerable") and r.get("predicted_vulnerable")
    ]

    disputed = fn_cases + fp_cases
    print(f"  Disputed cases: {len(fn_cases)} FN + {len(fp_cases)} FP = {len(disputed)}")

    # Run debates
    debater = DebateRound(max_debate_rounds=2, max_cases=15)
    debate_output = debater.run_debates(disputed, code_loader)

    # Apply flips
    updated_results = apply_debate_flips(critique_results, debate_output)
    metrics_debate = compute_metrics(updated_results)

    print(f"\n  After debate:")
    print(f"  F1={metrics_debate['f1']:.4f}  P={metrics_debate['precision']:.4f}  R={metrics_debate['recall']:.4f}")
    print(f"  TP={metrics_debate['tp']} FP={metrics_debate['fp']} FN={metrics_debate['fn']} TN={metrics_debate['tn']}")
    print(f"  Flips: {debate_output['flips']}")
    print(f"  Debate tokens: {debate_output['total_tokens']:,}")

    return {
        "config": "+debate",
        "description": "LLM+RAG + Critic + Adversarial Debate (Red Team vs Student)",
        "metrics": metrics_debate,
        "tokens": debate_output["total_tokens"],
        "debate_summary": {
            "total_debates": debate_output["total_debates"],
            "flips": debate_output["flips"],
        },
        "results": updated_results,
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="DmAVID Ablation Study")
    parser.add_argument("--skip-baseline", action="store_true",
                        help="Load baseline from existing results instead of re-running")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 70)
    print("DmAVID ABLATION STUDY")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Model: {MODEL}")
    print("Configs: Baseline | +Critique | +Debate")
    print("=" * 70)

    # Load dataset
    contracts = load_dataset()
    print(f"Dataset: {len(contracts)} contracts")

    # Build code loader
    id_to_filepath = {}
    for c in contracts:
        cid = c.get("id", "")
        fp = c.get("filepath", "")
        if cid and fp:
            id_to_filepath[cid] = fp

    def code_loader(contract_id):
        fp = id_to_filepath.get(contract_id, "")
        return load_contract_code(fp)

    # Run configs
    start_time = time.time()

    # Config 1: Baseline
    baseline = run_baseline(contracts, code_loader)

    # Config 2: +Critique (uses baseline results as input)
    critique = run_with_critique(contracts, code_loader, baseline["results"])

    # Config 3: +Debate (uses critique results as input)
    debate = run_with_debate(contracts, code_loader, critique["results"])

    total_time = time.time() - start_time

    # Ablation table
    print("\n" + "=" * 70)
    print("ABLATION RESULTS")
    print("=" * 70)
    print(f"\n{'Config':<20} {'F1':>8} {'P':>8} {'R':>8} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5} {'Tokens':>10}")
    print("-" * 80)

    configs = [baseline, critique, debate]
    for cfg in configs:
        m = cfg["metrics"]
        print(f"{cfg['config']:<20} {m['f1']:>8.4f} {m['precision']:>8.4f} {m['recall']:>8.4f} "
              f"{m['tp']:>5} {m['fp']:>5} {m['fn']:>5} {m['tn']:>5} {cfg['tokens']:>10,}")

    # Improvement analysis
    base_f1 = baseline["metrics"]["f1"]
    crit_f1 = critique["metrics"]["f1"]
    debate_f1 = debate["metrics"]["f1"]

    print(f"\nBaseline F1:       {base_f1:.4f}")
    print(f"+Critique F1:      {crit_f1:.4f} (delta: {crit_f1 - base_f1:+.4f})")
    print(f"+Debate F1:        {debate_f1:.4f} (delta: {debate_f1 - base_f1:+.4f})")
    print(f"\nTotal time: {total_time/60:.1f} minutes")

    # Save results (without full per-contract results to keep file size small)
    output = {
        "experiment": "ablation_study",
        "description": "Ablation: Baseline vs +Critique vs +Debate",
        "model": MODEL,
        "dataset_size": len(contracts),
        "timestamp": datetime.now().isoformat(),
        "total_time_seconds": round(total_time, 1),
        "configs": [],
    }

    for cfg in configs:
        cfg_summary = {k: v for k, v in cfg.items() if k != "results"}
        output["configs"].append(cfg_summary)

    outfile = os.path.join(OUTPUT_DIR, "ablation_results.json")
    with open(outfile, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {outfile}")

    # Also save per-config detailed results
    for cfg in configs:
        detail_file = os.path.join(OUTPUT_DIR, f"ablation_{cfg['config'].strip('+')}_details.json")
        with open(detail_file, "w") as f:
            json.dump({
                "config": cfg["config"],
                "metrics": cfg["metrics"],
                "results": cfg["results"],
            }, f, indent=2, ensure_ascii=False)
        print(f"Saved: {detail_file}")


if __name__ == "__main__":
    main()
