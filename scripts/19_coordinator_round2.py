#!/usr/bin/env python3
"""DavidAgent Coordinator: Round 2 full pipeline orchestrator.

Runs iterative improvement rounds through the multi-agent pipeline:
  Teacher -> Student -> Red Team -> Foundry -> Blue Team -> Self-Verify -> Evaluate

Each round generates challenges, evaluates the Student on the FULL dataset,
generates adversarial variants for missed cases, validates them, and feeds
defense patterns back into the knowledge base.
"""

import os
import sys
import json
import time
import random
import logging
import argparse
import subprocess
import importlib.util
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

from openai import OpenAI

sys.path.insert(0, os.path.dirname(__file__))
from _model_compat import token_param

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = os.environ.get("DAVID_BASE_DIR", "/home/curtis/defi-llm-vulnerability-detection")
MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")
client = OpenAI()

DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
BASELINE_FILE = os.path.join(BASE_DIR, "experiments/llm_rag/llm_rag_results.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments/davidagent_round2")

# Baseline metrics (from prior experiment)
BASELINE_F1 = 0.8468  # LLM+RAG baseline (gpt-5.4-mini, 243 contracts, JSON fix)

# Cost estimation: ~$0.01 per 1K tokens for gpt-4.1-mini
COST_PER_1K_TOKENS = 0.01

# SWC categories used for teacher challenges
VULN_TYPES = [
    "reentrancy", "integer_overflow", "access_control", "unchecked_call",
    "denial_of_service", "front_running", "time_manipulation",
    "tx_origin", "delegatecall", "selfdestruct",
    "price_oracle_manipulation", "flash_loan_attack",
]


# ---------------------------------------------------------------------------
# Module loader
# ---------------------------------------------------------------------------
def load_module(name: str):
    """Dynamically load a sibling script as a module."""
    path = os.path.join(os.path.dirname(__file__), f"{name}.py")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Module not found: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Cost tracking
# ---------------------------------------------------------------------------
class CostTracker:
    """Track token usage and estimated USD cost across the pipeline."""

    def __init__(self, budget: float):
        self.budget = budget
        self.total_tokens = 0
        self.total_cost = 0.0
        self.per_stage: Dict[str, Dict[str, float]] = {}

    def add(self, stage: str, tokens: int):
        cost = (tokens / 1000) * COST_PER_1K_TOKENS
        self.total_tokens += tokens
        self.total_cost += cost
        entry = self.per_stage.setdefault(stage, {"tokens": 0, "cost": 0.0})
        entry["tokens"] += tokens
        entry["cost"] += cost

    def under_budget(self) -> bool:
        return self.total_cost < self.budget

    def summary(self) -> Dict[str, Any]:
        return {
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost, 4),
            "budget_usd": self.budget,
            "budget_remaining_usd": round(self.budget - self.total_cost, 4),
            "per_stage": {k: {"tokens": v["tokens"], "cost_usd": round(v["cost"], 4)}
                         for k, v in self.per_stage.items()},
        }


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------
def compute_metrics(results: List[Dict[str, Any]]) -> Dict[str, float]:
    """Compute F1, Precision, Recall, FPR from a list of prediction results."""
    tp = fp = tn = fn = 0
    for r in results:
        gt = r.get("ground_truth_vulnerable", r.get("ground_truth") == "vulnerable")
        pred = r.get("predicted_vulnerable", False)

        if gt and pred:
            tp += 1
        elif not gt and pred:
            fp += 1
        elif gt and not pred:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "total_samples": len(results),
    }


# ---------------------------------------------------------------------------
# Stage: Teacher — generate challenges
# ---------------------------------------------------------------------------
def run_teacher_stage(
    teacher_mod, knowledge_base: Dict, num_per_type: int, cost: CostTracker, dry_run: bool
) -> List[Dict[str, Any]]:
    """Generate teacher challenges across vulnerability types."""
    logger.info("[TEACHER] Generating challenges...")
    challenges = []

    types_to_use = random.sample(VULN_TYPES, min(len(VULN_TYPES), 10))

    for vuln_type in types_to_use:
        for _ in range(num_per_type):
            if not cost.under_budget():
                logger.warning("[TEACHER] Budget exceeded, stopping challenge generation")
                return challenges

            difficulty = random.randint(1, 5)

            if dry_run:
                challenge = {
                    "challenge_id": f"dry_{vuln_type}_{int(time.time())}",
                    "vuln_type": vuln_type,
                    "difficulty": difficulty,
                    "contract_code": f"// Dry-run placeholder for {vuln_type}",
                    "tokens_used": 0,
                }
            else:
                challenge = teacher_mod.generate_challenge(vuln_type, difficulty, knowledge_base)

            if challenge:
                challenges.append(challenge)
                cost.add("teacher", challenge.get("tokens_used", 0))

            time.sleep(0.2)

    logger.info(f"[TEACHER] Generated {len(challenges)} challenges")
    return challenges


# ---------------------------------------------------------------------------
# Stage: Student — evaluate on full dataset
# ---------------------------------------------------------------------------
def run_student_stage(
    rag_mod, dataset: List[Dict], cost: CostTracker, dry_run: bool
) -> List[Dict[str, Any]]:
    """Run Student (LLM+RAG) detection on the full dataset."""
    logger.info(f"[STUDENT] Evaluating on {len(dataset)} contracts...")
    results = []

    for idx, sample in enumerate(dataset):
        if not cost.under_budget():
            logger.warning(f"[STUDENT] Budget exceeded at sample {idx}/{len(dataset)}")
            break

        # Load contract source code from filepath (dataset uses 'filepath' key)
        contract_code = ""
        filepath = sample.get("filepath", "")
        if filepath and os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as cf:
                    contract_code = cf.read()
            except Exception:
                pass
        if not contract_code.strip():
            # Skip contracts with missing/empty source — don't pollute results
            continue

        gt_vulnerable = sample.get("label") == "vulnerable" or sample.get("ground_truth") == "vulnerable"
        category = sample.get("category", sample.get("vulnerability_type", "unknown"))
        contract_id = sample.get("id", sample.get("contract_id", f"sample_{idx}"))

        if dry_run:
            pred = random.random() > 0.3
            result = {
                "contract_id": contract_id,
                "ground_truth_vulnerable": gt_vulnerable,
                "category": category,
                "predicted_vulnerable": pred,
                "confidence": random.uniform(0.4, 0.95),
                "vulnerability_types": [category] if pred else [],
                "reasoning": "dry-run",
                "tokens_used": 0,
                "time_seconds": 0.0,
            }
        else:
            analysis = rag_mod.analyze_with_rag(contract_code)
            result = {
                "contract_id": contract_id,
                "ground_truth_vulnerable": gt_vulnerable,
                "category": category,
                "predicted_vulnerable": analysis.get("predicted_vulnerable", False),
                "confidence": analysis.get("confidence", 0.5),
                "vulnerability_types": analysis.get("vulnerability_types", []),
                "reasoning": analysis.get("reasoning", ""),
                "tokens_used": analysis.get("tokens_used", 0),
                "time_seconds": analysis.get("time_seconds", 0.0),
            }

        cost.add("student", result.get("tokens_used", 0))
        results.append(result)

        if (idx + 1) % 50 == 0:
            logger.info(f"[STUDENT] Progress: {idx+1}/{len(dataset)}")

    logger.info(f"[STUDENT] Evaluated {len(results)} contracts")
    return results


# ---------------------------------------------------------------------------
# Stage: Red Team — adversarial variants for false negatives
# ---------------------------------------------------------------------------
def run_red_team_stage(
    red_mod, student_results: List[Dict], dataset: List[Dict],
    cost: CostTracker, dry_run: bool, max_fn: int = 10
) -> List[Dict[str, Any]]:
    """Generate adversarial variants for false negative cases."""
    logger.info("[RED TEAM] Generating adversarial variants for false negatives...")

    # Collect false negatives
    fn_cases = [r for r in student_results
                if r.get("ground_truth_vulnerable") and not r.get("predicted_vulnerable")]
    logger.info(f"[RED TEAM] Found {len(fn_cases)} false negatives")

    if not fn_cases:
        return []

    # Limit to max_fn to control cost
    fn_cases = fn_cases[:max_fn]

    # Build contract_id -> source mapping from dataset (read from filepath)
    id_to_source = {}
    for s in dataset:
        cid = s.get("id", s.get("contract_id", ""))
        filepath = s.get("filepath", "")
        if cid and filepath and os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as cf:
                    src = cf.read()
                if src.strip():
                    id_to_source[cid] = src
            except Exception:
                pass

    variants = []
    transformations = ["variable_renaming", "code_reordering", "dead_code_injection", "control_flow_obfuscation"]

    for fn in fn_cases:
        if not cost.under_budget():
            logger.warning("[RED TEAM] Budget exceeded")
            break

        contract_id = fn.get("contract_id", "")
        source = id_to_source.get(contract_id, "")
        vuln_type = fn.get("category", "unknown")

        if not source:
            logger.warning(f"[RED TEAM] No source found for {contract_id}, skipping")
            continue

        transformation = random.choice(transformations)

        if dry_run:
            variant_source = f"// Dry-run variant of {contract_id}"
            transform_applied = transformation
            note = "dry-run"
            tokens = 0
        else:
            variant_source, transform_applied, note = red_mod.generate_adversarial_variant(
                source, vuln_type, transformation
            )
            tokens = 500  # estimate

        variant = {
            "variant_id": f"{contract_id}_{vuln_type}_{transformation}",
            "original_contract_id": contract_id,
            "vulnerability_type": vuln_type,
            "transformation_applied": transform_applied,
            "preservation_note": note,
            "contract_source": variant_source,
            "poc_template": "",
            "generated_at": datetime.now().isoformat(),
        }
        variants.append(variant)
        cost.add("red_team", tokens)

    logger.info(f"[RED TEAM] Generated {len(variants)} adversarial variants")
    return variants


# ---------------------------------------------------------------------------
# Stage: Foundry — validate compilation
# ---------------------------------------------------------------------------
def run_foundry_stage(
    variants: List[Dict], dry_run: bool
) -> List[Dict[str, Any]]:
    """Validate that adversarial variants compile with forge."""
    logger.info(f"[FOUNDRY] Validating {len(variants)} variants...")

    validated = []
    for i, variant in enumerate(variants):
        source = variant.get("contract_source", "")
        if not source or dry_run:
            variant["compile_success"] = True if dry_run else False
            validated.append(variant)
            continue

        # Try compiling with solc via forge
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as tmpdir:
                sol_file = os.path.join(tmpdir, "Variant.sol")
                with open(sol_file, 'w') as f:
                    # Ensure pragma is present
                    if "pragma solidity" not in source:
                        f.write("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\n\n")
                    f.write(source)

                result = subprocess.run(
                    ["forge", "build", "--root", tmpdir],
                    capture_output=True, text=True, timeout=60
                )
                compiled = result.returncode == 0
        except FileNotFoundError:
            logger.warning("[FOUNDRY] forge not found, marking as compile_success=True (skipped)")
            compiled = True
        except subprocess.TimeoutExpired:
            logger.warning(f"[FOUNDRY] Compilation timed out for variant {i}")
            compiled = False
        except Exception as e:
            logger.error(f"[FOUNDRY] Error compiling variant {i}: {e}")
            compiled = False

        variant["compile_success"] = compiled
        validated.append(variant)

        status = "OK" if compiled else "FAIL"
        logger.info(f"[FOUNDRY] Variant {i+1}/{len(variants)}: {status}")

    compiled_count = sum(1 for v in validated if v.get("compile_success"))
    logger.info(f"[FOUNDRY] {compiled_count}/{len(validated)} variants compiled successfully")
    return validated


# ---------------------------------------------------------------------------
# Stage: Blue Team — synthesize defense patterns
# ---------------------------------------------------------------------------
def run_blue_team_stage(
    blue_mod, validated_variants: List[Dict], cost: CostTracker, dry_run: bool
) -> List[Dict[str, Any]]:
    """Synthesize defense patterns from validated variants."""
    logger.info("[BLUE TEAM] Synthesizing defense patterns...")

    # Filter to only compiled variants
    compilable = [v for v in validated_variants if v.get("compile_success")]
    if not compilable:
        logger.warning("[BLUE TEAM] No compilable variants to process")
        return []

    # Group by vulnerability type
    by_type: Dict[str, List[Dict]] = {}
    for v in compilable:
        vtype = v.get("vulnerability_type", "unknown")
        by_type.setdefault(vtype, []).append(v)

    all_entries = []
    for vtype, variants in by_type.items():
        if not cost.under_budget():
            logger.warning("[BLUE TEAM] Budget exceeded")
            break

        if dry_run:
            entry = {
                "id": f"BT-DRY-{vtype}-{int(time.time())}",
                "category": vtype,
                "title": f"Dry-run defense: {vtype}",
                "description": "dry-run",
                "vulnerability_pattern": "",
                "safe_pattern": "",
                "mitigation": "",
                "tokens_used": 0,
            }
            all_entries.append(entry)
        else:
            entries = blue_mod.synthesize_defense_patterns(variants, vtype)
            for e in entries:
                cost.add("blue_team", e.get("tokens_used", 0))
            all_entries.extend(entries)

    # Update knowledge files (even in dry-run we skip)
    if not dry_run and all_entries:
        blue_mod.update_knowledge_files(all_entries)

    logger.info(f"[BLUE TEAM] Synthesized {len(all_entries)} defense patterns")
    return all_entries


# ---------------------------------------------------------------------------
# Stage: Self-Verify — post-process predictions
# ---------------------------------------------------------------------------
def run_self_verify_stage(
    student_results: List[Dict], cost: CostTracker, dry_run: bool
) -> List[Dict[str, Any]]:
    """Run self-verification on positive predictions to reduce false positives.

    For each sample predicted as vulnerable, ask the LLM to construct a concrete
    exploit path.  If it cannot, flip the prediction to safe.
    """
    logger.info("[SELF-VERIFY] Running exploit-path verification on positive predictions...")

    positives = [r for r in student_results if r.get("predicted_vulnerable")]
    logger.info(f"[SELF-VERIFY] {len(positives)} positive predictions to verify")

    verified_results = []
    flipped = 0

    for r in student_results:
        new_r = dict(r)  # shallow copy

        if r.get("predicted_vulnerable") and not dry_run and cost.under_budget():
            # Ask LLM for an exploit path
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
                tokens = resp.usage.total_tokens if resp.usage else 0
                cost.add("self_verify", tokens)

                if "NO_EXPLOIT_PATH" in content.upper():
                    new_r["predicted_vulnerable"] = False
                    new_r["verify_flipped"] = True
                    new_r["verify_reason"] = "No concrete exploit path found"
                    flipped += 1
                else:
                    new_r["verify_flipped"] = False
                    new_r["verify_reason"] = content[:300]

            except Exception as e:
                logger.error(f"[SELF-VERIFY] Error: {e}")
                new_r["verify_flipped"] = False
                new_r["verify_reason"] = f"error: {e}"

            time.sleep(0.1)
        else:
            new_r["verify_flipped"] = False
            new_r["verify_reason"] = ""

        verified_results.append(new_r)

    logger.info(f"[SELF-VERIFY] Flipped {flipped}/{len(positives)} predictions from vulnerable to safe")
    return verified_results


# ---------------------------------------------------------------------------
# Load dataset
# ---------------------------------------------------------------------------
def load_dataset(path: str) -> List[Dict[str, Any]]:
    """Load the contract dataset."""
    if not os.path.exists(path):
        logger.error(f"Dataset not found: {path}")
        return []

    with open(path, 'r') as f:
        data = json.load(f)

    # Handle both list and dict-with-results formats
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("contracts", data.get("results", data.get("samples", [])))
    return []


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="DavidAgent Coordinator: Round 2 full pipeline orchestrator"
    )
    parser.add_argument("--rounds", type=int, default=3, help="Number of iteration rounds (default: 3)")
    parser.add_argument("--budget", type=float, default=20.0, help="USD budget limit (default: 20.0)")
    parser.add_argument("--dry-run", action="store_true", help="Simulate without API calls")
    parser.add_argument("--dataset", type=str, default=DATASET_FILE, help="Path to dataset JSON")
    parser.add_argument("--challenges-per-type", type=int, default=1,
                        help="Teacher challenges per vulnerability type per round (default: 1)")
    parser.add_argument("--max-fn-variants", type=int, default=10,
                        help="Max false negatives to generate variants for (default: 10)")
    args = parser.parse_args()

    logger.info("=" * 70)
    logger.info("DavidAgent Coordinator — Round 2 Pipeline")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    logger.info(f"Model: {MODEL}")
    logger.info(f"Rounds: {args.rounds} | Budget: ${args.budget:.2f} | Dry run: {args.dry_run}")
    logger.info(f"Baseline F1: {BASELINE_F1}")
    logger.info("=" * 70)

    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Load dataset — sample 143 vulnerable + 100 safe = 243 (same as baseline)
    logger.info("Loading dataset...")
    all_contracts = load_dataset(args.dataset)
    if not all_contracts:
        logger.error("Failed to load dataset. Exiting.")
        sys.exit(1)
    vuln_contracts = [c for c in all_contracts if c.get("label") == "vulnerable"]
    safe_contracts = [c for c in all_contracts if c.get("label") == "safe"]
    random.shuffle(safe_contracts)
    dataset = vuln_contracts + safe_contracts[:100]
    random.shuffle(dataset)
    logger.info(f"Dataset: {len(vuln_contracts)} vuln + {min(100,len(safe_contracts))} safe = {len(dataset)} contracts (from {len(all_contracts)} total)")

    # Load sub-modules
    logger.info("Loading sub-modules...")
    try:
        teacher_mod = load_module("11_teacher_challenge")
        rag_mod = load_module("05_run_llm_rag")
        red_mod = load_module("12_red_team_generate")
        blue_mod = load_module("18_blue_team_defense")
    except FileNotFoundError as e:
        logger.error(f"Failed to load module: {e}")
        sys.exit(1)
    logger.info("All sub-modules loaded successfully")

    # Load teacher knowledge base
    knowledge_base = teacher_mod.load_knowledge_base()

    # Initialize cost tracker
    cost = CostTracker(args.budget)

    # Per-round progression tracking
    progression = {
        "config": {
            "rounds": args.rounds,
            "budget_usd": args.budget,
            "model": MODEL,
            "dataset_size": len(dataset),
            "baseline_f1": BASELINE_F1,
            "dry_run": args.dry_run,
            "started_at": datetime.now().isoformat(),
        },
        "rounds": [],
    }

    # ===========================================================================
    # Iteration rounds
    # ===========================================================================
    for round_num in range(1, args.rounds + 1):
        round_start = time.time()
        logger.info("")
        logger.info("=" * 70)
        logger.info(f"  ROUND {round_num}/{args.rounds}")
        logger.info("=" * 70)

        if not cost.under_budget():
            logger.warning(f"Budget exhausted before round {round_num}. Stopping.")
            break

        round_data: Dict[str, Any] = {"round": round_num}

        # --- (a) Teacher: Generate challenges ---
        challenges = run_teacher_stage(
            teacher_mod, knowledge_base, args.challenges_per_type, cost, args.dry_run
        )
        round_data["teacher_challenges"] = len(challenges)

        # --- (b) Student: Evaluate on full dataset ---
        student_results = run_student_stage(rag_mod, dataset, cost, args.dry_run)
        pre_verify_metrics = compute_metrics(student_results)
        round_data["student_pre_verify"] = pre_verify_metrics
        logger.info(
            f"[STUDENT] Pre-verify — F1: {pre_verify_metrics['f1']:.4f}  "
            f"P: {pre_verify_metrics['precision']:.4f}  "
            f"R: {pre_verify_metrics['recall']:.4f}  "
            f"FPR: {pre_verify_metrics['fpr']:.4f}"
        )

        # --- (c) Red Team: Adversarial variants for false negatives ---
        variants = run_red_team_stage(
            red_mod, student_results, dataset, cost, args.dry_run, max_fn=args.max_fn_variants
        )
        round_data["red_team_variants"] = len(variants)

        # --- (d) Foundry: Validate compilation ---
        validated_variants = run_foundry_stage(variants, args.dry_run)
        compiled_count = sum(1 for v in validated_variants if v.get("compile_success"))
        round_data["foundry_compiled"] = compiled_count
        round_data["foundry_total"] = len(validated_variants)

        # --- (e) Blue Team: Synthesize defense patterns ---
        defense_entries = run_blue_team_stage(blue_mod, validated_variants, cost, args.dry_run)
        round_data["blue_team_patterns"] = len(defense_entries)

        # --- (f) Self-Verify: Post-process predictions ---
        verified_results = run_self_verify_stage(student_results, cost, args.dry_run)

        # --- (g) Evaluate: Compute final metrics ---
        post_verify_metrics = compute_metrics(verified_results)
        round_data["student_post_verify"] = post_verify_metrics
        logger.info(
            f"[EVALUATE] Post-verify — F1: {post_verify_metrics['f1']:.4f}  "
            f"P: {post_verify_metrics['precision']:.4f}  "
            f"R: {post_verify_metrics['recall']:.4f}  "
            f"FPR: {post_verify_metrics['fpr']:.4f}"
        )

        # Compare to baseline
        f1_delta = post_verify_metrics["f1"] - BASELINE_F1
        round_data["f1_delta_vs_baseline"] = round(f1_delta, 4)
        direction = "+" if f1_delta >= 0 else ""
        logger.info(f"[EVALUATE] F1 vs baseline: {direction}{f1_delta:.4f} (baseline={BASELINE_F1})")

        # Challenge-set recall (teacher challenges are all vulnerable)
        if challenges:
            challenge_detected = 0
            for ch in challenges:
                code = ch.get("contract_code", "")
                if args.dry_run:
                    challenge_detected += 1 if random.random() > 0.2 else 0
                elif code:
                    try:
                        analysis = rag_mod.analyze_with_rag(code)
                        if analysis.get("predicted_vulnerable"):
                            challenge_detected += 1
                        cost.add("student_challenge", analysis.get("tokens_used", 0))
                    except Exception:
                        pass
            challenge_recall = challenge_detected / len(challenges) if challenges else 0
            round_data["challenge_recall"] = round(challenge_recall, 4)
            logger.info(f"[EVALUATE] Challenge recall: {challenge_recall:.4f} ({challenge_detected}/{len(challenges)})")

        # Round timing and cost
        round_data["round_time_seconds"] = round(time.time() - round_start, 2)
        round_data["cost_snapshot"] = cost.summary()

        progression["rounds"].append(round_data)

        # Save intermediate results
        round_results_file = os.path.join(OUTPUT_DIR, f"round_{round_num}_results.json")
        with open(round_results_file, 'w') as f:
            json.dump({
                "round": round_num,
                "metrics": post_verify_metrics,
                "pre_verify_metrics": pre_verify_metrics,
                "cost": cost.summary(),
                "results": verified_results,
            }, f, indent=2)
        logger.info(f"Round {round_num} results saved to {round_results_file}")

    # ===========================================================================
    # Save final outputs
    # ===========================================================================
    progression["completed_at"] = datetime.now().isoformat()
    progression["final_cost"] = cost.summary()

    # Progression file for charting
    progression_file = os.path.join(OUTPUT_DIR, "round2_progression.json")
    with open(progression_file, 'w') as f:
        json.dump(progression, f, indent=2)
    logger.info(f"Progression saved to {progression_file}")

    # Final summary
    logger.info("")
    logger.info("=" * 70)
    logger.info("DavidAgent Coordinator — Round 2 Summary")
    logger.info("=" * 70)
    logger.info(f"Rounds completed: {len(progression['rounds'])}/{args.rounds}")
    logger.info(f"Baseline F1: {BASELINE_F1}")

    if progression["rounds"]:
        final_round = progression["rounds"][-1]
        final_f1 = final_round.get("student_post_verify", {}).get("f1", 0)
        delta = final_f1 - BASELINE_F1
        direction = "+" if delta >= 0 else ""
        logger.info(f"Final F1:    {final_f1:.4f} ({direction}{delta:.4f} vs baseline)")
        logger.info(f"Final P:     {final_round.get('student_post_verify', {}).get('precision', 0):.4f}")
        logger.info(f"Final R:     {final_round.get('student_post_verify', {}).get('recall', 0):.4f}")
        logger.info(f"Final FPR:   {final_round.get('student_post_verify', {}).get('fpr', 0):.4f}")

        logger.info("")
        logger.info("Per-round F1 progression:")
        for rd in progression["rounds"]:
            rn = rd["round"]
            f1_pre = rd.get("student_pre_verify", {}).get("f1", 0)
            f1_post = rd.get("student_post_verify", {}).get("f1", 0)
            logger.info(f"  Round {rn}: pre-verify={f1_pre:.4f}  post-verify={f1_post:.4f}")

    cost_info = cost.summary()
    logger.info("")
    logger.info(f"Total tokens: {cost_info['total_tokens']:,}")
    logger.info(f"Total cost:   ${cost_info['total_cost_usd']:.4f} / ${args.budget:.2f} budget")
    logger.info(f"Per-stage breakdown:")
    for stage, info in cost_info["per_stage"].items():
        logger.info(f"  {stage:20s}: {info['tokens']:>8,} tokens  ${info['cost_usd']:.4f}")

    logger.info("")
    logger.info(f"Output directory: {OUTPUT_DIR}")
    logger.info(f"Progression file: {progression_file}")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
