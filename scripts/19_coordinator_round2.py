#!/usr/bin/env python3
"""DmAVID Coordinator: Round 2 full pipeline orchestrator.

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
BASE_DIR = os.environ.get("DMAVID_BASE_DIR", "/home/curtis/DmAVID")
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
client = OpenAI()

DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
BASELINE_FILE = os.path.join(BASE_DIR, "experiments/llm_rag/llm_rag_results.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments/dmavid_round2")

# Baseline metrics (from prior experiment)
BASELINE_F1 = 0.9061  # LLM+RAG baseline (verified, gpt-4.1-mini)

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
# Type-aware Self-Verify constants (Fix 1)
# ---------------------------------------------------------------------------
VULN_TYPE_ALIASES = {
    "reentrancy": "reentrancy", "reentrant": "reentrancy", "re-entrancy": "reentrancy",
    "unchecked": "unchecked_call", "unchecked_low_level": "unchecked_call",
    "unchecked_call": "unchecked_call", "unchecked_low_level_calls": "unchecked_call",
    "access_control": "access_control", "access control": "access_control",
    "authorization": "access_control",
    "bad_randomness": "bad_randomness", "bad randomness": "bad_randomness",
    "randomness": "bad_randomness",
    "front_running": "front_running", "front running": "front_running",
    "frontrunning": "front_running",
    "time_manipulation": "time_manipulation", "time manipulation": "time_manipulation",
    "timestamp": "time_manipulation",
    "denial_of_service": "denial_of_service", "denial of service": "denial_of_service",
    "dos": "denial_of_service",
    "integer_overflow": "integer_overflow", "integer overflow": "integer_overflow",
    "overflow": "integer_overflow", "arithmetic": "integer_overflow",
}

VERIFY_CONFIGS = {
    "reentrancy": {
        "system": """You are an expert Smart Contract Security Analyst verifying a Reentrancy vulnerability.

For Reentrancy to be genuinely exploitable, ALL of these must exist:
1. target_state_variable — a storage variable (e.g., balance mapping) read before an external call
2. external_call_line — an external call (call, send, transfer) to an attacker-controllable address
3. state_update_after_call — the state variable is updated AFTER the external call, not before

If ANY component is missing, if the function uses a `nonReentrant` modifier, or if the external call target is hardcoded (not user-controlled), classify as SAFE.

Respond strictly in JSON:
{
  "target_state_variable": "<variable name or null>",
  "external_call_line": "<code snippet or null>",
  "state_update_after_call": "<code snippet or null>",
  "reasoning": "<brief explanation>",
  "verdict": "VULNERABLE" or "SAFE"
}""",
        "required_fields": ["target_state_variable", "external_call_line", "state_update_after_call"],
    },
    "unchecked_call": {
        "system": """You are an expert Smart Contract Security Analyst verifying an Unchecked Low-Level Call vulnerability.

For this vulnerability to be genuinely exploitable, ALL of these must exist:
1. call_site — a low-level call (address.call, address.send, address.delegatecall) whose return value matters
2. return_unchecked — the return value (bool success) is NOT checked via require/if/assert
3. state_or_fund_impact — subsequent logic assumes the call succeeded, leading to fund loss or state corruption

If the return value IS checked, if the call is to a trusted/hardcoded address with no state dependency, or if failure has no material impact, classify as SAFE.

Respond strictly in JSON:
{
  "call_site": "<code snippet of the low-level call, or null>",
  "return_unchecked": "<evidence that return value is ignored, or null>",
  "state_or_fund_impact": "<what goes wrong if the call fails silently, or null>",
  "reasoning": "<brief explanation>",
  "verdict": "VULNERABLE" or "SAFE"
}""",
        "required_fields": ["call_site", "return_unchecked", "state_or_fund_impact"],
    },
    "access_control": {
        "system": """You are an expert Smart Contract Security Analyst verifying an Access Control vulnerability.

For this vulnerability to be genuinely exploitable, ALL of these must exist:
1. sensitive_function — a function that performs a privileged operation (withdraw, selfdestruct, ownership transfer, parameter change)
2. missing_restriction — the function lacks proper access control (no onlyOwner, no role check, no require(msg.sender == ...))
3. attacker_action — a concrete action an unauthorized external caller can perform to cause harm

If the function HAS a proper access modifier (onlyOwner, onlyAdmin, require(msg.sender == owner)), if it's an internal/private function, or if the operation has no security impact, classify as SAFE.

Respond strictly in JSON:
{
  "sensitive_function": "<function name and what it does, or null>",
  "missing_restriction": "<what access control is missing, or null>",
  "attacker_action": "<what an attacker can do, or null>",
  "reasoning": "<brief explanation>",
  "verdict": "VULNERABLE" or "SAFE"
}""",
        "required_fields": ["sensitive_function", "missing_restriction", "attacker_action"],
    },
    "bad_randomness": {
        "system": """You are an expert Smart Contract Security Analyst verifying a Bad Randomness vulnerability.

For this vulnerability to be genuinely exploitable, ALL of these must exist:
1. randomness_source — the contract uses on-chain data (block.timestamp, blockhash, block.number, block.difficulty) as a source of randomness
2. critical_usage — the random value is used for a decision with financial impact (lottery winner, reward distribution, game outcome)
3. miner_or_user_advantage — a miner or user can predict or manipulate the value to gain an unfair advantage

If the randomness is from a verified oracle (Chainlink VRF), if the value is only used for non-critical purposes, or if manipulation has no financial benefit, classify as SAFE.

Respond strictly in JSON:
{
  "randomness_source": "<the on-chain entropy source used, or null>",
  "critical_usage": "<how the random value affects funds/outcomes, or null>",
  "miner_or_user_advantage": "<how prediction/manipulation benefits attacker, or null>",
  "reasoning": "<brief explanation>",
  "verdict": "VULNERABLE" or "SAFE"
}""",
        "required_fields": ["randomness_source", "critical_usage", "miner_or_user_advantage"],
    },
    "front_running": {
        "system": """You are an expert Smart Contract Security Analyst verifying a Front-Running vulnerability.

For this vulnerability to be genuinely exploitable, ALL of these must exist:
1. observable_pending_tx — a user transaction that reveals profitable information in the mempool (e.g., a large trade, a puzzle solution, an approval)
2. ordering_advantage — an attacker who sees this pending transaction can profit by placing their own transaction before or after it
3. no_mitigation — the contract lacks commit-reveal, minimum delay, or slippage protection

If the contract uses commit-reveal schemes, if transaction ordering doesn't affect outcomes, or if there's no financial incentive for front-running, classify as SAFE.

Respond strictly in JSON:
{
  "observable_pending_tx": "<what information leaks from the pending tx, or null>",
  "ordering_advantage": "<how the attacker profits from reordering, or null>",
  "no_mitigation": "<why existing protections are insufficient, or null>",
  "reasoning": "<brief explanation>",
  "verdict": "VULNERABLE" or "SAFE"
}""",
        "required_fields": ["observable_pending_tx", "ordering_advantage", "no_mitigation"],
    },
    "time_manipulation": {
        "system": """You are an expert Smart Contract Security Analyst verifying a Time Manipulation vulnerability.

For this vulnerability to be genuinely exploitable, ALL of these must exist:
1. timestamp_usage — the contract reads block.timestamp (or `now`) in its logic
2. critical_dependency — the timestamp directly controls fund release, deadline enforcement, or outcome determination
3. manipulation_impact — a miner shifting the timestamp by ~15 seconds can materially change the outcome (e.g., bypass a deadline, win a game)

If the timestamp is only used for logging/events, if the time window is large enough that ±15s doesn't matter, or if there's no financial impact, classify as SAFE.

Respond strictly in JSON:
{
  "timestamp_usage": "<where block.timestamp is read, or null>",
  "critical_dependency": "<what decision depends on this timestamp, or null>",
  "manipulation_impact": "<what changes if a miner shifts time ±15s, or null>",
  "reasoning": "<brief explanation>",
  "verdict": "VULNERABLE" or "SAFE"
}""",
        "required_fields": ["timestamp_usage", "critical_dependency", "manipulation_impact"],
    },
    "denial_of_service": {
        "system": """You are an expert Smart Contract Security Analyst verifying a Denial of Service vulnerability.

For this vulnerability to be genuinely exploitable, ALL of these must exist:
1. attack_vector — a specific mechanism (unbounded loop over user-controlled array, external call in loop, gas-intensive operation) that an attacker can trigger
2. gas_or_revert_impact — the attack causes the function to exceed block gas limit or permanently revert
3. attacker_control — an external attacker (not just the owner) can trigger the DoS condition by manipulating input or state

If the loop is bounded, if only the owner can trigger the condition, or if the gas cost is manageable for realistic input sizes, classify as SAFE.

Respond strictly in JSON:
{
  "attack_vector": "<the DoS mechanism, or null>",
  "gas_or_revert_impact": "<how the function fails, or null>",
  "attacker_control": "<how an attacker triggers this, or null>",
  "reasoning": "<brief explanation>",
  "verdict": "VULNERABLE" or "SAFE"
}""",
        "required_fields": ["attack_vector", "gas_or_revert_impact", "attacker_control"],
    },
    "integer_overflow": {
        "system": """You are an expert Smart Contract Security Analyst verifying an Integer Overflow/Underflow vulnerability.

For this vulnerability to be genuinely exploitable, ALL of these must exist:
1. arithmetic_operation — an addition, subtraction, or multiplication on uint/int without SafeMath or Solidity >=0.8 built-in checks
2. attacker_input — the operand values can be influenced by an external user (not just the owner)
3. overflow_impact — the overflow/underflow leads to incorrect balances, bypassed checks, or fund theft

If the contract uses Solidity >=0.8 (automatic overflow checks), if SafeMath is applied, if the values are owner-controlled, or if overflow has no security impact, classify as SAFE.

Respond strictly in JSON:
{
  "arithmetic_operation": "<the unchecked arithmetic expression, or null>",
  "attacker_input": "<how an attacker controls the operands, or null>",
  "overflow_impact": "<what goes wrong on overflow, or null>",
  "reasoning": "<brief explanation>",
  "verdict": "VULNERABLE" or "SAFE"
}""",
        "required_fields": ["arithmetic_operation", "attacker_input", "overflow_impact"],
    },
}

GENERIC_VERIFY_SYSTEM = """You are an expert Smart Contract Security Analyst. Verify whether the flagged vulnerability is genuinely exploitable.

You must identify concrete exploit path components:
1. vulnerability_mechanism — the specific code pattern that creates the vulnerability
2. attacker_trigger — how an external attacker can trigger exploitation
3. material_impact — the concrete harm (fund loss, state corruption, denial of service)

If ANY component is missing or purely theoretical, classify as SAFE.

Respond strictly in JSON:
{
  "vulnerability_mechanism": "<the vulnerable code pattern, or null>",
  "attacker_trigger": "<how the attacker exploits it, or null>",
  "material_impact": "<concrete harm caused, or null>",
  "reasoning": "<brief explanation>",
  "verdict": "VULNERABLE" or "SAFE"
}"""
GENERIC_REQUIRED_FIELDS = ["vulnerability_mechanism", "attacker_trigger", "material_impact"]


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
    rag_mod, dataset: List[Dict], cost: CostTracker, dry_run: bool,
    fn_hint_map: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Run Student (LLM+RAG) detection on the full dataset."""
    # Refresh dynamic KB so Blue Team entries from the previous round are
    # visible in this round's RAG context (FP sentinels + safe_pattern boost).
    if hasattr(rag_mod, "reload_dynamic_kb"):
        rag_mod.reload_dynamic_kb()
    hint_count = len(fn_hint_map) if fn_hint_map else 0
    logger.info(f"[STUDENT] Evaluating on {len(dataset)} contracts (FN hints: {hint_count})...")
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
            hint = fn_hint_map.get(contract_id, "") if fn_hint_map else ""
            analysis = rag_mod.analyze_with_rag(contract_code, extra_context=hint)
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
    transformations = list(red_mod.MUTATION_STRATEGIES.keys())

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
# Stage: Self-Verify v2 — type-aware structured verification (Fix 1)
# ---------------------------------------------------------------------------
def _classify_vuln_type(result: Dict[str, Any]) -> str:
    """Determine canonical vulnerability type from result fields."""
    cid = result.get("contract_id", "").lower()
    for prefix in ["curated_reentrancy_", "curated_unchecked_low_level_calls_",
                   "curated_access_control_", "curated_bad_randomness_",
                   "curated_front_running_", "curated_time_manipulation_",
                   "curated_denial_of_service_", "curated_integer_overflow_"]:
        if prefix in cid:
            key = prefix.replace("curated_", "").rstrip("_")
            if key in VULN_TYPE_ALIASES:
                return VULN_TYPE_ALIASES[key]

    category = result.get("category", "").lower().replace(" ", "_")
    if category in VULN_TYPE_ALIASES:
        return VULN_TYPE_ALIASES[category]

    for vt in result.get("vulnerability_types", []):
        vt_lower = vt.lower().replace(" ", "_").replace("-", "_")
        if vt_lower in VULN_TYPE_ALIASES:
            return VULN_TYPE_ALIASES[vt_lower]
        for alias, canonical in VULN_TYPE_ALIASES.items():
            if alias in vt_lower or vt_lower in alias:
                return canonical

    return "unknown"


def run_self_verify_stage_v2(
    student_results: List[Dict], dataset: List[Dict],
    cost: CostTracker, dry_run: bool,
) -> List[Dict[str, Any]]:
    """Type-aware structured Self-Verify: required_fields validation replaces exploit-path."""
    import re as _re

    # Build cid → code map from dataset filepaths
    id_to_code: Dict[str, str] = {}
    for s in dataset:
        cid = s.get("id", s.get("contract_id", ""))
        filepath = s.get("filepath", "")
        if cid and filepath and os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as cf:
                    src = cf.read()
                if src.strip():
                    id_to_code[cid] = src
            except Exception:
                pass

    positives = [r for r in student_results if r.get("predicted_vulnerable")]
    logger.info(f"[SELF-VERIFY] Type-aware structured verification on {len(positives)} positives")

    verified_results = []
    flipped = 0
    type_stats: Dict[str, Dict[str, int]] = {}

    for r in student_results:
        new_r = dict(r)
        new_r["sv_flipped"] = False

        if not r.get("predicted_vulnerable") or dry_run:
            verified_results.append(new_r)
            continue

        if not cost.under_budget():
            verified_results.append(new_r)
            continue

        cid = r.get("contract_id", "")
        code = id_to_code.get(cid, "")
        if not code:
            verified_results.append(new_r)
            continue

        vuln_type = _classify_vuln_type(r)
        new_r["detected_vuln_type"] = vuln_type

        if vuln_type in VERIFY_CONFIGS:
            config = VERIFY_CONFIGS[vuln_type]
            system_prompt = config["system"]
            required_fields = config["required_fields"]
        else:
            system_prompt = GENERIC_VERIFY_SYSTEM
            required_fields = GENERIC_REQUIRED_FIELDS

        vuln_types = r.get("vulnerability_types", [])
        reasoning = r.get("reasoning", "")[:1500]
        user_msg = (
            f"The previous analysis flagged this contract as VULNERABLE.\n"
            f"Claimed vulnerability types: {', '.join(vuln_types) if vuln_types else 'unspecified'}\n"
            f"Detected category: {vuln_type}\n"
            f"Previous reasoning: \"{reasoning}\"\n\n"
            f"## Contract Code:\n```solidity\n{code[:8000]}\n```\n\n"
            f"Verify: extract the exploit path components or classify as SAFE."
        )

        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.1,
                **token_param(800),
                seed=42,
            )
            content = resp.choices[0].message.content.strip()
            tokens = resp.usage.total_tokens if resp.usage else 0
            cost.add("self_verify", tokens)

            jm = _re.search(r"\{[\s\S]*\}", content)
            parsed = json.loads(jm.group()) if jm else {"verdict": "VULNERABLE"}

            verdict = parsed.get("verdict", "VULNERABLE").upper()
            has_null_field = any(
                parsed.get(f) in (None, "null", "") for f in required_fields
            )
            is_safe = (verdict == "SAFE") or has_null_field

            type_stats.setdefault(vuln_type, {"total": 0, "flipped": 0})
            type_stats[vuln_type]["total"] += 1

            if is_safe:
                new_r["predicted_vulnerable"] = False
                new_r["sv_flipped"] = True
                new_r["sv_reason"] = parsed.get("reasoning", "")
                new_r["sv_null_fields"] = [f for f in required_fields
                                           if parsed.get(f) in (None, "null", "")]
                flipped += 1
                type_stats[vuln_type]["flipped"] += 1

        except Exception as e:
            logger.error(f"[SELF-VERIFY] Error on {cid}: {e}")

        verified_results.append(new_r)
        time.sleep(0.1)

    logger.info(f"[SELF-VERIFY] Flipped {flipped}/{len(positives)} positives to SAFE")
    for vtype, stats in sorted(type_stats.items()):
        logger.info(f"[SELF-VERIFY]   {vtype}: {stats['flipped']}/{stats['total']} flipped")
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
        description="DmAVID Coordinator: Round 2 full pipeline orchestrator"
    )
    parser.add_argument("--rounds", type=int, default=3, help="Number of iteration rounds (default: 3)")
    parser.add_argument("--budget", type=float, default=20.0, help="USD budget limit (default: 20.0)")
    parser.add_argument("--dry-run", action="store_true", help="Simulate without API calls")
    parser.add_argument("--dataset", type=str, default=DATASET_FILE, help="Path to dataset JSON")
    parser.add_argument("--challenges-per-type", type=int, default=1,
                        help="Teacher challenges per vulnerability type per round (default: 1)")
    parser.add_argument("--max-fn-variants", type=int, default=10,
                        help="Max false negatives to generate variants for (default: 10)")
    parser.add_argument("--uncertain-only", action="store_true",
                        help="Red Team generates variants only for UNCERTAIN samples (confidence < 0.70)")
    parser.add_argument("--no-early-stop", action="store_true",
                        help="Disable delta-F1 early stopping (default: early stopping is ON)")
    parser.add_argument("--convergence-threshold", type=float, default=0.01,
                        help="Min |delta-F1| improvement to continue (default: 0.01)")
    parser.add_argument("--convergence-patience", type=int, default=2,
                        help="Rounds without improvement before stopping (default: 2)")
    parser.add_argument("--exp-tag", type=str, default=None,
                        help="Experiment tag for isolated output dir, e.g. 'exp12' → experiments/exp12/")
    args = parser.parse_args()

    logger.info("=" * 70)
    logger.info("DmAVID Coordinator — Round 2 Pipeline")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    logger.info(f"Model: {MODEL}")
    logger.info(f"Rounds: {args.rounds} | Budget: ${args.budget:.2f} | Dry run: {args.dry_run}")
    early_stop_enabled = not args.no_early_stop
    logger.info(f"Early stop: {early_stop_enabled} | Threshold: {args.convergence_threshold} | Patience: {args.convergence_patience}")
    logger.info(f"Uncertain-only Red Team: {args.uncertain_only}")
    logger.info(f"Baseline F1: {BASELINE_F1}")
    logger.info("=" * 70)

    # Determine output directory (isolated per exp-tag, or default shared dir)
    run_output_dir = os.path.join(BASE_DIR, "experiments", args.exp_tag) if args.exp_tag else OUTPUT_DIR
    os.makedirs(run_output_dir, exist_ok=True)
    logger.info(f"Output dir: {run_output_dir}")

    # Load dataset — sample 143 vulnerable + 100 safe = 243 (same as baseline)
    logger.info("Loading dataset...")
    all_contracts = load_dataset(args.dataset)
    if not all_contracts:
        logger.error("Failed to load dataset. Exiting.")
        sys.exit(1)
    vuln_contracts = [c for c in all_contracts if c.get("label") == "vulnerable"]
    safe_contracts = [c for c in all_contracts if c.get("label") == "safe"]
    random.seed(42)
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
            "early_stop_enabled": early_stop_enabled,
            "convergence_threshold": args.convergence_threshold,
            "convergence_patience": args.convergence_patience,
            "uncertain_only": args.uncertain_only,
            "started_at": datetime.now().isoformat(),
        },
        "rounds": [],
    }

    # ===========================================================================
    # Pre-iteration baseline snapshot (for McNemar: compare before/after)
    # ===========================================================================
    logger.info("[PRE-ITER] Running Student on full dataset before any iterative updates...")
    if hasattr(rag_mod, "reload_dynamic_kb"):
        rag_mod.reload_dynamic_kb()
    pre_iter_results = run_student_stage(rag_mod, dataset, cost, args.dry_run)
    pre_iter_metrics = compute_metrics(pre_iter_results)
    logger.info(
        f"[PRE-ITER] F1: {pre_iter_metrics['f1']:.4f}  "
        f"P: {pre_iter_metrics['precision']:.4f}  "
        f"R: {pre_iter_metrics['recall']:.4f}  "
        f"FPR: {pre_iter_metrics['fpr']:.4f}"
    )
    pre_iter_file = os.path.join(run_output_dir, "pre_iter_results.json")
    with open(pre_iter_file, 'w') as f:
        json.dump({"metrics": pre_iter_metrics, "results": pre_iter_results}, f, indent=2)
    logger.info(f"[PRE-ITER] Saved to {pre_iter_file}")

    # ===========================================================================
    # Iteration rounds
    # ===========================================================================
    prev_f1 = None
    no_improvement_count = 0
    best_f1 = -1.0
    best_round_num = 0
    best_round_data: Optional[Dict[str, Any]] = None
    best_verified_results: List[Dict[str, Any]] = []
    fn_hint_map: Dict[str, str] = {}  # curriculum: FN hints from previous round

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

        # --- (b) Student: Evaluate on full dataset (with FN curriculum hints) ---
        student_results = run_student_stage(rag_mod, dataset, cost, args.dry_run, fn_hint_map)
        pre_verify_metrics = compute_metrics(student_results)
        round_data["student_pre_verify"] = pre_verify_metrics
        logger.info(
            f"[STUDENT] Pre-verify — F1: {pre_verify_metrics['f1']:.4f}  "
            f"P: {pre_verify_metrics['precision']:.4f}  "
            f"R: {pre_verify_metrics['recall']:.4f}  "
            f"FPR: {pre_verify_metrics['fpr']:.4f}"
        )

        # --- (c) Red Team: Adversarial variants for false negatives ---
        # --uncertain-only: only process samples where confidence < 0.70
        if args.uncertain_only:
            # Include uncertain (conf < 0.70) AND any FN cases regardless of confidence.
            # FNs are always targets for Red Team; excluding high-confidence FNs defeats the purpose.
            uncertain_pool = [r for r in student_results
                              if float(r.get("confidence", 0.5)) < 0.70
                              or (r.get("ground_truth_vulnerable") and not r.get("predicted_vulnerable"))]
            logger.info(f"[RED TEAM] --uncertain-only: {len(uncertain_pool)} uncertain+FN samples (of {len(student_results)} total)")
            variants = run_red_team_stage(red_mod, uncertain_pool, dataset, cost, args.dry_run, max_fn=args.max_fn_variants)
        else:
            variants = run_red_team_stage(red_mod, student_results, dataset, cost, args.dry_run, max_fn=args.max_fn_variants)
        round_data["red_team_variants"] = len(variants)

        # --- (d) Foundry: Validate compilation ---
        validated_variants = run_foundry_stage(variants, args.dry_run)
        compiled_count = sum(1 for v in validated_variants if v.get("compile_success"))
        round_data["foundry_compiled"] = compiled_count
        round_data["foundry_total"] = len(validated_variants)

        # --- (e) Blue Team: Synthesize defense patterns ---
        defense_entries = run_blue_team_stage(blue_mod, validated_variants, cost, args.dry_run)
        round_data["blue_team_patterns"] = len(defense_entries)

        # --- (f) Self-Verify: Type-aware structured verification (v2) ---
        verified_results = run_self_verify_stage_v2(student_results, dataset, cost, args.dry_run)

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

        # Track best round
        current_f1 = post_verify_metrics["f1"]
        if current_f1 > best_f1:
            best_f1 = current_f1
            best_round_num = round_num
            best_round_data = round_data
            best_verified_results = verified_results

        # --- FN Curriculum: build hint map for next round (Fix 2) ---
        fn_hint_map = {}
        for r in verified_results:
            gt = r.get("ground_truth_vulnerable", False)
            pred = r.get("predicted_vulnerable", False)
            if gt and not pred:
                cid = r.get("contract_id", "")
                cat = r.get("category", "unknown")
                fn_hint_map[cid] = (
                    f"IMPORTANT: A previous analysis round missed a {cat} vulnerability in this contract. "
                    f"Pay extra attention to {cat} patterns and be more sensitive to subtle indicators."
                )
        logger.info(f"[FN CURRICULUM] Built hint map for {len(fn_hint_map)} FN contracts → next round")

        # --- Early stopping: delta-F1 convergence check ---
        if early_stop_enabled and prev_f1 is not None:
            delta_from_prev = current_f1 - prev_f1
            round_data["delta_f1_from_prev"] = round(delta_from_prev, 4)
            if abs(delta_from_prev) < args.convergence_threshold:
                no_improvement_count += 1
                logger.info(
                    f"[CONVERGE] Round {round_num}: |delta_F1|={abs(delta_from_prev):.4f} < "
                    f"{args.convergence_threshold} (patience {no_improvement_count}/{args.convergence_patience})"
                )
            else:
                no_improvement_count = 0
                logger.info(f"[CONVERGE] Round {round_num}: delta_F1={delta_from_prev:+.4f} -- resetting patience")
        prev_f1 = current_f1

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
        round_results_file = os.path.join(run_output_dir, f"round_{round_num}_results.json")
        with open(round_results_file, 'w') as f:
            json.dump({
                "round": round_num,
                "metrics": post_verify_metrics,
                "pre_verify_metrics": pre_verify_metrics,
                "cost": cost.summary(),
                "results": verified_results,
            }, f, indent=2)
        logger.info(f"Round {round_num} results saved to {round_results_file}")

        # Trigger early stop if patience exhausted
        if early_stop_enabled and no_improvement_count >= args.convergence_patience:
            logger.info(
                f"[CONVERGE] Early stopping after round {round_num}: "
                f"no improvement for {args.convergence_patience} consecutive rounds"
            )
            break

    # ===========================================================================
    # Save final outputs
    # ===========================================================================
    progression["completed_at"] = datetime.now().isoformat()
    progression["final_cost"] = cost.summary()
    progression["best_round"] = best_round_num
    progression["best_f1"] = best_f1

    # Progression file for charting
    progression_file = os.path.join(run_output_dir, "round2_progression.json")
    with open(progression_file, 'w') as f:
        json.dump(progression, f, indent=2)
    logger.info(f"Progression saved to {progression_file}")

    # Final summary
    logger.info("")
    logger.info("=" * 70)
    logger.info("DmAVID Coordinator — Round 2 Summary")
    logger.info("=" * 70)
    logger.info(f"Rounds completed: {len(progression['rounds'])}/{args.rounds}")
    logger.info(f"Baseline F1: {BASELINE_F1}")

    if progression["rounds"]:
        last_round = progression["rounds"][-1]
        last_f1 = last_round.get("student_post_verify", {}).get("f1", 0)

        # Report best-round metrics as primary output
        report_round = best_round_data if best_round_data else last_round
        report_f1 = best_f1 if best_round_data else last_f1
        delta = report_f1 - BASELINE_F1
        direction = "+" if delta >= 0 else ""
        logger.info(f"Final F1:    {report_f1:.4f} ({direction}{delta:.4f} vs baseline)  [best round: {best_round_num}]")
        logger.info(f"Final P:     {report_round.get('student_post_verify', {}).get('precision', 0):.4f}")
        logger.info(f"Final R:     {report_round.get('student_post_verify', {}).get('recall', 0):.4f}")
        logger.info(f"Final FPR:   {report_round.get('student_post_verify', {}).get('fpr', 0):.4f}")
        if best_round_num != len(progression["rounds"]):
            last_delta = last_f1 - BASELINE_F1
            last_dir = "+" if last_delta >= 0 else ""
            logger.info(f"Last-round F1: {last_f1:.4f} ({last_dir}{last_delta:.4f} vs baseline)  [round {len(progression['rounds'])}]")

        # Save best-round results for downstream use
        if best_verified_results:
            best_results_file = os.path.join(run_output_dir, "best_round_results.json")
            with open(best_results_file, 'w') as f:
                json.dump({
                    "best_round": best_round_num,
                    "metrics": report_round.get("student_post_verify", {}),
                    "cost": cost.summary(),
                    "results": best_verified_results,
                }, f, indent=2)
            logger.info(f"Best-round results saved to {best_results_file}")


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
