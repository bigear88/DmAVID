#!/usr/bin/env python3
"""
DmAVID Red Team Agent: Generates adversarial contract variants from false negative cases.

This script analyzes false negative results from the Student Agent and generates
semantically equivalent contract variants that preserve the original vulnerabilities.
These variants are used to test the robustness of vulnerability detection systems.
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict, Any
import logging

from openai import OpenAI

import sys; sys.path.insert(0, os.path.dirname(__file__))
from _model_compat import token_param, MODEL as COMPAT_MODEL

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
BASE_DIR = os.environ.get(
    "DMAVID_BASE_DIR",
    "/home/curtis/DmAVID"
)
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")
import random

DEFAULT_VARIANTS_PER_CASE = 3

# Advanced mutation strategies for adversarial variant generation.
# Each strategy targets a different structural dimension to maximize
# the diversity of variants while preserving vulnerability semantics.
MUTATION_STRATEGIES = {
    "control_flow_flattening": (
        "Restructure the contract's control flow without changing semantics. "
        "Convert if/else branches into a state-machine pattern using an integer "
        "dispatch variable (e.g. `uint8 _step`). Add intermediate conditional "
        "checks that always resolve to the original execution path. "
        "The resulting code must appear structurally different while executing "
        "identically to the original."
    ),
    "dead_code_insertion": (
        "Insert plausible-looking but unreachable defensive code throughout "
        "the contract. Examples: require() checks on constants that always pass, "
        "dummy SafeMath-style arithmetic on local variables that are never stored, "
        "event emissions in code paths that are never reached. "
        "None of the inserted code may affect any state variable or alter "
        "the execution path of the vulnerability trigger."
    ),
    "cross_contract_delegation": (
        "Split the contract into two Solidity contracts: a thin proxy/wrapper "
        "and a Library (or second contract) containing the extracted core logic. "
        "Use `delegatecall` or Solidity `library` syntax so the vulnerable "
        "function's execution context and storage layout remain identical. "
        "The vulnerability must reside in the extracted library/contract and "
        "still be triggerable through the wrapper's external interface."
    ),
}

# Per-vulnerability-type semantic constraints injected into the prompt.
# These prevent the LLM from accidentally 'fixing' the vulnerability
# while applying the chosen mutation strategy.
VULN_SEMANTIC_CONSTRAINTS = {
    "reentrancy": (
        "CONSTRAINT — Reentrancy: The external call (.call / .transfer / .send) "
        "MUST still occur BEFORE the state variable that tracks the balance/flag "
        "is updated. Do NOT add a nonReentrant modifier or any reentrancy guard. "
        "Do NOT reorder the call so it comes after the state write."
    ),
    "arithmetic": (
        "CONSTRAINT — Arithmetic: The unchecked arithmetic operation "
        "(overflow/underflow) MUST be preserved. Do NOT wrap the operation "
        "in SafeMath, use Solidity 0.8.x checked arithmetic, or add any "
        "overflow/underflow guard."
    ),
    "access_control": (
        "CONSTRAINT — Access Control: The missing authorization check MUST "
        "remain missing. Do NOT add onlyOwner, require(msg.sender == owner), "
        "or any access-control modifier to the vulnerable function."
    ),
    "unchecked_low_level_calls": (
        "CONSTRAINT — Unchecked Low-Level Call: The return value of the "
        ".call()/.send()/.delegatecall() MUST remain unchecked. Do NOT add "
        "require(success) or any check on the boolean return value."
    ),
    "time_manipulation": (
        "CONSTRAINT — Time Manipulation: The dependency on block.timestamp "
        "(or 'now') MUST be preserved as the source of randomness or a "
        "condition. Do NOT replace it with a Chainlink oracle or block.number."
    ),
    "bad_randomness": (
        "CONSTRAINT — Bad Randomness: The use of block.number, blockhash, "
        "or block.timestamp as a randomness source MUST be preserved. "
        "Do NOT introduce a commit-reveal scheme or any external oracle."
    ),
    "front_running": (
        "CONSTRAINT — Front Running: The state-revealing transaction ordering "
        "vulnerability MUST be preserved. Do NOT add a commit-reveal mechanism "
        "or slippage check that would neutralise the front-running vector."
    ),
    "denial_of_service": (
        "CONSTRAINT — Denial of Service: The DoS vector (unbounded loop over "
        "a user-controlled array, or a .transfer() inside a loop) MUST be "
        "preserved. Do NOT add a gas limit check or pull-payment pattern "
        "that would fix the DoS."
    ),
}
_DEFAULT_CONSTRAINT = (
    "CONSTRAINT: The original vulnerability trigger condition MUST be fully "
    "preserved. Do NOT fix, mitigate, or neutralise the vulnerability."
)

# Initialize OpenAI client
client = OpenAI()


def load_false_negatives(results_file: str):
    """Load FN cases from LLM+RAG results (fixed for actual JSON format)."""
    with open(results_file, "r") as f:
        data = json.load(f)
    results = data.get("results", [])
    dataset_path = os.path.join(BASE_DIR, "data", "dataset_1000.json")
    filepath_map = {}
    if os.path.exists(dataset_path):
        with open(dataset_path) as df:
            ds = json.load(df)
        for c in ds.get("contracts", []):
            filepath_map[c.get("id", "")] = c.get("filepath", "")
            filepath_map[c.get("filename", "")] = c.get("filepath", "")
    false_negatives = []
    for item in results:
        if item.get("ground_truth") == "vulnerable" and not item.get("predicted_vulnerable"):
            cid = item.get("contract_id", "")
            fp = filepath_map.get(cid, "") or filepath_map.get(item.get("filename", ""), "")
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as cf:
                    source = cf.read()
            except Exception:
                source = ""
            vt = item.get("category", "unknown")
            meta = {"contract_id": cid, "category": vt, "confidence": item.get("confidence", 0)}
            false_negatives.append((source, vt, meta))
    logger.info(f"Found {len(false_negatives)} false negative cases")
    return false_negatives


def _pick_strategies(requested: str | None, n: int = 2) -> list[str]:
    """Return 1-2 strategy names. If a known strategy is requested use it;
    otherwise sample randomly (prefer 2 strategies for diversity)."""
    all_keys = list(MUTATION_STRATEGIES.keys())
    if requested and requested in MUTATION_STRATEGIES:
        chosen = [requested]
        remaining = [k for k in all_keys if k != requested]
        if remaining and random.random() < 0.5:
            chosen.append(random.choice(remaining))
        return chosen
    # Legacy names → map to closest new strategy
    legacy_map = {
        "variable_renaming": "dead_code_insertion",
        "code_reordering": "control_flow_flattening",
        "dead_code_injection": "dead_code_insertion",
        "control_flow_obfuscation": "control_flow_flattening",
    }
    if requested and requested in legacy_map:
        return [legacy_map[requested]]
    k = min(n, len(all_keys))
    return random.sample(all_keys, k=random.randint(1, k))


def generate_adversarial_variant(
    contract_source: str,
    vuln_type: str,
    transformation_type: str = None,
) -> Tuple[str, str, str]:
    """Generate a semantically equivalent but structurally distinct variant.

    Applies 1-2 advanced mutation strategies from MUTATION_STRATEGIES while
    enforcing per-vulnerability semantic constraints so the vulnerability
    trigger is never accidentally removed.

    Returns:
        (variant_source, strategies_label, preservation_note)
    """
    strategies = _pick_strategies(transformation_type)
    strategy_label = "+".join(strategies)

    strategy_descriptions = "\n".join(
        f"  Strategy {i+1} — {name}:\n    {MUTATION_STRATEGIES[name]}"
        for i, name in enumerate(strategies)
    )

    semantic_constraint = VULN_SEMANTIC_CONSTRAINTS.get(
        vuln_type.lower().replace(" ", "_"), _DEFAULT_CONSTRAINT
    )

    prompt = f"""You are an expert Solidity adversarial code transformer working on a \
security-research benchmark. Your task is to produce a VARIANT of the contract below \
that is structurally different from the original yet preserves all execution semantics \
— including its {vuln_type} vulnerability.

=== MUTATION STRATEGIES TO APPLY ===
{strategy_descriptions}

=== HARD SEMANTIC CONSTRAINT (NEVER VIOLATE) ===
{semantic_constraint}

=== ADDITIONAL RULES ===
- Apply ALL listed strategies; the variant must show visible structural changes.
- Do NOT rename the external interface (function names visible to callers must stay the same).
- Do NOT change storage variable types or layouts unless required by cross-contract delegation.
- Return ONLY valid Solidity source code — no markdown fences, no explanation.

=== ORIGINAL CONTRACT ({vuln_type}) ===
{contract_source}

=== TRANSFORMED VARIANT ==="""

    try:
        logger.info(f"[RED TEAM] Generating variant [{strategy_label}] for {vuln_type}")
        response = client.chat.completions.create(
            model=MODEL,
            **token_param(4096),
            messages=[{"role": "user", "content": prompt}],
            temperature=0.8,
        )

        variant_source = response.choices[0].message.content.strip()
        # Strip any residual markdown fences
        for fence in ("```solidity", "```"):
            if variant_source.startswith(fence):
                variant_source = variant_source[len(fence):]
        if variant_source.endswith("```"):
            variant_source = variant_source[:-3]
        variant_source = variant_source.strip()

        preservation_note = (
            f"Strategies: {strategy_label} | vuln: {vuln_type} preserved"
        )
        return variant_source, strategy_label, preservation_note

    except Exception as e:
        logger.error(f"Error generating variant: {e}")
        return contract_source, strategy_label, f"Failed: {e}"


def generate_poc_template(variant_source: str, vuln_type: str) -> str:
    """Generate a Foundry exploit PoC for the given variant.

    The hint section gives the LLM a concrete exploit skeleton tailored to
    the vulnerability type, reducing hallucination and improving forge test
    pass rates.
    """
    # Type-specific exploit hints fed to the LLM
    vuln_hints = {
        "reentrancy": (
            "Create an Attacker contract with a receive()/fallback() that "
            "re-enters the target's withdrawal function. Call attack() to "
            "drain the contract balance. Assert attacker balance > initial."
        ),
        "arithmetic": (
            "Call the arithmetic function with boundary inputs that trigger "
            "overflow or underflow. Assert the resulting value wraps around "
            "(e.g., type(uint256).max + 1 == 0)."
        ),
        "access_control": (
            "Call the privileged function from a non-owner address (address(this) "
            "or a fresh EOA). Assert the call succeeds (no revert) when it should "
            "have been restricted."
        ),
        "unchecked_low_level_calls": (
            "Deploy a Rejecter contract whose fallback reverts. Trigger the "
            "vulnerable low-level .call()/.send() to Rejecter. Assert the "
            "outer transaction still succeeds despite the inner failure."
        ),
        "bad_randomness": (
            "Predict the outcome by computing the same blockhash/block expression "
            "inside the test. Call the vulnerable function with the predicted value "
            "and assert it wins consistently."
        ),
        "time_manipulation": (
            "Use vm.warp() to set block.timestamp to a value that satisfies the "
            "time-based condition. Assert the condition is exploitable."
        ),
        "front_running": (
            "Submit two transactions in a single test: first record the target's "
            "pending state, then front-run with a higher-priority call. Assert the "
            "front-run call captures the value."
        ),
        "denial_of_service": (
            "Add many entries to the victim array (via a loop). Then call the "
            "function that iterates over all entries and assert it reverts with "
            "out-of-gas or that a legitimate user is permanently blocked."
        ),
    }
    hint = vuln_hints.get(vuln_type.lower().replace(" ", "_"), "")
    if hint:
        hint_section = f"\nExploit hint for {vuln_type}:\n{hint}\n"
    else:
        hint_section = ""

    poc_prompt = f"""You are a Solidity security expert writing a Foundry exploit test.
Write a complete, self-contained test contract in Solidity that:
1. Imports forge-std/Test.sol and uses the Test base contract.
2. Deploys the vulnerable contract inside setUp().
3. Implements a test function (name it test_exploit_{vuln_type.replace('-','_')}) that exploits the {vuln_type} vulnerability.
4. Uses assertTrue / assertGt / assertEq to assert the exploit succeeded.
5. Works with `forge test` without external dependencies beyond forge-std.
{hint_section}
Vulnerable contract:
{variant_source}

Return ONLY valid Solidity code. No markdown fences, no explanation."""

    try:
        logger.info(f"Generating PoC template for {vuln_type}")
        response = client.chat.completions.create(
            model=MODEL,
            **token_param(2048),
            messages=[
                {
                    "role": "user",
                    "content": poc_prompt
                }
            ],
            temperature=0.7,
        )

        poc_code = response.choices[0].message.content.strip()

        # Clean up markdown code blocks if present
        if poc_code.startswith("```solidity"):
            poc_code = poc_code[11:]
        if poc_code.startswith("```"):
            poc_code = poc_code[3:]
        if poc_code.endswith("```"):
            poc_code = poc_code[:-3]
        poc_code = poc_code.strip()

        return poc_code

    except Exception as e:
        logger.error(f"Error generating PoC: {e}")
        return f"// Failed to generate PoC: {str(e)}"


def main():
    """Main execution flow for red team agent."""
    logger.info("=" * 60)
    logger.info("DmAVID Red Team Agent Starting")
    logger.info("=" * 60)

    # Determine paths
    results_file = os.path.join(
        BASE_DIR,
        "experiments/hybrid/hybrid_results.json"
    )
    red_team_dir = os.path.join(BASE_DIR, "experiments/red_team")
    poc_dir = os.path.join(red_team_dir, "poc_templates")

    # Create directories
    Path(red_team_dir).mkdir(parents=True, exist_ok=True)
    Path(poc_dir).mkdir(parents=True, exist_ok=True)

    # Load false negatives
    false_negatives = load_false_negatives(results_file)

    if not false_negatives:
        logger.warning("No false negatives found. Exiting.")
        return

    # Generate variants
    variants_list = []
    vuln_type_counts = {}

    for contract_source, vuln_type, metadata in false_negatives:
        logger.info(f"Processing {vuln_type} false negative case")

        # Generate K variants for this FN case
        strategy_keys = list(MUTATION_STRATEGIES.keys())
        for variant_idx in range(DEFAULT_VARIANTS_PER_CASE):
            transformation = strategy_keys[variant_idx % len(strategy_keys)]

            variant_source, transform_applied, preservation_note = generate_adversarial_variant(
                contract_source,
                vuln_type,
                transformation
            )

            # Generate PoC template
            poc_code = generate_poc_template(variant_source, vuln_type)

            # Create variant record
            variant_record = {
                "variant_id": f"{metadata.get('contract_id')}_{vuln_type}_{variant_idx}",
                "original_contract_id": metadata.get("contract_id"),
                "vulnerability_type": vuln_type,
                "transformation_applied": transform_applied,
                "preservation_note": preservation_note,
                "contract_source": variant_source,
                "poc_template": poc_code,
                "metadata": metadata,
                "generated_at": datetime.now().isoformat()
            }

            variants_list.append(variant_record)

            # Track counts
            vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1

            # Save PoC template to file
            poc_filename = f"poc_{metadata.get('contract_id')}_{vuln_type}_{variant_idx}.sol"
            poc_path = os.path.join(poc_dir, poc_filename)

            try:
                with open(poc_path, 'w') as f:
                    f.write(poc_code)
                logger.info(f"Saved PoC template: {poc_filename}")
            except IOError as e:
                logger.error(f"Failed to save PoC template: {e}")

    # Save all variants to JSON
    output_file = os.path.join(
        red_team_dir,
        f"adversarial_variants_round_{int(datetime.now().timestamp())}.json"
    )

    output_data = {
        "generated_at": datetime.now().isoformat(),
        "total_variants": len(variants_list),
        "variants_by_type": vuln_type_counts,
        "results": variants_list
    }

    try:
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        logger.info(f"Saved variants to {output_file}")
    except IOError as e:
        logger.error(f"Failed to save variants: {e}")
        return

    # Print summary
    logger.info("=" * 60)
    logger.info("Red Team Agent Execution Summary")
    logger.info("=" * 60)
    logger.info(f"Total false negatives processed: {len(false_negatives)}")
    logger.info(f"Total variants generated: {len(variants_list)}")
    logger.info("Variants per vulnerability type:")
    for vuln_type, count in sorted(vuln_type_counts.items()):
        logger.info(f"  {vuln_type}: {count}")
    logger.info(f"PoC templates saved to: {poc_dir}")
    logger.info(f"Variants file: {output_file}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
