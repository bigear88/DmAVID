#!/usr/bin/env python3
"""
DavidAgent Red Team Agent: Generates adversarial contract variants from false negative cases.

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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
BASE_DIR = os.environ.get(
    "DAVID_BASE_DIR",
    "/home/curtis/defi-llm-vulnerability-detection"
)
MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")
DEFAULT_VARIANTS_PER_CASE = 3
TRANSFORMATION_TYPES = [
    "variable_renaming",
    "code_reordering",
    "dead_code_injection",
    "control_flow_obfuscation"
]

# Initialize OpenAI client
client = OpenAI()


def load_false_negatives(results_file: str) -> List[Tuple[str, str, Dict[str, Any]]]:
    """
    Load false negative cases from Student Agent results JSON.

    Args:
        results_file: Path to the Student Agent results JSON file

    Returns:
        List of tuples: (contract_source, vuln_type, ground_truth_metadata)
    """
    logger.info(f"Loading false negative cases from {results_file}")

    if not os.path.exists(results_file):
        logger.error(f"Results file not found: {results_file}")
        return []

    false_negatives = []

    try:
        with open(results_file, 'r') as f:
            results = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from {results_file}: {e}")
        return []

    # Extract false negative cases (vulnerabilities missed by Student Agent)
    if isinstance(results, dict) and "results" in results:
        for item in results.get("results", []):
            # Check if this is a false negative (has ground truth vulnerability but wasn't detected)
            if item.get("ground_truth_vulnerabilities") and not item.get("detected_vulnerabilities"):
                contract_source = item.get("contract_source", "")
                ground_truth = item.get("ground_truth_vulnerabilities", [])

                # Create an entry for each vulnerability type
                for vuln in ground_truth:
                    vuln_type = vuln.get("type", "unknown")
                    metadata = {
                        "contract_id": item.get("contract_id"),
                        "severity": vuln.get("severity", "unknown"),
                        "location": vuln.get("location", ""),
                        "description": vuln.get("description", "")
                    }
                    false_negatives.append((contract_source, vuln_type, metadata))

    logger.info(f"Found {len(false_negatives)} false negative cases")
    return false_negatives


def generate_adversarial_variant(
    contract_source: str,
    vuln_type: str,
    transformation_type: str = None
) -> Tuple[str, str, str]:
    """
    Generate a semantically equivalent contract variant using LLM.

    The variant preserves the vulnerability while applying code transformations
    to test the robustness of detection systems.

    Args:
        contract_source: Original Solidity contract source code
        vuln_type: Type of vulnerability to preserve
        transformation_type: Specific transformation to apply (optional)

    Returns:
        Tuple of (variant_source, transformation_applied, preservation_note)
    """
    if not transformation_type:
        transformation_type = TRANSFORMATION_TYPES[0]

    transformation_descriptions = {
        "variable_renaming": "Rename all state variables and local variables to obscure names while preserving functionality",
        "code_reordering": "Reorder function definitions and code blocks without changing execution semantics",
        "dead_code_injection": "Inject unused code paths and dead code blocks that don't affect the vulnerability",
        "control_flow_obfuscation": "Use conditional statements and loops to obfuscate the original control flow"
    }

    prompt = f"""You are a Solidity code transformation expert. Transform the following contract to preserve the {vuln_type} vulnerability while applying the transformation: {transformation_descriptions.get(transformation_type, transformation_type)}.

IMPORTANT:
- The vulnerability MUST be preserved exactly as it is
- The transformed contract must remain functionally equivalent
- Only apply the specified transformation type
- Return ONLY the transformed Solidity code, no explanation

Original contract:
```solidity
{contract_source}
```

Transformed contract:"""

    try:
        logger.info(f"Generating variant with {transformation_type} for {vuln_type}")
        response = client.chat.completions.create(
            model=MODEL,
            max_tokens=4096,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.7,
        )

        variant_source = response.choices[0].message.content.strip()

        # Clean up markdown code blocks if present
        if variant_source.startswith("```solidity"):
            variant_source = variant_source[11:]
        if variant_source.startswith("```"):
            variant_source = variant_source[3:]
        if variant_source.endswith("```"):
            variant_source = variant_source[:-3]
        variant_source = variant_source.strip()

        preservation_note = f"Variant preserves {vuln_type} vulnerability with {transformation_type} applied"

        return variant_source, transformation_type, preservation_note

    except Exception as e:
        logger.error(f"Error generating variant: {e}")
        return contract_source, transformation_type, f"Failed to transform: {str(e)}"


def generate_poc_template(variant_source: str, vuln_type: str) -> str:
    """
    Generate a Foundry/Hardhat test template for the variant.

    Creates basic test code that attempts to exploit the vulnerability in the variant.

    Args:
        variant_source: Transformed contract source code
        vuln_type: Type of vulnerability to test

    Returns:
        Solidity test code template
    """
    poc_prompt = f"""You are a Solidity security testing expert. Create a Foundry test template that attempts to exploit the {vuln_type} vulnerability in the following contract.

Return ONLY valid Solidity code for a test contract that:
1. Deploys the vulnerable contract
2. Sets up necessary state
3. Attempts to exploit the {vuln_type} vulnerability
4. Asserts that the exploit succeeds

Contract to test:
```solidity
{variant_source}
```

Test contract code:"""

    try:
        logger.info(f"Generating PoC template for {vuln_type}")
        response = client.chat.completions.create(
            model=MODEL,
            max_tokens=2048,
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
    logger.info("DavidAgent Red Team Agent Starting")
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
        for variant_idx in range(DEFAULT_VARIANTS_PER_CASE):
            transformation = TRANSFORMATION_TYPES[variant_idx % len(TRANSFORMATION_TYPES)]

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
