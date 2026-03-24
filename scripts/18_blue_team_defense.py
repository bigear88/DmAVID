#!/usr/bin/env python3
"""DavidAgent Blue Team Agent: Synthesizes defensive detection patterns from validated exploits."""

import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime
from typing import List, Dict, Any

from openai import OpenAI

sys.path.insert(0, os.path.dirname(__file__))
from _model_compat import token_param

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BASE_DIR = os.environ.get("DAVID_BASE_DIR", "/home/curtis/defi-llm-vulnerability-detection")
MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")
client = OpenAI()

KNOWLEDGE_FILE = os.path.join(BASE_DIR, "scripts/knowledge/vulnerability_knowledge.json")
RAG_KB_FILE = os.path.join(BASE_DIR, "data/rag_knowledge_base.json")


DEFENSE_SYNTHESIS_PROMPT = """You are an expert smart contract security researcher on a Blue Team.
Given the following validated exploit variant, extract defensive detection patterns.

Exploit Details:
- Vulnerability Type: {vuln_type}
- Transformation Applied: {transformation}
- Preservation Note: {preservation_note}

Contract Source:
```solidity
{contract_source}
```

PoC Template (if available):
```solidity
{poc_template}
```

Extract the following in JSON format ONLY:
{{
  "vulnerable_code_pattern": "The specific code pattern that makes this exploitable (generalized regex-friendly description)",
  "exploitability_reason": "What makes this pattern exploitable — root cause analysis",
  "mitigation_strategy": "Concrete mitigation that would prevent this vulnerability",
  "safe_code_version": "A corrected version of the vulnerable code pattern",
  "detection_indicators": ["list", "of", "static", "analysis", "indicators"],
  "severity": "High/Medium/Low",
  "generalized_pattern": "A generalized description of this vulnerability class for pattern matching"
}}"""


def synthesize_defense_patterns(variants: List[Dict[str, Any]], vuln_type: str) -> List[Dict[str, Any]]:
    """
    Synthesize defensive detection patterns from validated exploit variants.

    Takes validated exploit variants, uses LLM to extract generalizable
    vulnerability patterns and mitigation indicators.

    Args:
        variants: List of validated exploit variant dicts (each with contract_source,
                  transformation_applied, preservation_note, poc_template, etc.)
        vuln_type: The vulnerability type these variants demonstrate.

    Returns:
        List of RAG-compatible knowledge base entries with fields:
        category, title, description, vulnerability_pattern, safe_pattern, mitigation.
    """
    defense_entries = []

    for i, variant in enumerate(variants):
        contract_source = variant.get("contract_source", "")
        if not contract_source:
            logger.warning(f"Variant {i} has no contract source, skipping")
            continue

        transformation = variant.get("transformation_applied", "unknown")
        preservation_note = variant.get("preservation_note", "")
        poc_template = variant.get("poc_template", "// No PoC available")

        prompt = DEFENSE_SYNTHESIS_PROMPT.format(
            vuln_type=vuln_type,
            transformation=transformation,
            preservation_note=preservation_note,
            contract_source=contract_source[:6000],
            poc_template=poc_template[:3000],
        )

        try:
            logger.info(f"Synthesizing defense pattern {i+1}/{len(variants)} for {vuln_type} ({transformation})")
            response = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                **token_param(2048),
            )

            content = response.choices[0].message.content.strip()

            # Parse JSON from response
            import re
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                parsed = json.loads(json_match.group())
            else:
                parsed = json.loads(content)

            # Build RAG-compatible entry
            entry_id = f"BT-{vuln_type[:3].upper()}-{int(time.time())}-{i}"
            entry = {
                "id": entry_id,
                "category": vuln_type,
                "title": f"Blue Team Defense: {vuln_type} via {transformation}",
                "description": parsed.get("exploitability_reason", ""),
                "vulnerability_pattern": parsed.get("vulnerable_code_pattern", ""),
                "safe_pattern": parsed.get("safe_code_version", ""),
                "mitigation": parsed.get("mitigation_strategy", ""),
                "severity": parsed.get("severity", "Medium"),
                "detection_indicators": parsed.get("detection_indicators", []),
                "generalized_pattern": parsed.get("generalized_pattern", ""),
                "source": "blue_team_synthesis",
                "source_variant_id": variant.get("variant_id", f"variant_{i}"),
                "generated_at": datetime.now().isoformat(),
                "tokens_used": response.usage.total_tokens if response.usage else 0,
            }

            defense_entries.append(entry)
            logger.info(f"  Synthesized pattern: {entry['title']}")

            time.sleep(0.3)  # Rate limiting

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response for variant {i}: {e}")
        except Exception as e:
            logger.error(f"Error synthesizing defense for variant {i}: {e}")

    logger.info(f"Synthesized {len(defense_entries)} defense patterns from {len(variants)} variants")
    return defense_entries


def update_knowledge_files(new_entries: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Append new defense entries to knowledge files.

    Updates both:
      - scripts/knowledge/vulnerability_knowledge.json (structured KB)
      - data/rag_knowledge_base.json (RAG patterns)

    Args:
        new_entries: List of RAG-compatible knowledge entries.

    Returns:
        Dict with counts of entries added to each file.
    """
    stats = {"vulnerability_knowledge": 0, "rag_knowledge_base": 0}

    # --- Update vulnerability_knowledge.json ---
    if os.path.exists(KNOWLEDGE_FILE):
        with open(KNOWLEDGE_FILE, 'r') as f:
            kb = json.load(f)
    else:
        kb = {"metadata": {"description": "DeFi Vulnerability Knowledge Base", "total_entries": 0}, "entries": []}

    existing_ids = {e.get("id") for e in kb.get("entries", [])}

    for entry in new_entries:
        if entry["id"] not in existing_ids:
            # Map to KB schema (keep only fields the KB uses)
            kb_entry = {
                "id": entry["id"],
                "category": entry["category"],
                "title": entry["title"],
                "description": entry["description"],
                "vulnerability_pattern": entry["vulnerability_pattern"],
                "safe_pattern": entry["safe_pattern"],
                "mitigation": entry["mitigation"],
                "severity": entry.get("severity", "Medium"),
                "swc_id": "Custom-BT",
                "real_world_case": f"Blue team synthesis from variant {entry.get('source_variant_id', 'unknown')}",
            }
            kb["entries"].append(kb_entry)
            stats["vulnerability_knowledge"] += 1

    kb["metadata"]["total_entries"] = len(kb["entries"])

    os.makedirs(os.path.dirname(KNOWLEDGE_FILE), exist_ok=True)
    with open(KNOWLEDGE_FILE, 'w') as f:
        json.dump(kb, f, indent=2)
    logger.info(f"Updated {KNOWLEDGE_FILE}: added {stats['vulnerability_knowledge']} entries (total: {kb['metadata']['total_entries']})")

    # --- Update rag_knowledge_base.json ---
    if os.path.exists(RAG_KB_FILE):
        with open(RAG_KB_FILE, 'r') as f:
            rag_kb = json.load(f)
    else:
        rag_kb = {"patterns": {}}

    for entry in new_entries:
        pattern_key = f"bt_{entry['id']}"
        if pattern_key not in rag_kb.get("patterns", {}):
            rag_kb.setdefault("patterns", {})[pattern_key] = {
                "vulnerability_type": entry["category"],
                "pattern": entry.get("generalized_pattern", entry["vulnerability_pattern"]),
                "confidence": 0.85,
                "source": "blue_team_defense",
                "mitigation": entry["mitigation"],
            }
            stats["rag_knowledge_base"] += 1

    os.makedirs(os.path.dirname(RAG_KB_FILE), exist_ok=True)
    with open(RAG_KB_FILE, 'w') as f:
        json.dump(rag_kb, f, indent=2)
    logger.info(f"Updated {RAG_KB_FILE}: added {stats['rag_knowledge_base']} patterns")

    return stats


def main():
    """Main execution flow for the Blue Team Defense Agent."""
    parser = argparse.ArgumentParser(description="DavidAgent Blue Team Agent")
    parser.add_argument("--input", type=str, default=None,
                        help="Path to Foundry validation results JSON")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be done without making API calls or writing files")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("DavidAgent Blue Team Agent Starting")
    logger.info(f"Model: {MODEL}")
    logger.info(f"Dry run: {args.dry_run}")
    logger.info("=" * 60)

    # Determine input file
    input_file = args.input or os.path.join(
        BASE_DIR, "experiments/foundry_validation/foundry_results.json"
    )

    if not os.path.exists(input_file):
        logger.error(f"Input file not found: {input_file}")
        logger.info("Use --input to specify path to Foundry validation results")
        sys.exit(1)

    # Load validated variants
    with open(input_file, 'r') as f:
        validation_data = json.load(f)

    # Extract variants grouped by vulnerability type
    variants_by_type: Dict[str, List[Dict]] = {}
    results_key = "results" if "results" in validation_data else "variants"
    for item in validation_data.get(results_key, []):
        # Only use variants that compiled successfully
        if not item.get("compile_success", True):
            continue
        vtype = item.get("vulnerability_type", "unknown")
        variants_by_type.setdefault(vtype, []).append(item)

    total_variants = sum(len(v) for v in variants_by_type.values())
    logger.info(f"Loaded {total_variants} compilable variants across {len(variants_by_type)} vulnerability types")

    if args.dry_run:
        logger.info("[DRY RUN] Would synthesize defense patterns for:")
        for vtype, variants in sorted(variants_by_type.items()):
            logger.info(f"  {vtype}: {len(variants)} variants")
        logger.info("[DRY RUN] No API calls made, no files written.")
        return

    # Synthesize defense patterns for each vulnerability type
    all_entries = []
    for vtype, variants in sorted(variants_by_type.items()):
        logger.info(f"Processing {vtype}: {len(variants)} variants")
        entries = synthesize_defense_patterns(variants, vtype)
        all_entries.extend(entries)

    if not all_entries:
        logger.warning("No defense patterns synthesized. Exiting.")
        return

    # Update knowledge files
    stats = update_knowledge_files(all_entries)

    # Save synthesis report
    report_dir = os.path.join(BASE_DIR, "experiments/blue_team")
    os.makedirs(report_dir, exist_ok=True)
    report_file = os.path.join(report_dir, f"defense_synthesis_{int(time.time())}.json")
    report = {
        "generated_at": datetime.now().isoformat(),
        "model": MODEL,
        "input_file": input_file,
        "total_variants_processed": total_variants,
        "total_patterns_synthesized": len(all_entries),
        "patterns_by_type": {vtype: len([e for e in all_entries if e["category"] == vtype])
                            for vtype in variants_by_type},
        "knowledge_updates": stats,
        "entries": all_entries,
    }
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    # Summary
    logger.info("=" * 60)
    logger.info("Blue Team Defense Agent Summary")
    logger.info("=" * 60)
    logger.info(f"Variants processed: {total_variants}")
    logger.info(f"Defense patterns synthesized: {len(all_entries)}")
    logger.info(f"Knowledge base entries added: {stats['vulnerability_knowledge']}")
    logger.info(f"RAG patterns added: {stats['rag_knowledge_base']}")
    logger.info(f"Report saved to: {report_file}")
    total_tokens = sum(e.get("tokens_used", 0) for e in all_entries)
    logger.info(f"Total tokens used: {total_tokens:,}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
