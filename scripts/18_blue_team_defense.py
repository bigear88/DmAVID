"""DmAVID Blue Team Agent: Synthesizes defensive detection patterns from validated exploits."""

import os
import re
import json
import time
import logging
import argparse
from datetime import datetime
from collections import Counter

from openai import OpenAI
import sys
sys.path.insert(0, os.path.dirname(__file__))
from _model_compat import token_param

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BASE_DIR = os.environ.get("DMAVID_BASE_DIR", "/home/curtis/DmAVID")
MODEL    = os.environ.get("DMAVID_MODEL",    "gpt-4.1-mini")
KNOWLEDGE_FILE = os.path.join(BASE_DIR, "scripts/knowledge/vulnerability_knowledge.json")
RAG_KB_FILE    = os.path.join(BASE_DIR, "data/rag_knowledge_base.json")

client = OpenAI()

# Terms that appear in SAFE code — if vulnerability_pattern uses them without
# indicating they are *absent/missing*, the entry risks flagging safe contracts.
_FP_KEYWORDS   = {"safeMath", "nonReentrant", "reentrancyGuard", "onlyOwner",
                   "safeTransfer", "require", "openzeppelin"}
_ABSENCE_WORDS = {"missing", "without", "absent", "lack", "no ", "not ", "never",
                  "should not", "doesn't", "does not"}
_ADD_WORDS     = {"add", "apply", "use", "implement", "include", "should"}

DEFENSE_SYNTHESIS_PROMPT = """You are an expert smart contract security researcher on a Blue Team.
Given the following validated exploit variant, extract defensive detection patterns.

Exploit Details:
- Vulnerability Type: {vuln_type}
- Contract Source:
{contract_source}
- Transformation Applied: {transformation}
- Preservation Note: {preservation_note}
- PoC Template:
{poc_template}

Extract JSON with this exact schema (no markdown, raw JSON only):
{{
  "title": "Short descriptive name for this defensive pattern",
  "exploitability_reason": "Why this variant is exploitable",
  "vulnerable_code_pattern": "Concise code pattern or idiom that indicates the vulnerability",
  "safe_code_version": "Corresponding safe code pattern or fix",
  "mitigation_strategy": "Actionable mitigation guidance",
  "severity": "High/Medium/Low",
  "detection_indicators": "Keywords or patterns an auditor should flag",
  "generalized_pattern": "Generalized description for RAG retrieval"
}}"""


def _is_fp_polluting(entry: dict) -> bool:
    """Return True if this entry risks generating false positives.

    An entry is FP-polluting when its vulnerability_pattern or generalized_pattern
    mentions a term commonly found in *safe* code without qualifying that the term
    is *absent* or *needs to be added*.
    """
    for field in ("vulnerability_pattern", "generalized_pattern"):
        text = entry.get(field, "").lower()
        for kw in _FP_KEYWORDS:
            if kw.lower() in text:
                # Acceptable only if the entry explicitly notes absence or recommends adding it
                has_absence = any(aw in text for aw in _ABSENCE_WORDS)
                has_add     = any(aw in text for aw in _ADD_WORDS)
                if not has_absence and not has_add:
                    logger.warning(
                        f"  [KB-VALIDATE] FP-pollution risk: {field} mentions '{kw}'"
                        " without flagging its absence. Entry rejected."
                    )
                    return True
    return False


def synthesize_defense_patterns(variants: list, vuln_type: str) -> list:
    """Synthesize defensive detection patterns from validated exploit variants.

    Takes validated exploit variants, uses LLM to extract generalizable
    vulnerability patterns and mitigation indicators.
    """
    results = []
    for idx, variant in enumerate(variants):
        source = (variant.get("contract_source")
                  or variant.get("variant_source")
                  or variant.get("source", ""))
        if not source:
            logger.warning(f"Variant {idx} has no contract source, skipping")
            continue

        transformation = variant.get("transformation_applied", "unknown")
        preservation   = variant.get("preservation_note", "")
        poc            = variant.get("poc_template", "// No PoC available")

        logger.info(f"Synthesizing defense pattern {idx+1}/{len(variants)} for {vuln_type}")
        try:
            prompt = DEFENSE_SYNTHESIS_PROMPT.format(
                vuln_type=vuln_type,
                contract_source=source[:3000],
                transformation=transformation,
                preservation_note=preservation,
                poc_template=poc[:1000],
            )
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                **token_param(1024),
            )
            content = resp.choices[0].message.content.strip()
            m = re.search(r'\{[\s\S]*\}', content)
            if not m:
                raise json.JSONDecodeError("no JSON found", content, 0)
            data = json.loads(m.group())

            entry = {
                "category":               vuln_type,
                "title":                  f"Blue Team Defense: {data.get('title', vuln_type)}",
                "description":            data.get("exploitability_reason", ""),
                "vulnerable_code_pattern": data.get("vulnerable_code_pattern", ""),
                "safe_code_version":      data.get("safe_code_version", ""),
                "mitigation_strategy":    data.get("mitigation_strategy", ""),
                "severity":               data.get("severity", "Medium"),
                "detection_indicators":   data.get("detection_indicators", ""),
                "generalized_pattern":    data.get("generalized_pattern", ""),
                "blue_team_synthesis":    True,
                "variant_id":             variant.get("id", f"variant_{idx}"),
                "timestamp":              datetime.now().isoformat(),
                "tokens_used":            resp.usage.total_tokens,
            }

            if _is_fp_polluting(entry):
                logger.info(f"  [KB-VALIDATE] Rejected entry {idx} -- FP pollution risk")
            else:
                logger.info(f"  Synthesized pattern: {entry['title']}")
                results.append(entry)

        except json.JSONDecodeError:
            logger.error(f"Failed to parse LLM response for variant {idx}")
        except Exception as exc:
            logger.error(f"Error synthesizing defense for variant {idx}: {exc}")

        time.sleep(0.3)

    logger.info(f"Synthesized {len(results)} defense patterns from {len(variants)} variants")
    return results


def update_knowledge_files(new_entries: list) -> dict:
    """Append new defense entries to knowledge files.

    Updates both:
      - scripts/knowledge/vulnerability_knowledge.json (structured KB)
      - data/rag_knowledge_base.json (RAG patterns)

    Applies a per-category cap of 5 Blue Team entries to avoid
    overwhelming the KB with generated content.
    """
    # ---------- vulnerability_knowledge.json ----------
    if os.path.exists(KNOWLEDGE_FILE):
        with open(KNOWLEDGE_FILE) as f:
            vk = json.load(f)
    else:
        vk = {"metadata": {"description": "DeFi Vulnerability Knowledge Base"}, "entries": []}

    existing_bt = Counter(
        e.get("category") for e in vk.get("entries", [])
        if "Blue Team Defense" in e.get("title", "")
    )

    added_vk = 0
    for e in new_entries:
        cat = e.get("category", "unknown")
        if existing_bt[cat] >= 5:
            logger.info(f"  [KB-CAP] Skipping {cat} entry — already {existing_bt[cat]} Blue Team entries")
            continue
        vk.setdefault("entries", []).append({
            "id":                   f"BT-{cat[:4].upper()}-{int(time.time()) % 100000:05d}",
            "category":             cat,
            "title":                e.get("title", ""),
            "description":          e.get("description", ""),
            "vulnerability_pattern": e.get("vulnerable_code_pattern", ""),
            "safe_pattern":         e.get("safe_code_version", ""),
            "mitigation":           e.get("mitigation_strategy", ""),
            "severity":             e.get("severity", "Medium"),
            "source_variant_id":    e.get("variant_id", "unknown"),
        })
        existing_bt[cat] += 1
        added_vk += 1

    vk.setdefault("metadata", {})["total_entries"] = len(vk["entries"])
    vk["metadata"]["last_updated"] = datetime.now().isoformat()
    os.makedirs(os.path.dirname(KNOWLEDGE_FILE), exist_ok=True)
    with open(KNOWLEDGE_FILE, "w") as f:
        json.dump(vk, f, indent=2, ensure_ascii=False)
    logger.info(f"Updated vulnerability_knowledge: added {added_vk} entries "
                f"(total: {len(vk['entries'])})")

    # ---------- rag_knowledge_base.json ----------
    if os.path.exists(RAG_KB_FILE):
        with open(RAG_KB_FILE) as f:
            rag = json.load(f)
    else:
        rag = {}

    rag.setdefault("patterns", {})
    added_rag = 0
    for e in new_entries:
        key = f"bt_{e.get('variant_id', 'unknown')}_{added_rag}"
        rag["patterns"][key] = {
            "vulnerability_type": e.get("category", "unknown"),
            "pattern":            e.get("generalized_pattern", ""),
            "blue_team_defense":  e.get("mitigation_strategy", ""),
            "source":             "blue_team_synthesis",
        }
        added_rag += 1

    with open(RAG_KB_FILE, "w") as f:
        json.dump(rag, f, indent=2, ensure_ascii=False)
    logger.info(f"Updated rag_knowledge_base: added {added_rag} patterns")

    return {
        "vulnerability_knowledge": added_vk,
        "rag_knowledge_base": added_rag,
    }


def main():
    """Main execution flow for the Blue Team Defense Agent."""
    parser = argparse.ArgumentParser(description="DmAVID Blue Team Agent")
    parser.add_argument("--input", type=str, help="Path to Foundry validation results JSON")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be done without making API calls or writing files")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("DmAVID Blue Team Agent Starting")
    logger.info(f"Model: {MODEL}")
    logger.info(f"Dry run: {args.dry_run}")
    logger.info("=" * 60)

    input_path = args.input or os.path.join(BASE_DIR, "experiments/foundry_validation/foundry_results.json")
    if not os.path.exists(input_path):
        logger.error(f"Input file not found: {input_path}")
        logger.error("Use --input to specify path to Foundry validation results")
        return

    with open(input_path) as f:
        data = json.load(f)

    by_type: dict = {}
    for r in data.get("results", data.get("variants", [])):
        if r.get("compile_success"):
            vt = r.get("vulnerability_type", "unknown")
            by_type.setdefault(vt, []).append(r)

    total = sum(len(v) for v in by_type.values())
    logger.info(f"Loaded {total} compilable variants across {len(by_type)} vulnerability types")

    if args.dry_run:
        logger.info("[DRY RUN] Would synthesize defense patterns for:")
        for vt, vs in by_type.items():
            logger.info(f"  {vt}: {len(vs)} variants")
        logger.info("[DRY RUN] No API calls made, no files written.")
        return

    all_entries = []
    for vt, vs in by_type.items():
        entries = synthesize_defense_patterns(vs, vt)
        all_entries.extend(entries)

    if not all_entries:
        logger.info("No defense patterns synthesized. Exiting.")
        return

    stats = update_knowledge_files(all_entries)

    output_dir = os.path.join(BASE_DIR, "experiments/blue_team")
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"defense_synthesis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(report_path, "w") as f:
        json.dump({"entries": all_entries, "stats": stats}, f, indent=2, ensure_ascii=False)

    logger.info("=" * 60)
    logger.info("Blue Team Defense Agent Summary")
    logger.info(f"Variants processed: {total}")
    logger.info(f"Defense patterns synthesized: {len(all_entries)}")
    logger.info(f"Knowledge base entries added: {stats.get('vulnerability_knowledge', 0)}")
    logger.info(f"RAG patterns added: {stats.get('rag_knowledge_base', 0)}")
    logger.info(f"Total tokens used: {sum(e.get('tokens_used', 0) for e in all_entries)}")
    logger.info(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()
