#!/usr/bin/env python3
"""
DmAVID Error Analysis + Pattern Synthesis + KB Update Pipeline.

Combines three Perplexity-recommended agents into one script:
1. Error-Explainer: Analyzes why FN/hard cases were misclassified
2. Pattern-Synthesis: Proposes new KB entries from FN patterns
3. KB-Update: Merges approved patterns into RAG knowledge base

Usage:
  python scripts/21_error_analysis.py --phase analyze   # Extract FN + hard cases
  python scripts/21_error_analysis.py --phase explain    # Run Error-Explainer agent (OpenAI)
  python scripts/21_error_analysis.py --phase synthesize # Run Pattern-Synthesis agent (OpenAI)
  python scripts/21_error_analysis.py --phase update-kb  # Update KB with approved patterns
  python scripts/21_error_analysis.py --phase all        # Run all phases
"""
import os, sys, json, time, argparse, logging
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _model_compat import token_param
from openai import OpenAI

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = os.environ.get("DAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL = os.environ.get("DAVID_MODEL", "gpt-5.4-mini")
client = OpenAI()

BASELINE_FILE = os.path.join(BASE_DIR, "experiments/llm_rag/llm_rag_results.json")
HYBRID_FILE = os.path.join(BASE_DIR, "experiments/hybrid/self_verify_results.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments/agentic")
KB_FILE = os.path.join(BASE_DIR, "scripts/knowledge/vulnerability_knowledge.json")
DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")


# ============================================================
# Phase 1: Analyze — Extract FN + hard cases
# ============================================================
def phase_analyze(baseline_path, hybrid_path):
    logger.info("[ANALYZE] Extracting FN and hard cases...")

    with open(baseline_path) as f:
        baseline = json.load(f)
    with open(hybrid_path) as f:
        hybrid = json.load(f)

    base_results = baseline.get("results", [])
    hybr_results = hybrid.get("samples", hybrid.get("results", []))

    # Index by contract_id
    base_idx = {r.get("contract_id", ""): r for r in base_results}
    hybr_idx = {r.get("contract_id", ""): r for r in hybr_results}

    # Load filepath map
    filepath_map = {}
    if os.path.exists(DATASET_FILE):
        with open(DATASET_FILE) as f:
            ds = json.load(f)
        for c in ds["contracts"]:
            filepath_map[c.get("id", "")] = c.get("filepath", "")

    cases = []
    fn_cases = []

    for cid, hr in hybr_idx.items():
        br = base_idx.get(cid, {})
        gt = hr.get("ground_truth", "")
        if gt not in ("vulnerable", "safe"):
            continue

        h_pred = hr.get("hybrid_pred_vuln", hr.get("predicted_vulnerable", False))
        h_conf = hr.get("stage1_conf", hr.get("confidence", 0.5))
        b_pred = br.get("predicted_vulnerable", False)
        b_conf = br.get("confidence", 0.5)

        case_type = None
        if gt == "vulnerable" and not h_pred:
            case_type = "FN"
        elif gt == "vulnerable" and h_pred and h_conf < 0.8:
            case_type = "hard_TP"
        elif gt == "safe" and h_pred and h_conf < 0.8:
            case_type = "hard_FP"

        if not case_type:
            continue

        # Load contract source
        fp = filepath_map.get(cid, "")
        code = ""
        if fp and os.path.exists(fp):
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()[:8000]
            except Exception:
                pass

        case = {
            "contract_id": cid,
            "category": hr.get("category", br.get("category", "")),
            "ground_truth": gt,
            "case_type": case_type,
            "baseline_pred": b_pred,
            "baseline_conf": b_conf,
            "baseline_reason": str(br.get("reasoning", ""))[:500],
            "hybrid_pred": h_pred,
            "hybrid_conf": h_conf,
            "hybrid_reason": str(hr.get("verify_reason", hr.get("reasoning", "")))[:500],
            "code_snippet": code[:3000],
        }
        cases.append(case)
        if case_type == "FN":
            fn_cases.append(case)

    output = {
        "model": MODEL,
        "baseline_metrics": baseline.get("metrics", {}),
        "total_cases": len(cases),
        "fn_count": len(fn_cases),
        "cases": cases,
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "error_analysis_cases.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    logger.info(f"[ANALYZE] Found {len(cases)} cases: {len(fn_cases)} FN, "
                f"{sum(1 for c in cases if c['case_type']=='hard_TP')} hard_TP, "
                f"{sum(1 for c in cases if c['case_type']=='hard_FP')} hard_FP")
    logger.info(f"[ANALYZE] Saved to {out_path}")
    return cases, fn_cases


# ============================================================
# Phase 2: Explain — Run Error-Explainer agent on each case
# ============================================================
def phase_explain(cases):
    logger.info(f"[EXPLAIN] Running Error-Explainer on {len(cases)} cases...")
    explanations = []

    for i, case in enumerate(cases):
        prompt = f"""You are an expert Ethereum smart contract security auditor.

We have a {case['case_type']} case in our detection pipeline:
- Contract: {case['contract_id'][:50]}
- Category: {case['category']}
- Ground truth: {case['ground_truth'].upper()}
- Baseline LLM+RAG: {'VULNERABLE' if case['baseline_pred'] else 'SAFE'} (conf={case['baseline_conf']:.2f})
- After Self-Verify: {'VULNERABLE' if case['hybrid_pred'] else 'SAFE'} (conf={case['hybrid_conf']:.2f})
- Baseline reasoning: {case['baseline_reason'][:300]}

Contract code (excerpt):
```solidity
{case['code_snippet'][:2000]}
```

Analyze:
1. Why did our pipeline {'miss this vulnerability' if case['case_type']=='FN' else 'struggle with this case'}?
2. What patterns are present but not in our RAG knowledge base?
3. What new detection rule would catch this?

Respond JSON only:
{{"root_causes": ["..."], "missing_patterns": ["..."], "suggested_rule": "..."}}"""

        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                **token_param(1024),
            )
            content = resp.choices[0].message.content.strip()
            tokens = resp.usage.total_tokens if resp.usage else 0

            import re
            match = re.search(r"\{[\s\S]*\}", content)
            parsed = json.loads(match.group()) if match else {"raw": content[:500]}

            explanations.append({
                "contract_id": case["contract_id"],
                "case_type": case["case_type"],
                "category": case["category"],
                "explanation": parsed,
                "tokens_used": tokens,
            })
            logger.info(f"  [{i+1}/{len(cases)}] {case['case_type']} {case['contract_id'][:40]} — "
                        f"{len(parsed.get('root_causes', []))} root causes, {tokens} tokens")

        except Exception as e:
            logger.error(f"  [{i+1}] Error: {e}")
            explanations.append({
                "contract_id": case["contract_id"],
                "case_type": case["case_type"],
                "error": str(e),
            })

        time.sleep(0.2)

    out_path = os.path.join(OUTPUT_DIR, "error_explanations.json")
    with open(out_path, "w") as f:
        json.dump(explanations, f, indent=2, ensure_ascii=False)
    logger.info(f"[EXPLAIN] Saved {len(explanations)} explanations to {out_path}")
    return explanations


# ============================================================
# Phase 3: Synthesize — Propose new KB patterns from FN batch
# ============================================================
def phase_synthesize(fn_cases):
    if not fn_cases:
        logger.info("[SYNTHESIZE] No FN cases to synthesize from")
        return []

    logger.info(f"[SYNTHESIZE] Synthesizing patterns from {len(fn_cases)} FN cases...")

    examples = ""
    for i, c in enumerate(fn_cases[:5]):
        examples += f"\nFN #{i+1}: {c['contract_id'][:40]}\n"
        examples += f"  Category: {c['category']}\n"
        examples += f"  Baseline reason: {c['baseline_reason'][:200]}\n"
        examples += f"  Code: {c['code_snippet'][:500]}\n"

    prompt = f"""You are a smart contract vulnerability research expert.

We have {len(fn_cases)} FALSE NEGATIVE cases — contracts that ARE vulnerable but our LLM+RAG system predicted SAFE.

Examples:
{examples}

Your task:
1. Identify common patterns across these FN cases
2. Propose 1-3 new vulnerability pattern categories for our RAG knowledge base
3. For each, provide: name, description, vulnerable code pattern, safe pattern, detection hints

Respond JSON only:
{{"proposed_patterns": [{{"category": "...", "title": "...", "description": "...", "vulnerability_pattern": "...", "safe_pattern": "...", "detection_hints": ["..."]}}]}}"""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            **token_param(2048),
        )
        content = resp.choices[0].message.content.strip()
        tokens = resp.usage.total_tokens if resp.usage else 0

        import re
        match = re.search(r"\{[\s\S]*\}", content)
        parsed = json.loads(match.group()) if match else {"raw": content}
        patterns = parsed.get("proposed_patterns", [])

        out_path = os.path.join(OUTPUT_DIR, "proposed_patterns.json")
        with open(out_path, "w") as f:
            json.dump({"patterns": patterns, "tokens_used": tokens, "fn_count": len(fn_cases)},
                      f, indent=2, ensure_ascii=False)
        logger.info(f"[SYNTHESIZE] Proposed {len(patterns)} new patterns ({tokens} tokens)")
        logger.info(f"[SYNTHESIZE] Saved to {out_path}")
        return patterns

    except Exception as e:
        logger.error(f"[SYNTHESIZE] Error: {e}")
        return []


# ============================================================
# Phase 4: Update KB — Merge approved patterns into knowledge base
# ============================================================
def phase_update_kb(patterns):
    if not patterns:
        logger.info("[UPDATE-KB] No patterns to merge")
        return

    logger.info(f"[UPDATE-KB] Merging {len(patterns)} patterns into knowledge base...")

    # Load existing KB
    kb = {"metadata": {}, "entries": []}
    if os.path.exists(KB_FILE):
        with open(KB_FILE) as f:
            kb = json.load(f)

    existing_ids = {e.get("id", "") for e in kb.get("entries", [])}
    added = 0

    for p in patterns:
        entry_id = f"AGENT-{p.get('category', 'unknown').upper()}-{int(time.time())}-{added}"
        if entry_id in existing_ids:
            continue

        entry = {
            "id": entry_id,
            "category": p.get("category", "unknown"),
            "title": p.get("title", "Agent-discovered pattern"),
            "description": p.get("description", ""),
            "vulnerability_pattern": p.get("vulnerability_pattern", ""),
            "safe_pattern": p.get("safe_pattern", ""),
            "mitigation": "See detection hints",
            "severity": "Medium",
            "swc_id": "Custom",
            "real_world_case": "Discovered via DmAVID error analysis",
            "source": "DmAVID Pattern-Synthesis Agent",
        }
        kb["entries"].append(entry)
        added += 1
        logger.info(f"  Added: {entry_id} — {entry['title'][:60]}")

    kb["metadata"]["total_entries"] = len(kb["entries"])
    kb["metadata"]["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")

    with open(KB_FILE, "w") as f:
        json.dump(kb, f, indent=2, ensure_ascii=False)

    logger.info(f"[UPDATE-KB] Added {added} new entries. Total: {len(kb['entries'])}")


# ============================================================
# Main
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="DmAVID Error Analysis Pipeline")
    parser.add_argument("--phase", choices=["analyze", "explain", "synthesize", "update-kb", "all"],
                        default="all")
    parser.add_argument("--baseline", default=BASELINE_FILE)
    parser.add_argument("--hybrid", default=HYBRID_FILE)
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("DmAVID Error Analysis Pipeline")
    logger.info(f"Model: {MODEL} | Phase: {args.phase}")
    logger.info("=" * 60)

    cases, fn_cases = [], []
    explanations = []
    patterns = []

    if args.phase in ("analyze", "all"):
        cases, fn_cases = phase_analyze(args.baseline, args.hybrid)

    if args.phase in ("explain", "all"):
        if not cases:
            # Load from saved file
            saved = os.path.join(OUTPUT_DIR, "error_analysis_cases.json")
            if os.path.exists(saved):
                with open(saved) as f:
                    data = json.load(f)
                cases = data.get("cases", [])
                fn_cases = [c for c in cases if c["case_type"] == "FN"]
        explanations = phase_explain(cases)

    if args.phase in ("synthesize", "all"):
        if not fn_cases:
            saved = os.path.join(OUTPUT_DIR, "error_analysis_cases.json")
            if os.path.exists(saved):
                with open(saved) as f:
                    data = json.load(f)
                fn_cases = [c for c in data.get("cases", []) if c["case_type"] == "FN"]
        patterns = phase_synthesize(fn_cases)

    if args.phase in ("update-kb", "all"):
        if not patterns:
            saved = os.path.join(OUTPUT_DIR, "proposed_patterns.json")
            if os.path.exists(saved):
                with open(saved) as f:
                    patterns = json.load(f).get("patterns", [])
        phase_update_kb(patterns)

    logger.info("\n" + "=" * 60)
    logger.info("Pipeline complete.")
    logger.info(f"Cases: {len(cases)} | Explanations: {len(explanations)} | New patterns: {len(patterns)}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
