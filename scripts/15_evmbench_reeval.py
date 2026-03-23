#!/usr/bin/env python3
"""
DavidAgent EVMbench Re-evaluation: Re-tests on EVMbench after adversarial enhancement

This script runs after the adversarial iteration loop (14_adversarial_iterate.py) to
measure improvements in vulnerability detection on the EVMbench benchmark.

Key Design:
- Uses ENHANCED knowledge base (post-iteration) with newly discovered patterns
- Applies Hybrid detection (Slither + GPT-4.1-mini + enhanced RAG) on all 10 EVMbench audits
- Compares against baseline (7.69% initial detect rate) to measure improvement
- Generates comparison metrics and identifies newly detected vulnerabilities
"""

import json
import os
import subprocess
import time
import yaml
import glob
import re
from pathlib import Path
from datetime import datetime
from openai import OpenAI

import sys; sys.path.insert(0, os.path.dirname(__file__))
from _model_compat import token_param, MODEL as COMPAT_MODEL

client = OpenAI()
MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")

# Base directory for knowledge bases and results
BASE_DIR = os.environ.get("DAVID_BASE_DIR", "/home/curtis/defi-llm-vulnerability-detection")
EVMBENCH_DIR = os.path.join(BASE_DIR, "data", "evmbench")
REPOS_DIR = os.path.join(BASE_DIR, "data", "evmbench_repos")
KB_DIR = os.path.join(BASE_DIR, "knowledge_bases")
RESULTS_DIR = os.path.join(BASE_DIR, "experiments/evmbench_reeval")
BASELINE_RESULTS_DIR = os.path.join(BASE_DIR, "experiments/evmbench")

os.makedirs(RESULTS_DIR, exist_ok=True)

# EVMbench audits from Paradigm + OpenAI
EVMBENCH_AUDITS = [
    "2024-01-curves",
    "2024-03-taiko",
    "2024-05-olas",
    "2024-07-basin",
    "2024-01-renft",
    "2024-06-size",
    "2024-08-phi",
    "2024-12-secondswap",
    "2025-04-forte",
    "2026-01-tempo-stablecoin-dex",
]

SOLC_VERSIONS = {
    "0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12",
    "0.7": "0.7.6", "0.8": "0.8.0"
}


def detect_solc_version(code):
    """Detect Solidity compiler version from pragma statement."""
    match = re.search(r'pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)', code)
    return SOLC_VERSIONS.get(match.group(1), "0.8.0") if match else "0.8.0"


def load_enhanced_knowledge_base():
    """
    Load the ENHANCED knowledge base that was updated during adversarial iteration.
    Falls back to baseline if enhanced KB doesn't exist.

    Returns:
        str: Combined knowledge base with standard patterns + enhanced patterns
    """
    # Try to load enhanced KB from adversarial iteration
    enhanced_kb_path = os.path.join(KB_DIR, "knowledge_base_enhanced.json")
    baseline_kb_path = os.path.join(KB_DIR, "knowledge_base.json")

    base_patterns = """
## Common Smart Contract Vulnerability Patterns

### Reentrancy
- External calls before state updates
- Cross-function reentrancy via shared state
- Read-only reentrancy through view functions
- Callbacks during transfers

### Access Control
- Missing onlyOwner/onlyAdmin modifiers
- Incorrect role checks
- Unprotected initialization functions
- Delegatecall to user-supplied contracts

### Price/Oracle Manipulation
- Using spot prices from AMMs
- Flash loan price manipulation
- Stale oracle data
- Multi-block MEV attacks

### Logic Errors
- Incorrect conditional checks
- Off-by-one errors in loops
- Missing validation of function parameters
- Incorrect order of operations
- State not properly updated after operations

### Flash Loan Attacks
- Manipulable state within single transaction
- Governance attacks using flash-borrowed tokens
- Cross-protocol flash loan exploits

### DeFi-Specific
- Incorrect fee calculation/distribution
- Token transfer hooks not handled
- Missing checks for deflationary/rebasing tokens
- Incorrect LP token accounting
- Sandwich attacks in swaps
"""

    enhanced_patterns = ""

    # Try to load enhanced patterns from iteration
    if os.path.exists(enhanced_kb_path):
        try:
            with open(enhanced_kb_path) as f:
                enhanced_data = json.load(f)
                if isinstance(enhanced_data, dict):
                    patterns = enhanced_data.get("new_patterns", [])
                    if patterns:
                        enhanced_patterns = "\n## New Patterns Discovered During Adversarial Iteration\n"
                        for pattern in patterns[:20]:  # Limit to 20 patterns
                            if isinstance(pattern, dict):
                                title = pattern.get("title", "Unknown")
                                desc = pattern.get("description", "")
                                enhanced_patterns += f"- {title}: {desc}\n"
                            else:
                                enhanced_patterns += f"- {pattern}\n"
        except Exception as e:
            print(f"  [Warning] Could not load enhanced KB from {enhanced_kb_path}: {e}")

    # Fallback: try baseline KB
    if not enhanced_patterns and os.path.exists(baseline_kb_path):
        try:
            with open(baseline_kb_path) as f:
                baseline_data = json.load(f)
                if isinstance(baseline_data, dict):
                    patterns = baseline_data.get("patterns", [])
                    if patterns:
                        enhanced_patterns = "\n## Additional Patterns from Baseline\n"
                        for pattern in patterns[:15]:
                            if isinstance(pattern, dict):
                                enhanced_patterns += f"- {pattern.get('name', 'Unknown')}\n"
        except Exception as e:
            print(f"  [Info] Could not load baseline KB: {e}")

    return base_patterns + enhanced_patterns


def extract_solidity_files(repo_dir, max_files=15, max_chars=80000):
    """Extract Solidity source files from repository."""
    all_sol = glob.glob(os.path.join(repo_dir, "**/*.sol"), recursive=True)

    filtered = []
    for f in all_sol:
        rel = os.path.relpath(f, repo_dir)
        lower = rel.lower()
        if any(skip in lower for skip in ["test/", "tests/", "mock", "node_modules/", "lib/", ".t.sol"]):
            continue
        filtered.append(f)

    filtered.sort(key=lambda f: os.path.getsize(f), reverse=True)

    sol_files = []
    total_chars = 0
    for f in filtered[:max_files]:
        try:
            content = open(f).read()
            if total_chars + len(content) > max_chars:
                content = content[:max_chars - total_chars]
            sol_files.append({
                "path": os.path.relpath(f, repo_dir),
                "content": content,
                "abs_path": f
            })
            total_chars += len(content)
            if total_chars >= max_chars:
                break
        except Exception:
            continue
    return sol_files


def run_slither_on_files(sol_files, timeout_per_file=60):
    """Run Slither on each Solidity file and collect ALL findings."""
    all_findings = []
    files_with_alerts = 0

    for sf in sol_files:
        filepath = sf["abs_path"]
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            ver = detect_solc_version(code)
            subprocess.run(["solc-select", "use", ver], capture_output=True, timeout=5)

            r = subprocess.run(
                ["slither", filepath, "--json", "-"],
                capture_output=True, text=True, timeout=timeout_per_file
            )

            if r.stdout:
                try:
                    out = json.loads(r.stdout)
                    detectors = out.get("results", {}).get("detectors", [])
                    if detectors:
                        files_with_alerts += 1
                    for d in detectors:
                        all_findings.append({
                            "file": sf["path"],
                            "check": d.get("check", "unknown"),
                            "impact": d.get("impact", "unknown"),
                            "confidence": d.get("confidence", "unknown"),
                            "description": d.get("description", "")[:300],
                        })
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            all_findings.append({
                "file": sf["path"],
                "check": "timeout",
                "impact": "Unknown",
                "confidence": "Unknown",
                "description": f"Slither timed out"
            })
        except Exception as e:
            pass

    return all_findings, files_with_alerts


def format_slither_for_hybrid(findings):
    """Format Slither findings as attention anchors for LLM."""
    if not findings:
        return "NO_ALERTS"

    high_med = [f for f in findings if f["impact"] in ["High", "Medium"]]
    low_info = [f for f in findings if f["impact"] in ["Low", "Informational"]]
    other = [f for f in findings if f["impact"] not in ["High", "Medium", "Low", "Informational"]]

    parts = []
    parts.append(f"Total Slither alerts: {len(findings)} ({len(high_med)} High/Med, {len(low_info)} Low/Info)")

    if high_med:
        parts.append("\nHIGH/MEDIUM severity alerts:")
        for f in high_med[:8]:
            parts.append(f"  - [{f['impact']}/{f['confidence']}] {f['check']} in {f['file']}")
            parts.append(f"    {f['description'][:200]}")

    if low_info:
        parts.append(f"\nLOW/INFORMATIONAL alerts ({len(low_info)} total):")
        check_types = {}
        for f in low_info:
            key = f['check']
            if key not in check_types:
                check_types[key] = []
            check_types[key].append(f['file'])
        for check, files in list(check_types.items())[:10]:
            parts.append(f"  - {check}: found in {', '.join(set(files[:3]))}")

    return "\n".join(parts)


def load_audit_config(audit_id):
    """Load EVMbench audit configuration."""
    config_path = os.path.join(EVMBENCH_DIR, "audits", audit_id, "config.yaml")
    if os.path.exists(config_path):
        with open(config_path) as f:
            return yaml.safe_load(f)
    return {"vulnerabilities": []}


def run_evmbench_detect(audit_id, sol_files, slither_findings, knowledge_base):
    """
    Run enhanced Hybrid detection on EVMbench audit.

    Args:
        audit_id: EVMbench audit identifier
        sol_files: List of Solidity files
        slither_findings: Slither analysis results
        knowledge_base: Enhanced knowledge base

    Returns:
        dict: Detection results with vulnerabilities found
    """
    contract_text = ""
    for sf in sol_files:
        contract_text += f"\n// File: {sf['path']}\n{sf['content']}\n"
    if len(contract_text) > 60000:
        contract_text = contract_text[:60000] + "\n// ... (truncated)"

    slither_report = format_slither_for_hybrid(slither_findings)
    has_slither_alerts = slither_report != "NO_ALERTS"

    if has_slither_alerts:
        # Hybrid mode with Slither guidance
        prompt = f"""You are an expert smart contract security auditor performing ENHANCED HYBRID ANALYSIS.

## Phase 1: Static Analysis (Slither)
{slither_report}

## Phase 2: Enhanced LLM Deep Analysis
Use Slither's alerts as starting points. Look for deeper vulnerabilities that Slither missed.
Apply the enhanced vulnerability patterns below to identify critical issues.

## Enhanced Vulnerability Knowledge Base:
{knowledge_base}

## Smart Contract Source Code:
{contract_text}

## Task:
1. Use Slither alerts as code region anchors for focused analysis
2. Identify HIGH severity vulnerabilities (loss of funds, unauthorized access)
3. Apply enhanced patterns to find business logic flaws
4. Perform independent analysis beyond Slither findings

Output ONLY a JSON object (no markdown):
{{
  "vulnerabilities": [
    {{
      "title": "vulnerability title",
      "severity": "high",
      "summary": "root cause",
      "file": "path/to/file.sol",
      "impact": "impact description",
      "exploit_scenario": "exploitation method",
      "confidence": "high/medium",
      "slither_connection": "related Slither alert or 'independent'"
    }}
  ],
  "analysis_notes": "brief summary"
}}

ONLY report HIGH severity vulnerabilities. Be precise."""
    else:
        # Fallback: Independent LLM+RAG analysis
        prompt = f"""You are an expert smart contract security auditor. Analyze for HIGH severity vulnerabilities.

## Enhanced Vulnerability Knowledge Base:
{knowledge_base}

## Smart Contract Source Code:
{contract_text}

## Context:
Slither found NO alerts. Perform deep semantic analysis for logic errors and business logic flaws.

## Task:
Identify HIGH severity vulnerabilities (loss of funds, critical logic errors).

Output ONLY a JSON object (no markdown):
{{
  "vulnerabilities": [
    {{
      "title": "vulnerability title",
      "severity": "high",
      "summary": "root cause",
      "file": "path/to/file.sol",
      "impact": "impact description",
      "exploit_scenario": "exploitation method",
      "confidence": "high/medium"
    }}
  ]
}}

Only report HIGH severity issues."""

    start_time = time.time()
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            **token_param(4000),
            seed=42
        )
        elapsed = time.time() - start_time
        content = response.choices[0].message.content
        tokens_used = response.usage.total_tokens if response.usage else 0

        vulns = []
        try:
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0].strip()
            else:
                json_str = content.strip()
            parsed = json.loads(json_str)
            vulns = parsed.get("vulnerabilities", [])
        except (json.JSONDecodeError, IndexError):
            try:
                parsed = json.loads(content)
                vulns = parsed.get("vulnerabilities", [])
            except:
                vulns = []

        return {
            "mode": "enhanced_hybrid" if has_slither_alerts else "enhanced_llm_rag",
            "vulnerabilities_found": vulns,
            "num_found": len(vulns),
            "time_seconds": round(elapsed, 2),
            "tokens_used": tokens_used,
            "slither_alerts_count": len(slither_findings),
            "error": None
        }
    except Exception as e:
        return {
            "mode": "error",
            "vulnerabilities_found": [],
            "num_found": 0,
            "time_seconds": 0,
            "tokens_used": 0,
            "slither_alerts_count": len(slither_findings),
            "error": str(e)
        }


def judge_detection(found_vulns, gold_vulns):
    """Use LLM to judge if detected vulnerabilities match gold standard."""
    results = []
    for gv in gold_vulns:
        vuln_id = gv.get("id", "unknown")
        vuln_title = gv.get("title", "unknown")
        our_findings = json.dumps(found_vulns, indent=2, ensure_ascii=False)

        judge_prompt = f"""Determine if this audit report detected the vulnerability:

TARGET: {vuln_id} - {vuln_title}

FINDINGS: {our_findings}

CRITERIA: Match if report identifies SAME root cause, points to same code mechanism, or describes similar exploit.

Respond ONLY:
{{"detected": true/false, "reasoning": "brief explanation"}}"""

        try:
            response = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": judge_prompt}],
                temperature=0.0,
                **token_param(300),
            )
            content = response.choices[0].message.content.strip()

            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0].strip()
            else:
                json_str = content

            result = json.loads(json_str)
            results.append({
                "vuln_id": vuln_id,
                "vuln_title": vuln_title,
                "detected": result.get("detected", False),
                "reasoning": result.get("reasoning", "")
            })
        except Exception as e:
            results.append({
                "vuln_id": vuln_id,
                "vuln_title": vuln_title,
                "detected": False,
                "reasoning": f"Error: {str(e)}"
            })

    return results


def compare_with_baseline(baseline_results, enhanced_results):
    """
    Compare baseline results with enhanced results.

    Returns:
        dict: Comparison metrics including improvement
    """
    baseline_detected = baseline_results.get("total_detected", 0)
    baseline_total = baseline_results.get("total_vulnerabilities", 1)
    baseline_score = baseline_detected / baseline_total if baseline_total > 0 else 0.0

    enhanced_detected = enhanced_results.get("total_detected", 0)
    enhanced_total = enhanced_results.get("total_vulnerabilities", 1)
    enhanced_score = enhanced_detected / enhanced_total if enhanced_total > 0 else 0.0

    improvement = enhanced_score - baseline_score
    improvement_pct = (improvement / baseline_score * 100) if baseline_score > 0 else 0

    return {
        "baseline_detected": baseline_detected,
        "baseline_total": baseline_total,
        "baseline_score": round(baseline_score, 4),
        "enhanced_detected": enhanced_detected,
        "enhanced_total": enhanced_total,
        "enhanced_score": round(enhanced_score, 4),
        "absolute_improvement": round(improvement, 4),
        "relative_improvement_pct": round(improvement_pct, 2),
        "new_detections": enhanced_detected - baseline_detected
    }


def load_baseline_results():
    """Load baseline EVMbench results for comparison."""
    baseline_path = os.path.join(BASELINE_RESULTS_DIR, "evmbench_hybrid_results.json")
    if os.path.exists(baseline_path):
        try:
            with open(baseline_path) as f:
                return json.load(f)
        except Exception as e:
            print(f"  [Warning] Could not load baseline results: {e}")

    # Fallback: return minimal baseline with 7.69% detect rate
    return {
        "total_vulnerabilities": 39,
        "total_detected": 3,
        "overall_detect_score": 0.0769,
        "per_audit_results": []
    }


def main():
    print("=" * 80)
    print("DavidAgent EVMbench Re-evaluation: Post-Adversarial Iteration")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 80)

    # Load enhanced knowledge base
    print("\n[1/4] Loading enhanced knowledge base...")
    knowledge_base = load_enhanced_knowledge_base()
    print(f"  Knowledge base loaded: {len(knowledge_base)} characters")

    # Load baseline results
    print("[2/4] Loading baseline results...")
    baseline_results = load_baseline_results()
    baseline_score = baseline_results.get("overall_detect_score", 0.0769)
    print(f"  Baseline detect rate: {baseline_score:.2%}")

    # Run enhanced detection on all EVMbench audits
    print("[3/4] Running enhanced detection on EVMbench audits...")
    all_results = []
    total_vulns = 0
    total_detected = 0
    total_time = 0
    total_tokens = 0

    for i, audit_id in enumerate(EVMBENCH_AUDITS):
        print(f"\n  [{i+1}/{len(EVMBENCH_AUDITS)}] {audit_id}")

        # Load config and gold standard
        config = load_audit_config(audit_id)
        gold_vulns = config.get("vulnerabilities", [])
        print(f"    Gold vulnerabilities: {len(gold_vulns)}")

        # Extract Solidity files
        repo_dir = os.path.join(REPOS_DIR, audit_id)
        if not os.path.exists(repo_dir):
            print(f"    [Skip] Repo not found")
            all_results.append({
                "audit_id": audit_id, "status": "repo_not_found",
                "num_gold_vulns": len(gold_vulns), "num_detected": 0
            })
            total_vulns += len(gold_vulns)
            continue

        sol_files = extract_solidity_files(repo_dir)
        if not sol_files:
            print(f"    [Skip] No Solidity files extracted")
            all_results.append({
                "audit_id": audit_id, "status": "no_sol_files",
                "num_gold_vulns": len(gold_vulns), "num_detected": 0
            })
            total_vulns += len(gold_vulns)
            continue

        # Run Slither
        slither_findings, _ = run_slither_on_files(sol_files)
        print(f"    Slither: {len(slither_findings)} alerts")

        # Run enhanced detection
        print(f"    Running enhanced detection...")
        detect_result = run_evmbench_detect(audit_id, sol_files, slither_findings, knowledge_base)
        print(f"    Found: {detect_result['num_found']} potential vulns ({detect_result['time_seconds']}s)")

        # Judge results
        judge_results = judge_detection(detect_result["vulnerabilities_found"], gold_vulns)
        num_detected = sum(1 for jr in judge_results if jr["detected"])

        print(f"    Detected: {num_detected}/{len(gold_vulns)}")

        audit_result = {
            "audit_id": audit_id,
            "status": "completed",
            "num_gold_vulns": len(gold_vulns),
            "num_found_by_enhanced": detect_result["num_found"],
            "num_detected": num_detected,
            "detect_score": round(num_detected / len(gold_vulns) if gold_vulns else 0, 4),
            "time_seconds": detect_result["time_seconds"],
            "tokens_used": detect_result["tokens_used"],
            "judge_results": judge_results
        }
        all_results.append(audit_result)

        total_vulns += len(gold_vulns)
        total_detected += num_detected
        total_time += detect_result["time_seconds"]
        total_tokens += detect_result["tokens_used"]

    # Calculate overall metrics
    enhanced_score = total_detected / total_vulns if total_vulns > 0 else 0

    # Compare with baseline
    print("\n[4/4] Comparing with baseline...")
    enhanced_results = {
        "total_vulnerabilities": total_vulns,
        "total_detected": total_detected,
        "overall_detect_score": enhanced_score
    }
    comparison = compare_with_baseline(baseline_results, enhanced_results)

    # Print summary
    print("\n" + "=" * 80)
    print("EVMbench RE-EVALUATION SUMMARY")
    print("=" * 80)
    print(f"  Audits processed: {len(EVMBENCH_AUDITS)}")
    print(f"  Total gold vulnerabilities: {total_vulns}")
    print(f"  Total detected: {total_detected}")
    print(f"  Enhanced detect rate: {enhanced_score:.2%}")
    print()
    print("  BASELINE vs ENHANCED COMPARISON:")
    print(f"  {'Metric':<35} {'Baseline':<15} {'Enhanced':<15}")
    print(f"  {'-'*65}")
    baseline_score_pct = f"{comparison['baseline_score']:.2%}"
    enhanced_score_pct = f"{comparison['enhanced_score']:.2%}"
    print(f"  {'Detect Rate':<35} {baseline_score_pct:<15} {enhanced_score_pct:<15}")
    baseline_det = str(comparison['baseline_detected'])
    enhanced_det = str(comparison['enhanced_detected'])
    print(f"  {'Vulnerabilities Detected':<35} {baseline_det:<15} {enhanced_det:<15}")
    abs_imp_pct = f"{comparison['absolute_improvement']:.2%}"
    print(f"  {'Absolute Improvement':<35} {'—':<15} {abs_imp_pct:<15}")
    rel_imp = f"{comparison['relative_improvement_pct']}%"
    print(f"  {'Relative Improvement':<35} {'—':<15} {rel_imp:<15}")
    print()

    # Per-audit table
    print("  PER-AUDIT RESULTS:")
    print(f"  {'Audit':<30} {'Gold':>6} {'Enhanced':>8} {'Score':>10}")
    print(f"  {'-'*56}")
    for r in all_results:
        if r["status"] == "completed":
            score_pct = f"{r['detect_score']:.2%}"
            print(f"  {r['audit_id']:<30} {r['num_gold_vulns']:>6} {r['num_detected']:>8} {score_pct:>10}")

    print()
    print(f"  Total LLM time: {total_time:.1f}s")
    print(f"  Total tokens: {total_tokens}")
    print("=" * 80)

    # Save results
    summary = {
        "experiment": "EVMbench Re-evaluation (Post-Adversarial)",
        "model": MODEL,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "timestamp": datetime.now().isoformat(),
        "num_audits": len(EVMBENCH_AUDITS),
        "total_vulnerabilities": total_vulns,
        "total_detected": total_detected,
        "overall_detect_score": round(enhanced_score, 4),
        "total_time_seconds": round(total_time, 2),
        "total_tokens": total_tokens,
        "baseline_comparison": comparison,
        "per_audit_results": all_results
    }

    results_path = os.path.join(RESULTS_DIR, "reeval_results.json")
    with open(results_path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to: {results_path}")


if __name__ == "__main__":
    main()
