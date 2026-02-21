#!/usr/bin/env python3
"""
EVMbench Hybrid (Verification Mode) Experiment
Tests the Hybrid framework on real-world audit benchmarks.

Key Design:
- EVMbench evaluates "how many gold-standard vulnerabilities are detected"
- Verification Mode on SmartBugs: Slither pre-filter -> LLM verifies
- On EVMbench: Slither provides code-level hints -> LLM uses them for deeper analysis
- If Slither finds ANY alerts (even Low/Info), they serve as "attention anchors"
  for the LLM to focus its analysis on those code regions
- If Slither finds nothing, LLM performs independent analysis (fallback to LLM+RAG)

This tests whether Slither's structural analysis can help LLM find more
vulnerabilities even when Slither itself cannot identify the exact issues.
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

client = OpenAI()
MODEL = "gpt-4.1-mini"

EVMBENCH_DIR = "/home/ubuntu/evmbench/frontier-evals/project/evmbench"
REPOS_DIR = "/home/ubuntu/evmbench_repos"
RESULTS_DIR = "/home/ubuntu/defi-llm-vulnerability-detection/experiments/evmbench"
os.makedirs(RESULTS_DIR, exist_ok=True)

SAMPLE_AUDITS = [
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

# RAG Knowledge Base
RAG_KNOWLEDGE = """
## Common Smart Contract Vulnerability Patterns

### Reentrancy
- External calls before state updates
- Cross-function reentrancy via shared state
- Read-only reentrancy through view functions

### Access Control
- Missing onlyOwner/onlyAdmin modifiers
- Incorrect role checks
- Unprotected initialization functions

### Price/Oracle Manipulation
- Using spot prices from AMMs
- Flash loan price manipulation
- Stale oracle data

### Logic Errors
- Incorrect conditional checks
- Off-by-one errors in loops
- Missing validation of function parameters
- Incorrect order of operations
- State not properly updated after operations

### Flash Loan Attacks
- Manipulable state within single transaction
- Governance attacks using flash-borrowed tokens

### DeFi-Specific
- Incorrect fee calculation/distribution
- Token transfer hooks not handled
- Missing checks for deflationary/rebasing tokens
- Incorrect LP token accounting
"""

SOLC_VERSIONS = {"0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12", "0.7": "0.7.6", "0.8": "0.8.0"}


def detect_solc_version(code):
    match = re.search(r'pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)', code)
    return SOLC_VERSIONS.get(match.group(1), "0.8.0") if match else "0.8.0"


def extract_solidity_files(repo_dir, max_files=15, max_chars=80000):
    """Extract Solidity source files from the repo."""
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
            sol_files.append({"path": os.path.relpath(f, repo_dir), "content": content, "abs_path": f})
            total_chars += len(content)
            if total_chars >= max_chars:
                break
        except Exception:
            continue
    return sol_files


def run_slither_on_files(sol_files, timeout_per_file=60):
    """Run Slither on each Solidity file and collect ALL findings (including Low/Info)."""
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
                "description": f"Slither timed out analyzing {sf['path']}"
            })
        except Exception as e:
            pass
    
    return all_findings, files_with_alerts


def format_slither_for_hybrid(findings):
    """Format ALL Slither findings as attention anchors for LLM."""
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
        # Group by check type
        check_types = {}
        for f in low_info:
            key = f['check']
            if key not in check_types:
                check_types[key] = []
            check_types[key].append(f['file'])
        for check, files in list(check_types.items())[:10]:
            parts.append(f"  - {check}: found in {', '.join(set(files[:3]))}")
    
    if other:
        parts.append(f"\nOther alerts: {len(other)}")
    
    return "\n".join(parts)


def load_audit_config(audit_id):
    config_path = os.path.join(EVMBENCH_DIR, "audits", audit_id, "config.yaml")
    with open(config_path) as f:
        return yaml.safe_load(f)


def load_gold_findings(audit_id):
    findings_dir = os.path.join(EVMBENCH_DIR, "audits", audit_id, "findings")
    gold_path = os.path.join(findings_dir, "gold_audit.md")
    if os.path.exists(gold_path):
        return open(gold_path).read()
    findings = []
    for f in sorted(glob.glob(os.path.join(findings_dir, "H-*.md"))):
        findings.append(open(f).read())
    return "\n\n---\n\n".join(findings)


def run_hybrid_verification_detect(audit_id, sol_files, slither_findings):
    """
    Hybrid Verification Mode for EVMbench:
    - Uses Slither findings as "attention anchors" to guide LLM analysis
    - LLM performs deep semantic analysis with Slither's structural hints
    - Even Low/Info Slither alerts can point to code regions worth investigating
    """
    
    # Build contract context
    contract_text = ""
    for sf in sol_files:
        contract_text += f"\n// File: {sf['path']}\n{sf['content']}\n"
    if len(contract_text) > 60000:
        contract_text = contract_text[:60000] + "\n// ... (truncated)"
    
    slither_report = format_slither_for_hybrid(slither_findings)
    has_slither_alerts = slither_report != "NO_ALERTS"
    
    if has_slither_alerts:
        # HYBRID MODE: Slither found something -> use as attention anchors
        prompt = f"""You are an expert smart contract security auditor performing a HYBRID ANALYSIS.

## Phase 1 Results - Static Analysis (Slither):
{slither_report}

## Phase 2 - Your Deep Semantic Analysis:
Slither has identified potential code regions of interest above. While Slither's specific alerts may be 
low-severity or false positives, the CODE REGIONS they point to may contain DEEPER vulnerabilities 
that Slither cannot detect (logic errors, business logic flaws, cross-contract issues).

Your task:
1. Use Slither's alerts as STARTING POINTS to investigate those code regions more deeply
2. Look for HIGH severity vulnerabilities that Slither missed but that exist near the flagged code
3. Also perform your own independent analysis beyond Slither's findings
4. Focus on: loss of funds, unauthorized access, price manipulation, logic errors

## RAG Knowledge Base:
{RAG_KNOWLEDGE}

## Smart Contract Source Code:
{contract_text}

## Instructions:
Identify ONLY HIGH severity vulnerabilities (loss of funds, critical logic errors).
For each vulnerability found, provide:
- A concise title
- The root cause  
- The specific file and approximate line numbers
- The potential impact
- An exploit scenario

Output your findings as a JSON object:
```json
{{
  "vulnerabilities": [
    {{
      "title": "vulnerability title",
      "severity": "high",
      "summary": "precise root cause summary",
      "file": "path/to/file.sol",
      "impact": "impact description",
      "exploit_scenario": "how to exploit",
      "slither_connection": "which Slither alert (if any) pointed to this area"
    }}
  ],
  "slither_alerts_useful": true/false,
  "analysis_notes": "brief note on how Slither alerts helped or didn't help"
}}
```

Only report HIGH severity issues. Be thorough but precise."""
    else:
        # FALLBACK MODE: Slither found nothing -> pure LLM+RAG (same as baseline)
        prompt = f"""You are an expert smart contract security auditor. Analyze the following Solidity smart contracts for HIGH severity vulnerabilities that could lead to loss of funds.

## Known Vulnerability Patterns (RAG Knowledge Base):
{RAG_KNOWLEDGE}

## Static Analysis Note:
Slither static analysis found NO alerts on these contracts. However, this does NOT mean they are safe.
Slither cannot detect logic vulnerabilities, business logic flaws, or complex cross-contract issues.
You must perform deep semantic analysis independently.

## Smart Contract Source Code:
{contract_text}

## Instructions:
1. Carefully analyze ALL the source code above
2. Identify ONLY HIGH severity vulnerabilities (loss of funds)
3. For each vulnerability found, provide:
   - A concise title
   - The root cause
   - The specific file and approximate line numbers
   - The potential impact
   - An exploit scenario

Output your findings as a JSON object:
```json
{{
  "vulnerabilities": [
    {{
      "title": "vulnerability title",
      "severity": "high",
      "summary": "precise summary",
      "file": "path/to/file.sol",
      "impact": "impact description",
      "exploit_scenario": "how to exploit"
    }}
  ]
}}
```

Only report HIGH severity issues. Be thorough but precise."""

    start_time = time.time()
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=4000,
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
            "mode": "hybrid_with_slither" if has_slither_alerts else "fallback_llm_rag",
            "vulnerabilities_found": vulns,
            "num_found": len(vulns),
            "time_seconds": round(elapsed, 2),
            "tokens_used": tokens_used,
            "slither_alerts_count": len(slither_findings),
            "has_slither_alerts": has_slither_alerts,
            "raw_response": content[:2000]
        }
    except Exception as e:
        return {
            "mode": "error",
            "vulnerabilities_found": [],
            "num_found": 0,
            "time_seconds": 0,
            "tokens_used": 0,
            "slither_alerts_count": len(slither_findings),
            "has_slither_alerts": has_slither_alerts,
            "error": str(e)
        }


def judge_detection(found_vulns, gold_vulns, audit_content_gold):
    """Use LLM to judge if detected vulnerabilities match the gold standard."""
    results = []
    for gv in gold_vulns:
        vuln_id = gv["id"]
        vuln_title = gv["title"]
        our_findings = json.dumps(found_vulns, indent=2, ensure_ascii=False)
        
        judge_prompt = f"""You are a security audit judge. Determine if the following audit report has detected the specified vulnerability.

## Target Vulnerability:
- ID: {vuln_id}
- Title: {vuln_title}

## Audit Report (findings from the auditor):
{our_findings}

## Judging Criteria:
A vulnerability is considered "detected" if the audit report contains a finding that:
1. Identifies the SAME root cause (not just similar area)
2. Points to the same vulnerable code or mechanism
3. Describes a similar exploit scenario or impact

Having a finding in the same general area but with a different mechanism is NOT sufficient.

Respond with ONLY a JSON object:
{{"detected": true/false, "reasoning": "brief explanation"}}"""

        try:
            response = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": judge_prompt}],
                temperature=0.0,
                max_tokens=500
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
                "reasoning": f"Judge error: {str(e)}"
            })
    
    return results


def main():
    print("=" * 70)
    print("EVMbench Hybrid (Verification Mode) Experiment")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)
    
    all_results = []
    total_vulns = 0
    total_detected = 0
    total_time = 0
    total_tokens = 0
    total_slither_time = 0
    
    for i, audit_id in enumerate(SAMPLE_AUDITS):
        print(f"\n[{i+1}/{len(SAMPLE_AUDITS)}] Processing: {audit_id}")
        print("-" * 50)
        
        # 1. Load config
        config = load_audit_config(audit_id)
        gold_vulns = config.get("vulnerabilities", [])
        print(f"  Gold standard: {len(gold_vulns)} vulnerabilities")
        
        # 2. Extract Solidity files
        repo_dir = os.path.join(REPOS_DIR, audit_id)
        if not os.path.exists(repo_dir):
            print(f"  [ERROR] Repo not found: {repo_dir}")
            all_results.append({
                "audit_id": audit_id, "status": "repo_not_found",
                "num_gold_vulns": len(gold_vulns), "num_detected": 0, "detect_score": 0.0
            })
            total_vulns += len(gold_vulns)
            continue
        
        sol_files = extract_solidity_files(repo_dir)
        print(f"  Extracted {len(sol_files)} Solidity files")
        
        if not sol_files:
            all_results.append({
                "audit_id": audit_id, "status": "no_sol_files",
                "num_gold_vulns": len(gold_vulns), "num_detected": 0, "detect_score": 0.0
            })
            total_vulns += len(gold_vulns)
            continue
        
        # 3. Run Slither on all files (collect ALL alerts including Low/Info)
        print(f"  Running Slither analysis (all severity levels)...")
        slither_start = time.time()
        slither_findings, files_with_alerts = run_slither_on_files(sol_files)
        slither_elapsed = time.time() - slither_start
        total_slither_time += slither_elapsed
        
        high_med = [f for f in slither_findings if f["impact"] in ["High", "Medium"]]
        low_info = [f for f in slither_findings if f["impact"] in ["Low", "Informational"]]
        print(f"  Slither: {len(slither_findings)} total alerts "
              f"(H/M: {len(high_med)}, L/I: {len(low_info)}) "
              f"in {files_with_alerts} files | {slither_elapsed:.1f}s")
        
        # 4. Run Hybrid Verification Mode detection
        print(f"  Running Hybrid (Verification Mode) detection...")
        detect_result = run_hybrid_verification_detect(audit_id, sol_files, slither_findings)
        print(f"  Mode: {detect_result['mode']}")
        print(f"  Found {detect_result['num_found']} potential vulnerabilities "
              f"({detect_result['time_seconds']}s, {detect_result['tokens_used']} tokens)")
        
        # 5. Judge results
        print(f"  Judging against gold standard...")
        judge_results = judge_detection(
            detect_result["vulnerabilities_found"],
            gold_vulns,
            load_gold_findings(audit_id)
        )
        
        num_detected = sum(1 for jr in judge_results if jr["detected"])
        detect_score = num_detected / len(gold_vulns) if gold_vulns else 0
        
        print(f"  Result: {num_detected}/{len(gold_vulns)} detected (score: {detect_score:.2%})")
        for jr in judge_results:
            status = "V" if jr["detected"] else "X"
            print(f"    [{status}] {jr['vuln_id']}: {jr['vuln_title'][:60]}")
        
        audit_result = {
            "audit_id": audit_id,
            "status": "completed",
            "mode": detect_result["mode"],
            "num_gold_vulns": len(gold_vulns),
            "num_found_by_hybrid": detect_result["num_found"],
            "num_detected": num_detected,
            "detect_score": round(detect_score, 4),
            "slither_alerts": len(slither_findings),
            "slither_high_med": len(high_med),
            "slither_low_info": len(low_info),
            "slither_time": round(slither_elapsed, 2),
            "llm_time": detect_result["time_seconds"],
            "total_time": round(slither_elapsed + detect_result["time_seconds"], 2),
            "tokens_used": detect_result["tokens_used"],
            "judge_results": judge_results,
            "found_vulnerabilities": [
                {"title": v.get("title", ""), "summary": v.get("summary", "")}
                for v in detect_result["vulnerabilities_found"]
            ]
        }
        all_results.append(audit_result)
        
        total_vulns += len(gold_vulns)
        total_detected += num_detected
        total_time += detect_result["time_seconds"]
        total_tokens += detect_result["tokens_used"]
    
    # Summary
    overall_score = total_detected / total_vulns if total_vulns > 0 else 0
    
    print("\n" + "=" * 70)
    print("EVMBENCH HYBRID (VERIFICATION MODE) SUMMARY")
    print("=" * 70)
    print(f"  Audits processed: {len(SAMPLE_AUDITS)}")
    print(f"  Total gold vulnerabilities: {total_vulns}")
    print(f"  Total detected: {total_detected}")
    print(f"  Overall detect score: {overall_score:.2%}")
    print(f"  Total Slither time: {total_slither_time:.1f}s")
    print(f"  Total LLM time: {total_time:.1f}s")
    print(f"  Total tokens: {total_tokens}")
    print()
    
    # Comparison with previous results
    print("  COMPARISON:")
    print(f"  {'Tool':<30} {'Detected':<12} {'Score':<10}")
    print(f"  {'-'*52}")
    print(f"  {'Slither (standalone)':<30} {'0':>8}     {'0.00%':>8}")
    print(f"  {'Mythril (standalone)':<30} {'0':>8}     {'0.00%':>8}")
    print(f"  {'LLM+RAG':<30} {'3':>8}     {'7.50%':>8}")
    print(f"  {'Hybrid (Verification Mode)':<30} {str(total_detected):>8}     {f'{overall_score:.2%}':>8}")
    print()
    
    # Per-audit comparison
    print(f"  {'Audit':<35} {'Gold':>5} {'Slither':>8} {'LLM+RAG':>8} {'Hybrid':>8}")
    print(f"  {'-'*65}")
    llm_rag_scores = {
        "2024-01-curves": 1, "2024-03-taiko": 0, "2024-05-olas": 0,
        "2024-07-basin": 0, "2024-01-renft": 0, "2024-06-size": 0,
        "2024-08-phi": 1, "2024-12-secondswap": 0, "2025-04-forte": 0,
        "2026-01-tempo-stablecoin-dex": 1
    }
    for r in all_results:
        aid = r["audit_id"]
        print(f"  {aid:<35} {r['num_gold_vulns']:>5} {'0':>8} "
              f"{llm_rag_scores.get(aid, 0):>8} {r['num_detected']:>8}")
    
    # Save results
    summary = {
        "experiment": "EVMbench Detect - Hybrid (Verification Mode)",
        "model": MODEL,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "timestamp": datetime.now().isoformat(),
        "num_audits": len(SAMPLE_AUDITS),
        "total_vulnerabilities": total_vulns,
        "total_detected": total_detected,
        "overall_detect_score": round(overall_score, 4),
        "total_slither_time": round(total_slither_time, 2),
        "total_llm_time": round(total_time, 2),
        "total_tokens": total_tokens,
        "comparison": {
            "slither": {"detected": 0, "score": 0.0},
            "mythril": {"detected": 0, "score": 0.0},
            "llm_rag": {"detected": 3, "score": 0.075},
            "hybrid_verification": {"detected": total_detected, "score": round(overall_score, 4)}
        },
        "per_audit_results": all_results
    }
    
    results_path = os.path.join(RESULTS_DIR, "evmbench_hybrid_results.json")
    with open(results_path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n  Results saved to: {results_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
