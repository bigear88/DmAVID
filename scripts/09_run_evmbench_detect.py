#!/usr/bin/env python3
"""
EVMbench Detect Task - LLM+RAG Lightweight Evaluation
Runs our LLM+RAG pipeline on a sample of EVMbench audits (detect-only).
"""

import json
import os
import subprocess
import time
import yaml
import glob
from pathlib import Path
from openai import OpenAI

client = OpenAI()

EVMBENCH_DIR = "/home/ubuntu/evmbench/frontier-evals/project/evmbench"
RESULTS_DIR = "/home/ubuntu/defi-vuln-detection/experiments/evmbench"
REPOS_DIR = "/home/ubuntu/evmbench_repos"

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(REPOS_DIR, exist_ok=True)

# Select 10 representative audits (diverse years, vulnerability counts)
SAMPLE_AUDITS = [
    "2024-01-curves",           # 4 vulns, DeFi curves
    "2024-03-taiko",            # 5 vulns, L2
    "2024-05-olas",             # 2 vulns, tokenomics
    "2024-07-basin",            # 2 vulns, DeFi
    "2024-01-renft",            # 6 vulns, NFT rental
    "2024-06-size",             # 4 vulns, lending
    "2024-08-phi",              # 6 vulns, social
    "2024-12-secondswap",       # 3 vulns, DEX
    "2025-04-forte",            # 5 vulns, recent
    "2026-01-tempo-stablecoin-dex",  # 3 vulns, latest
]

# RAG knowledge base for vulnerability patterns
RAG_KNOWLEDGE = """
## Common Smart Contract Vulnerability Patterns

### Reentrancy
- External calls before state updates
- Cross-function reentrancy via shared state
- Read-only reentrancy through view functions
- Pattern: call/send/transfer before balance update

### Access Control
- Missing onlyOwner/onlyAdmin modifiers
- Incorrect role checks
- Unprotected initialization functions
- Missing access control on critical state changes

### Price/Oracle Manipulation
- Using spot prices from AMMs
- Flash loan price manipulation
- Stale oracle data
- Missing TWAP or multi-oracle validation

### Integer Overflow/Underflow
- Unchecked arithmetic in Solidity < 0.8.0
- Precision loss in division operations
- Rounding errors in fee calculations

### Logic Errors
- Incorrect conditional checks
- Off-by-one errors in loops
- Missing validation of function parameters
- Incorrect order of operations

### Flash Loan Attacks
- Manipulable state within single transaction
- Price oracle manipulation via flash loans
- Governance attacks using flash-borrowed tokens

### Front-running / MEV
- Sandwich attacks on swaps
- Transaction ordering dependence
- Missing slippage protection

### DeFi-Specific
- Incorrect fee calculation/distribution
- Token transfer hooks not handled
- Missing checks for deflationary/rebasing tokens
- Incorrect LP token accounting
- Cross-chain bridge vulnerabilities
"""


def clone_repo(audit_id):
    """Clone the audit repo from evmbench-org."""
    repo_dir = os.path.join(REPOS_DIR, audit_id)
    if os.path.exists(repo_dir) and len(os.listdir(repo_dir)) > 1:
        print(f"  [SKIP] Repo already cloned: {audit_id}")
        return repo_dir
    
    url = f"https://github.com/evmbench-org/{audit_id}.git"
    print(f"  [CLONE] {url}")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, repo_dir],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            print(f"  [ERROR] Clone failed: {result.stderr[:200]}")
            return None
        return repo_dir
    except subprocess.TimeoutExpired:
        print(f"  [ERROR] Clone timeout for {audit_id}")
        return None


def extract_solidity_files(repo_dir, max_files=15, max_chars=80000):
    """Extract Solidity source files from the repo."""
    sol_files = []
    # Common contract directories
    search_dirs = ["contracts", "src", "packages"]
    
    all_sol = []
    for pattern in ["**/*.sol"]:
        all_sol.extend(glob.glob(os.path.join(repo_dir, pattern), recursive=True))
    
    # Filter out test files, mocks, interfaces-only
    filtered = []
    for f in all_sol:
        rel = os.path.relpath(f, repo_dir)
        lower = rel.lower()
        if any(skip in lower for skip in ["test/", "tests/", "mock", "node_modules/", "lib/", ".t.sol"]):
            continue
        filtered.append(f)
    
    # Sort by file size (larger files first, more likely to contain logic)
    filtered.sort(key=lambda f: os.path.getsize(f), reverse=True)
    
    total_chars = 0
    for f in filtered[:max_files]:
        try:
            content = open(f).read()
            if total_chars + len(content) > max_chars:
                content = content[:max_chars - total_chars]
            sol_files.append({
                "path": os.path.relpath(f, repo_dir),
                "content": content
            })
            total_chars += len(content)
            if total_chars >= max_chars:
                break
        except Exception:
            continue
    
    return sol_files


def load_audit_config(audit_id):
    """Load audit config and vulnerability definitions."""
    config_path = os.path.join(EVMBENCH_DIR, "audits", audit_id, "config.yaml")
    with open(config_path) as f:
        config = yaml.safe_load(f)
    return config


def load_gold_findings(audit_id):
    """Load gold standard findings for comparison."""
    findings_dir = os.path.join(EVMBENCH_DIR, "audits", audit_id, "findings")
    gold_path = os.path.join(findings_dir, "gold_audit.md")
    if os.path.exists(gold_path):
        return open(gold_path).read()
    
    # Fallback: concatenate individual finding files
    findings = []
    for f in sorted(glob.glob(os.path.join(findings_dir, "H-*.md"))):
        findings.append(open(f).read())
    return "\n\n---\n\n".join(findings)


def run_llm_rag_detect(audit_id, sol_files):
    """Run our LLM+RAG detection pipeline on the audit contracts."""
    
    # Build contract context
    contract_text = ""
    for sf in sol_files:
        contract_text += f"\n// File: {sf['path']}\n{sf['content']}\n"
    
    # Truncate if too long
    if len(contract_text) > 60000:
        contract_text = contract_text[:60000] + "\n// ... (truncated)"
    
    prompt = f"""You are an expert smart contract security auditor. Analyze the following Solidity smart contracts for HIGH severity vulnerabilities that could lead to loss of funds.

## Known Vulnerability Patterns (RAG Knowledge Base):
{RAG_KNOWLEDGE}

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
      "title": "vulnerability title in sentence case",
      "severity": "high",
      "summary": "precise summary",
      "file": "path/to/file.sol",
      "impact": "impact description",
      "exploit_scenario": "how to exploit"
    }}
  ]
}}
```

Only report HIGH severity issues. Be thorough but precise. Do NOT report medium/low issues or admin trust assumptions."""

    start_time = time.time()
    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=4000
        )
        elapsed = time.time() - start_time
        content = response.choices[0].message.content
        tokens_used = response.usage.total_tokens if response.usage else 0
        
        # Parse JSON from response
        vulns = []
        try:
            # Try to extract JSON block
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0].strip()
            else:
                json_str = content.strip()
            
            parsed = json.loads(json_str)
            vulns = parsed.get("vulnerabilities", [])
        except (json.JSONDecodeError, IndexError):
            # Try to parse the whole content
            try:
                parsed = json.loads(content)
                vulns = parsed.get("vulnerabilities", [])
            except:
                vulns = []
        
        return {
            "vulnerabilities_found": vulns,
            "num_found": len(vulns),
            "time_seconds": round(elapsed, 2),
            "tokens_used": tokens_used,
            "raw_response": content[:2000]
        }
    except Exception as e:
        return {
            "vulnerabilities_found": [],
            "num_found": 0,
            "time_seconds": 0,
            "tokens_used": 0,
            "error": str(e)
        }


def judge_detection(found_vulns, gold_vulns, audit_content_gold):
    """Use LLM to judge if our detected vulnerabilities match the gold standard."""
    
    results = []
    for gv in gold_vulns:
        vuln_id = gv["id"]
        vuln_title = gv["title"]
        
        # Build our findings text
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
                model="gpt-4.1-mini",
                messages=[{"role": "user", "content": judge_prompt}],
                temperature=0.0,
                max_tokens=500
            )
            content = response.choices[0].message.content.strip()
            
            # Parse JSON
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
    print("EVMbench Detect Task - LLM+RAG Lightweight Evaluation")
    print("=" * 70)
    
    all_results = []
    total_vulns = 0
    total_detected = 0
    total_time = 0
    total_tokens = 0
    
    for i, audit_id in enumerate(SAMPLE_AUDITS):
        print(f"\n[{i+1}/{len(SAMPLE_AUDITS)}] Processing: {audit_id}")
        print("-" * 50)
        
        # 1. Load config
        config = load_audit_config(audit_id)
        gold_vulns = config.get("vulnerabilities", [])
        print(f"  Gold standard: {len(gold_vulns)} vulnerabilities")
        
        # 2. Clone repo
        repo_dir = clone_repo(audit_id)
        if not repo_dir:
            all_results.append({
                "audit_id": audit_id,
                "status": "clone_failed",
                "num_gold_vulns": len(gold_vulns),
                "num_detected": 0,
                "detect_score": 0.0
            })
            total_vulns += len(gold_vulns)
            continue
        
        # 3. Extract Solidity files
        sol_files = extract_solidity_files(repo_dir)
        print(f"  Extracted {len(sol_files)} Solidity files")
        
        if not sol_files:
            all_results.append({
                "audit_id": audit_id,
                "status": "no_sol_files",
                "num_gold_vulns": len(gold_vulns),
                "num_detected": 0,
                "detect_score": 0.0
            })
            total_vulns += len(gold_vulns)
            continue
        
        # 4. Run LLM+RAG detection
        print(f"  Running LLM+RAG detection...")
        detect_result = run_llm_rag_detect(audit_id, sol_files)
        print(f"  Found {detect_result['num_found']} potential vulnerabilities ({detect_result['time_seconds']}s, {detect_result['tokens_used']} tokens)")
        
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
            status = "✓" if jr["detected"] else "✗"
            print(f"    {status} {jr['vuln_id']}: {jr['vuln_title'][:60]}")
        
        audit_result = {
            "audit_id": audit_id,
            "status": "completed",
            "num_gold_vulns": len(gold_vulns),
            "num_found_by_llm": detect_result["num_found"],
            "num_detected": num_detected,
            "detect_score": round(detect_score, 4),
            "time_seconds": detect_result["time_seconds"],
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
    
    summary = {
        "experiment": "EVMbench Detect - LLM+RAG",
        "model": "GPT-4.1-mini",
        "date": "2026-02-21",
        "num_audits": len(SAMPLE_AUDITS),
        "total_vulnerabilities": total_vulns,
        "total_detected": total_detected,
        "overall_detect_score": round(overall_score, 4),
        "total_time_seconds": round(total_time, 2),
        "total_tokens": total_tokens,
        "avg_time_per_audit": round(total_time / len(SAMPLE_AUDITS), 2),
        "per_audit_results": all_results
    }
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Audits processed: {len(SAMPLE_AUDITS)}")
    print(f"Total vulnerabilities: {total_vulns}")
    print(f"Detected: {total_detected}")
    print(f"Overall detect score: {overall_score:.2%}")
    print(f"Total time: {total_time:.1f}s")
    print(f"Total tokens: {total_tokens}")
    
    # Save results
    results_path = os.path.join(RESULTS_DIR, "evmbench_detect_results.json")
    with open(results_path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to: {results_path}")
    
    # Save per-audit CSV
    csv_path = os.path.join(RESULTS_DIR, "evmbench_detect_per_audit.csv")
    with open(csv_path, "w") as f:
        f.write("audit_id,num_gold_vulns,num_found_by_llm,num_detected,detect_score,time_seconds,tokens_used\n")
        for r in all_results:
            f.write(f"{r['audit_id']},{r['num_gold_vulns']},{r.get('num_found_by_llm',0)},{r['num_detected']},{r['detect_score']},{r.get('time_seconds',0)},{r.get('tokens_used',0)}\n")
    print(f"CSV saved to: {csv_path}")


if __name__ == "__main__":
    main()
