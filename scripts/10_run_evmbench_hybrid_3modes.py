#!/usr/bin/env python3
"""
EVMbench Hybrid Three-Mode Comparison Experiment

Compares three Hybrid integration strategies on EVMbench real-world audits:
  1. Original Hybrid (OR-like): Slither context fed to LLM, LLM tends to follow Slither
  2. Verification Mode: Slither pre-filter -> LLM as final judge / verifier
  3. Context Mode: LLM always decides, Slither report as advisory reference only

Also includes baseline comparisons:
  - Slither standalone (0% on EVMbench)
  - LLM+RAG standalone (7.50% on EVMbench)

Evaluation metric: detect_score = detected_vulns / total_gold_vulns
"""

import json, os, subprocess, time, yaml, glob, re
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

SOLC_VERSIONS = {"0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12", "0.7": "0.7.6", "0.8": "0.8.0"}

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

# ============================================================
# Utility Functions
# ============================================================

def detect_solc_version(code):
    match = re.search(r'pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)', code)
    return SOLC_VERSIONS.get(match.group(1), "0.8.0") if match else "0.8.0"


def extract_solidity_files(repo_dir, max_files=15, max_chars=80000):
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
    """Run Slither on each file, collect ALL findings including Low/Info."""
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
                "file": sf["path"], "check": "timeout", "impact": "Unknown",
                "confidence": "Unknown", "description": f"Slither timed out on {sf['path']}"
            })
        except Exception:
            pass
    return all_findings, files_with_alerts


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


def format_slither_alerts(findings):
    if not findings:
        return "No alerts from Slither."
    high_med = [f for f in findings if f["impact"] in ["High", "Medium"]]
    low_info = [f for f in findings if f["impact"] in ["Low", "Informational"]]
    parts = [f"Total: {len(findings)} alerts ({len(high_med)} H/M, {len(low_info)} L/I)"]
    if high_med:
        parts.append("HIGH/MEDIUM:")
        for f in high_med[:8]:
            parts.append(f"  - [{f['impact']}/{f['confidence']}] {f['check']} in {f['file']}: {f['description'][:150]}")
    if low_info:
        check_types = {}
        for f in low_info:
            check_types.setdefault(f['check'], []).append(f['file'])
        parts.append(f"LOW/INFO ({len(low_info)}):")
        for check, files in list(check_types.items())[:10]:
            parts.append(f"  - {check}: {', '.join(set(files[:3]))}")
    return "\n".join(parts)


# ============================================================
# MODE 1: ORIGINAL HYBRID (OR-like)
# Slither context directly fed to LLM, LLM tends to follow
# ============================================================

def run_original_hybrid(sol_files, slither_findings, contract_text):
    """Original Hybrid: feed Slither report directly to LLM without guidance to override."""
    slither_report = format_slither_alerts(slither_findings)
    
    prompt = f"""You are an expert smart contract security auditor. You have access to both a vulnerability knowledge base AND a static analysis report from Slither.

## Slither Static Analysis Report:
{slither_report}

## Known Vulnerability Patterns (RAG Knowledge Base):
{RAG_KNOWLEDGE}

## Smart Contract Source Code:
{contract_text}

## Instructions:
1. Review the Slither findings and the source code
2. Identify HIGH severity vulnerabilities (loss of funds, critical logic errors)
3. Consider both Slither's findings and your own analysis
4. For each vulnerability found, provide title, root cause, file, impact, and exploit scenario

Output as JSON:
```json
{{
  "vulnerabilities": [
    {{
      "title": "vulnerability title",
      "severity": "high",
      "summary": "root cause summary",
      "file": "path/to/file.sol",
      "impact": "impact description",
      "exploit_scenario": "how to exploit"
    }}
  ]
}}
```

Only report HIGH severity issues. Be thorough but precise."""

    return _call_llm(prompt)


# ============================================================
# MODE 2: VERIFICATION MODE
# Slither pre-filter -> LLM verifies with skepticism
# ============================================================

def run_verification_mode(sol_files, slither_findings, contract_text):
    """Verification Mode: LLM uses Slither alerts as attention anchors, but judges independently."""
    has_alerts = len(slither_findings) > 0
    slither_report = format_slither_alerts(slither_findings)
    
    if has_alerts:
        prompt = f"""You are an expert smart contract security auditor performing a HYBRID ANALYSIS.

## Phase 1 - Static Analysis (Slither) Results:
{slither_report}

## Phase 2 - Your Deep Semantic Analysis:
Slither has identified potential code regions of interest. While Slither's specific alerts may be
low-severity or false positives, the CODE REGIONS they point to may contain DEEPER vulnerabilities
that Slither cannot detect (logic errors, business logic flaws, cross-contract issues).

IMPORTANT: Slither has a known ~87% false positive rate. You MUST:
1. Use Slither's alerts as STARTING POINTS to investigate those code regions more deeply
2. Look for HIGH severity vulnerabilities that Slither missed but exist near the flagged code
3. Also perform your own independent analysis beyond Slither's findings
4. Focus on: loss of funds, unauthorized access, price manipulation, logic errors

## RAG Knowledge Base:
{RAG_KNOWLEDGE}

## Smart Contract Source Code:
{contract_text}

## Instructions:
Identify ONLY HIGH severity vulnerabilities. For each, provide title, root cause, file, impact, exploit scenario.

Output as JSON:
```json
{{
  "vulnerabilities": [
    {{
      "title": "vulnerability title",
      "severity": "high",
      "summary": "root cause summary",
      "file": "path/to/file.sol",
      "impact": "impact description",
      "exploit_scenario": "how to exploit",
      "slither_connection": "which Slither alert (if any) pointed to this area"
    }}
  ]
}}
```

Only report HIGH severity issues."""
    else:
        # Fallback: Slither found nothing -> pure LLM+RAG with explicit note
        prompt = f"""You are an expert smart contract security auditor.

## Static Analysis Note:
Slither static analysis found NO alerts on these contracts. However, this does NOT mean they are safe.
Slither cannot detect logic vulnerabilities, business logic flaws, or complex cross-contract issues.
You must perform deep semantic analysis independently.

## Known Vulnerability Patterns (RAG Knowledge Base):
{RAG_KNOWLEDGE}

## Smart Contract Source Code:
{contract_text}

## Instructions:
1. Carefully analyze ALL the source code
2. Identify ONLY HIGH severity vulnerabilities (loss of funds)
3. For each, provide title, root cause, file, impact, exploit scenario

Output as JSON:
```json
{{
  "vulnerabilities": [
    {{
      "title": "vulnerability title",
      "severity": "high",
      "summary": "root cause summary",
      "file": "path/to/file.sol",
      "impact": "impact description",
      "exploit_scenario": "how to exploit"
    }}
  ]
}}
```

Only report HIGH severity issues. Be thorough but precise."""

    return _call_llm(prompt)


# ============================================================
# MODE 3: CONTEXT MODE
# LLM always decides, Slither report as advisory only
# ============================================================

def run_context_mode(sol_files, slither_findings, contract_text):
    """Context Mode: LLM makes independent judgment, Slither report is advisory reference."""
    slither_report = format_slither_alerts(slither_findings)
    has_alerts = len(slither_findings) > 0
    
    if has_alerts:
        slither_section = f"""## Slither Static Analysis Report (ADVISORY ONLY - DO NOT BLINDLY FOLLOW):
{slither_report}

CRITICAL INSTRUCTIONS about Slither:
1. Slither has a known ~87% FALSE POSITIVE rate - most of its alerts are wrong
2. The report is provided ONLY as advisory reference for code location hints
3. You MUST make your OWN independent judgment based on semantic understanding
4. If Slither reports issues but the code has proper security patterns, classify as safe
5. If Slither reports no issues, still check for logic vulnerabilities"""
    else:
        slither_section = """## Static Analysis Note:
Slither found NO alerts. This does NOT guarantee safety - Slither misses logic vulnerabilities.
Perform your own independent deep analysis."""

    prompt = f"""You are an expert smart contract security auditor with access to both a vulnerability knowledge base AND a static analysis report.

{slither_section}

## Known Vulnerability Patterns (RAG Knowledge Base):
{RAG_KNOWLEDGE}

## Smart Contract Source Code:
{contract_text}

## Instructions:
1. Make your OWN independent judgment - do NOT follow Slither blindly
2. Identify ONLY HIGH severity vulnerabilities (loss of funds, critical logic errors)
3. For each, provide title, root cause, file, impact, exploit scenario

Output as JSON:
```json
{{
  "vulnerabilities": [
    {{
      "title": "vulnerability title",
      "severity": "high",
      "summary": "root cause summary",
      "file": "path/to/file.sol",
      "impact": "impact description",
      "exploit_scenario": "how to exploit"
    }}
  ]
}}
```

Only report HIGH severity issues. Be PRECISE - quality over quantity."""

    return _call_llm(prompt)


# ============================================================
# Shared LLM Call & Judge Functions
# ============================================================

def _call_llm(prompt):
    """Call LLM and parse vulnerability JSON response."""
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
            "time_seconds": round(time.time() - start_time, 2),
            "tokens_used": 0,
            "error": str(e)
        }


def judge_detection(found_vulns, gold_vulns):
    """Use LLM to judge if detected vulnerabilities match gold standard."""
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
                "vuln_id": vuln_id, "vuln_title": vuln_title,
                "detected": result.get("detected", False),
                "reasoning": result.get("reasoning", "")
            })
        except Exception as e:
            results.append({
                "vuln_id": vuln_id, "vuln_title": vuln_title,
                "detected": False, "reasoning": f"Judge error: {str(e)}"
            })
    return results


# ============================================================
# Main Experiment Loop
# ============================================================

def main():
    timestamp = datetime.now().isoformat()
    print("=" * 70)
    print("EVMbench Three-Mode Hybrid Comparison Experiment")
    print(f"Timestamp: {timestamp}")
    print(f"Model: {MODEL}")
    print("Modes: Original Hybrid | Verification Mode | Context Mode")
    print("=" * 70)
    
    MODE_NAMES = ["original", "verification", "context"]
    MODE_FUNCS = {
        "original": run_original_hybrid,
        "verification": run_verification_mode,
        "context": run_context_mode,
    }
    
    # Accumulate results per mode
    mode_results = {m: {"total_vulns": 0, "total_detected": 0, "total_time": 0,
                        "total_tokens": 0, "per_audit": []} for m in MODE_NAMES}
    
    # Previous baseline results for comparison
    llm_rag_per_audit = {
        "2024-01-curves": 1, "2024-03-taiko": 0, "2024-05-olas": 0,
        "2024-07-basin": 0, "2024-01-renft": 0, "2024-06-size": 0,
        "2024-08-phi": 1, "2024-12-secondswap": 0, "2025-04-forte": 0,
        "2026-01-tempo-stablecoin-dex": 1
    }
    
    for i, audit_id in enumerate(SAMPLE_AUDITS):
        print(f"\n{'='*70}")
        print(f"[{i+1}/{len(SAMPLE_AUDITS)}] Audit: {audit_id}")
        print(f"{'='*70}")
        
        # 1. Load config
        config = load_audit_config(audit_id)
        gold_vulns = config.get("vulnerabilities", [])
        print(f"  Gold standard: {len(gold_vulns)} HIGH vulnerabilities")
        for gv in gold_vulns:
            print(f"    - [{gv['id']}] {gv['title'][:70]}")
        
        # 2. Extract Solidity files
        repo_dir = os.path.join(REPOS_DIR, audit_id)
        if not os.path.exists(repo_dir):
            print(f"  [ERROR] Repo not found: {repo_dir}")
            for m in MODE_NAMES:
                mode_results[m]["total_vulns"] += len(gold_vulns)
                mode_results[m]["per_audit"].append({
                    "audit_id": audit_id, "status": "repo_not_found",
                    "num_gold_vulns": len(gold_vulns), "num_detected": 0, "detect_score": 0.0
                })
            continue
        
        sol_files = extract_solidity_files(repo_dir)
        print(f"  Extracted {len(sol_files)} Solidity files")
        
        if not sol_files:
            for m in MODE_NAMES:
                mode_results[m]["total_vulns"] += len(gold_vulns)
                mode_results[m]["per_audit"].append({
                    "audit_id": audit_id, "status": "no_sol_files",
                    "num_gold_vulns": len(gold_vulns), "num_detected": 0, "detect_score": 0.0
                })
            continue
        
        # 3. Build contract text (shared across modes)
        contract_text = ""
        for sf in sol_files:
            contract_text += f"\n// File: {sf['path']}\n{sf['content']}\n"
        if len(contract_text) > 60000:
            contract_text = contract_text[:60000] + "\n// ... (truncated)"
        
        # 4. Run Slither (shared across modes)
        print(f"\n  --- Slither Analysis (shared) ---")
        slither_start = time.time()
        slither_findings, files_with_alerts = run_slither_on_files(sol_files)
        slither_time = time.time() - slither_start
        
        high_med = [f for f in slither_findings if f["impact"] in ["High", "Medium"]]
        low_info = [f for f in slither_findings if f["impact"] in ["Low", "Informational"]]
        print(f"  Slither: {len(slither_findings)} alerts "
              f"(H/M: {len(high_med)}, L/I: {len(low_info)}) | {slither_time:.1f}s")
        
        # 5. Run each mode
        for mode_name in MODE_NAMES:
            print(f"\n  --- Mode: {mode_name.upper()} ---")
            
            detect_result = MODE_FUNCS[mode_name](sol_files, slither_findings, contract_text)
            print(f"  Found {detect_result['num_found']} potential vulns "
                  f"({detect_result['time_seconds']}s, {detect_result['tokens_used']} tokens)")
            
            # Judge
            judge_results = judge_detection(detect_result["vulnerabilities_found"], gold_vulns)
            num_detected = sum(1 for jr in judge_results if jr["detected"])
            detect_score = num_detected / len(gold_vulns) if gold_vulns else 0
            
            print(f"  Detected: {num_detected}/{len(gold_vulns)} ({detect_score:.2%})")
            for jr in judge_results:
                status = "V" if jr["detected"] else "X"
                print(f"    [{status}] {jr['vuln_id']}: {jr['vuln_title'][:55]}")
            
            audit_result = {
                "audit_id": audit_id,
                "status": "completed",
                "num_gold_vulns": len(gold_vulns),
                "num_found": detect_result["num_found"],
                "num_detected": num_detected,
                "detect_score": round(detect_score, 4),
                "slither_alerts": len(slither_findings),
                "slither_high_med": len(high_med),
                "slither_low_info": len(low_info),
                "slither_time": round(slither_time, 2),
                "llm_time": detect_result["time_seconds"],
                "tokens_used": detect_result["tokens_used"],
                "judge_results": judge_results,
                "found_vulnerabilities": [
                    {"title": v.get("title", ""), "summary": v.get("summary", "")}
                    for v in detect_result["vulnerabilities_found"]
                ]
            }
            
            mode_results[mode_name]["total_vulns"] += len(gold_vulns)
            mode_results[mode_name]["total_detected"] += num_detected
            mode_results[mode_name]["total_time"] += detect_result["time_seconds"]
            mode_results[mode_name]["total_tokens"] += detect_result["tokens_used"]
            mode_results[mode_name]["per_audit"].append(audit_result)
    
    # ============================================================
    # Summary
    # ============================================================
    print("\n" + "=" * 70)
    print("EVMBENCH THREE-MODE HYBRID COMPARISON SUMMARY")
    print("=" * 70)
    
    print(f"\n  {'Method':<30} {'Detected':>10} {'Total':>8} {'Score':>10}")
    print(f"  {'-'*60}")
    print(f"  {'Slither (standalone)':<30} {'0':>10} {'40':>8} {'0.00%':>10}")
    print(f"  {'Mythril (standalone)':<30} {'0':>10} {'40':>8} {'0.00%':>10}")
    print(f"  {'LLM+RAG (standalone)':<30} {'3':>10} {'40':>8} {'7.50%':>10}")
    
    for mode_name in MODE_NAMES:
        mr = mode_results[mode_name]
        score = mr["total_detected"] / mr["total_vulns"] if mr["total_vulns"] > 0 else 0
        label = {
            "original": "Hybrid (Original)",
            "verification": "Hybrid (Verification)",
            "context": "Hybrid (Context)"
        }[mode_name]
        print(f"  {label:<30} {mr['total_detected']:>10} {mr['total_vulns']:>8} {score:>9.2%}")
    
    # Per-audit comparison table
    print(f"\n  Per-Audit Comparison:")
    header = f"  {'Audit':<30} {'Gold':>5} {'Slither':>8} {'LLM+RAG':>8}"
    for m in MODE_NAMES:
        short = {"original": "Orig", "verification": "Verify", "context": "Context"}[m]
        header += f" {short:>8}"
    print(header)
    print(f"  {'-'*85}")
    
    for idx, audit_id in enumerate(SAMPLE_AUDITS):
        gold_n = mode_results["original"]["per_audit"][idx]["num_gold_vulns"]
        row = f"  {audit_id:<30} {gold_n:>5} {'0':>8} {llm_rag_per_audit.get(audit_id, 0):>8}"
        for m in MODE_NAMES:
            detected = mode_results[m]["per_audit"][idx]["num_detected"]
            row += f" {detected:>8}"
        print(row)
    
    # Time & cost comparison
    print(f"\n  Time & Token Comparison:")
    print(f"  {'Mode':<30} {'Total Time':>12} {'Total Tokens':>14}")
    print(f"  {'-'*58}")
    for mode_name in MODE_NAMES:
        mr = mode_results[mode_name]
        label = {"original": "Hybrid (Original)", "verification": "Hybrid (Verification)",
                 "context": "Hybrid (Context)"}[mode_name]
        print(f"  {label:<30} {mr['total_time']:>10.1f}s {mr['total_tokens']:>14,}")
    
    # Save results
    summary = {
        "experiment": "EVMbench Three-Mode Hybrid Comparison",
        "model": MODEL,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "timestamp": timestamp,
        "num_audits": len(SAMPLE_AUDITS),
        "total_gold_vulnerabilities": 40,
        "baselines": {
            "slither": {"detected": 0, "score": 0.0},
            "mythril": {"detected": 0, "score": 0.0},
            "llm_rag": {"detected": 3, "score": 0.075, "per_audit": llm_rag_per_audit}
        },
        "hybrid_modes": {}
    }
    
    for mode_name in MODE_NAMES:
        mr = mode_results[mode_name]
        score = mr["total_detected"] / mr["total_vulns"] if mr["total_vulns"] > 0 else 0
        summary["hybrid_modes"][mode_name] = {
            "total_detected": mr["total_detected"],
            "total_vulns": mr["total_vulns"],
            "detect_score": round(score, 4),
            "total_time_seconds": round(mr["total_time"], 2),
            "total_tokens": mr["total_tokens"],
            "per_audit_results": mr["per_audit"]
        }
    
    results_path = os.path.join(RESULTS_DIR, "evmbench_hybrid_3modes_results.json")
    with open(results_path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n  Results saved to: {results_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
