#!/usr/bin/env python3
"""
Experiment 5 (Optimized): Hybrid Framework with Three Modes.
  - baseline:     Original OR-like logic (Slither context fed to LLM, LLM tends to follow Slither)
  - verification: Slither pre-filter -> LLM as final judge (only verify Slither alerts)
  - context:      LLM always decides, Slither report as advisory context with explicit instruction to override

Goal: Achieve F1 > LLM+RAG (89.17%) by leveraging Slither's high recall to pre-filter,
      while using LLM's semantic understanding to eliminate Slither's false positives.
"""

import os, json, subprocess, time, glob, random, re, argparse
from datetime import datetime
from openai import OpenAI

random.seed(42)
BASE_DIR = "/home/curtis/DmAVID"
DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")

client = OpenAI()
MODEL = "gpt-4.1-mini"

SOLC_VERSIONS = {"0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12", "0.7": "0.7.6", "0.8": "0.8.0"}

# ============================================================
# RAG Knowledge Base (same as 05_run_llm_rag.py)
# ============================================================
VULN_KNOWLEDGE_BASE = {
    "reentrancy": {
        "description": "Reentrancy occurs when a contract makes an external call before updating its state.",
        "patterns": ["call.value() before state update", "external call followed by state change",
                     "transfer() or send() before balance reset", "msg.sender.call{value: amount}('')"],
        "safe_patterns": ["Checks-Effects-Interactions pattern", "ReentrancyGuard modifier",
                          "nonReentrant modifier", "State update before external call"],
        "example_vulnerable": "function withdraw() { uint amount = balances[msg.sender]; (bool success,) = msg.sender.call{value: amount}(''); balances[msg.sender] = 0; }",
        "example_safe": "function withdraw() { uint amount = balances[msg.sender]; balances[msg.sender] = 0; (bool success,) = msg.sender.call{value: amount}(''); require(success); }"
    },
    "integer_overflow": {
        "description": "Integer overflow/underflow occurs when arithmetic operations exceed the max/min value.",
        "patterns": ["Arithmetic without SafeMath (Solidity < 0.8)", "Unchecked { } block with arithmetic",
                     "Type casting to smaller integer types", "Multiplication without overflow check"],
        "safe_patterns": ["Using SafeMath library", "Solidity >= 0.8.0 (built-in overflow checks)",
                          "require() before arithmetic", "Explicit bounds checking"],
        "example_vulnerable": "function transfer(address to, uint256 value) { balances[msg.sender] -= value; balances[to] += value; }",
        "example_safe": "function transfer(address to, uint256 value) { require(balances[msg.sender] >= value); balances[msg.sender] -= value; balances[to] += value; }"
    },
    "access_control": {
        "description": "Access control vulnerabilities occur when critical functions lack proper authorization.",
        "patterns": ["Missing onlyOwner modifier", "tx.origin for authentication",
                     "Public/external visibility on sensitive functions", "Missing require(msg.sender == owner)"],
        "safe_patterns": ["onlyOwner modifier", "Role-based access control (RBAC)",
                          "OpenZeppelin Ownable", "msg.sender == owner check"],
        "example_vulnerable": "function setOwner(address newOwner) public { owner = newOwner; }",
        "example_safe": "function setOwner(address newOwner) public onlyOwner { owner = newOwner; }"
    },
    "unchecked_call": {
        "description": "Unchecked low-level calls can silently fail, leading to unexpected behavior.",
        "patterns": ["address.call() without checking return value", "address.send() without checking return value",
                     "address.delegatecall() without return check", "Low-level call in loop"],
        "safe_patterns": ["require(success) after call", "if(!success) revert()",
                          "Using transfer() instead of send()", "Checking return value of call"],
        "example_vulnerable": "msg.sender.send(amount);",
        "example_safe": "require(msg.sender.send(amount), 'Transfer failed');"
    },
    "denial_of_service": {
        "description": "DoS vulnerabilities allow attackers to prevent legitimate users from using the contract.",
        "patterns": ["Unbounded loop over dynamic array", "External call in loop",
                     "Block gas limit vulnerability", "Unexpected revert in fallback"],
        "safe_patterns": ["Pull over push pattern", "Bounded loops",
                          "Pagination for large arrays", "Gas-efficient patterns"],
        "example_vulnerable": "function refundAll() { for(uint i=0; i<investors.length; i++) { investors[i].transfer(amounts[i]); } }",
        "example_safe": "function withdraw() { uint amount = pendingWithdrawals[msg.sender]; pendingWithdrawals[msg.sender] = 0; msg.sender.transfer(amount); }"
    },
    "front_running": {
        "description": "Front-running occurs when transaction ordering can be exploited.",
        "patterns": ["Price-dependent operations without slippage protection", "Commit-reveal scheme missing",
                     "Token approval race condition", "Predictable transaction outcome"],
        "safe_patterns": ["Commit-reveal scheme", "Slippage protection",
                          "Minimum output amount", "Deadline parameter"],
        "example_vulnerable": "function swap(uint amountIn) { uint price = oracle.getPrice(); uint amountOut = amountIn * price; token.transfer(msg.sender, amountOut); }",
        "example_safe": "function swap(uint amountIn, uint minAmountOut, uint deadline) { require(block.timestamp <= deadline); uint amountOut = calculateOutput(amountIn); require(amountOut >= minAmountOut); }"
    },
    "bad_randomness": {
        "description": "Using blockchain data as randomness source is predictable and exploitable.",
        "patterns": ["block.timestamp as random source", "block.number for randomness",
                     "blockhash() for randomness", "keccak256(block.difficulty, block.timestamp)"],
        "safe_patterns": ["Chainlink VRF", "Commit-reveal scheme",
                          "External oracle for randomness", "Multiple block hash combination"],
        "example_vulnerable": "function random() returns (uint) { return uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty))); }",
        "example_safe": "// Use Chainlink VRF for verifiable randomness"
    },
    "time_manipulation": {
        "description": "Miners can manipulate block.timestamp within a small range.",
        "patterns": ["block.timestamp for critical logic", "now (alias for block.timestamp)",
                     "Time-based access control", "Timestamp comparison for state transitions"],
        "safe_patterns": ["Block number instead of timestamp", "Tolerance for timestamp variation",
                          "External time oracle", "Large time windows"],
        "example_vulnerable": "function unlock() { require(now >= unlockTime); token.transfer(beneficiary, amount); }",
        "example_safe": "function unlock() { require(block.number >= unlockBlock); token.transfer(beneficiary, amount); }"
    }
}


def detect_solc_version(code):
    match = re.search(r'pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)', code)
    return SOLC_VERSIONS.get(match.group(1), "0.8.0") if match else "0.8.0"


def run_slither_quick(filepath, timeout=30):
    """Quick Slither analysis returning structured findings."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        ver = detect_solc_version(code)
        subprocess.run(["solc-select", "use", ver], capture_output=True, timeout=5)

        r = subprocess.run(
            ["slither", filepath, "--json", "-"],
            capture_output=True, text=True, timeout=timeout
        )
        detectors = []
        if r.stdout:
            try:
                out = json.loads(r.stdout)
                if "results" in out and "detectors" in out["results"]:
                    detectors = out["results"]["detectors"]
            except:
                pass

        findings = []
        for d in detectors:
            findings.append({
                "check": d.get("check", "unknown"),
                "impact": d.get("impact", "unknown"),
                "confidence": d.get("confidence", "unknown"),
                "description": d.get("description", "")[:200]
            })
        return findings
    except:
        return []


def build_rag_context(code):
    """Build RAG context by matching code patterns to knowledge base (same as 05_run_llm_rag.py)."""
    context_parts = []
    code_lower = code.lower()

    scores = {}
    for vuln_type, kb in VULN_KNOWLEDGE_BASE.items():
        score = 0
        matched_patterns = []
        for pattern in kb["patterns"]:
            pattern_keywords = pattern.lower().split()
            if any(kw in code_lower for kw in pattern_keywords if len(kw) > 3):
                score += 1
                matched_patterns.append(pattern)
        safe_score = 0
        for sp in kb["safe_patterns"]:
            sp_keywords = sp.lower().split()
            if any(kw in code_lower for kw in sp_keywords if len(kw) > 3):
                safe_score += 1
        scores[vuln_type] = (score, safe_score, matched_patterns)

    sorted_vulns = sorted(scores.items(), key=lambda x: x[1][0], reverse=True)
    for vuln_type, (score, safe_score, matched) in sorted_vulns[:3]:
        if score > 0:
            kb = VULN_KNOWLEDGE_BASE[vuln_type]
            ctx = f"\n--- {vuln_type.upper()} ---\n"
            ctx += f"Description: {kb['description']}\n"
            ctx += f"Matched risk patterns: {', '.join(matched)}\n"
            ctx += f"Safe patterns found: {safe_score}\n"
            ctx += f"Vulnerable example: {kb['example_vulnerable']}\n"
            ctx += f"Safe example: {kb['example_safe']}\n"
            context_parts.append(ctx)

    return "\n".join(context_parts) if context_parts else "No specific vulnerability patterns matched."


# ============================================================
# MODE 1: VERIFICATION MODE
# Slither pre-filter -> LLM verifies only Slither alerts
# ============================================================

VERIFICATION_PROMPT = """You are an expert smart contract security auditor performing a SECOND-PASS VERIFICATION.

A static analysis tool (Slither) has flagged this contract with the following alerts:
{slither_alerts}

Your job is to VERIFY whether these Slither alerts represent REAL vulnerabilities or FALSE POSITIVES.

Slither is known to have a HIGH false positive rate (~87%). Many of its alerts are:
- Informational/Low severity issues that are not real vulnerabilities
- Patterns that look risky but have proper mitigations in the code
- Style warnings rather than security issues

You MUST independently analyze the code and make YOUR OWN judgment:
- If the code has proper mitigations (ReentrancyGuard, SafeMath, onlyOwner, require checks), 
  the Slither alerts are likely FALSE POSITIVES -> mark as SAFE
- Only confirm as VULNERABLE if you find actual exploitable security flaws

Use the RAG knowledge base context below to inform your decision:
{rag_context}

Respond in JSON format ONLY:
{{
  "has_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "vulnerability_types": ["type1"],
  "severity": "High/Medium/Low/None",
  "slither_assessment": "confirmed/false_positive/partially_confirmed",
  "reasoning": "explanation of why Slither alerts are real or false positives"
}}"""


# ============================================================
# MODE 2: CONTEXT MODE
# LLM always decides, Slither report as advisory reference
# ============================================================

CONTEXT_PROMPT = """You are an expert smart contract security auditor with access to both a vulnerability knowledge base AND a static analysis report.

## RAG Knowledge Base Context:
{rag_context}

## Slither Static Analysis Report (ADVISORY ONLY):
{slither_report}

IMPORTANT INSTRUCTIONS:
1. The Slither report is provided as ADVISORY REFERENCE ONLY - it has a known ~87% false positive rate
2. You MUST make your OWN independent judgment based on your semantic understanding of the code
3. Slither is useful for LOCATING specific code patterns, but NOT for final vulnerability determination
4. If Slither reports issues but the code has proper security patterns (guards, checks, safe patterns), 
   you should classify it as SAFE
5. If Slither reports no issues, still check for logic vulnerabilities that static tools cannot detect

Be PRECISE and BALANCED. A contract with external calls is NOT automatically vulnerable.

Respond in JSON format ONLY:
{{
  "has_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "vulnerability_types": ["type1"],
  "severity": "High/Medium/Low/None",
  "reasoning": "brief explanation referencing both your analysis and Slither findings"
}}"""


def format_slither_alerts(findings):
    """Format Slither findings for prompt injection."""
    if not findings:
        return "No alerts from Slither."

    high_med = [f for f in findings if f["impact"] in ["High", "Medium"]]
    low_info = [f for f in findings if f["impact"] in ["Low", "Informational"]]

    parts = []
    if high_med:
        parts.append(f"HIGH/MEDIUM severity ({len(high_med)} alerts):")
        for f in high_med[:5]:
            parts.append(f"  - [{f['impact']}/{f['confidence']}] {f['check']}: {f['description'][:120]}")
    if low_info:
        parts.append(f"LOW/INFO ({len(low_info)} alerts): {', '.join(set(f['check'] for f in low_info[:10]))}")

    return "\n".join(parts)


def format_slither_report(findings):
    """Format Slither findings as advisory report for context mode."""
    if not findings:
        return "Slither static analysis: NO issues detected. (Note: this does not guarantee safety - Slither may miss logic vulnerabilities)"

    high_med = [f for f in findings if f["impact"] in ["High", "Medium"]]
    low_info = [f for f in findings if f["impact"] in ["Low", "Informational"]]

    parts = ["Slither static analysis report (ADVISORY - known ~87% false positive rate):"]
    if high_med:
        parts.append(f"  HIGH/MEDIUM alerts ({len(high_med)}):")
        for f in high_med[:5]:
            parts.append(f"    - [{f['impact']}] {f['check']}: {f['description'][:120]}")
    if low_info:
        parts.append(f"  LOW/INFO alerts ({len(low_info)}): {', '.join(set(f['check'] for f in low_info[:10]))}")
    parts.append("  NOTE: Many of these may be false positives. Verify independently.")

    return "\n".join(parts)


def analyze_verification(code, slither_findings, max_retries=2):
    """Verification Mode: LLM verifies Slither alerts."""
    if len(code) > 12000:
        code = code[:12000] + "\n// ... (truncated)"

    rag_context = build_rag_context(code)
    slither_alerts = format_slither_alerts(slither_findings)

    prompt = VERIFICATION_PROMPT.format(
        slither_alerts=slither_alerts,
        rag_context=rag_context
    )

    for attempt in range(max_retries + 1):
        try:
            start = time.time()
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": f"## Contract Code to Verify:\n```solidity\n{code}\n```"}
                ],
                temperature=0.1, max_tokens=1024, seed=42
            )
            elapsed = time.time() - start
            content = resp.choices[0].message.content.strip()

            json_match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
            parsed = json.loads(json_match.group()) if json_match else json.loads(content)

            return {
                "success": True,
                "predicted_vulnerable": parsed.get("has_vulnerability", False),
                "confidence": parsed.get("confidence", 0.5),
                "vulnerability_types": parsed.get("vulnerability_types", []),
                "severity": parsed.get("severity", "None"),
                "slither_assessment": parsed.get("slither_assessment", "unknown"),
                "reasoning": parsed.get("reasoning", ""),
                "time_seconds": round(elapsed, 3),
                "tokens_used": resp.usage.total_tokens if resp.usage else 0,
                "error": None
            }
        except json.JSONDecodeError:
            has_vuln = any(w in content.lower() for w in ["true", "vulnerable", "confirmed"])
            return {
                "success": True, "predicted_vulnerable": has_vuln,
                "confidence": 0.5, "vulnerability_types": [], "severity": "Unknown",
                "slither_assessment": "unknown", "reasoning": content[:200],
                "time_seconds": round(time.time() - start, 3), "tokens_used": 0,
                "error": "json_parse_error"
            }
        except Exception as e:
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {
                "success": False, "predicted_vulnerable": False,
                "confidence": 0, "vulnerability_types": [], "severity": "None",
                "slither_assessment": "error", "reasoning": "",
                "time_seconds": 0, "tokens_used": 0, "error": str(e)
            }


def analyze_context(code, slither_findings, max_retries=2):
    """Context Mode: LLM decides with Slither report as advisory."""
    if len(code) > 12000:
        code = code[:12000] + "\n// ... (truncated)"

    rag_context = build_rag_context(code)
    slither_report = format_slither_report(slither_findings)

    prompt = CONTEXT_PROMPT.format(
        rag_context=rag_context,
        slither_report=slither_report
    )

    for attempt in range(max_retries + 1):
        try:
            start = time.time()
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": f"## Contract Code:\n```solidity\n{code}\n```"}
                ],
                temperature=0.1, max_tokens=1024, seed=42
            )
            elapsed = time.time() - start
            content = resp.choices[0].message.content.strip()

            json_match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
            parsed = json.loads(json_match.group()) if json_match else json.loads(content)

            return {
                "success": True,
                "predicted_vulnerable": parsed.get("has_vulnerability", False),
                "confidence": parsed.get("confidence", 0.5),
                "vulnerability_types": parsed.get("vulnerability_types", []),
                "severity": parsed.get("severity", "None"),
                "reasoning": parsed.get("reasoning", ""),
                "time_seconds": round(elapsed, 3),
                "tokens_used": resp.usage.total_tokens if resp.usage else 0,
                "error": None
            }
        except json.JSONDecodeError:
            has_vuln = any(w in content.lower() for w in ["true", "vulnerable", "yes"])
            return {
                "success": True, "predicted_vulnerable": has_vuln,
                "confidence": 0.5, "vulnerability_types": [], "severity": "Unknown",
                "reasoning": content[:200],
                "time_seconds": round(time.time() - start, 3), "tokens_used": 0,
                "error": "json_parse_error"
            }
        except Exception as e:
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {
                "success": False, "predicted_vulnerable": False,
                "confidence": 0, "vulnerability_types": [], "severity": "None",
                "reasoning": "",
                "time_seconds": 0, "tokens_used": 0, "error": str(e)
            }


def main():
    parser = argparse.ArgumentParser(description="Optimized Hybrid Framework")
    parser.add_argument("--mode", choices=["baseline", "verification", "context"],
                        default="verification", help="Hybrid strategy mode")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="Slither confidence threshold (for verification mode)")
    args = parser.parse_args()

    mode = args.mode
    output_file = os.path.join(BASE_DIR, f"experiments/hybrid/hybrid_{mode}_results.json")

    print("=" * 60)
    print(f"Experiment 5 (Optimized): Hybrid Framework - {mode.upper()} MODE")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Model: {MODEL}")
    print(f"Mode: {mode}")
    print("=" * 60)

    with open(DATASET_FILE, 'r') as f:
        dataset = json.load(f)

    contracts = dataset["contracts"]
    vuln = [c for c in contracts if c["label"] == "vulnerable"]
    safe = [c for c in contracts if c["label"] == "safe"]
    random.shuffle(safe)
    sample = vuln + safe[:100]
    random.shuffle(sample)

    print(f"\nSample: {len(vuln)} vulnerable + {min(100, len(safe))} safe = {len(sample)} total")

    if mode == "verification":
        print("Pipeline: Slither pre-filter -> LLM+RAG verification (LLM as final judge)")
        print("  - Slither no alert -> SAFE (skip LLM)")
        print("  - Slither has alert -> LLM verifies (may override as SAFE)")
    elif mode == "context":
        print("Pipeline: LLM+RAG with Slither advisory context (LLM always decides)")
        print("  - Slither report injected as ADVISORY reference")
        print("  - LLM makes independent judgment")
    else:
        print("Pipeline: Original baseline (Slither context fed to LLM)")

    results = []
    total_tokens = 0
    total_slither_time = 0
    total_llm_time = 0
    skipped_by_slither = 0

    for i, contract in enumerate(sample):
        try:
            with open(contract["filepath"], 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
        except:
            continue

        # Step 1: Slither analysis (always run for all modes)
        slither_start = time.time()
        slither_findings = run_slither_quick(contract["filepath"])
        slither_time = time.time() - slither_start
        total_slither_time += slither_time

        slither_has_alert = len(slither_findings) > 0
        slither_high_med = [f for f in slither_findings if f["impact"] in ["High", "Medium"]]

        # Step 2: Mode-specific LLM analysis
        if mode == "verification":
            if not slither_has_alert:
                # Slither says clean -> skip LLM, mark as SAFE
                result = {
                    "success": True, "predicted_vulnerable": False,
                    "confidence": 0.8, "vulnerability_types": [],
                    "severity": "None", "slither_assessment": "no_alert",
                    "reasoning": "Slither found no issues; skipped LLM verification.",
                    "time_seconds": 0, "tokens_used": 0, "error": None
                }
                skipped_by_slither += 1
            else:
                # Slither has alerts -> LLM verifies
                result = analyze_verification(code, slither_findings)
                total_llm_time += result["time_seconds"]

        elif mode == "context":
            # Always run LLM with Slither context as advisory
            result = analyze_context(code, slither_findings)
            total_llm_time += result["time_seconds"]

        else:
            # Baseline: original hybrid logic (from 06_run_hybrid.py)
            from scripts_06_original import analyze_hybrid as analyze_baseline
            result = analyze_baseline(code, slither_findings)
            total_llm_time += result["time_seconds"]

        result["contract_id"] = contract["id"]
        result["ground_truth"] = contract["label"]
        result["category"] = contract["category"]
        result["filename"] = contract["filename"]
        result["lines"] = contract["lines"]
        result["slither_time"] = round(slither_time, 3)
        result["slither_has_alert"] = slither_has_alert
        result["slither_high_med_count"] = len(slither_high_med)
        result["slither_total_count"] = len(slither_findings)
        result["total_time"] = round(slither_time + result["time_seconds"], 3)
        result["mode"] = mode
        results.append(result)
        total_tokens += result.get("tokens_used", 0)

        if (i + 1) % 25 == 0 or i == 0:
            tp = sum(1 for r in results if r["ground_truth"] == "vulnerable" and r["predicted_vulnerable"])
            fn = sum(1 for r in results if r["ground_truth"] == "vulnerable" and not r["predicted_vulnerable"])
            fp = sum(1 for r in results if r["ground_truth"] == "safe" and r["predicted_vulnerable"])
            tn = sum(1 for r in results if r["ground_truth"] == "safe" and not r["predicted_vulnerable"])
            tv = tp + fn if (tp + fn) > 0 else 1
            ts = fp + tn if (fp + tn) > 0 else 1
            prec_i = tp / (tp + fp) if (tp + fp) > 0 else 0
            f1_i = 2 * prec_i * (tp / tv) / (prec_i + tp / tv) if (prec_i + tp / tv) > 0 else 0
            print(f"  [{i + 1}/{len(sample)}] TP={tp} FN={fn} FP={fp} TN={tn} | "
                  f"Recall={tp / tv * 100:.1f}% Prec={prec_i * 100:.1f}% F1={f1_i * 100:.1f}% FPR={fp / ts * 100:.1f}% | "
                  f"skipped={skipped_by_slither} tokens={total_tokens:,}")

        time.sleep(0.2)

    # ============================================================
    # Final Metrics
    # ============================================================
    print("\n" + "=" * 60)
    print(f"HYBRID FRAMEWORK ({mode.upper()}) RESULTS SUMMARY")
    print("=" * 60)

    tp = sum(1 for r in results if r["ground_truth"] == "vulnerable" and r["predicted_vulnerable"])
    fn = sum(1 for r in results if r["ground_truth"] == "vulnerable" and not r["predicted_vulnerable"])
    fp = sum(1 for r in results if r["ground_truth"] == "safe" and r["predicted_vulnerable"])
    tn = sum(1 for r in results if r["ground_truth"] == "safe" and not r["predicted_vulnerable"])
    total = tp + fn + fp + tn
    acc = (tp + tn) / total if total else 0
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    fpr_val = fp / (fp + tn) if (fp + tn) else 0
    spec = tn / (tn + fp) if (tn + fp) else 0
    avg_total_t = sum(r["total_time"] for r in results) / len(results) if results else 0
    avg_slither_t = total_slither_time / len(results) if results else 0
    avg_llm_t = total_llm_time / len(results) if results else 0

    print(f"  Total: {total} | TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"  Accuracy:    {acc:.4f} ({acc * 100:.2f}%)")
    print(f"  Precision:   {prec:.4f} ({prec * 100:.2f}%)")
    print(f"  Recall:      {rec:.4f} ({rec * 100:.2f}%)")
    print(f"  F1 Score:    {f1:.4f} ({f1 * 100:.2f}%)")
    print(f"  FPR:         {fpr_val:.4f} ({fpr_val * 100:.2f}%)")
    print(f"  Specificity: {spec:.4f} ({spec * 100:.2f}%)")
    print(f"  Avg Total Time: {avg_total_t:.3f}s (Slither: {avg_slither_t:.3f}s + LLM: {avg_llm_t:.3f}s)")
    print(f"  Total Tokens: {total_tokens:,}")
    print(f"  Skipped by Slither (no alert): {skipped_by_slither}")

    # Comparison with LLM+RAG baseline
    llm_rag_f1 = 0.8917
    improvement = ((f1 - llm_rag_f1) / llm_rag_f1) * 100
    print(f"\n  vs LLM+RAG (F1=89.17%): {'IMPROVED' if f1 > llm_rag_f1 else 'NOT IMPROVED'} "
          f"({'+' if improvement > 0 else ''}{improvement:.2f}%)")

    # Per-category
    print("\n  Per-category Recall:")
    for cat in sorted(set(r["category"] for r in results if r["ground_truth"] == "vulnerable")):
        cr = [r for r in results if r["category"] == cat and r["ground_truth"] == "vulnerable"]
        ctp = sum(1 for r in cr if r["predicted_vulnerable"])
        print(f"    {cat}: {ctp}/{len(cr)} ({ctp / len(cr) * 100:.1f}%)")

    # Slither override analysis (for verification mode)
    if mode == "verification":
        slither_alerted = [r for r in results if r.get("slither_has_alert")]
        overridden = [r for r in slither_alerted if not r["predicted_vulnerable"]]
        print(f"\n  Verification Analysis:")
        print(f"    Slither alerted: {len(slither_alerted)}")
        print(f"    LLM overrode to SAFE: {len(overridden)} ({len(overridden)/len(slither_alerted)*100:.1f}% override rate)")
        override_correct = sum(1 for r in overridden if r["ground_truth"] == "safe")
        print(f"    Correct overrides: {override_correct}/{len(overridden)} ({override_correct/len(overridden)*100:.1f}% accuracy)" if overridden else "")

    output = {
        "experiment": f"hybrid_{mode}",
        "model": MODEL,
        "mode": mode,
        "timestamp": datetime.now().isoformat(),
        "pipeline": {
            "verification": "Slither pre-filter -> LLM+RAG verification",
            "context": "LLM+RAG with Slither advisory context",
            "baseline": "Original Slither+LLM hybrid"
        }.get(mode, mode),
        "metrics": {
            "total": total, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "accuracy": round(acc, 4), "precision": round(prec, 4),
            "recall": round(rec, 4), "f1_score": round(f1, 4),
            "fpr": round(fpr_val, 4), "specificity": round(spec, 4),
            "avg_total_time": round(avg_total_t, 3),
            "avg_slither_time": round(avg_slither_t, 3),
            "avg_llm_time": round(avg_llm_t, 3),
            "total_tokens": total_tokens,
            "skipped_by_slither": skipped_by_slither
        },
        "results": results
    }
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved to: {output_file}")


if __name__ == "__main__":
    main()
