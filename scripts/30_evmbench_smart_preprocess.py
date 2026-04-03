#!/usr/bin/env python3
"""
Step 1: Smart preprocessing for EVMbench — fix code truncation.

Strategy: Interface Summary + Key Module Deep Analysis
Instead of truncating at 60K chars, extract:
1. All interface definitions (function signatures, events, modifiers)
2. Deep analysis of security-critical modules (access control, fund flows, external calls)
3. Import/inheritance graph summary

Then re-run detection on preprocessed code.
"""
import os, sys, re, json, glob, time, yaml
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _model_compat import token_param
from openai import OpenAI

BASE_DIR = os.environ.get("DAVID_BASE_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPOS_DIR = os.path.join(BASE_DIR, "data", "evmbench_repos")
EVMBENCH_DIR = os.path.join(BASE_DIR, "data", "evmbench")
MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments", "evmbench_smart")
client = OpenAI()

AUDITS = [
    "2024-01-curves", "2024-03-taiko", "2024-05-olas", "2024-07-basin",
    "2024-01-renft", "2024-06-size", "2024-08-phi",
    "2024-12-secondswap", "2025-04-forte", "2026-01-tempo-stablecoin-dex",
]

MAX_DEEP_CHARS = 8000  # per module
MAX_TOTAL_CHARS = 25000  # total to send to LLM


def extract_interfaces(code):
    """Extract function signatures, events, modifiers from Solidity code."""
    lines = code.split("\n")
    interfaces = []
    for line in lines:
        stripped = line.strip()
        # Function signatures
        if re.match(r"^\s*function\s+\w+", stripped):
            sig = stripped.split("{")[0].strip()
            if sig:
                interfaces.append(sig)
        # Events
        elif re.match(r"^\s*event\s+", stripped):
            interfaces.append(stripped.rstrip(";").strip())
        # Modifiers
        elif re.match(r"^\s*modifier\s+", stripped):
            interfaces.append(stripped.split("{")[0].strip())
        # Contract/interface declarations
        elif re.match(r"^\s*(contract|interface|library|abstract)\s+", stripped):
            interfaces.append(stripped.split("{")[0].strip())
    return interfaces


def score_security_relevance(code, filename):
    """Score a file's security relevance (higher = more likely to contain vulns)."""
    score = 0
    low = code.lower()
    # High-risk patterns
    for pattern, weight in [
        (".call", 5), (".send", 4), (".transfer", 4),
        ("delegatecall", 6), ("selfdestruct", 5),
        ("msg.value", 4), ("msg.sender", 2),
        ("external", 3), ("payable", 3),
        ("withdraw", 5), ("deposit", 4), ("swap", 5),
        ("liquidat", 6), ("borrow", 5), ("repay", 4),
        ("oracle", 5), ("price", 4), ("flash", 6),
        ("approve", 3), ("transferfrom", 4),
        ("onlyowner", -2), ("nonreentrant", -2),  # mitigations reduce score
        ("require(", 1), ("assert(", 1),
    ]:
        score += low.count(pattern) * weight
    # Bonus for shorter files (more likely core logic)
    if len(code) < 5000:
        score += 10
    return score


def smart_preprocess(audit_id):
    """Create a security-focused summary of the audit project."""
    repo_dir = os.path.join(REPOS_DIR, audit_id)
    if not os.path.exists(repo_dir):
        return None

    # Collect all .sol source files (exclude test/script/lib)
    sol_files = []
    for f in glob.glob(os.path.join(repo_dir, "**/*.sol"), recursive=True):
        if "/test/" in f or "/script/" in f or "/lib/" in f:
            continue
        if not os.path.isfile(f):
            continue
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                code = fh.read()
            sol_files.append((f, code, os.path.relpath(f, repo_dir)))
        except Exception:
            pass

    if not sol_files:
        return None

    total_chars = sum(len(c) for _, c, _ in sol_files)

    # Part 1: Interface summary (all files)
    all_interfaces = []
    for filepath, code, relpath in sol_files:
        ifaces = extract_interfaces(code)
        if ifaces:
            all_interfaces.append(f"// File: {relpath}")
            all_interfaces.extend(ifaces)

    interface_summary = "\n".join(all_interfaces)

    # Part 2: Score and rank files by security relevance
    scored = [(score_security_relevance(code, relpath), filepath, code, relpath)
              for filepath, code, relpath in sol_files]
    scored.sort(key=lambda x: x[0], reverse=True)

    # Part 3: Deep analysis of top security-critical files
    deep_analysis = []
    remaining_budget = MAX_TOTAL_CHARS - min(len(interface_summary), 5000)

    for score, filepath, code, relpath in scored:
        if remaining_budget <= 0:
            break
        chunk = code[:min(MAX_DEEP_CHARS, remaining_budget)]
        deep_analysis.append(f"// === {relpath} (security score: {score}) ===\n{chunk}")
        remaining_budget -= len(chunk)

    # Combine
    preprocessed = (
        f"// PROJECT: {audit_id}\n"
        f"// Total: {len(sol_files)} source files, {total_chars:,} chars\n"
        f"// Preprocessing: Interface Summary + Top {len(deep_analysis)} Security-Critical Modules\n\n"
        f"// === INTERFACE SUMMARY (all files) ===\n"
        f"{interface_summary[:5000]}\n\n"
        f"// === SECURITY-CRITICAL MODULES (deep analysis) ===\n"
        + "\n\n".join(deep_analysis)
    )

    return preprocessed[:MAX_TOTAL_CHARS]


def detect_with_smart_preprocess(preprocessed_code, knowledge_base, gold_vulns):
    """Run LLM+RAG detection on smart-preprocessed code."""
    prompt = f"""You are an expert DeFi security auditor. Analyze this smart contract project for HIGH severity vulnerabilities.

## DeFi Vulnerability Knowledge Base:
{knowledge_base[:3000]}

## Smart Contract Project (preprocessed: interface summary + security-critical modules):
```solidity
{preprocessed_code}
```

## Task:
1. Identify ALL high-severity vulnerabilities
2. For each, provide: title, severity, root cause, exploit scenario
3. Focus on DeFi-specific issues: flash loan, oracle manipulation, reentrancy, access control, precision loss

Output JSON only:
{{"vulnerabilities": [{{"title": "...", "severity": "high", "summary": "...", "exploit_scenario": "..."}}]}}"""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            **token_param(2000),
        )
        content = resp.choices[0].message.content.strip()
        tokens = resp.usage.total_tokens if resp.usage else 0
        match = re.search(r"\{[\s\S]*\}", content)
        if match:
            parsed = json.loads(match.group())
            return parsed.get("vulnerabilities", []), tokens
        return [], tokens
    except Exception as e:
        return [], 0


def load_gold_vulns(audit_id):
    """Load gold standard vulnerabilities from EVMbench config."""
    config_path = os.path.join(EVMBENCH_DIR, "audits", audit_id, "config.yaml")
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = yaml.safe_load(f)
        return config.get("vulnerabilities", [])
    return []


def load_knowledge_base():
    """Load enhanced KB."""
    kb_path = os.path.join(BASE_DIR, "scripts", "knowledge", "vulnerability_knowledge.json")
    if os.path.exists(kb_path):
        with open(kb_path) as f:
            kb = json.load(f)
        entries = kb.get("entries", [])
        parts = []
        for e in entries[:20]:
            parts.append(f"[{e.get('category','?')}] {e.get('title','')}: {e.get('description','')[:200]}")
        return "\n".join(parts)
    return ""


def judge_detection(found_vulns, gold_vulns):
    """Simple matching: check if found vulns match gold vulns by keyword overlap."""
    detected = 0
    for gv in gold_vulns:
        gold_title = gv.get("title", "").lower()
        gold_id = gv.get("id", "").lower()
        for fv in found_vulns:
            found_title = fv.get("title", "").lower()
            found_summary = fv.get("summary", "").lower()
            # Check keyword overlap
            gold_words = set(gold_title.split())
            found_words = set(found_title.split()) | set(found_summary.split())
            overlap = len(gold_words & found_words)
            if overlap >= 2 or gold_id in found_summary:
                detected += 1
                break
    return detected


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 60)
    print("EVMbench Smart Preprocessing + Detection")
    print(f"Model: {MODEL}")
    print(f"Strategy: Interface Summary + Key Module Deep Analysis")
    print("=" * 60)

    kb = load_knowledge_base()
    total_gold = 0
    total_detected = 0
    total_tokens = 0
    results = []

    for i, audit_id in enumerate(AUDITS):
        print(f"\n[{i+1}/{len(AUDITS)}] {audit_id}")

        gold_vulns = load_gold_vulns(audit_id)
        total_gold += len(gold_vulns)
        print(f"  Gold vulnerabilities: {len(gold_vulns)}")

        preprocessed = smart_preprocess(audit_id)
        if not preprocessed:
            print(f"  SKIP: no code found")
            results.append({"audit_id": audit_id, "status": "no_code"})
            continue

        print(f"  Preprocessed: {len(preprocessed):,} chars (from full codebase)")

        found_vulns, tokens = detect_with_smart_preprocess(preprocessed, kb, gold_vulns)
        total_tokens += tokens
        detected = judge_detection(found_vulns, gold_vulns)
        total_detected += detected

        score = detected / len(gold_vulns) if gold_vulns else 0
        print(f"  Found: {len(found_vulns)} vulns, Matched: {detected}/{len(gold_vulns)} ({score:.0%})")
        print(f"  Tokens: {tokens}")

        results.append({
            "audit_id": audit_id,
            "gold_count": len(gold_vulns),
            "found_count": len(found_vulns),
            "detected": detected,
            "score": round(score, 4),
            "tokens": tokens,
            "found_vulns": [v.get("title", "?") for v in found_vulns],
        })

    # Summary
    detect_rate = total_detected / total_gold if total_gold > 0 else 0
    print("\n" + "=" * 60)
    print("SMART PREPROCESSING RESULTS")
    print("=" * 60)
    print(f"  Total: {total_detected}/{total_gold} ({detect_rate:.2%})")
    print(f"  vs Previous (truncated): 8/39 (20.51%)")
    print(f"  vs Baseline: 5/39 (12.82%)")
    print(f"  Tokens: {total_tokens:,}")

    print(f"\n  {'Audit':<35} {'Gold':>5} {'Found':>6} {'Match':>6} {'Score':>7}")
    print(f"  {'-'*60}")
    for r in results:
        if r.get("status") == "no_code":
            continue
        print(f"  {r['audit_id']:<35} {r['gold_count']:>5} {r['found_count']:>6} "
              f"{r['detected']:>6} {r['score']:>6.0%}")

    output = {
        "experiment": "evmbench_smart_preprocess",
        "model": MODEL,
        "strategy": "Interface Summary + Key Module Deep Analysis",
        "total_gold": total_gold,
        "total_detected": total_detected,
        "detect_rate": round(detect_rate, 4),
        "total_tokens": total_tokens,
        "per_audit": results,
    }
    with open(os.path.join(OUTPUT_DIR, "smart_preprocess_results.json"), "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved: {OUTPUT_DIR}/smart_preprocess_results.json")


if __name__ == "__main__":
    main()
