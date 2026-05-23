#!/usr/bin/env python3
"""
Experiment 4: LLM + RAG Enhanced Vulnerability Detection.
Uses a knowledge base of vulnerability patterns to enhance LLM detection.
RAG provides relevant vulnerability examples and patterns as context.
"""

import os, json, time, glob, random, re
from datetime import datetime
from openai import OpenAI

import sys; sys.path.insert(0, os.path.dirname(__file__))
from _model_compat import token_param, MODEL as COMPAT_MODEL

random.seed(42)
BASE_DIR = "/home/curtis/DmAVID"
DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments/llm_rag/llm_rag_results.json")

client = OpenAI()
MODEL = os.environ.get("DMAVID_MODEL", "gpt-4.1-mini")

# ---------------------------------------------------------------------------
# Dynamic KB: load false_positive + Blue Team entries from vulnerability_knowledge.json
# Loaded once at module import time so the coordinator's per-round KB updates
# are picked up when the module is reloaded between rounds.
# ---------------------------------------------------------------------------
_DYNAMIC_KB_PATH = os.path.join(BASE_DIR, "scripts/knowledge/vulnerability_knowledge.json")

def _load_dynamic_kb():
    """Return (fp_entries, bt_safe_patterns_by_category) from the dynamic KB."""
    fp_entries = []          # false_positive entries → anti-FP hints
    bt_safe = {}             # category → list of safe_pattern keyword strings (Blue Team)
    try:
        with open(_DYNAMIC_KB_PATH) as f:
            kb = json.load(f)
        for e in kb.get("entries", []):
            cat = e.get("category", "")
            title = e.get("title", "")
            if cat == "false_positive":
                fp_entries.append(e)
            elif "Blue Team Defense" in title and e.get("safe_pattern"):
                bt_safe.setdefault(cat, []).append(e["safe_pattern"])
    except Exception:
        pass
    return fp_entries, bt_safe

_FP_ENTRIES, _BT_SAFE_PATTERNS = _load_dynamic_kb()




def strip_answer_comments(code):
    """Remove SmartBugs answer-revealing markers before LLM analysis."""
    import re as _re
    code = _re.sub(r'[^\n]*<(?:yes|no)>[^\n]*', '', code)
    code = _re.sub(r'[^\n]*@vulnerable_at_lines:[^\n]*\n?', '', code)
    return code
# ============================================================
# RAG Knowledge Base: Vulnerability patterns and examples
# ============================================================
VULN_KNOWLEDGE_BASE = {
    "reentrancy": {
        "description": "Reentrancy occurs when a contract makes an external call before updating its state, allowing the called contract to re-enter and exploit the inconsistent state.",
        "patterns": [
            "call.value() before state update",
            "transfer() or send() before balance reset",
            "external call followed by state change",
            "msg.sender.call{value: amount}('')"
        ],
        "safe_patterns": [
            "Checks-Effects-Interactions pattern",
            "ReentrancyGuard modifier",
            "nonReentrant modifier",
            "State update before external call"
        ],
        "example_vulnerable": "function withdraw() { uint amount = balances[msg.sender]; (bool success,) = msg.sender.call{value: amount}(''); balances[msg.sender] = 0; }",
        "example_safe": "function withdraw() { uint amount = balances[msg.sender]; balances[msg.sender] = 0; (bool success,) = msg.sender.call{value: amount}(''); require(success); }"
    },
    "integer_overflow": {
        "description": "Integer overflow/underflow occurs when arithmetic operations exceed the maximum or minimum value of the integer type.",
        "patterns": [
            "Arithmetic without SafeMath (Solidity < 0.8)",
            "Unchecked { } block with arithmetic",
            "Type casting to smaller integer types",
            "Multiplication without overflow check"
        ],
        "safe_patterns": [
            "Using SafeMath library",
            "Solidity >= 0.8.0 (built-in overflow checks)",
            "require() before arithmetic",
            "Explicit bounds checking"
        ],
        "example_vulnerable": "function transfer(address to, uint256 value) { balances[msg.sender] -= value; balances[to] += value; }",
        "example_safe": "function transfer(address to, uint256 value) { require(balances[msg.sender] >= value); balances[msg.sender] -= value; balances[to] += value; }"
    },
    "access_control": {
        "description": "Access control vulnerabilities occur when critical functions lack proper authorization checks.",
        "patterns": [
            "Missing onlyOwner modifier",
            "tx.origin for authentication",
            "Public/external visibility on sensitive functions",
            "Missing require(msg.sender == owner)"
        ],
        "safe_patterns": [
            "onlyOwner modifier",
            "Role-based access control (RBAC)",
            "OpenZeppelin Ownable",
            "msg.sender == owner check"
        ],
        "example_vulnerable": "function setOwner(address newOwner) public { owner = newOwner; }",
        "example_safe": "function setOwner(address newOwner) public onlyOwner { owner = newOwner; }"
    },
    "unchecked_call": {
        "description": "Unchecked low-level calls can silently fail, leading to unexpected behavior.",
        "patterns": [
            "address.call() without checking return value",
            "address.send() without checking return value",
            "address.delegatecall() without return check",
            "Low-level call in loop"
        ],
        "safe_patterns": [
            "require(success) after call",
            "if(!success) revert()",
            "Using transfer() instead of send()",
            "Checking return value of call"
        ],
        "example_vulnerable": "msg.sender.send(amount);",
        "example_safe": "require(msg.sender.send(amount), 'Transfer failed');"
    },
    "denial_of_service": {
        "description": "DoS vulnerabilities allow attackers to prevent legitimate users from using the contract.",
        "patterns": [
            "Unbounded loop over dynamic array",
            "External call in loop",
            "Block gas limit vulnerability",
            "Unexpected revert in fallback"
        ],
        "safe_patterns": [
            "Pull over push pattern",
            "Bounded loops",
            "Pagination for large arrays",
            "Gas-efficient patterns"
        ],
        "example_vulnerable": "function refundAll() { for(uint i=0; i<investors.length; i++) { investors[i].transfer(amounts[i]); } }",
        "example_safe": "function withdraw() { uint amount = pendingWithdrawals[msg.sender]; pendingWithdrawals[msg.sender] = 0; msg.sender.transfer(amount); }"
    },
    "front_running": {
        "description": "Front-running occurs when transaction ordering can be exploited by observing pending transactions.",
        "patterns": [
            "Price-dependent operations without slippage protection",
            "Commit-reveal scheme missing",
            "Token approval race condition",
            "Predictable transaction outcome"
        ],
        "safe_patterns": [
            "Commit-reveal scheme",
            "Slippage protection",
            "Minimum output amount",
            "Deadline parameter"
        ],
        "example_vulnerable": "function swap(uint amountIn) { uint price = oracle.getPrice(); uint amountOut = amountIn * price; token.transfer(msg.sender, amountOut); }",
        "example_safe": "function swap(uint amountIn, uint minAmountOut, uint deadline) { require(block.timestamp <= deadline); uint amountOut = calculateOutput(amountIn); require(amountOut >= minAmountOut); token.transfer(msg.sender, amountOut); }"
    },
    "bad_randomness": {
        "description": "Using blockchain data as randomness source is predictable and exploitable.",
        "patterns": [
            "block.timestamp as random source",
            "block.number for randomness",
            "blockhash() for randomness",
            "keccak256(block.difficulty, block.timestamp)"
        ],
        "safe_patterns": [
            "Chainlink VRF",
            "Commit-reveal scheme",
            "External oracle for randomness",
            "Multiple block hash combination"
        ],
        "example_vulnerable": "function random() returns (uint) { return uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty))); }",
        "example_safe": "// Use Chainlink VRF for verifiable randomness"
    },
    "time_manipulation": {
        "description": "Miners can manipulate block.timestamp within a small range.",
        "patterns": [
            "block.timestamp for critical logic",
            "now (alias for block.timestamp)",
            "Time-based access control",
            "Timestamp comparison for state transitions"
        ],
        "safe_patterns": [
            "Block number instead of timestamp",
            "Tolerance for timestamp variation",
            "External time oracle",
            "Large time windows"
        ],
        "example_vulnerable": "function unlock() { require(now >= unlockTime); token.transfer(beneficiary, amount); }",
        "example_safe": "function unlock() { require(block.number >= unlockBlock); token.transfer(beneficiary, amount); }"
    }
}

def build_rag_context(code):
    """Build RAG context by matching code patterns to knowledge base.

    Two sources of signal are combined:
    1. Static VULN_KNOWLEDGE_BASE — keyword-based risk/safe scoring per vuln type.
    2. Dynamic KB (_FP_ENTRIES, _BT_SAFE_PATTERNS) — false-positive sentinel
       patterns and Blue Team safe_pattern augmentation loaded from disk.
    """
    context_parts = []
    code_lower = code.lower()

    # ------------------------------------------------------------------
    # Phase 1: Score each vulnerability type (static KB)
    # ------------------------------------------------------------------
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

        # Augment safe_score with Blue Team safe_patterns for this category
        for bt_sp in _BT_SAFE_PATTERNS.get(vuln_type, []):
            kws = bt_sp.lower().split()
            if any(kw in code_lower for kw in kws if len(kw) > 3):
                safe_score += 1
                break  # count at most +1 per category from Blue Team

        scores[vuln_type] = (score, safe_score, matched_patterns)

    # ------------------------------------------------------------------
    # Phase 2: Check false_positive sentinel patterns (dynamic KB)
    # Match on distinctive code identifiers extracted from safe_pattern,
    # not generic prose keywords. Require ≥2 unique identifiers to match.
    # ------------------------------------------------------------------
    # Common Solidity keywords / types that are NOT discriminative
    _SOLIDITY_STOPWORDS = {
        "pragma", "solidity", "contract", "function", "public", "external",
        "internal", "private", "returns", "return", "require", "revert",
        "address", "uint256", "uint", "bool", "bytes", "string", "mapping",
        "memory", "storage", "calldata", "payable", "modifier", "event",
        "emit", "import", "interface", "library", "struct", "enum", "this",
        "super", "true", "false", "value", "amount", "owner", "sender",
        "balance", "balances", "transfer", "success", "failed", "error",
    }

    known_safe_hits = []
    for fp_entry in _FP_ENTRIES:
        sp_text = fp_entry.get("safe_pattern", "")
        # Extract identifiers: sequences of ≥5 alnum chars containing at least one letter
        identifiers = re.findall(r'\b[A-Za-z][A-Za-z0-9_]{4,}\b', sp_text)
        # Keep only distinctive ones (not stopwords, and case-sensitive check in code)
        distinctive = [
            ident for ident in dict.fromkeys(identifiers)
            if ident.lower() not in _SOLIDITY_STOPWORDS
        ]
        hit_count = sum(1 for ident in distinctive if ident in code)
        if hit_count >= 2:
            known_safe_hits.append(fp_entry.get("title", ""))

    if known_safe_hits:
        context_parts.append(
            "\n=== KNOWN SAFE PATTERNS DETECTED ===\n"
            + "\n".join(f"  ✓ {h}" for h in known_safe_hits)
            + "\nThese patterns strongly indicate the code is SAFE for the relevant vulnerability types.\n"
        )

    # ------------------------------------------------------------------
    # Phase 3: Build per-type context (top-3 by net risk)
    # ------------------------------------------------------------------
    sorted_vulns = sorted(scores.items(), key=lambda x: x[1][0] - x[1][1], reverse=True)

    for vuln_type, (score, safe_score, matched) in sorted_vulns[:3]:
        if score == 0:
            continue
        kb = VULN_KNOWLEDGE_BASE[vuln_type]
        net = score - safe_score
        if net <= 0:
            ctx = (
                f"\n--- {vuln_type.upper()} [NET RISK: LOW — LIKELY MITIGATED] ---\n"
                f"Risk signals: {score}  |  Safe/mitigating signals: {safe_score}\n"
                f"The code shows as many or more safe patterns than risk patterns for this type.\n"
                f"Safe example: {kb['example_safe']}\n"
            )
        else:
            ctx = (
                f"\n--- {vuln_type.upper()} [NET RISK: {'HIGH' if net >= 2 else 'MEDIUM'}] ---\n"
                f"Description: {kb['description']}\n"
                f"Matched risk patterns: {', '.join(matched)}\n"
                f"Safe/mitigating signals: {safe_score}\n"
                f"Vulnerable example: {kb['example_vulnerable']}\n"
                f"Safe example: {kb['example_safe']}\n"
            )
        context_parts.append(ctx)

    return "\n".join(context_parts) if context_parts else "No specific vulnerability patterns matched."

RAG_SYSTEM_PROMPT = """You are an expert smart contract security auditor with access to a vulnerability knowledge base.
You will be provided with:
1. The Solidity source code to analyze
2. Relevant vulnerability patterns and examples from the knowledge base (RAG context)

Decision rules — apply in order:
1. If the RAG context marks a type as [NET RISK: LOW — LIKELY MITIGATED], treat it as SAFE for that type unless you see a clear, specific exploit path in the actual code.
2. Only set has_vulnerability=true when you can identify a CONCRETE, EXPLOITABLE weakness in the code — not merely the presence of a risky pattern.
3. When in doubt, default to has_vulnerability=false. False negatives are recoverable; false positives waste audit resources.
4. A contract is SAFE if it properly implements security best practices (ReentrancyGuard, SafeMath, onlyOwner, require checks, CEI pattern).

Respond in JSON format ONLY:
{
  "has_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "vulnerability_types": ["type1"],
  "severity": "High/Medium/Low/None",
  "reasoning": "brief explanation referencing the RAG context"
}"""

def analyze_with_rag(code, max_retries=2, extra_context=""):
    """Analyze contract with RAG-enhanced LLM."""
    if len(code) > 12000:
        code = code[:12000] + "\n// ... (truncated)"
    
    rag_context = build_rag_context(code)
    
    for attempt in range(max_retries + 1):
        try:
            start = time.time()
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": RAG_SYSTEM_PROMPT},
                    {"role": "user", "content": f"## RAG Knowledge Base Context:\n{rag_context}\n\n{extra_context}\n\n## Contract to Analyze:\n```solidity\n{code}\n```"}
                ],
                temperature=0.1, **token_param(1024), seed=42
            )
            elapsed = time.time() - start
            content = resp.choices[0].message.content.strip()
            
            # Try nested JSON first, then simple JSON
            json_match = re.search(r'\{[\s\S]*\}', content)
            if not json_match:
                json_match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
            parsed = json.loads(json_match.group()) if json_match else json.loads(content)
            
            return {
                "success": True,
                "predicted_vulnerable": parsed.get("has_vulnerability", False),
                "confidence": parsed.get("confidence", 0.5),
                "vulnerability_types": parsed.get("vulnerability_types", []),
                "severity": parsed.get("severity", "None"),
                "reasoning": parsed.get("reasoning", ""),
                "rag_context_length": len(rag_context),
                "time_seconds": round(elapsed, 3),
                "tokens_used": resp.usage.total_tokens if resp.usage else 0,
                "error": None
            }
        except json.JSONDecodeError:
            has_vuln = any(w in content.lower() for w in ["true", "vulnerable", "yes"])
            # Try to extract confidence from raw text
            conf_match = re.search(r'"confidence"\s*:\s*([\d.]+)', content)
            conf = float(conf_match.group(1)) if conf_match else 0.5
            return {
                "success": True, "predicted_vulnerable": has_vuln,
                "confidence": conf, "vulnerability_types": [], "severity": "Unknown",
                "reasoning": content[:500], "rag_context_length": len(rag_context),
                "time_seconds": round(time.time()-start, 3),
                "tokens_used": resp.usage.total_tokens if resp.usage else 0,
                "error": "json_parse_error"
            }
        except Exception as e:
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {
                "success": False, "predicted_vulnerable": False,
                "confidence": 0, "vulnerability_types": [], "severity": "None",
                "reasoning": "", "rag_context_length": 0,
                "time_seconds": 0, "tokens_used": 0, "error": str(e)
            }

def main():
    print("=" * 60)
    print("Experiment 4: LLM + RAG Enhanced Detection")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Model: {MODEL}")
    print(f"Knowledge Base: {len(VULN_KNOWLEDGE_BASE)} vulnerability types")
    print("=" * 60)
    
    with open(DATASET_FILE, 'r') as f:
        dataset = json.load(f)
    
    contracts = dataset["contracts"]
    vuln = [c for c in contracts if c["label"] == "vulnerable"]
    safe = [c for c in contracts if c["label"] == "safe"]
    random.shuffle(safe)
    sample = vuln + safe[:100]
    random.shuffle(sample)
    
    print(f"\nSample: {len(vuln)} vulnerable + {min(100,len(safe))} safe = {len(sample)} total")
    
    results = []
    total_tokens = 0
    
    for i, contract in enumerate(sample):
        try:
            with open(contract["filepath"], 'r', encoding='utf-8', errors='ignore') as f:
                code = strip_answer_comments(f.read())
        except:
            continue
        
        result = analyze_with_rag(code)
        result["contract_id"] = contract["id"]
        result["ground_truth"] = contract["label"]
        result["category"] = contract["category"]
        result["filename"] = contract["filename"]
        result["lines"] = contract["lines"]
        results.append(result)
        total_tokens += result.get("tokens_used", 0)
        
        if (i + 1) % 25 == 0 or i == 0:
            tp = sum(1 for r in results if r["ground_truth"]=="vulnerable" and r["predicted_vulnerable"])
            fn = sum(1 for r in results if r["ground_truth"]=="vulnerable" and not r["predicted_vulnerable"])
            fp = sum(1 for r in results if r["ground_truth"]=="safe" and r["predicted_vulnerable"])
            tn = sum(1 for r in results if r["ground_truth"]=="safe" and not r["predicted_vulnerable"])
            tv = tp+fn if (tp+fn) > 0 else 1
            ts = fp+tn if (fp+tn) > 0 else 1
            print(f"  [{i+1}/{len(sample)}] TP={tp} FN={fn} FP={fp} TN={tn} | "
                  f"Recall={tp/tv*100:.1f}% FPR={fp/ts*100:.1f}% | tokens={total_tokens:,}")
        
        time.sleep(0.3)
    
    # Metrics
    print("\n" + "=" * 60)
    print("LLM + RAG DETECTION RESULTS SUMMARY")
    print("=" * 60)
    
    tp = sum(1 for r in results if r["ground_truth"]=="vulnerable" and r["predicted_vulnerable"])
    fn = sum(1 for r in results if r["ground_truth"]=="vulnerable" and not r["predicted_vulnerable"])
    fp = sum(1 for r in results if r["ground_truth"]=="safe" and r["predicted_vulnerable"])
    tn = sum(1 for r in results if r["ground_truth"]=="safe" and not r["predicted_vulnerable"])
    total = tp+fn+fp+tn
    acc = (tp+tn)/total if total else 0
    prec = tp/(tp+fp) if (tp+fp) else 0
    rec = tp/(tp+fn) if (tp+fn) else 0
    f1 = 2*prec*rec/(prec+rec) if (prec+rec) else 0
    fpr_val = fp/(fp+tn) if (fp+tn) else 0
    spec = tn/(tn+fp) if (tn+fp) else 0
    avg_t = sum(r["time_seconds"] for r in results)/len(results) if results else 0
    avg_conf = sum(r["confidence"] for r in results)/len(results) if results else 0
    
    print(f"  Total: {total} | TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"  Accuracy:    {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision:   {prec:.4f} ({prec*100:.2f}%)")
    print(f"  Recall:      {rec:.4f} ({rec*100:.2f}%)")
    print(f"  F1 Score:    {f1:.4f} ({f1*100:.2f}%)")
    print(f"  FPR:         {fpr_val:.4f} ({fpr_val*100:.2f}%)")
    print(f"  Specificity: {spec:.4f} ({spec*100:.2f}%)")
    print(f"  Avg Time:    {avg_t:.3f}s per contract")
    print(f"  Avg Confidence: {avg_conf:.3f}")
    print(f"  Total Tokens: {total_tokens:,}")
    
    # Per-category
    print("\n  Per-category Recall:")
    for cat in sorted(set(r["category"] for r in results if r["ground_truth"]=="vulnerable")):
        cr = [r for r in results if r["category"]==cat and r["ground_truth"]=="vulnerable"]
        ctp = sum(1 for r in cr if r["predicted_vulnerable"])
        print(f"    {cat}: {ctp}/{len(cr)} ({ctp/len(cr)*100:.1f}%)")
    
    output = {
        "experiment": "llm_rag_detection",
        "model": MODEL,
        "timestamp": datetime.now().isoformat(),
        "knowledge_base_types": list(VULN_KNOWLEDGE_BASE.keys()),
        "metrics": {
            "total": total, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "accuracy": round(acc,4), "precision": round(prec,4),
            "recall": round(rec,4), "f1_score": round(f1,4),
            "fpr": round(fpr_val,4), "specificity": round(spec,4),
            "avg_time_seconds": round(avg_t,3),
            "avg_confidence": round(avg_conf,3),
            "total_tokens": total_tokens
        },
        "results": results
    }
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
