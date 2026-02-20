#!/usr/bin/env python3
"""
Experiment 5: Hybrid Framework (Slither + LLM + RAG).
Combines static analysis pre-filtering with LLM+RAG for final decision.
Pipeline: Slither -> LLM+RAG (with Slither findings as additional context)
"""

import os, json, subprocess, time, glob, random, re
from datetime import datetime
from openai import OpenAI

random.seed(42)
BASE_DIR = "/home/ubuntu/defi-vuln-detection"
DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
SLITHER_RESULTS = os.path.join(BASE_DIR, "experiments/slither/slither_results.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments/hybrid/hybrid_results.json")

client = OpenAI()
MODEL = "gpt-4.1-mini"

SOLC_VERSIONS = {"0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12", "0.7": "0.7.6", "0.8": "0.8.0"}

# Same RAG knowledge base
VULN_KNOWLEDGE_BASE = {
    "reentrancy": {
        "description": "Reentrancy occurs when external call before state update.",
        "patterns": ["call.value() before state update", "external call followed by state change"],
        "safe_patterns": ["Checks-Effects-Interactions", "ReentrancyGuard", "nonReentrant"]
    },
    "integer_overflow": {
        "description": "Arithmetic overflow/underflow without checks.",
        "patterns": ["Arithmetic without SafeMath", "Unchecked block"],
        "safe_patterns": ["SafeMath library", "Solidity >= 0.8.0"]
    },
    "access_control": {
        "description": "Missing authorization on critical functions.",
        "patterns": ["Missing onlyOwner", "tx.origin auth", "Public sensitive functions"],
        "safe_patterns": ["onlyOwner modifier", "Role-based access", "msg.sender == owner"]
    },
    "unchecked_call": {
        "description": "Low-level calls without return value check.",
        "patterns": ["call() without check", "send() without check"],
        "safe_patterns": ["require(success)", "transfer() instead of send()"]
    },
    "denial_of_service": {
        "description": "Unbounded loops or external calls in loops.",
        "patterns": ["Unbounded loop", "External call in loop"],
        "safe_patterns": ["Pull over push", "Bounded loops"]
    },
    "front_running": {
        "description": "Transaction ordering exploitation.",
        "patterns": ["No slippage protection", "Missing commit-reveal"],
        "safe_patterns": ["Slippage protection", "Commit-reveal scheme"]
    },
    "bad_randomness": {
        "description": "Predictable randomness from blockchain data.",
        "patterns": ["block.timestamp as random", "blockhash for randomness"],
        "safe_patterns": ["Chainlink VRF", "External oracle"]
    },
    "time_manipulation": {
        "description": "Block timestamp manipulation by miners.",
        "patterns": ["block.timestamp for critical logic", "now for state transitions"],
        "safe_patterns": ["Block number instead", "Large time windows"]
    }
}

def detect_solc_version(code):
    match = re.search(r'pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)', code)
    return SOLC_VERSIONS.get(match.group(1), "0.8.0") if match else "0.8.0"

def run_slither_quick(filepath, timeout=30):
    """Quick Slither analysis for the hybrid pipeline."""
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
            except: pass
        
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

def build_hybrid_context(code, slither_findings):
    """Build context combining RAG knowledge and Slither findings."""
    parts = []
    
    # Slither findings context
    if slither_findings:
        parts.append("## Slither Static Analysis Findings:")
        high_med = [f for f in slither_findings if f["impact"] in ["High", "Medium"]]
        low_info = [f for f in slither_findings if f["impact"] in ["Low", "Informational"]]
        
        if high_med:
            parts.append(f"  HIGH/MEDIUM severity issues ({len(high_med)}):")
            for f in high_med[:5]:
                parts.append(f"  - [{f['impact']}] {f['check']}: {f['description'][:100]}")
        if low_info:
            parts.append(f"  LOW/INFO issues ({len(low_info)}): {', '.join(set(f['check'] for f in low_info))}")
        parts.append("")
    else:
        parts.append("## Slither: No issues detected by static analysis.\n")
    
    # RAG knowledge context
    code_lower = code.lower()
    parts.append("## Relevant Vulnerability Knowledge:")
    for vtype, kb in VULN_KNOWLEDGE_BASE.items():
        score = sum(1 for p in kb["patterns"] if any(kw in code_lower for kw in p.lower().split() if len(kw)>3))
        safe = sum(1 for p in kb["safe_patterns"] if any(kw in code_lower for kw in p.lower().split() if len(kw)>3))
        if score > 0:
            parts.append(f"  {vtype}: {kb['description']} (risk_patterns={score}, safe_patterns={safe})")
    
    return "\n".join(parts)

HYBRID_PROMPT = """You are an expert smart contract security auditor using a hybrid analysis approach.
You have TWO sources of information:
1. Slither static analysis findings (automated tool results)
2. RAG vulnerability knowledge base (patterns and best practices)

Use BOTH sources to make your final decision:
- If Slither found HIGH/MEDIUM issues AND the code matches known vulnerability patterns -> likely VULNERABLE
- If Slither found NO issues AND the code follows safe patterns -> likely SAFE
- If Slither found issues but code has proper mitigations -> might be SAFE (false positive from Slither)
- If Slither missed issues but code matches vulnerability patterns -> might be VULNERABLE (Slither limitation)

Be BALANCED: Consider both risk indicators and safety mitigations.

Respond in JSON format ONLY:
{
  "has_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "vulnerability_types": ["type1"],
  "severity": "High/Medium/Low/None",
  "reasoning": "explanation referencing both Slither findings and RAG knowledge"
}"""

def analyze_hybrid(code, slither_findings, max_retries=2):
    if len(code) > 10000:
        code = code[:10000] + "\n// ... (truncated)"
    
    context = build_hybrid_context(code, slither_findings)
    
    for attempt in range(max_retries + 1):
        try:
            start = time.time()
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": HYBRID_PROMPT},
                    {"role": "user", "content": f"{context}\n\n## Contract Code:\n```solidity\n{code}\n```"}
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
                "slither_findings_count": len(slither_findings),
                "slither_high_med": len([f for f in slither_findings if f["impact"] in ["High","Medium"]]),
                "time_seconds": round(elapsed, 3),
                "tokens_used": resp.usage.total_tokens if resp.usage else 0,
                "error": None
            }
        except json.JSONDecodeError:
            has_vuln = any(w in content.lower() for w in ["true", "vulnerable"])
            return {
                "success": True, "predicted_vulnerable": has_vuln,
                "confidence": 0.5, "vulnerability_types": [], "severity": "Unknown",
                "reasoning": content[:200], "slither_findings_count": len(slither_findings),
                "slither_high_med": 0, "time_seconds": round(time.time()-start, 3),
                "tokens_used": 0, "error": "json_parse_error"
            }
        except Exception as e:
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {
                "success": False, "predicted_vulnerable": False,
                "confidence": 0, "vulnerability_types": [], "severity": "None",
                "reasoning": "", "slither_findings_count": 0, "slither_high_med": 0,
                "time_seconds": 0, "tokens_used": 0, "error": str(e)
            }

def main():
    print("=" * 60)
    print("Experiment 5: Hybrid Framework (Slither + LLM + RAG)")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Model: {MODEL}")
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
    print("Pipeline: Slither -> LLM+RAG (with Slither context)")
    
    results = []
    total_tokens = 0
    total_slither_time = 0
    total_llm_time = 0
    
    for i, contract in enumerate(sample):
        try:
            with open(contract["filepath"], 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
        except:
            continue
        
        # Step 1: Slither analysis
        slither_start = time.time()
        slither_findings = run_slither_quick(contract["filepath"])
        slither_time = time.time() - slither_start
        total_slither_time += slither_time
        
        # Step 2: LLM+RAG with Slither context
        result = analyze_hybrid(code, slither_findings)
        total_llm_time += result["time_seconds"]
        
        result["contract_id"] = contract["id"]
        result["ground_truth"] = contract["label"]
        result["category"] = contract["category"]
        result["filename"] = contract["filename"]
        result["lines"] = contract["lines"]
        result["slither_time"] = round(slither_time, 3)
        result["total_time"] = round(slither_time + result["time_seconds"], 3)
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
        
        time.sleep(0.2)
    
    # Metrics
    print("\n" + "=" * 60)
    print("HYBRID FRAMEWORK RESULTS SUMMARY")
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
    avg_total_t = sum(r["total_time"] for r in results)/len(results) if results else 0
    avg_slither_t = total_slither_time/len(results) if results else 0
    avg_llm_t = total_llm_time/len(results) if results else 0
    
    print(f"  Total: {total} | TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"  Accuracy:    {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision:   {prec:.4f} ({prec*100:.2f}%)")
    print(f"  Recall:      {rec:.4f} ({rec*100:.2f}%)")
    print(f"  F1 Score:    {f1:.4f} ({f1*100:.2f}%)")
    print(f"  FPR:         {fpr_val:.4f} ({fpr_val*100:.2f}%)")
    print(f"  Specificity: {spec:.4f} ({spec*100:.2f}%)")
    print(f"  Avg Total Time: {avg_total_t:.3f}s (Slither: {avg_slither_t:.3f}s + LLM: {avg_llm_t:.3f}s)")
    print(f"  Total Tokens: {total_tokens:,}")
    
    # Per-category
    print("\n  Per-category Recall:")
    for cat in sorted(set(r["category"] for r in results if r["ground_truth"]=="vulnerable")):
        cr = [r for r in results if r["category"]==cat and r["ground_truth"]=="vulnerable"]
        ctp = sum(1 for r in cr if r["predicted_vulnerable"])
        print(f"    {cat}: {ctp}/{len(cr)} ({ctp/len(cr)*100:.1f}%)")
    
    output = {
        "experiment": "hybrid_slither_llm_rag",
        "model": MODEL,
        "timestamp": datetime.now().isoformat(),
        "pipeline": "Slither -> LLM+RAG (with Slither context)",
        "metrics": {
            "total": total, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "accuracy": round(acc,4), "precision": round(prec,4),
            "recall": round(rec,4), "f1_score": round(f1,4),
            "fpr": round(fpr_val,4), "specificity": round(spec,4),
            "avg_total_time": round(avg_total_t,3),
            "avg_slither_time": round(avg_slither_t,3),
            "avg_llm_time": round(avg_llm_t,3),
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
