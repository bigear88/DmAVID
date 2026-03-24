#!/usr/bin/env python3
"""
Experiment 3: LLM-based vulnerability detection using GPT-4.1-mini.
This is the baseline LLM approach without RAG enhancement.
We analyze contracts from the dataset using carefully designed prompts.
"""

import os
import json
import time
import glob
import random
from datetime import datetime
from openai import OpenAI

import sys; sys.path.insert(0, os.path.dirname(__file__))
from _model_compat import token_param, MODEL as COMPAT_MODEL

random.seed(42)

BASE_DIR = "/home/curtis/defi-llm-vulnerability-detection"
DATASET_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments/llm_base/llm_base_results.json")

client = OpenAI()
MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")

SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in Ethereum Solidity contracts. 
Your task is to analyze the given Solidity source code and determine if it contains security vulnerabilities.

You must respond in the following JSON format ONLY (no other text):
{
  "has_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "vulnerability_types": ["type1", "type2"],
  "severity": "High/Medium/Low/None",
  "reasoning": "brief explanation"
}

Common vulnerability types to check:
- Reentrancy
- Integer Overflow/Underflow
- Access Control issues
- Unchecked External Calls
- Denial of Service
- Front Running
- Bad Randomness
- Time Manipulation
- Short Address Attack
- Flash Loan Attack
- Price Oracle Manipulation"""

def analyze_contract_with_llm(code, max_retries=2):
    """Analyze a single contract using GPT-4.1-mini."""
    # Truncate very long contracts
    if len(code) > 15000:
        code = code[:15000] + "\n// ... (truncated)"
    
    for attempt in range(max_retries + 1):
        try:
            start_time = time.time()
            response = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Analyze this Solidity contract for vulnerabilities:\n\n```solidity\n{code}\n```"}
                ],
                temperature=0.1,
                **token_param(1024),
                seed=42
            )
            elapsed = time.time() - start_time
            
            content = response.choices[0].message.content.strip()
            
            # Parse JSON response
            # Try to extract JSON from the response
            import re
            json_match = re.search(r'\{[\s\S]*\}', content) or re.search(r'\{[^{}]*\}', content, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
            else:
                parsed = json.loads(content)
            
            return {
                "success": True,
                "predicted_vulnerable": parsed.get("has_vulnerability", False),
                "confidence": parsed.get("confidence", 0.5),
                "vulnerability_types": parsed.get("vulnerability_types", []),
                "severity": parsed.get("severity", "None"),
                "reasoning": parsed.get("reasoning", ""),
                "time_seconds": round(elapsed, 3),
                "tokens_used": response.usage.total_tokens if response.usage else 0,
                "error": None
            }
        except json.JSONDecodeError:
            # If JSON parsing fails, try to extract key info
            has_vuln = any(word in content.lower() for word in ["true", "vulnerable", "yes", "found"])
            return {
                "success": True,
                "predicted_vulnerable": has_vuln,
                "confidence": 0.5,
                "vulnerability_types": [],
                "severity": "Unknown",
                "reasoning": content[:200],
                "time_seconds": round(time.time() - start_time, 3),
                "tokens_used": 0,
                "error": "json_parse_error"
            }
        except Exception as e:
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            return {
                "success": False,
                "predicted_vulnerable": False,
                "confidence": 0,
                "vulnerability_types": [],
                "severity": "None",
                "reasoning": "",
                "time_seconds": 0,
                "tokens_used": 0,
                "error": str(e)
            }

def main():
    print("=" * 60)
    print("Experiment 3: LLM Base Detection (GPT-4.1-mini)")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Model: {MODEL}")
    print("=" * 60)
    
    # Load dataset
    with open(DATASET_FILE, 'r') as f:
        dataset = json.load(f)
    
    contracts = dataset["contracts"]
    print(f"\nLoaded {len(contracts)} contracts from dataset")
    
    # We'll analyze a representative sample for LLM (200 contracts to manage API costs)
    # 143 vulnerable + 57 safe = 200 total
    vuln_contracts = [c for c in contracts if c["label"] == "vulnerable"]
    safe_contracts = [c for c in contracts if c["label"] == "safe"]
    
    # Use all vulnerable + sample of safe
    random.shuffle(safe_contracts)
    sample_safe = safe_contracts[:100]
    sample = vuln_contracts + sample_safe
    random.shuffle(sample)
    
    print(f"Sample: {len(vuln_contracts)} vulnerable + {len(sample_safe)} safe = {len(sample)} total")
    
    results = []
    total_tokens = 0
    
    for i, contract in enumerate(sample):
        # Read the actual code
        filepath = contract["filepath"]
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
        except:
            print(f"  Skipping {contract['id']}: file not found")
            continue
        
        result = analyze_contract_with_llm(code)
        result["contract_id"] = contract["id"]
        result["ground_truth"] = contract["label"]
        result["category"] = contract["category"]
        result["filename"] = contract["filename"]
        result["lines"] = contract["lines"]
        results.append(result)
        total_tokens += result.get("tokens_used", 0)
        
        if (i + 1) % 25 == 0 or i == 0:
            tp = sum(1 for r in results if r["ground_truth"] == "vulnerable" and r["predicted_vulnerable"])
            fn = sum(1 for r in results if r["ground_truth"] == "vulnerable" and not r["predicted_vulnerable"])
            fp = sum(1 for r in results if r["ground_truth"] == "safe" and r["predicted_vulnerable"])
            tn = sum(1 for r in results if r["ground_truth"] == "safe" and not r["predicted_vulnerable"])
            total_v = tp + fn if (tp + fn) > 0 else 1
            total_s = fp + tn if (fp + tn) > 0 else 1
            print(f"  [{i+1}/{len(sample)}] TP={tp} FN={fn} FP={fp} TN={tn} | "
                  f"Recall={tp/total_v*100:.1f}% FPR={fp/total_s*100:.1f}% | "
                  f"tokens={total_tokens:,}")
        
        # Small delay to avoid rate limiting
        time.sleep(0.3)
    
    # Calculate metrics
    print("\n" + "=" * 60)
    print("LLM BASE DETECTION RESULTS SUMMARY")
    print("=" * 60)
    
    tp = sum(1 for r in results if r["ground_truth"] == "vulnerable" and r["predicted_vulnerable"])
    fn = sum(1 for r in results if r["ground_truth"] == "vulnerable" and not r["predicted_vulnerable"])
    fp = sum(1 for r in results if r["ground_truth"] == "safe" and r["predicted_vulnerable"])
    tn = sum(1 for r in results if r["ground_truth"] == "safe" and not r["predicted_vulnerable"])
    
    total = tp + fn + fp + tn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    
    avg_time = sum(r["time_seconds"] for r in results) / len(results) if results else 0
    avg_confidence = sum(r["confidence"] for r in results) / len(results) if results else 0
    
    print(f"  Total contracts analyzed: {total}")
    print(f"  TP={tp}, FN={fn}, FP={fp}, TN={tn}")
    print(f"  Accuracy:    {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  Precision:   {precision:.4f} ({precision*100:.2f}%)")
    print(f"  Recall:      {recall:.4f} ({recall*100:.2f}%)")
    print(f"  F1 Score:    {f1:.4f} ({f1*100:.2f}%)")
    print(f"  FPR:         {fpr:.4f} ({fpr*100:.2f}%)")
    print(f"  Specificity: {specificity:.4f} ({specificity*100:.2f}%)")
    print(f"  Avg Time:    {avg_time:.3f}s per contract")
    print(f"  Avg Confidence: {avg_confidence:.3f}")
    print(f"  Total Tokens: {total_tokens:,}")
    
    # Per-category analysis
    print("\n  Per-category Recall:")
    for cat in sorted(set(r["category"] for r in results if r["ground_truth"] == "vulnerable")):
        cat_results = [r for r in results if r["category"] == cat and r["ground_truth"] == "vulnerable"]
        cat_tp = sum(1 for r in cat_results if r["predicted_vulnerable"])
        cat_total = len(cat_results)
        if cat_total > 0:
            print(f"    {cat}: {cat_tp}/{cat_total} ({cat_tp/cat_total*100:.1f}%)")
    
    # Save
    output = {
        "experiment": "llm_base_detection",
        "model": MODEL,
        "timestamp": datetime.now().isoformat(),
        "metrics": {
            "total": total, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "fpr": round(fpr, 4),
            "specificity": round(specificity, 4),
            "avg_time_seconds": round(avg_time, 3),
            "avg_confidence": round(avg_confidence, 3),
            "total_tokens": total_tokens
        },
        "results": results
    }
    
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n  Results saved to: {OUTPUT_FILE}")
    print("=" * 60)

if __name__ == "__main__":
    main()
