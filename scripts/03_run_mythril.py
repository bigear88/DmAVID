#!/usr/bin/env python3
"""
Experiment 2: Run Mythril symbolic execution on SmartBugs contracts.
Mythril uses symbolic execution and SMT solving for deeper analysis.
Due to its slower speed, we run on a smaller sample.
"""

import os
import json
import subprocess
import time
import glob
import random
import re
from datetime import datetime

random.seed(42)

BASE_DIR = "/home/curtis/DmAVID"
CURATED_DIR = os.path.join(BASE_DIR, "data/smartbugs_curated_repo/dataset")
WILD_DIR = os.path.join(BASE_DIR, "data/smartbugs_wild_repo/contracts")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments/mythril/mythril_results.json")

SOLC_VERSIONS = {
    "0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12",
    "0.7": "0.7.6", "0.8": "0.8.0"
}

def detect_solc_version(code):
    match = re.search(r'pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)', code)
    if match:
        return SOLC_VERSIONS.get(match.group(1), "0.8.0")
    return "0.8.0"

def run_mythril_on_file(filepath, timeout=120):
    """Run Mythril on a single Solidity file."""
    start_time = time.time()
    try:
        # Read code to detect solc version
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        version = detect_solc_version(code)
        
        result = subprocess.run(
            ["myth", "analyze", filepath, "--solv", version,
             "--execution-timeout", "90", "-o", "json"],
            capture_output=True, text=True, timeout=timeout
        )
        elapsed = time.time() - start_time
        
        issues = []
        if result.stdout:
            try:
                output = json.loads(result.stdout)
                if "issues" in output:
                    issues = output["issues"]
                elif isinstance(output, list):
                    issues = output
            except json.JSONDecodeError:
                # Try to parse line by line
                pass
        
        vuln_types = set()
        severities = []
        for issue in issues:
            vuln_types.add(issue.get("title", "unknown"))
            severities.append(issue.get("severity", "unknown"))
        
        has_high = any(s in ["High", "Medium"] for s in severities)
        
        return {
            "success": True,
            "num_detections": len(issues),
            "vuln_types": list(vuln_types),
            "severities": severities,
            "predicted_vulnerable": len(issues) > 0,
            "high_severity": has_high,
            "time_seconds": round(elapsed, 3),
            "error": None
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False, "num_detections": 0,
            "vuln_types": [], "severities": [],
            "predicted_vulnerable": False, "high_severity": False,
            "time_seconds": timeout, "error": "timeout"
        }
    except Exception as e:
        return {
            "success": False, "num_detections": 0,
            "vuln_types": [], "severities": [],
            "predicted_vulnerable": False, "high_severity": False,
            "time_seconds": time.time() - start_time, "error": str(e)
        }

def main():
    print("=" * 60)
    print("Experiment 2: Mythril Symbolic Execution")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 60)
    
    results = []
    
    # 1. Curated vulnerable contracts (sample 50 for speed)
    print("\n[1/2] Running Mythril on SmartBugs Curated (vulnerable)...")
    curated_files = glob.glob(os.path.join(CURATED_DIR, "**/*.sol"), recursive=True)
    random.shuffle(curated_files)
    curated_sample = curated_files[:50]
    print(f"  Sampling {len(curated_sample)} from {len(curated_files)} vulnerable contracts")
    
    for i, filepath in enumerate(curated_sample):
        parts = filepath.split('/')
        category = "unknown"
        for p in parts:
            if p in ["access_control", "arithmetic", "bad_randomness", "denial_of_service",
                      "front_running", "other", "reentrancy", "short_addresses",
                      "time_manipulation", "unchecked_low_level_calls"]:
                category = p
                break
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        
        result = run_mythril_on_file(filepath)
        result["contract_id"] = f"curated_{category}_{os.path.basename(filepath)}"
        result["ground_truth"] = "vulnerable"
        result["category"] = category
        result["filename"] = os.path.basename(filepath)
        result["lines"] = len(code.split('\n'))
        results.append(result)
        
        if (i + 1) % 10 == 0 or i == 0:
            tp = sum(1 for r in results if r["ground_truth"] == "vulnerable" and r["predicted_vulnerable"])
            fn = sum(1 for r in results if r["ground_truth"] == "vulnerable" and not r["predicted_vulnerable"])
            total_v = tp + fn
            print(f"  [{i+1}/{len(curated_sample)}] TP={tp}, FN={fn}, "
                  f"Recall={tp/total_v*100:.1f}% | time={result['time_seconds']:.1f}s")
    
    # 2. Wild safe contracts (sample 50)
    print("\n[2/2] Running Mythril on SmartBugs Wild (safe sample)...")
    wild_files = glob.glob(os.path.join(WILD_DIR, "**/*.sol"), recursive=True)
    random.shuffle(wild_files)
    
    safe_sample = []
    for f in wild_files:
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                code = fh.read()
            if 100 < len(code.strip()) < 20000:
                safe_sample.append(f)
            if len(safe_sample) >= 50:
                break
        except:
            continue
    
    print(f"  Selected {len(safe_sample)} safe contracts")
    
    for i, filepath in enumerate(safe_sample):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        
        result = run_mythril_on_file(filepath)
        result["contract_id"] = f"wild_safe_{i:04d}_{os.path.basename(filepath)}"
        result["ground_truth"] = "safe"
        result["category"] = "none"
        result["filename"] = os.path.basename(filepath)
        result["lines"] = len(code.split('\n'))
        results.append(result)
        
        if (i + 1) % 10 == 0:
            fp = sum(1 for r in results if r["ground_truth"] == "safe" and r["predicted_vulnerable"])
            tn = sum(1 for r in results if r["ground_truth"] == "safe" and not r["predicted_vulnerable"])
            total_s = fp + tn
            if total_s > 0:
                print(f"  [{i+1}/{len(safe_sample)}] FP={fp}, TN={tn}, "
                      f"FPR={fp/total_s*100:.1f}% | time={result['time_seconds']:.1f}s")
    
    # Calculate metrics
    print("\n" + "=" * 60)
    print("MYTHRIL RESULTS SUMMARY")
    print("=" * 60)
    
    successful = [r for r in results if r["success"]]
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
    success_rate = len(successful) / len(results) * 100 if results else 0
    
    print(f"  Total contracts analyzed: {total}")
    print(f"  Successful analyses: {len(successful)}/{len(results)}")
    print(f"  TP={tp}, FN={fn}, FP={fp}, TN={tn}")
    print(f"  Accuracy:    {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  Precision:   {precision:.4f} ({precision*100:.2f}%)")
    print(f"  Recall:      {recall:.4f} ({recall*100:.2f}%)")
    print(f"  F1 Score:    {f1:.4f} ({f1*100:.2f}%)")
    print(f"  FPR:         {fpr:.4f} ({fpr*100:.2f}%)")
    print(f"  Specificity: {specificity:.4f} ({specificity*100:.2f}%)")
    print(f"  Avg Time:    {avg_time:.3f}s per contract")
    print(f"  Success Rate: {success_rate:.1f}%")
    
    # Save
    output = {
        "experiment": "mythril_symbolic_execution",
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
            "success_rate": round(success_rate, 2)
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
