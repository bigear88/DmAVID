#!/usr/bin/env python3
"""
Experiment 1: Run Slither static analysis on SmartBugs contracts.
Slither is a fast static analysis tool for Solidity.
We run it on a sample of contracts and record detection results.
"""

import os
import json
import subprocess
import time
import glob
from datetime import datetime

BASE_DIR = "/home/curtis/DmAVID"
CURATED_DIR = os.path.join(BASE_DIR, "data/smartbugs_curated_repo/dataset")
WILD_DIR = os.path.join(BASE_DIR, "data/smartbugs_wild_repo/contracts")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments/slither/slither_results.json")

# Solc versions for different pragma ranges
SOLC_VERSIONS = {
    "0.4": "0.4.26",
    "0.5": "0.5.17",
    "0.6": "0.6.12",
    "0.7": "0.7.6",
    "0.8": "0.8.0"
}

def detect_solc_version(code):
    """Detect required solc version from pragma."""
    import re
    match = re.search(r'pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)', code)
    if match:
        major_minor = match.group(1)
        return SOLC_VERSIONS.get(major_minor, "0.8.0")
    return "0.8.0"

def set_solc_version(version):
    """Set the active solc version."""
    try:
        subprocess.run(["solc-select", "use", version], capture_output=True, timeout=10)
    except:
        pass

def run_slither_on_file(filepath, timeout=60):
    """Run Slither on a single Solidity file."""
    start_time = time.time()
    try:
        result = subprocess.run(
            ["slither", filepath, "--json", "-"],
            capture_output=True, text=True, timeout=timeout
        )
        elapsed = time.time() - start_time
        
        # Parse JSON output
        detectors = []
        if result.stdout:
            try:
                output = json.loads(result.stdout)
                if "results" in output and "detectors" in output["results"]:
                    detectors = output["results"]["detectors"]
            except json.JSONDecodeError:
                pass
        
        # Extract vulnerability types
        vuln_types = set()
        severities = []
        for d in detectors:
            vuln_types.add(d.get("check", "unknown"))
            severities.append(d.get("impact", "unknown"))
        
        has_high_severity = any(s in ["High", "Medium"] for s in severities)
        
        return {
            "success": True,
            "num_detections": len(detectors),
            "vuln_types": list(vuln_types),
            "severities": severities,
            "predicted_vulnerable": has_high_severity or len(detectors) > 0,
            "high_severity": has_high_severity,
            "time_seconds": round(elapsed, 3),
            "error": None
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "num_detections": 0,
            "vuln_types": [],
            "severities": [],
            "predicted_vulnerable": False,
            "high_severity": False,
            "time_seconds": timeout,
            "error": "timeout"
        }
    except Exception as e:
        return {
            "success": False,
            "num_detections": 0,
            "vuln_types": [],
            "severities": [],
            "predicted_vulnerable": False,
            "high_severity": False,
            "time_seconds": time.time() - start_time,
            "error": str(e)
        }

def main():
    print("=" * 60)
    print("Experiment 1: Slither Static Analysis")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 60)
    
    results = []
    
    # 1. Run on all curated (vulnerable) contracts
    print("\n[1/2] Running Slither on SmartBugs Curated (vulnerable)...")
    curated_files = glob.glob(os.path.join(CURATED_DIR, "**/*.sol"), recursive=True)
    print(f"  Found {len(curated_files)} vulnerable contracts")
    
    for i, filepath in enumerate(curated_files):
        # Detect and set solc version
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        version = detect_solc_version(code)
        set_solc_version(version)
        
        # Determine category from path
        parts = filepath.split('/')
        category = "unknown"
        for p in parts:
            if p in ["access_control", "arithmetic", "bad_randomness", "denial_of_service",
                      "front_running", "other", "reentrancy", "short_addresses",
                      "time_manipulation", "unchecked_low_level_calls"]:
                category = p
                break
        
        result = run_slither_on_file(filepath)
        result["contract_id"] = f"curated_{category}_{os.path.basename(filepath)}"
        result["ground_truth"] = "vulnerable"
        result["category"] = category
        result["filename"] = os.path.basename(filepath)
        result["lines"] = len(code.split('\n'))
        results.append(result)
        
        if (i + 1) % 20 == 0 or i == 0:
            tp = sum(1 for r in results if r["ground_truth"] == "vulnerable" and r["predicted_vulnerable"])
            fn = sum(1 for r in results if r["ground_truth"] == "vulnerable" and not r["predicted_vulnerable"])
            print(f"  [{i+1}/{len(curated_files)}] TP={tp}, FN={fn}, "
                  f"Recall={tp/(tp+fn)*100:.1f}% (last: {result['num_detections']} findings)")
    
    # 2. Run on sample of wild (safe) contracts
    print("\n[2/2] Running Slither on SmartBugs Wild (safe sample)...")
    wild_files = glob.glob(os.path.join(WILD_DIR, "**/*.sol"), recursive=True)
    
    import random
    random.seed(42)
    random.shuffle(wild_files)
    safe_sample = wild_files[:100]  # Sample 100 safe contracts
    print(f"  Sampling {len(safe_sample)} safe contracts from {len(wild_files)} total")
    
    for i, filepath in enumerate(safe_sample):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            if len(code.strip()) < 50:
                continue
        except:
            continue
        
        version = detect_solc_version(code)
        set_solc_version(version)
        
        result = run_slither_on_file(filepath)
        result["contract_id"] = f"wild_safe_{i:04d}_{os.path.basename(filepath)}"
        result["ground_truth"] = "safe"
        result["category"] = "none"
        result["filename"] = os.path.basename(filepath)
        result["lines"] = len(code.split('\n'))
        results.append(result)
        
        if (i + 1) % 20 == 0:
            fp = sum(1 for r in results if r["ground_truth"] == "safe" and r["predicted_vulnerable"])
            tn = sum(1 for r in results if r["ground_truth"] == "safe" and not r["predicted_vulnerable"])
            total_safe = fp + tn
            if total_safe > 0:
                print(f"  [{i+1}/{len(safe_sample)}] FP={fp}, TN={tn}, "
                      f"FPR={fp/total_safe*100:.1f}%")
    
    # Calculate metrics
    print("\n" + "=" * 60)
    print("SLITHER RESULTS SUMMARY")
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
    success_rate = sum(1 for r in results if r["success"]) / len(results) * 100 if results else 0
    
    print(f"  Total contracts analyzed: {total}")
    print(f"  TP={tp}, FN={fn}, FP={fp}, TN={tn}")
    print(f"  Accuracy:    {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  Precision:   {precision:.4f} ({precision*100:.2f}%)")
    print(f"  Recall:      {recall:.4f} ({recall*100:.2f}%)")
    print(f"  F1 Score:    {f1:.4f} ({f1*100:.2f}%)")
    print(f"  FPR:         {fpr:.4f} ({fpr*100:.2f}%)")
    print(f"  Specificity: {specificity:.4f} ({specificity*100:.2f}%)")
    print(f"  Avg Time:    {avg_time:.3f}s per contract")
    print(f"  Success Rate: {success_rate:.1f}%")
    
    # Save results
    output = {
        "experiment": "slither_static_analysis",
        "timestamp": datetime.now().isoformat(),
        "metrics": {
            "total": total,
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
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
