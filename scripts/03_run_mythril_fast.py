#!/usr/bin/env python3
"""
Experiment 2: Run Mythril symbolic execution (fast version).
Reduced sample size and shorter timeout due to Mythril's slow speed.
"""

import os, json, subprocess, time, glob, random, re
from datetime import datetime

random.seed(42)
BASE_DIR = "/home/ubuntu/defi-vuln-detection"
CURATED_DIR = os.path.join(BASE_DIR, "data/smartbugs_curated_repo/dataset")
WILD_DIR = os.path.join(BASE_DIR, "data/smartbugs_wild_repo/contracts")
OUTPUT_FILE = os.path.join(BASE_DIR, "experiments/mythril/mythril_results.json")

SOLC_VERSIONS = {"0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12", "0.7": "0.7.6", "0.8": "0.8.0"}

def detect_solc_version(code):
    match = re.search(r'pragma\s+solidity\s+[\^>=<]*\s*(0\.\d+)', code)
    return SOLC_VERSIONS.get(match.group(1), "0.8.0") if match else "0.8.0"

def run_mythril(filepath, timeout=45):
    start = time.time()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        ver = detect_solc_version(code)
        r = subprocess.run(
            ["myth", "analyze", filepath, "--solv", ver, "--execution-timeout", "30", "-o", "json"],
            capture_output=True, text=True, timeout=timeout
        )
        elapsed = time.time() - start
        issues = []
        if r.stdout:
            try:
                out = json.loads(r.stdout)
                issues = out.get("issues", out if isinstance(out, list) else [])
            except: pass
        
        vtypes = list(set(i.get("title","unknown") for i in issues))
        sevs = [i.get("severity","unknown") for i in issues]
        return {
            "success": True, "num_detections": len(issues),
            "vuln_types": vtypes, "severities": sevs,
            "predicted_vulnerable": len(issues) > 0,
            "high_severity": any(s in ["High","Medium"] for s in sevs),
            "time_seconds": round(elapsed, 3), "error": None
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "num_detections": 0, "vuln_types": [], "severities": [],
                "predicted_vulnerable": False, "high_severity": False,
                "time_seconds": timeout, "error": "timeout"}
    except Exception as e:
        return {"success": False, "num_detections": 0, "vuln_types": [], "severities": [],
                "predicted_vulnerable": False, "high_severity": False,
                "time_seconds": time.time()-start, "error": str(e)}

def main():
    print("=" * 60)
    print("Experiment 2: Mythril Symbolic Execution (Fast)")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 60)
    
    results = []
    
    # 1. Curated: sample 20 vulnerable
    print("\n[1/2] Mythril on SmartBugs Curated (vulnerable, sample=20)...")
    curated = glob.glob(os.path.join(CURATED_DIR, "**/*.sol"), recursive=True)
    random.shuffle(curated)
    sample_v = curated[:20]
    
    for i, fp in enumerate(sample_v):
        parts = fp.split('/')
        cat = next((p for p in parts if p in ["access_control","arithmetic","bad_randomness",
            "denial_of_service","front_running","other","reentrancy","short_addresses",
            "time_manipulation","unchecked_low_level_calls"]), "unknown")
        with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        r = run_mythril(fp)
        r.update({"contract_id": f"curated_{cat}_{os.path.basename(fp)}", "ground_truth": "vulnerable",
                  "category": cat, "filename": os.path.basename(fp), "lines": len(code.split('\n'))})
        results.append(r)
        tp = sum(1 for x in results if x["ground_truth"]=="vulnerable" and x["predicted_vulnerable"])
        fn = sum(1 for x in results if x["ground_truth"]=="vulnerable" and not x["predicted_vulnerable"])
        print(f"  [{i+1}/{len(sample_v)}] TP={tp} FN={fn} Recall={tp/(tp+fn)*100:.1f}% | {r['time_seconds']:.1f}s | {r['error'] or 'OK'}")
    
    # 2. Wild: sample 20 safe
    print("\n[2/2] Mythril on SmartBugs Wild (safe, sample=20)...")
    wild = glob.glob(os.path.join(WILD_DIR, "**/*.sol"), recursive=True)
    random.shuffle(wild)
    safe_sample = []
    for f in wild:
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                code = fh.read()
            if 100 < len(code.strip()) < 10000:
                safe_sample.append(f)
            if len(safe_sample) >= 20:
                break
        except: continue
    
    for i, fp in enumerate(safe_sample):
        with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        r = run_mythril(fp)
        r.update({"contract_id": f"wild_safe_{i:04d}_{os.path.basename(fp)}", "ground_truth": "safe",
                  "category": "none", "filename": os.path.basename(fp), "lines": len(code.split('\n'))})
        results.append(r)
        fp_count = sum(1 for x in results if x["ground_truth"]=="safe" and x["predicted_vulnerable"])
        tn = sum(1 for x in results if x["ground_truth"]=="safe" and not x["predicted_vulnerable"])
        ts = fp_count + tn
        print(f"  [{i+1}/{len(safe_sample)}] FP={fp_count} TN={tn} FPR={fp_count/ts*100:.1f}% | {r['time_seconds']:.1f}s")
    
    # Metrics
    print("\n" + "=" * 60)
    print("MYTHRIL RESULTS SUMMARY")
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
    succ = sum(1 for r in results if r["success"])/len(results)*100 if results else 0
    
    print(f"  Total: {total} | TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"  Accuracy:    {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision:   {prec:.4f} ({prec*100:.2f}%)")
    print(f"  Recall:      {rec:.4f} ({rec*100:.2f}%)")
    print(f"  F1 Score:    {f1:.4f} ({f1*100:.2f}%)")
    print(f"  FPR:         {fpr_val:.4f} ({fpr_val*100:.2f}%)")
    print(f"  Specificity: {spec:.4f} ({spec*100:.2f}%)")
    print(f"  Avg Time:    {avg_t:.3f}s per contract")
    print(f"  Success Rate: {succ:.1f}%")
    
    output = {
        "experiment": "mythril_symbolic_execution",
        "timestamp": datetime.now().isoformat(),
        "metrics": {"total": total, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "accuracy": round(acc,4), "precision": round(prec,4), "recall": round(rec,4),
            "f1_score": round(f1,4), "fpr": round(fpr_val,4), "specificity": round(spec,4),
            "avg_time_seconds": round(avg_t,3), "success_rate": round(succ,2)},
        "results": results
    }
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
