#!/usr/bin/env python3
"""
Step 1: Prepare the dataset for experiments.
- Load SmartBugs Curated (143 vulnerable contracts)
- Sample 857 safe contracts from SmartBugs Wild
- Total: 1000 contracts (14.3% vulnerable, 85.7% safe)
"""

import os
import json
import random
import glob
from datetime import datetime

SEED = 42
random.seed(SEED)

BASE_DIR = "/home/curtis/DmAVID"
CURATED_DIR = os.path.join(BASE_DIR, "data/smartbugs_curated_repo/dataset")
WILD_DIR = os.path.join(BASE_DIR, "data/smartbugs_wild_repo/contracts")
OUTPUT_FILE = os.path.join(BASE_DIR, "data/dataset_1000.json")

VULN_CATEGORIES = [
    "access_control", "arithmetic", "bad_randomness", "denial_of_service",
    "front_running", "other", "reentrancy", "short_addresses",
    "time_manipulation", "unchecked_low_level_calls"
]

def load_curated_contracts():
    """Load all vulnerable contracts from SmartBugs Curated."""
    contracts = []
    for category in VULN_CATEGORIES:
        cat_dir = os.path.join(CURATED_DIR, category)
        if not os.path.isdir(cat_dir):
            continue
        for sol_file in glob.glob(os.path.join(cat_dir, "*.sol")):
            try:
                with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                if len(code.strip()) < 50:
                    continue
                contracts.append({
                    "id": f"curated_{category}_{os.path.basename(sol_file)}",
                    "source": "smartbugs_curated",
                    "category": category,
                    "label": "vulnerable",
                    "filename": os.path.basename(sol_file),
                    "filepath": sol_file,
                    "code": code,
                    "lines": len(code.split('\n'))
                })
            except Exception as e:
                print(f"  Error reading {sol_file}: {e}")
    return contracts

def load_wild_contracts(target_count=857):
    """Load safe contracts from SmartBugs Wild."""
    # Find all .sol files in wild dataset
    all_sol = glob.glob(os.path.join(WILD_DIR, "**/*.sol"), recursive=True)
    if not all_sol:
        # Try alternative path
        alt_paths = glob.glob(os.path.join(BASE_DIR, "data/smartbugs_wild_repo/**/*.sol"), recursive=True)
        all_sol = alt_paths
    
    print(f"  Found {len(all_sol)} total .sol files in SmartBugs Wild")
    
    # Filter: only keep contracts with reasonable size (>50 chars, <50000 chars)
    valid_contracts = []
    for sol_file in all_sol:
        try:
            with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            if 50 < len(code.strip()) < 50000:
                valid_contracts.append({
                    "filepath": sol_file,
                    "code": code,
                    "filename": os.path.basename(sol_file)
                })
        except:
            continue
    
    print(f"  Valid contracts after filtering: {len(valid_contracts)}")
    
    # Random sample
    random.shuffle(valid_contracts)
    sampled = valid_contracts[:target_count]
    
    contracts = []
    for i, c in enumerate(sampled):
        contracts.append({
            "id": f"wild_safe_{i:04d}_{c['filename']}",
            "source": "smartbugs_wild",
            "category": "none",
            "label": "safe",
            "filename": c['filename'],
            "filepath": c['filepath'],
            "code": c['code'],
            "lines": len(c['code'].split('\n'))
        })
    
    return contracts

def main():
    print("=" * 60)
    print("Dataset Preparation for DeFi Vulnerability Detection")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Random Seed: {SEED}")
    print("=" * 60)
    
    # Load vulnerable contracts
    print("\n[1/3] Loading SmartBugs Curated (vulnerable contracts)...")
    vuln_contracts = load_curated_contracts()
    print(f"  Loaded {len(vuln_contracts)} vulnerable contracts")
    
    # Category breakdown
    cat_counts = {}
    for c in vuln_contracts:
        cat_counts[c['category']] = cat_counts.get(c['category'], 0) + 1
    print("  Category breakdown:")
    for cat, count in sorted(cat_counts.items()):
        print(f"    {cat}: {count}")
    
    # Load safe contracts
    target_safe = 1000 - len(vuln_contracts)
    print(f"\n[2/3] Loading SmartBugs Wild (safe contracts, target={target_safe})...")
    safe_contracts = load_wild_contracts(target_count=target_safe)
    print(f"  Loaded {len(safe_contracts)} safe contracts")
    
    # Combine
    all_contracts = vuln_contracts + safe_contracts
    random.shuffle(all_contracts)  # Shuffle for experiment
    
    print(f"\n[3/3] Final dataset:")
    print(f"  Total contracts: {len(all_contracts)}")
    print(f"  Vulnerable: {len(vuln_contracts)} ({len(vuln_contracts)/len(all_contracts)*100:.1f}%)")
    print(f"  Safe: {len(safe_contracts)} ({len(safe_contracts)/len(all_contracts)*100:.1f}%)")
    
    # Line count statistics
    lines = [c['lines'] for c in all_contracts]
    print(f"  Line count: min={min(lines)}, max={max(lines)}, avg={sum(lines)/len(lines):.0f}")
    
    # Save dataset (without full code to keep JSON manageable)
    dataset_meta = []
    for c in all_contracts:
        dataset_meta.append({
            "id": c['id'],
            "source": c['source'],
            "category": c['category'],
            "label": c['label'],
            "filename": c['filename'],
            "filepath": c['filepath'],
            "lines": c['lines'],
            "code_length": len(c['code'])
        })
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump({
            "metadata": {
                "created": datetime.now().isoformat(),
                "seed": SEED,
                "total": len(all_contracts),
                "vulnerable": len(vuln_contracts),
                "safe": len(safe_contracts)
            },
            "contracts": dataset_meta
        }, f, indent=2)
    
    print(f"\n  Dataset saved to: {OUTPUT_FILE}")
    print("=" * 60)

if __name__ == "__main__":
    main()
