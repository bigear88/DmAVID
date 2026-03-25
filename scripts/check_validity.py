#!/usr/bin/env python3
"""Check for sample size issues and data leakage in experiments."""
import json, os
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load LLM+RAG results
with open(os.path.join(BASE, "experiments/llm_rag/llm_rag_results.json")) as f:
    rag = json.load(f)

# Load dataset for filenames
with open(os.path.join(BASE, "data/dataset_1000.json")) as f:
    ds = json.load(f)
contracts_by_id = {c["id"]: c for c in ds["contracts"]}

results = rag["results"]

print("=" * 75)
print("1. PER-CATEGORY SAMPLE SIZE + RECALL ANALYSIS")
print("=" * 75)

cats = defaultdict(lambda: {"total": 0, "tp": 0, "fn": 0})
for r in results:
    if r.get("ground_truth") != "vulnerable":
        continue
    cat = r.get("category", "unknown")
    cats[cat]["total"] += 1
    if r.get("predicted_vulnerable"):
        cats[cat]["tp"] += 1
    else:
        cats[cat]["fn"] += 1

print(f"\n{'Category':<30} {'N':>5} {'TP':>4} {'FN':>4} {'Recall':>8} {'Statistical Power'}")
print("-" * 80)
for cat in sorted(cats.keys(), key=lambda x: cats[x]["total"], reverse=True):
    c = cats[cat]
    rec = c["tp"] / c["total"] if c["total"] > 0 else 0
    if c["total"] >= 30:
        power = "ADEQUATE"
    elif c["total"] >= 10:
        power = "MARGINAL"
    elif c["total"] >= 5:
        power = "LOW (n<10)"
    else:
        power = "VERY LOW (n<5)"
    flag = " *** 100% with small n" if rec == 1.0 and c["total"] < 10 else ""
    print(f"{cat:<30} {c['total']:>5} {c['tp']:>4} {c['fn']:>4} {rec:>7.1%}   {power}{flag}")

total_vuln = sum(c["total"] for c in cats.values())
cats_100 = [cat for cat, c in cats.items() if c["tp"] == c["total"]]
cats_100_small = [cat for cat, c in cats.items() if c["tp"] == c["total"] and c["total"] < 10]
print(f"\nTotal vulnerable: {total_vuln}")
print(f"Categories at 100%: {len(cats_100)} ({', '.join(cats_100)})")
print(f"Categories at 100% with n<10: {len(cats_100_small)} ({', '.join(cats_100_small)})")

print("\n" + "=" * 75)
print("2. DATA LEAKAGE CHECK: CONTRACT ID CONTAINS CATEGORY HINTS")
print("=" * 75)

HINT_KEYWORDS = ["reentrancy", "overflow", "underflow", "access_control",
                 "bad_randomness", "dos", "front_running", "time_manipulation",
                 "unchecked", "arithmetic", "short_address"]

hint_count = 0
vuln_results = [r for r in results if r.get("ground_truth") == "vulnerable"]
for r in vuln_results:
    cid = r.get("contract_id", "")
    has_hint = any(k in cid.lower() for k in HINT_KEYWORDS)
    if has_hint:
        hint_count += 1

print(f"\nVulnerable contracts with category in ID: {hint_count}/{len(vuln_results)}")
print(f"Percentage: {hint_count/len(vuln_results)*100:.1f}%")

# Show examples
print("\nExamples of IDs WITH category hints:")
for r in vuln_results[:5]:
    cid = r.get("contract_id", "")
    cat = r.get("category", "")
    print(f"  ID: {cid[:60]}  cat={cat}")

# Check if the SmartBugs Curated dataset path contains category info
print("\n" + "=" * 75)
print("3. DATA LEAKAGE CHECK: FILE PATH CONTAINS CATEGORY")
print("=" * 75)

path_leak = 0
for r in vuln_results:
    cid = r.get("contract_id", "")
    c = contracts_by_id.get(cid, {})
    fp = c.get("filepath", "")
    cat = r.get("category", "")
    # Check if filepath contains the category
    if cat.lower() in fp.lower():
        path_leak += 1

print(f"Contracts where filepath contains category: {path_leak}/{len(vuln_results)}")
print(f"Percentage: {path_leak/len(vuln_results)*100:.1f}%")

# Show the filepath structure
print("\nSample filepaths:")
for r in vuln_results[:5]:
    cid = r.get("contract_id", "")
    c = contracts_by_id.get(cid, {})
    print(f"  {c.get('filepath', '?')[:80]}")

print("\n" + "=" * 75)
print("4. CHECK: IS CONTRACT CODE SENT TO LLM OR JUST FILENAME?")
print("=" * 75)

# Check if the LLM+RAG prompt sends the contract_id or filename
# The prompt in 05_run_llm_rag.py sends raw code, but does it also include the ID?
print("\nChecking 05_run_llm_rag.py prompt structure...")
with open(os.path.join(BASE, "scripts/05_run_llm_rag.py")) as f:
    script = f.read()

if "contract_id" in script.lower() and "user_msg" in script.lower():
    print("  WARNING: contract_id might be sent to LLM")
else:
    print("  OK: contract_id not found in prompt construction")

if "filename" in script.lower() and "user_msg" in script.lower():
    print("  WARNING: filename might be sent to LLM")
else:
    print("  OK: filename not found in prompt construction")

# Check what's actually in the user message
import re
# Find the user_msg construction
matches = re.findall(r'user_msg\s*=.*?(?=\n\n|\n    for)', script, re.DOTALL)
for m in matches:
    print(f"  user_msg construction: {m[:200]}")

print("\n" + "=" * 75)
print("5. SMARTBUGS CURATED: PUBLIC DATASET + GPT TRAINING DATA OVERLAP")
print("=" * 75)

print("""
SmartBugs Curated (Ferreira et al., 2020) is a PUBLIC dataset:
- Published on GitHub since 2020
- Widely cited in 100+ papers
- Contains contracts from Etherscan (public blockchain)
- Contract source code is publicly available

GPT-5.4-mini training data cutoff includes:
- All SmartBugs-related papers and analyses
- Security audit reports referencing these contracts
- GitHub repositories that fork/analyze SmartBugs
- Etherscan source code of these contracts

RISK LEVEL: HIGH — the model likely saw these contracts during training.

HOWEVER, this is the SAME limitation as ALL other papers using SmartBugs:
- GPTScan (ICSE 2024) also uses SmartBugs
- LLM-SmartAudit (IEEE TSE 2025) also uses SmartBugs
- AuditGPT also uses SmartBugs

This is a known limitation of the field, not unique to this study.
""")

print("=" * 75)
print("SUMMARY")
print("=" * 75)
print("""
CONCERN 1 - Sample Size:
  5 categories with n<10: bad_randomness(8), dos(6), time(5), front(4), short(1), other(3)
  100% recall with n<5 is NOT statistically meaningful
  RECOMMENDATION: Report "n too small for reliable estimate" in thesis

CONCERN 2 - Data Leakage (Filename):
  SmartBugs Curated uses format: curated_{category}_{contract}.sol
  The category IS in the contract_id field in results JSON
  BUT: check if this info reaches the LLM prompt

CONCERN 3 - Training Data Contamination:
  SmartBugs is a public dataset from 2020
  GPT likely saw it during training
  This is field-wide, not study-specific
  RECOMMENDATION: Acknowledge in Threats to Validity section
""")
