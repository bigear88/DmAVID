#!/usr/bin/env python3
"""Test 10 contracts through LLM+RAG for OpenAI log verification."""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _model_compat import token_param
from importlib import import_module

MODEL = os.environ.get("DAVID_MODEL", "gpt-4.1-mini")
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

print("Model:", MODEL)
print("=" * 70)
print("Testing 10 contracts with LLM+RAG")
print("=" * 70)

with open(os.path.join(BASE_DIR, "data/dataset_1000.json")) as f:
    ds = json.load(f)
contracts = ds["contracts"]
vuln = [c for c in contracts if c["label"] == "vulnerable"][:5]
safe = [c for c in contracts if c["label"] == "safe"][:5]
sample = vuln + safe

rag_mod = import_module("05_run_llm_rag")

tp, fn, fp, tn = 0, 0, 0, 0
for i, c in enumerate(sample):
    filepath = c["filepath"]
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()
    
    code_preview = code[:80].replace("\n", " ").strip()
    print()
    print(f"[{i+1}/10] {c["label"]:10s} | {c["filename"][:45]}")
    print(f"  filepath: {filepath[:80]}")
    print(f"  code_len: {len(code)} | first_line: {code_preview}...")
    
    if not code.strip():
        print("  *** EMPTY CODE - SKIPPING ***")
        continue
    
    result = rag_mod.analyze_with_rag(code)
    
    pred = result.get("predicted_vulnerable", False)
    conf = result.get("confidence", 0)
    tokens = result.get("tokens_used", 0)
    error = result.get("error", None)
    reasoning = str(result.get("reasoning", ""))[:200]
    
    if c["label"] == "vulnerable" and pred: tp += 1
    elif c["label"] == "vulnerable" and not pred: fn += 1
    elif c["label"] == "safe" and pred: fp += 1
    else: tn += 1
    
    match = "CORRECT" if (c["label"]=="vulnerable")==pred else "WRONG"
    print(f"  result: pred={pred} conf={conf:.3f} tokens={tokens} error={error} [{match}]")
    print(f"  reasoning: {reasoning}")

print()
print("=" * 70)
print(f"TP={tp} FN={fn} FP={fp} TN={tn}")
prec = tp/(tp+fp) if (tp+fp) else 0
rec = tp/(tp+fn) if (tp+fn) else 0
f1 = 2*prec*rec/(prec+rec) if (prec+rec) else 0
print(f"Precision={prec:.2f} Recall={rec:.2f} F1={f1:.2f}")
print("=" * 70)
