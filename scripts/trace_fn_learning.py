#!/usr/bin/env python3
"""Trace whether R1 false-negatives get 'learned' (caught) by R3, and what it costs.
For treatment_seed42: compare per-contract predictions R1 vs R3."""
import json, os
BASE = "/home/curtis/DmAVID/experiments/seed_placebo/treatment_seed42"

def load(rn):
    d = json.load(open(os.path.join(BASE, f"round_{rn}_results.json")))
    out = {}
    for r in d["results"]:
        cid = r.get("contract_id") or r.get("filepath")
        out[cid] = (bool(r.get("ground_truth_vulnerable")), bool(r.get("predicted_vulnerable")))
    return out

r1, r3 = load(1), load(3)
common = set(r1) & set(r3)

fn_r1 = [c for c in common if r1[c][0] and not r1[c][1]]      # real vuln missed in R1
fp_r1 = [c for c in common if (not r1[c][0]) and r1[c][1]]

fn_fixed   = [c for c in fn_r1 if r3[c][1]]                   # FN in R1 -> caught in R3 (learned!)
fn_stillmiss = [c for c in fn_r1 if not r3[c][1]]
# new errors introduced by R3 that were correct in R1
new_fp = [c for c in common if (not r3[c][0]) and r3[c][1] and not (not r1[c][0] and r1[c][1])]
new_fn = [c for c in common if r3[c][0] and not r3[c][1] and not (r1[c][0] and not r1[c][1])]

print(f"contracts compared: {len(common)}")
print(f"\nR1 false-negatives (real vuln missed): {len(fn_r1)}")
print(f"  -> CAUGHT in R3 (the 'learned it' effect): {len(fn_fixed)}")
print(f"  -> still missed in R3:                    {len(fn_stillmiss)}")
print(f"\nBUT cost of the nudge:")
print(f"  NEW false-positives created by R3 (were correct in R1): {len(new_fp)}")
print(f"  NEW false-negatives created by R3 (were correct in R1): {len(new_fn)}")
print(f"\nNet on real-vuln detection: fixed {len(fn_fixed)} - newly-broken {len(new_fn)} = {len(fn_fixed)-len(new_fn):+d}")
print(f"Net on safe contracts:      new FP {len(new_fp)} (pure cost)")
