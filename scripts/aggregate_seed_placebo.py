#!/usr/bin/env python3
"""Aggregate the multi-seed treatment/placebo experiment.
Reads experiments/seed_placebo/*/summary.json and reports per-run F1 trajectories
plus treatment/placebo mean +/- std (final round) for the significance read."""
import json, glob, os, statistics as st

BASE = "/home/curtis/DmAVID"
rows = []
for f in sorted(glob.glob(os.path.join(BASE, "experiments/seed_placebo/*/summary.json"))):
    d = json.load(open(f))
    f1s = [r["f1"] for r in d["rounds"]]
    rows.append({"cond": d["cond"], "seed": d["seed"], "f1": f1s,
                 "r1": f1s[0] if f1s else None,
                 "r3": f1s[-1] if f1s else None})

print(f"{'cond':10} {'seed':5} {'R1':7} {'R2':7} {'R3':7} {'R1->R3':8}")
for r in sorted(rows, key=lambda x: (x["seed"], x["cond"])):
    f = r["f1"]
    if len(f) == 3:
        print(f"{r['cond']:10} {r['seed']:<5} {f[0]:.4f}  {f[1]:.4f}  {f[2]:.4f}  {f[2]-f[0]:+.4f}")
    else:
        print(f"{r['cond']:10} {r['seed']:<5} (incomplete: {f})")

print(f"\ncompleted runs: {len(rows)}/6")

def band(cond, key):
    vals = [r[key] for r in rows if r["cond"] == cond and r[key] is not None
            and len(r["f1"]) == 3]
    if not vals:
        return None
    m = st.mean(vals)
    s = st.pstdev(vals) if len(vals) > 1 else 0.0
    return m, s, vals

for cond in ("treatment", "placebo"):
    for key, lbl in (("r3", "final R3"), ("r1", "start R1")):
        b = band(cond, key)
        if b:
            m, s, vals = b
            print(f"{cond:10} {lbl:9}: mean={m:.4f}  std={s:.4f}  n={len(vals)}  band=[{m-s:.4f}, {m+s:.4f}]")

tr = band("treatment", "r3"); pl = band("placebo", "r3")
if tr and pl and len(tr[2]) >= 2 and len(pl[2]) >= 2:
    print("\n--- VERDICT (final R3) ---")
    print(f"treatment band [{tr[0]-tr[1]:.4f},{tr[0]+tr[1]:.4f}] vs placebo band [{pl[0]-pl[1]:.4f},{pl[0]+pl[1]:.4f}]")
    overlap = not (tr[0]-tr[1] > pl[0]+pl[1] or pl[0]-pl[1] > tr[0]+tr[1])
    print("bands OVERLAP -> iteration NOT significant (gain is noise)" if overlap
          else "bands SEPARATE -> treatment significantly differs from placebo")
