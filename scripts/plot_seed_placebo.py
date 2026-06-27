#!/usr/bin/env python3
"""Error-bar figure for the multi-seed treatment vs placebo iteration experiment."""
import json, glob, os
import statistics as st
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = "/home/curtis/DmAVID"
runs = {}
for f in sorted(glob.glob(os.path.join(BASE, "experiments/seed_placebo/*/summary.json"))):
    d = json.load(open(f))
    runs.setdefault(d["cond"], []).append([r["f1"] for r in d["rounds"]])

def stats(cond, ridx):
    vals = [f1[ridx] for f1 in runs[cond]]
    return st.mean(vals), (st.pstdev(vals) if len(vals) > 1 else 0.0)

rounds = ["R1", "R2", "R3"]
x = [1, 2, 3]
fig, ax = plt.subplots(figsize=(7.2, 4.6), dpi=150)

for cond, color, mk in [("treatment", "#dc2626", "o"), ("placebo", "#2563eb", "s")]:
    means = [stats(cond, i)[0] for i in range(3)]
    stds  = [stats(cond, i)[1] for i in range(3)]
    ax.errorbar(x, means, yerr=stds, label=f"{cond} (n=3 seeds)",
                color=color, marker=mk, markersize=7, capsize=5, linewidth=2,
                elinewidth=1.5, alpha=0.9)
    for xi, m, s in zip(x, means, stds):
        ax.annotate(f"{m:.4f}", (xi, m), textcoords="offset points",
                    xytext=(8, 8 if cond == "treatment" else -14), fontsize=8, color=color)

# baseline reference (published LLM+RAG)
ax.axhline(0.9061, color="#6b7280", ls="--", lw=1, alpha=0.7)
ax.annotate("LLM+RAG baseline 0.9061", (1.0, 0.9061), textcoords="offset points",
            xytext=(2, 4), fontsize=8, color="#6b7280")

ax.set_xticks(x); ax.set_xticklabels(rounds)
ax.set_xlabel("Iteration round")
ax.set_ylabel("F1-score (mean +/- std over seeds 42/7/123)")
ax.set_title("Adversarial Iteration: Treatment vs Placebo (DmAVID, SmartBugs 243)\n"
             "Bands overlap -> no significant iteration gain", fontsize=11)
ax.legend(loc="lower left", fontsize=9)
ax.grid(True, alpha=0.25)
ax.set_ylim(0.88, 0.945)
fig.tight_layout()
out = "/mnt/d/OneDrive/DmAVID/charts/fig_seed_placebo_errorbar.png"
fig.savefig(out, bbox_inches="tight")
print("saved:", out)

# also print final verdict numbers for the report
tm = stats("treatment", 2); pm = stats("placebo", 2)
print(f"treatment R3: {tm[0]:.4f} +/- {tm[1]:.4f}")
print(f"placebo   R3: {pm[0]:.4f} +/- {pm[1]:.4f}")
