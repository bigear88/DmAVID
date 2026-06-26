#!/usr/bin/env python3
"""
73_per_category_iteration_chart.py — 圖4-7 per-category F1 trend across iteration rounds.

Recomputed from the GENUINE autonomous run (with real forge test PoC validation):
experiments/dmavid_autonomous/round_{1,2,3}_results.json.

Per-category "F1" is computed over that category's vulnerable contracts only
(safe contracts excluded), so precision == 1.0 by construction and this F1 is a
recall transform — it tracks per-category missed detections, not false positives.
"""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from collections import defaultdict
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
CH = BASE / "charts"; CH.mkdir(exist_ok=True)

def per_cat_f1(round_num):
    res = json.load(open(BASE / f"experiments/dmavid_autonomous/round_{round_num}_results.json"))["results"]
    tpfn = defaultdict(lambda: [0, 0])
    for x in res:
        if x["ground_truth_vulnerable"]:
            tpfn[x["category"]][0 if x["predicted_vulnerable"] else 1] += 1
    out = {}
    for c, (tp, fn) in tpfn.items():
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        out[c] = 2 * rec / (1 + rec) if rec else 0.0
    return out

rounds = [1, 2, 3]
data = {r: per_cat_f1(r) for r in rounds}
cats = ["arithmetic", "access_control", "unchecked_low_level_calls",
        "bad_randomness", "time_manipulation"]
labels = {"arithmetic": "Arithmetic", "access_control": "Access Control",
          "unchecked_low_level_calls": "Unchecked Low-Level Calls",
          "bad_randomness": "Bad Randomness", "time_manipulation": "Time Manipulation"}

fig, ax = plt.subplots(figsize=(11, 6.5))
markers = ["o", "s", "^", "D", "v"]
for i, c in enumerate(cats):
    ys = [data[r].get(c, None) for r in rounds]
    ax.plot([f"R{r}" for r in rounds], ys, marker=markers[i], linewidth=2,
            markersize=8, label=labels[c])
    for r, y in zip(rounds, ys):
        if y is not None:
            ax.annotate(f"{y:.4f}", (f"R{r}", y), textcoords="offset points",
                        xytext=(0, 8), ha="center", fontsize=8)

ax.set_ylabel("Per-category F1 (recall-based; safe contracts excluded)")
ax.set_xlabel("Iteration round")
ax.set_ylim(0.83, 1.03)
ax.set_title("Per-category F1 across adversarial iteration rounds\n"
             "(genuine run with real forge test PoC validation)", fontsize=13)
ax.legend(loc="lower left", fontsize=9)
ax.grid(axis="y", alpha=0.3)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
fig.tight_layout()
out = CH / "fig4_7_per_category_iteration.png"
fig.savefig(out, dpi=150); plt.close(fig)
print("Saved:", out)
for r in rounds:
    print(f"R{r}:", {c: round(data[r].get(c, 0), 4) for c in cats})
