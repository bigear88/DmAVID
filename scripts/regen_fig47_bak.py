#!/usr/bin/env python3
"""Regenerate 圖 4-7 (per-category F1 across iteration rounds) from the MONOTONIC
compile-gated canonical (BAK 2026-06-22). Per-category F1 = 2R/(1+R), safe excluded.
Now rising, consistent with the monotonic main narrative."""
import json, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from collections import defaultdict

BAK = "/home/curtis/DmAVID/experiments/dmavid_autonomous_BAK_precompile_20260626"
OUT = "/tmp/fig4_7_bak.png"

def per_cat_f1(rn):
    res = json.load(open(f"{BAK}/round_{rn}_results.json"))["results"]
    tpfn = defaultdict(lambda: [0, 0])
    for x in res:
        if str(x["ground_truth_vulnerable"]).lower() == "true":
            tpfn[x["category"]][0 if str(x["predicted_vulnerable"]).lower() == "true" else 1] += 1
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
    ys = [data[r].get(c) for r in rounds]
    ax.plot([f"R{r}" for r in rounds], ys, marker=markers[i], linewidth=2,
            markersize=8, label=labels[c])
    for r, y in zip(rounds, ys):
        if y is not None:
            ax.annotate(f"{y:.4f}", (f"R{r}", y), textcoords="offset points",
                        xytext=(0, 8), ha="center", fontsize=8)

ax.set_ylabel("Per-category F1 (recall-based; safe contracts excluded)")
ax.set_xlabel("Iteration round")
ax.set_ylim(0.83, 1.08)
ax.set_yticks([0.85, 0.90, 0.95, 1.00])
ax.set_title("Per-category F1 across adversarial iteration rounds\n"
             "(canonical compile-gated run; monotonic overall F1 0.9103->0.9153->0.9158)",
             fontsize=12)
ax.legend(loc="lower right", fontsize=9)
ax.grid(axis="y", alpha=0.3)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
fig.tight_layout()
fig.savefig(OUT, dpi=150); plt.close(fig)
print("saved", OUT)
for r in rounds:
    print(f"R{r}:", {c: round(data[r].get(c, 0), 4) for c in cats})
