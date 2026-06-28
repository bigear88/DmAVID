#!/usr/bin/env python3
"""Visualize the reward-gated KB learning prototype:
left = VAL vs TEST for baseline/gated/ungated; right = TEST per-audit (renft collapse)."""
import json, os, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = "/home/curtis/DmAVID"
d = json.load(open(f"{BASE}/experiments/reward_gated/reward_gated_results.json"))
OUT = "/mnt/d/OneDrive/DmAVID/charts/fig_reward_gated.png"

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

# ---- Left: VAL & TEST for three conditions ----
conds = ["Baseline\n(KB only)", "GATED\n(2/8 committed)", "UNGATED\n(all 8, = current\nDmAVID write-all)"]
val = [d["baseline"]["val"], d["gated"]["val"], d["ungated"]["val"]]
test = [d["baseline"]["test"], d["gated"]["test"], d["ungated"]["test"]]
x = range(len(conds))
w = 0.36
b1 = ax1.bar([i - w/2 for i in x], val, w, label="VAL (gate selects on this)", color="#7CA6CF", edgecolor="white")
b2 = ax1.bar([i + w/2 for i in x], test, w, label="TEST (held-out, report)", color="#E0982E", edgecolor="white")
for bars in (b1, b2):
    for b in bars:
        ax1.text(b.get_x()+b.get_width()/2, b.get_height()+0.012, f"{b.get_height():.2f}",
                 ha="center", va="bottom", fontsize=10, fontweight="bold")
ax1.set_xticks(list(x)); ax1.set_xticklabels(conds, fontsize=9)
ax1.set_ylim(0, 1.0); ax1.set_ylabel("Detection Rate")
ax1.set_title("Reward Gate OVERFITS the Validation Slice\n"
              "GATED: VAL up (0.32->0.79) but TEST collapses (0.75->0.45, -0.30)\n"
              "UNGATED (write-all): TEST preserved (0.75)", fontsize=10.5)
ax1.legend(fontsize=9, loc="upper left")
ax1.grid(axis="y", linestyle=":", alpha=0.4)
ax1.annotate("gate overfit\n-0.30 on TEST", xy=(1+0.18, d["gated"]["test"]),
             xytext=(1.35, 0.62), fontsize=9, color="#dc2626", fontweight="bold",
             arrowprops=dict(arrowstyle="->", color="#dc2626", lw=1.5))

# ---- Right: TEST per-audit, baseline vs gated (renft collapse) ----
names = [r[0].split("-", 2)[-1] for r in d["baseline"]["test_rows"]]
base_r = [r[1] for r in d["baseline"]["test_rows"]]
gate_r = [next(g[1] for g in d["gated"]["test_rows"] if g[0]==r[0]) for r in d["baseline"]["test_rows"]]
gold_r = [r[2] for r in d["baseline"]["test_rows"]]
xi = range(len(names))
ax2.bar([i - w/2 for i in xi], base_r, w, label="baseline detected", color="#34618A", edgecolor="white")
ax2.bar([i + w/2 for i in xi], gate_r, w, label="GATED detected", color="#C0504D", edgecolor="white")
ax2.plot(list(xi), gold_r, "k_", markersize=22, markeredgewidth=2, label="gold (total)")
ax2.set_xticks(list(xi)); ax2.set_xticklabels(names, fontsize=9, rotation=15)
ax2.set_ylabel("Vulns detected on TEST")
ax2.set_title("Per-Audit TEST: the 2 gate-picked patches\n"
              "silently destroyed renft (6/6 -> 0/6)", fontsize=10.5)
ax2.legend(fontsize=9)
ax2.grid(axis="y", linestyle=":", alpha=0.4)
ax2.annotate("renft 6->0", xy=(2+0.18, 0.3), xytext=(2.4, 4),
             fontsize=10, color="#dc2626", fontweight="bold",
             arrowprops=dict(arrowstyle="->", color="#dc2626", lw=1.5))

plt.tight_layout()
plt.savefig(OUT, dpi=300, bbox_inches="tight")
print("saved:", OUT)
