#!/usr/bin/env python3
"""Regenerate 圖 4-13 (time-stratified degradation) with corrected, leak-free numbers.
Left: SmartBugs F1 0.9121 -> EVMbench 2024 (smart-preprocess) 64.10% -> post-cutoff 58.82%.
Right: per-audit post-cutoff detection (Table 4-17). English labels (CJK-font-safe)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT_CN = "/mnt/d/OneDrive/DmAVID/charts/圖4-13_時序分層驗證之效能衰退趨勢.png"
OUT_TMP = "/tmp/fig413_new.png"

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

# ---- Left: three-way comparison ----
labels = ["A. SmartBugs\n(pre-2023, likely leaked)",
          "B. EVMbench 2024\n(boundary, cutoff=2024-10)",
          "C. EVMbench 2025+\n(post-cutoff, clean)"]
vals = [0.9121, 0.6410, 0.5882]
notes = ["0.9121\n(F1 / N=243)", "0.6410\n(detect rate / 39 vulns)", "0.5882\n(detect rate / 17 vulns)"]
colors = ["#34618A", "#7CA6CF", "#E0982E"]
bars = ax1.bar(labels, vals, color=colors, width=0.6, edgecolor="white")
for b, n in zip(bars, notes):
    ax1.text(b.get_x()+b.get_width()/2, b.get_height()+0.015, n,
             ha="center", va="bottom", fontsize=10, fontweight="bold")
# decline arrows
d1 = vals[1]/vals[0]-1
d2 = vals[2]/vals[1]-1
ax1.annotate("", xy=(1, vals[1]+0.03), xytext=(0, vals[0]-0.03),
             arrowprops=dict(arrowstyle="->", color="gray", lw=1.5))
ax1.text(0.5, (vals[0]+vals[1])/2+0.02, f"{d1*100:.1f}%", color="gray", fontsize=11, ha="center")
ax1.annotate("", xy=(2, vals[2]+0.03), xytext=(1, vals[1]-0.03),
             arrowprops=dict(arrowstyle="->", color="gray", lw=1.5))
ax1.text(1.5, (vals[1]+vals[2])/2+0.02, f"{d2*100:.1f}%", color="gray", fontsize=11, ha="center")
ax1.set_ylim(0, 1.05)
ax1.set_ylabel("Detection Performance")
ax1.set_title("Three-way Comparison: Pre-cutoff vs. Post-cutoff Datasets\n"
              "(DmAVID pipeline, smart-preprocess, gpt-4.1-mini)", fontsize=11)
ax1.grid(axis="y", linestyle=":", alpha=0.4)

# ---- Right: per-audit post-cutoff (Table 4-17) ----
audits = [("liquid-ron\n2025-01", 1, 1), ("forte\n2025-04", 0, 5),
          ("virtuals\n2025-04", 3, 4), ("blackhole\n2025-05", 1, 1),
          ("panoptic\n2025-06", 2, 2), ("tempo-feeamm\n2026-01", 1, 1),
          ("tempo-mpp\n2026-01", 0, 1), ("tempo-stablecoin\n2026-01", 2, 2)]
names = [a[0] for a in audits]
rates = [a[1]/a[2] for a in audits]
tags = [f"{a[1]}/{a[2]}" for a in audits]
bcolors = ["#E0982E" if r > 0 else "#C9C9C9" for r in rates]
bars2 = ax2.bar(names, rates, color=bcolors, width=0.6, edgecolor="white")
for b, t, r in zip(bars2, tags, rates):
    ax2.text(b.get_x()+b.get_width()/2,
             (b.get_height()+0.03) if r > 0 else 0.03, t,
             ha="center", va="bottom", fontsize=9,
             fontweight="bold", color="#34618A" if r > 0 else "gray")
overall = 10/17
ax2.axhline(overall, color="#E0982E", linestyle="--", lw=1.5)
ax2.text(1, overall+0.04, f"Overall {overall*100:.2f}%",
         color="#E0982E", fontsize=10, ha="center", fontweight="bold",
         bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="#E0982E", alpha=0.9))
ax2.set_ylim(0, 1.12)
ax2.set_ylabel("Detection Rate")
ax2.set_title("Per-Audit Detection on Post-Cutoff Subset (N=8 audits, 17 vulns)\n"
              "5 audits 100%, 1 audit 75%, 2 audits 0%", fontsize=11)
ax2.tick_params(axis="x", labelsize=8)
ax2.grid(axis="y", linestyle=":", alpha=0.4)

plt.tight_layout()
plt.savefig(OUT_CN, dpi=300, bbox_inches="tight")
plt.savefig(OUT_TMP, dpi=300, bbox_inches="tight")
print("saved:", OUT_CN)
print("saved:", OUT_TMP)
