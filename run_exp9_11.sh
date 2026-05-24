#!/bin/bash
# Run Exp9, Exp10, Exp11 sequentially with fixed seed + temperature=0
# Results saved per-run to experiments/exp9_11_summary.json

source /home/curtis/DmAVID/env.sh
cd /home/curtis/DmAVID

SUMMARY_FILE="experiments/exp9_11_summary.json"
echo '{"runs":[]}' > "$SUMMARY_FILE"

for RUN in 9 10 11; do
    LOG="experiments/exp${RUN}.log"
    echo "=============================="
    echo "Starting Exp${RUN} at $(date)"
    echo "=============================="

    python3 scripts/19_coordinator_round2.py \
        --rounds 3 \
        --budget 20.0 \
        --challenges-per-type 1 \
        --max-fn-variants 10 \
        2>&1 | tee "$LOG"

    echo "=== Exp${RUN} 完成 ==="

    # Extract best F1, best round, final F1 from log
    BEST_LINE=$(grep 'Final F1:' "$LOG" | tail -1)
    BEST_F1=$(echo "$BEST_LINE" | grep -oP '(?<=Final F1:\s{4})\d+\.\d+')
    BEST_ROUND=$(echo "$BEST_LINE" | grep -oP '(?<=best round: )\d+')
    R1=$(grep 'Pre-verify' "$LOG" | sed -n '1p' | grep -oP '(?<=F1: )\d+\.\d+')
    R2=$(grep 'Pre-verify' "$LOG" | sed -n '2p' | grep -oP '(?<=F1: )\d+\.\d+')
    R3=$(grep 'Pre-verify' "$LOG" | sed -n '3p' | grep -oP '(?<=F1: )\d+\.\d+')
    COST=$(grep 'Total cost:' "$LOG" | tail -1 | grep -oP '\$[\d.]+' | head -1)

    echo "Exp${RUN}: Best F1=${BEST_F1} [round ${BEST_ROUND}], R1=${R1} R2=${R2} R3=${R3}, cost=${COST}"

    # Append to summary JSON (requires python3)
    python3 - <<PYEOF
import json, sys
with open("$SUMMARY_FILE") as f:
    data = json.load(f)
data["runs"].append({
    "exp": $RUN,
    "best_f1": float("${BEST_F1}" or 0),
    "best_round": int("${BEST_ROUND}" or 0),
    "r1_f1": float("${R1}" or 0),
    "r2_f1": float("${R2}" or 0),
    "r3_f1": float("${R3}" or 0),
    "cost": "${COST}",
})
# Compute running stats
f1s = [r["best_f1"] for r in data["runs"] if r["best_f1"] > 0]
if len(f1s) > 1:
    import statistics
    data["mean_best_f1"] = round(statistics.mean(f1s), 4)
    data["std_best_f1"] = round(statistics.stdev(f1s), 4)
elif f1s:
    data["mean_best_f1"] = f1s[0]
    data["std_best_f1"] = 0.0
with open("$SUMMARY_FILE", "w") as f:
    json.dump(data, f, indent=2)
print(json.dumps(data, indent=2))
PYEOF

done

echo ""
echo "=============================="
echo "All 3 runs complete. Summary:"
cat "$SUMMARY_FILE"
echo "=============================="
