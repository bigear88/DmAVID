#!/bin/bash
# Exp12: temperature=0.1, seed=42, isolated output dir experiments/exp12/
# Purpose: McNemar test needs pre_iter_results.json paired with R1/R2/R3

source /home/curtis/DmAVID/env.sh
cd /home/curtis/DmAVID

python3 scripts/19_coordinator_round2.py \
    --rounds 3 \
    --budget 20.0 \
    --challenges-per-type 1 \
    --max-fn-variants 10 \
    --exp-tag exp12 \
    2>&1 | tee experiments/exp12.log

echo '=== Exp12 完成 ==='

# Auto-run deep analysis
echo '=== Running deep analysis ==='
python3 scripts/20_deep_analysis.py --exp-tag exp12 2>&1 | tee -a experiments/exp12.log
