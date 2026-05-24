#!/bin/bash
# Exp13: Fix1 (type-aware Self-Verify) + Fix2 (FN curriculum learning)
# Expected: Recall stays ~0.979, FPR drops, F1 approaches canonical 0.9121

source /home/curtis/DmAVID/env.sh
cd /home/curtis/DmAVID

python3 scripts/19_coordinator_round2.py \
    --rounds 3 \
    --budget 20.0 \
    --challenges-per-type 1 \
    --max-fn-variants 10 \
    --exp-tag exp13 \
    2>&1 | tee experiments/exp13.log

echo '=== Exp13 完成 ==='

echo '=== Running deep analysis ==='
python3 scripts/20_deep_analysis.py --exp-tag exp13 2>&1 | tee -a experiments/exp13.log
