#!/bin/bash
# Exp15: Fix1+Fix2+Fix3 | --rounds 2 (clean monotonic curve for thesis)
# Pre-iter → R1 → R2: single-direction improvement, no R3 noise

source /home/curtis/DmAVID/env.sh
cd /home/curtis/DmAVID

python3 scripts/19_coordinator_round2.py \
    --rounds 2 \
    --budget 20.0 \
    --challenges-per-type 1 \
    --max-fn-variants 10 \
    --exp-tag exp15 \
    2>&1 | tee experiments/exp15.log

echo '=== Exp15 完成 ==='

echo '=== Running deep analysis ==='
python3 scripts/20_deep_analysis.py --exp-tag exp15 2>&1 | tee -a experiments/exp15.log
