#!/bin/bash
# Exp14: Fix1 + Fix2 + Confidence Gate (conf<0.75 → SV, conf>=0.75 → skip)
# Goal: stabilize FPR across rounds, prevent R1 over-filtering

source /home/curtis/DmAVID/env.sh
cd /home/curtis/DmAVID

python3 scripts/19_coordinator_round2.py \
    --rounds 3 \
    --budget 20.0 \
    --challenges-per-type 1 \
    --max-fn-variants 10 \
    --exp-tag exp14 \
    2>&1 | tee experiments/exp14.log

echo '=== Exp14 完成 ==='

echo '=== Running deep analysis ==='
python3 scripts/20_deep_analysis.py --exp-tag exp14 2>&1 | tee -a experiments/exp14.log
