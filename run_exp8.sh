#!/bin/bash
source /home/curtis/DmAVID/env.sh
cd /home/curtis/DmAVID
python3 scripts/19_coordinator_round2.py   --rounds 3   --budget 20.0   --challenges-per-type 1   --max-fn-variants 10   2>&1 | tee experiments/exp8.log
echo '=== 完成 ==='
