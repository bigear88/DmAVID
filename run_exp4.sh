#!/bin/bash
source /home/curtis/DmAVID/env.sh
cd /home/curtis/DmAVID
exec python3 scripts/19_coordinator_round2.py   --rounds 3   --budget 20.0   --uncertain-only   --max-fn-variants 10   --convergence-threshold 0.01   --convergence-patience 2
