#!/bin/bash
# Main experiment: multi-seed (treatment vs placebo) iteration significance test.
#   - compile gate (PoC decoupled, per agreed design)
#   - 3 seeds x {treatment, placebo} x 3 rounds, no early-stop
#   - KB reset to pristine clean_baseline before EVERY run (isolation/no contamination)
set -u
source /home/curtis/DmAVID/env.sh
cd /home/curtis/DmAVID

PRISTINE=scripts/knowledge/vulnerability_knowledge.json.clean_baseline
LIVE=scripts/knowledge/vulnerability_knowledge.json
BASE_OUT=experiments/seed_placebo
SEEDS="42 7 123"
BUDGET=35

mkdir -p "$BASE_OUT"
# Back up the live KB once so we can restore the repo to its pre-experiment state.
[ -f "$LIVE.preexp_backup" ] || cp "$LIVE" "$LIVE.preexp_backup"

run () {
  cond="$1"; seed="$2"; flag="$3"
  out="$BASE_OUT/${cond}_seed${seed}"
  mkdir -p "$out"
  if [ -f "$out/summary.json" ]; then
    echo "############ SKIP (already done): ${cond} seed=${seed} ############"
    return
  fi
  echo "############ $(date '+%F %T') :: ${cond} seed=${seed} ############"
  cp "$PRISTINE" "$LIVE"                 # isolation: identical pristine start every run
  python3 scripts/20_coordinator_autonomous.py \
      --rounds 3 --budget "$BUDGET" --no-early-stop \
      --gate compile --seed "$seed" $flag \
      --output-dir "$out" 2>&1 | tee "$out/run.log"
  # snapshot the 3 round F1s for quick aggregation
  python3 - "$out" "$cond" "$seed" <<'PY'
import json,sys,os,glob
out,cond,seed=sys.argv[1],sys.argv[2],sys.argv[3]
rows=[]
for rf in sorted(glob.glob(os.path.join(out,"round_*_results.json"))):
    d=json.load(open(rf)); m=d.get("metrics",{}); pm=d.get("pre_verify_metrics",{})
    rows.append({"round":d.get("round"),"f1":m.get("f1"),"pre_f1":pm.get("f1"),
                 "tp":m.get("tp"),"fp":m.get("fp"),"fn":m.get("fn"),"tn":m.get("tn")})
json.dump({"cond":cond,"seed":int(seed),"rounds":rows},
          open(os.path.join(out,"summary.json"),"w"),indent=2)
print("  -> summary:",[r.get("f1") for r in rows])
PY
}

for s in $SEEDS; do
  run treatment "$s" ""
  run placebo   "$s" "--placebo"
done

# restore the repo's live KB
cp "$LIVE.preexp_backup" "$LIVE"
touch "$BASE_OUT/ALL_DONE"
echo "ALL DONE $(date '+%F %T')"
