#!/bin/bash
# Resume an interrupted TLC run from its last checkpoint (e.g. after a reboot).
# Usage: ./resume_tlc.sh <cfg-name> [workers]     e.g. ./resume_tlc.sh attribution_ok 16
set -u
cd "$(dirname "$0")"
cfg=$1; WORKERS=${2:-8}
run=$(ls -d states/"$cfg"/*/ | sort | tail -1)
echo "resuming $cfg from $run"
start=$(date +%s)
java -Xmx6g -XX:+UseParallelGC -cp tools/tla2tools.jar tlc2.TLC -workers "$WORKERS" -deadlock \
     -recover "$run" -metadir "states/$cfg" -config "$cfg.cfg" ProveCPS.tla >> "results/$cfg.out" 2>&1
verdict=$(grep -qE "is violated|Error:" "results/$cfg.out" && echo "VIOLATED" || \
          (grep -q "No error has been found" "results/$cfg.out" && echo "HOLDS" || echo "UNKNOWN"))
states=$(grep -oE "[0-9,]+ distinct states found" "results/$cfg.out" | tail -1)
echo "$cfg $verdict ${states:-?} resumed, $(( $(date +%s) - start ))s after resume" | tee -a results/summary.txt
