#!/bin/bash
# Re-check one configuration with a different TLC fingerprint function, so that a state hidden by a
# fingerprint collision in the first run is found with independent probability.
# Usage: ./rerun_fp.sh <cfg> <fp index 0-130> [workers]   -> results/<cfg>.fp<idx>.out and a summary line
set -u
cd "$(dirname "$0")"
CFG=$1
FP=$2
WORKERS=${3:-8}
mkdir -p results states
start=$(date +%s)
java -Xmx6g -XX:+UseParallelGC -cp tools/tla2tools.jar tlc2.TLC -workers "$WORKERS" -deadlock -fp "$FP" \
     -checkpoint 30 -metadir "states/$CFG.fp$FP" -config "$CFG.cfg" ProveCPS.tla > "results/$CFG.fp$FP.out" 2>&1
rc=$?
verdict=$(grep -qE "is violated|Error:" "results/$CFG.fp$FP.out" && echo "VIOLATED" || \
          (grep -q "No error has been found" "results/$CFG.fp$FP.out" && echo "HOLDS" || echo "UNKNOWN(rc=$rc)"))
states=$(grep -oE "[0-9,]+ distinct states found" "results/$CFG.fp$FP.out" | tail -1)
echo "$CFG(fp $FP) $verdict ${states:-?} $(( $(date +%s) - start ))s" | tee -a results/summary.txt
