#!/bin/bash
# Model-check every configuration with TLC (needs Java 11+ and tools/tla2tools.jar from the official
# tlaplus release). Expected: *_ok holds, *_tight yields a counterexample (the bound is exact in the model).
# Usage: ./run_tlc.sh [workers]   -> results/<cfg>.out and a summary line per configuration
set -u
cd "$(dirname "$0")"
WORKERS=${1:-8}
mkdir -p results states
for cfg in nonframe_ok nonframe_tight detection_tight attribution_tight detection_ok attribution_ok; do
    start=$(date +%s)
    java -Xmx6g -XX:+UseParallelGC -cp tools/tla2tools.jar tlc2.TLC -workers "$WORKERS" -deadlock \
         -metadir "states/$cfg" -config "$cfg.cfg" ProveCPS.tla > "results/$cfg.out" 2>&1
    rc=$?
    verdict=$(grep -qE "is violated|Error:" "results/$cfg.out" && echo "VIOLATED" || \
              (grep -q "No error has been found" "results/$cfg.out" && echo "HOLDS" || echo "UNKNOWN(rc=$rc)"))
    states=$(grep -oE "[0-9,]+ distinct states found" "results/$cfg.out" | tail -1)
    echo "$cfg $verdict ${states:-?} $(( $(date +%s) - start ))s" | tee -a results/summary.txt
done
echo TLC_DONE | tee -a results/summary.txt
