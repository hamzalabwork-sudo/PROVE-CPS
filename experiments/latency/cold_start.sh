#!/usr/bin/env bash
# Cold-start inclusion delay on an on-demand chain: wait until the chain has been idle for
# IDLE_S seconds, send one anchor, repeat SAMPLES times. Sends only SAMPLES transactions in total.
# Usage (from the repo root, ideally under nohup): experiments/latency/cold_start.sh <vars-file> [samples] [idle_s]
set -euo pipefail
VARS="$1"; SAMPLES="${2:-5}"; IDLE_S="${3:-600}"
PY="${PYTHON:-.venv/bin/python}"
OUT="experiments/results/inclusion_latency.csv"
RPC=$(grep '^RPC=' "$VARS" | cut -d= -f2- | tr -d '\r')  # vars files may be written with CRLF on Windows
[[ "$RPC" =~ ^https?:// ]] || { echo "bad RPC in $VARS" >&2; exit 1; }

age() {
  curl -s --max-time 20 -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",false],"id":1}' "$RPC" |
    "$PY" -c "import sys,json,time; print(int(time.time()-int(json.load(sys.stdin)['result']['timestamp'],16)))"
}

age >/dev/null || { echo "cannot read latest block from $RPC" >&2; exit 1; }  # fail loudly, not loop forever
echo "[$(date -Is)] start: idle threshold ${IDLE_S}s, chain idle $(age)s now"
for i in $(seq 1 "$SAMPLES"); do
  until a=$(age 2>/dev/null) && [[ "$a" -ge "$IDLE_S" ]]; do sleep 30; done
  echo "[$(date -Is)] sample $i: chain idle ${a}s"
  "$PY" experiments/latency/measure_inclusion.py "$VARS" 0 "$OUT"
done
echo "[$(date -Is)] COLD-START DONE"
