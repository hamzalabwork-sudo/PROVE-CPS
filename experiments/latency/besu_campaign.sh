#!/bin/bash
# Delta_L / delta_ts on the local 4-validator QBFT network (blockperiod 2 s, requesttimeout 4 s):
#   E1 idle (2000 samples), E3 under a transaction storm (1000), E2 with one validator down (1000):
#   a faulty proposer forces a round change whenever its turn comes (f = 1 of n = 4).
set -u
cd "$(dirname "$0")"
PY=../../.venv/Scripts/python
V=../../testbed/besu/besu.vars
OUT=../results/latency_v2/besu.csv
trap 'docker start besu-node4 >/dev/null 2>&1' EXIT
$PY measure_inclusion.py $V 2000 $OUT besu-idle
$PY load_gen.py $V 25 2048 2700 > ../results/latency_v2/load.log 2>&1 &
LOAD=$!
sleep 20
$PY measure_inclusion.py $V 1000 $OUT besu-load-25tps-2KB
kill $LOAD 2>/dev/null; wait $LOAD 2>/dev/null
sleep 30
docker stop besu-node4
sleep 15
$PY measure_inclusion.py $V 1000 $OUT besu-1-of-4-validators-down
docker start besu-node4
echo CAMPAIGN_DONE
