#!/bin/bash
# Real-time end-to-end trials on the 4-validator Besu QBFT testbed with real network faults (run from the repo root
# on the machine that hosts the testbed). Each lane is a separate process; lanes of a phase run concurrently.
#   phase 1  healthy chain; netem cuts the gateway's uplink for 120 s (honest: no conviction; A7: attribution)
#   phase 2  validator 4 isolated with netem for the whole phase (f = 1 of n = 4)
#   phase 3  a cut longer than the response window (360 s > W_resp): Theorem 2 predicts conviction
set -u
cd "$(dirname "$0")/../prototype"
PY=../.venv/Scripts/python
OUT=../experiments/results/besu_rt_v4.jsonl
LOG=../experiments/results/besu_rt_v4.log
lanes() {  # run each lane spec as its own process and wait for all
    for spec in "$@"; do
        $PY -u run_besu_rt.py --out $OUT --lanes "$spec" $NOTE >> $LOG 2>&1 &
        sleep 20
    done
    wait
}
NOTE=""
echo "$(date '+%F %T') phase 1" >> $LOG
lanes "0:honest:test1/9:cut=120" "1:A7:test1/9:cut=120" "2:A9:test1/11:" "3:A1:test2/2:"
echo "$(date '+%F %T') phase 2" >> $LOG
docker run --rm --net container:besu-node4 --cap-add NET_ADMIN provecps-netem:1 tc qdisc add dev eth0 root netem loss 100% >> $LOG 2>&1
NOTE="--note isolate4=1"
lanes "0:honest:test2/13:cut=120" "1:A3:test2/13:" "2:A8:test2/24:" "3:A9:test2/2:"
docker run --rm --net container:besu-node4 --cap-add NET_ADMIN provecps-netem:1 tc qdisc del dev eth0 root >> $LOG 2>&1
echo "$(date '+%F %T') phase 3" >> $LOG
NOTE=""
sleep 30   # validator 4 catches up
lanes "0:honest:test1/11:cut=360" "1:A4:test1/9:" "2:A2:test2/24:"
echo "$(date '+%F %T') BESU_RT_V4_DONE" >> $LOG
