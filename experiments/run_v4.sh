#!/bin/bash
# v4 campaign: component ablation and gateway crash with state loss (strict witness, all 52 attacks, seed 0,
# the same 2,000-sample PoA delay profile as v3). Resumable: re-running skips trials already in the output.
#   ablation_v4  remove one mechanism at a time:
#                  receipts=0                    honest gateway without custody receipts (cost of the honest case)
#                  notice=0                      no on-chain NOTICE / NOTICE-FULL (A3, A7, A8)
#                  policy_checks=0               no committed policy: no AVAILABILITY, no NOTICE-FULL (A2, A4, A8)
#                  device_check=0,a9_stretch=600 devices accept any receipt deadline (A9 stretches it by 600 s)
#   crash_v4     honest gateway crashes at the start of the attack window for 30, 120 or 240 s and restarts with
#                no local state (recovery from the replicated store and the ledger)
set -u
cd ~/provecps/prototype
R=../experiments/results
PY=../.venv/bin/python
W=${1:-12}
log() { echo "$(date '+%F %T') $*" >> $R/run_v4.log; }

log "ablation_v4"
$PY run_matrix.py --out $R/ablation_v4.jsonl --strategies honest --policies strict --variants "receipts=0" \
    --workers $W >> $R/run_v4.log 2>&1
$PY run_matrix.py --out $R/ablation_v4.jsonl --strategies A3,A7,A8 --policies strict --variants "notice=0" \
    --workers $W >> $R/run_v4.log 2>&1
$PY run_matrix.py --out $R/ablation_v4.jsonl --strategies A2,A4,A8 --policies strict --variants "policy_checks=0" \
    --workers $W >> $R/run_v4.log 2>&1
$PY run_matrix.py --out $R/ablation_v4.jsonl --strategies A9 --policies strict \
    --variants "device_check=0,a9_stretch=600" --workers $W >> $R/run_v4.log 2>&1
log "crash_v4"
$PY run_matrix.py --out $R/crash_v4.jsonl --strategies honest --policies strict \
    --variants "crash_at=0,crash_dur=30;crash_at=0,crash_dur=120;crash_at=0,crash_dur=240" \
    --workers $W >> $R/run_v4.log 2>&1
log "ALL_V4_DONE"
