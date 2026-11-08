#!/bin/bash
# v3 campaign. Every trial replays block-time Delta_L from the 2,000-sample v2 measurements
# (Params.ledger, default "poa"). Resumable: re-running skips trials already in each output file.
#   1. matrix_v3     52 attacks x 27 strategy-policy pairs, seed 0                       (headline results)
#   2. robust_v3     faulty-validator / loaded ledger profiles; diverse and corrupt witnesses;
#                    nu and delta sweeps                                                 (robustness, sensitivity)
#   3. seeds_v3      seeds 1-9 of the strict matrix                                      (95% confidence intervals)
set -u
cd ~/provecps/prototype
R=../experiments/results
PY=../.venv/bin/python
W=12
STRICT=honest,A1,A2,A3,A4,A5,A6,A7,A8,A8-v1,A9,honest-partition,A1-unw,A3-unw,A4-unw
ECON=A1,A2,A3,A4,A6,A7,A8,A8-v1,A9,A1-unw,A3-unw,A4-unw
log() { echo "$(date '+%F %T') $*" >> $R/run_v3.log; }

log "phase 1: matrix_v3"
$PY run_matrix.py --out $R/matrix_v3.jsonl --strategies $STRICT --policies strict --workers $W >> $R/run_v3.log 2>&1
$PY run_matrix.py --out $R/matrix_v3.jsonl --strategies $ECON --policies economy --workers $W >> $R/run_v3.log 2>&1

log "phase 2a: ledger profiles"
$PY run_matrix.py --out $R/robust_v3.jsonl --strategies A1,A3,A7,A8,A9,honest,honest-partition --policies strict \
    --variants "ledger=besu-fault" --workers $W >> $R/run_v3.log 2>&1
$PY run_matrix.py --out $R/robust_v3.jsonl --strategies A1,A9,honest,honest-partition --policies strict \
    --variants "ledger=besu-load" --workers $W >> $R/run_v3.log 2>&1
log "phase 2b: witnesses"
$PY run_matrix.py --out $R/robust_v3.jsonl --strategies A1,A3,A4,A8,A9 --policies strict \
    --variants "witnesses=2,silent_witnesses=1;witnesses=1,silent_witnesses=1" --workers $W >> $R/run_v3.log 2>&1
log "phase 2c: nu and delta sweeps (test1)"
$PY run_matrix.py --out $R/robust_v3.jsonl --splits test1 --strategies A3,A9,honest,honest-partition --policies strict \
    --variants "notice_after=8;notice_after=10;notice_after=30;notice_after=60" --workers $W >> $R/run_v3.log 2>&1
$PY run_matrix.py --out $R/robust_v3.jsonl --splits test1 --strategies honest,A1 --policies strict \
    --variants "ledger=besu-fault,safety=1.0;ledger=besu-fault,safety=6.0" --workers $W >> $R/run_v3.log 2>&1
log "ROBUST_DONE"

log "phase 3: seeds 1-9"
$PY run_matrix.py --out $R/seeds_v3.jsonl --strategies $STRICT --policies strict --workers $W \
    --variants "seed=1;seed=2;seed=3;seed=4;seed=5;seed=6;seed=7;seed=8;seed=9" >> $R/run_v3.log 2>&1
log "ALL_V3_DONE"
