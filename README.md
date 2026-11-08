# PROVE-CPS: Omission Accountability for Blockchain-Anchored Cyber-Physical Evidence

A blockchain-anchored evidence log can be perfectly intact and still lie by omission: the edge gateway that decides which events to commit can silently drop the ones that would reveal an attack. PROVE-CPS makes such omissions **detectable and attributable on-chain**. Within a bounded time, every event of an honest device is either provably anchored, or the gateway that held custody of it is convicted by a smart contract.

This repository contains the protocol, the registry contract, the off-chain agents, the attack harness, every experiment log, and the paper sources.

## How it works

| Mechanism | What it achieves |
|---|---|
| Device-signed hash chains | An anchored head commits to the device's whole prefix, so only truncation remains, and truncation is a question of deadlines. |
| Custody receipts | A receipt with a policy deadline makes a dropped event the receipt holder's liability. |
| On-chain committed selection policy | "Not selected" becomes checkable, so suppression cannot hide as non-selection. |
| Witness path that bypasses the gateway | Required by an impossibility result: without it, only an unattributed alarm is possible. |
| Registry contract as a clocked adjudicator | Five dispute types (`CUSTODY`, `NOTICE`, `NOTICE-FULL`, `AVAILABILITY`, `EQUIVOCATION`) are decided against block time. A missed deadline yields `Late`, never a conviction. |

In the honest case the gateway's only on-chain action is one Merkle-root `anchor` per batch (48,086 gas). Batches are scheduled by deadline-safe earliest-deadline stabbing, which uses the fewest anchors possible.

## Results (v2)

All results come from 1,726 trials that replay all 52 attacks of the HAI 23.05 industrial-control dataset. Every verdict is produced by the deployed contract bytecode.

| Result | Value |
|---|---|
| Attribution (devices with a witness) | Every suppressed event the policy requires, under strategies A1–A9 (truncation, deletion, stonewalling, disguised suppression, equivocation, deadline delay, partition-timed, custody refusal, slow-walking) |
| Custody-refusal ablation (A8) | Without `NOTICE-FULL`: 7,811 of 7,811 FULL payloads lost, no conviction. With it: 7,811 of 7,811 attributed. |
| Tightness of the bound | The strongest timing adversary (A9) came within 3.6 s of the detection bound |
| Honest gateways convicted | 0 of 272 trials within the response-window assumption, including partitions and 107,919 challenges from a flooding witness |
| Outage sweep | The predicted conviction boundary matches 294 of 294 verdicts |
| Cost | 71% less gas than fixed-interval Merkle batching at a 30 s FULL deadline (85% less at 10 s) |
| Ledger inclusion delay Δ_L (p50 / p99 / max) | PoA network 1.88 / 1.93 / 2.89 s; Besu QBFT idle 1.78 / 1.85 / 2.73 s; Besu with 1 of 4 validators down 1.81 / 5.84 / 5.96 s |

## Repository layout

```
contracts/     Registry.sol (PROVE-CPS registry) and Baselines.sol (B1-B4 archetypes), Foundry tests
prototype/     Python device, gateway, witness and auditor agents (provecps/), attack harness, baselines,
               analysis, tables and figures
experiments/   latency campaigns (latency/) and every trial log (results/*.jsonl.gz)
testbed/       4-validator Besu QBFT network (docker compose) and deployment scripts
design/        protocol and theory design document, including the v2 revision log (section 10)
paper/         LaTeX sources (IEEE conference format)
research/      literature notes and the blind-review meta-review
```

## Reproducing

**Requirements:** Python 3.12+, Foundry (`forge`, `anvil`), Docker (only for the Besu testbed) and a LaTeX distribution (only for the paper).

```bash
# Contract tests: 34 tests, including 3 fuzz tests x 2,000 runs
cd contracts && forge build && forge test

# Python agents
python -m venv .venv && . .venv/bin/activate
pip install -r prototype/requirements.txt
python prototype/tests/test_crypto_vs_contract.py      # 382 byte-level cross-checks against the contract
```

**Dataset.** HAI 23.05 (CC BY-SA 4.0) is not redistributed here. Download it from the HAI repository (`icsdataset/hai`) and place the `hai-23.05` CSV files in `data/hai/hai-23.05/`.

**Re-analyse the committed logs.** No dataset is needed for this; gunzip the logs first.

```bash
gunzip -k experiments/results/*.jsonl.gz
python prototype/tables.py experiments/results/matrix_v2.jsonl                  # Table II -> paper/tables/matrix.tex
python prototype/analyze.py experiments/results/matrix_v2.jsonl                 # per-strategy summary
python experiments/results/paper_numbers_v2.py experiments/results/matrix_v2.jsonl   # every number quoted in the paper
python prototype/figs.py                                                        # Figs. 3-4
python experiments/latency/summarize_v2.py experiments/results/latency_v2/*.csv # ledger latency
```

**Re-run the experiments.** These need the dataset and `anvil` on the path.

```bash
python prototype/run_matrix.py --out matrix.jsonl --splits test1,test2 --strategies all --policies strict,economy --workers 12 --anvil "$(which anvil)"
python prototype/pareto.py experiments/results/pareto.json
```

**Besu testbed.** See `testbed/besu/README.md`: run `setup.sh`, then `docker compose up -d`, then `testbed/deploy.sh`. The keys in `testbed/besu/besu.vars` are the well-known public Anvil development keys; they are meaningful only on that private testnet.

## Status

This is research code accompanying a paper under submission. The implementation, contracts and harness are released so that the results can be checked and reproduced.
