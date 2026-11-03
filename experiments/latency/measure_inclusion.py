"""Measure ledger inclusion delay (Delta_L in the paper) for Registry.anchor on one chain.

For each anchor transaction we record:
  submit_to_receipt_ms : client clock, from send_raw_transaction to the receipt being visible
  rpc_rtt_ms           : a same-moment eth_blockNumber round trip (network + RPC overhead)
  block_age_before_s   : age of the latest block when we submitted; large => the chain was idle (cold)
Every row also records the vantage point (hostname), because RPC latency depends on where we measure from.

Usage: python measure_inclusion.py <vars-file> <n-warm> <out.csv>
The vars file is testbed/besu/besu.vars or testbed/purechain/.env (RPC, GATEWAY_KEY, chain id via RPC);
registry-address.txt must sit next to it.
"""
import csv
import os
import socket
import statistics
import sys
import time
from pathlib import Path

try:  # verify TLS against the OS trust store (needed behind TLS-inspecting antivirus on Windows)
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    pass

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware  # QBFT and Clique-style headers carry long extraData

POLL_S = 0.02


def load_vars(path):
    out = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    # Docker-internal hostname -> host loopback when running natively.
    out["RPC"] = out["RPC"].replace("host.docker.internal", "localhost")
    return out


def rtt_ms(w3):
    t = time.perf_counter()
    w3.eth.block_number
    return (time.perf_counter() - t) * 1000


def anchor_once(w3, acct, registry, chain_id, nonce, tag):
    root = Web3.keccak(text=f"latency-{tag}-{time.time_ns()}")
    data = Web3.keccak(text="anchor(bytes32)")[:4] + root
    tx = {"to": registry, "data": data, "gas": 100_000, "gasPrice": 0, "nonce": nonce, "chainId": chain_id}
    raw = acct.sign_transaction(tx).raw_transaction
    latest = w3.eth.get_block("latest")
    age = time.time() - latest.timestamp
    rtt = rtt_ms(w3)
    t0 = time.perf_counter()
    h = w3.eth.send_raw_transaction(raw)
    while True:
        try:
            rc = w3.eth.get_transaction_receipt(h)
            if rc is not None:
                break
        except Exception:  # not yet mined: web3 raises TransactionNotFound
            pass
        time.sleep(POLL_S)
    t1 = time.perf_counter()
    assert rc.status == 1, f"anchor reverted: {h.hex()}"
    # A load-balanced RPC endpoint may serve the receipt from one node and the block from another
    # that has not caught up; record how long reads take to become consistent.
    while True:
        try:
            blk = w3.eth.get_block(rc.blockNumber)
            break
        except Exception:
            time.sleep(POLL_S)
    t2 = time.perf_counter()
    return {
        "submit_to_receipt_ms": round((t1 - t0) * 1000, 1),
        "read_consistency_ms": round((t2 - t1) * 1000, 1),
        "rpc_rtt_ms": round(rtt, 1),
        "block_age_before_s": round(age, 1),
        "block": rc.blockNumber,
        "block_timestamp": blk.timestamp,
        "gas_used": rc.gasUsed,
    }


def main(vars_file, n_warm, out_csv):
    v = load_vars(vars_file)
    registry = Web3.to_checksum_address((Path(vars_file).parent / "registry-address.txt").read_text().strip())
    w3 = Web3(Web3.HTTPProvider(v["RPC"], request_kwargs={"timeout": 120}))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    acct = w3.eth.account.from_key(v["GATEWAY_KEY"])
    chain_id = w3.eth.chain_id
    nonce = w3.eth.get_transaction_count(acct.address, "pending")
    host = socket.gethostname()

    rows = []
    first = anchor_once(w3, acct, registry, chain_id, nonce, "first")
    first["phase"] = "cold" if first["block_age_before_s"] > 30 else "first"
    rows.append(first)
    for i in range(int(n_warm)):
        r = anchor_once(w3, acct, registry, chain_id, nonce + 1 + i, i)
        r["phase"] = "warm"
        rows.append(r)

    for r in rows:
        r.update({"chain_id": chain_id, "rpc": v["RPC"], "vantage": host, "measured_at": int(time.time())})
    new = not os.path.exists(out_csv)
    with open(out_csv, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        if new:
            w.writeheader()
        w.writerows(rows)

    print(f"chain {chain_id} via {v['RPC']} from {host}")
    print(f"  first tx: {rows[0]['submit_to_receipt_ms']} ms (phase={rows[0]['phase']}, "
          f"chain idle {rows[0]['block_age_before_s']} s before)")
    warm = [r["submit_to_receipt_ms"] for r in rows if r["phase"] == "warm"]
    if not warm:  # cold-start sampling sends a single transaction
        return
    # inclusive: percentiles stay within the observed range (the default extrapolates past max)
    q = statistics.quantiles(warm, n=100, method="inclusive") if len(warm) >= 2 else warm * 99
    print(f"  warm n={len(warm)}: p50={q[49]:.0f} ms  p95={q[94]:.0f} ms  p99={q[98]:.0f} ms  max={max(warm):.0f} ms")
    lag = [r["read_consistency_ms"] for r in rows]
    print(f"  receipt->block visible: max={max(lag):.0f} ms, nonzero in {sum(x > 30 for x in lag)}/{len(lag)} txs")
    print(f"  rpc rtt p50={statistics.median(r['rpc_rtt_ms'] for r in rows):.0f} ms; gas/anchor={rows[-1]['gas_used']}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
