"""Background transaction load for Delta_L under stress (a 'dispute storm'): a stream of calldata-heavy
transactions at a fixed rate from a separate account, so they compete with the measured anchors for block space
and for the proposer's attention. Usage: python load_gen.py <vars-file> <tx-per-s> <calldata-bytes> <seconds>"""
import os
import sys
import time
from pathlib import Path

from web3 import Web3

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_inclusion import load_vars  # noqa: E402


def main(vars_file, rate, size, seconds):
    v = load_vars(vars_file)
    w3 = Web3(Web3.HTTPProvider(v["RPC"], request_kwargs={"timeout": 30}))
    acct = w3.eth.account.from_key(v["LOAD_KEY"])
    cid, nonce = w3.eth.chain_id, w3.eth.get_transaction_count(acct.address, "pending")
    rate, size, end = float(rate), int(size), time.time() + float(seconds)
    sink = Web3.to_checksum_address("0x000000000000000000000000000000000000dEaD")
    sent, t_next = 0, time.time()
    while time.time() < end:
        data = os.urandom(size)  # ~16 gas per nonzero byte: about the calldata of a dispute with a payload
        tx = {"to": sink, "data": data, "gas": 21_000 + 16 * size + 1000, "gasPrice": 0, "nonce": nonce,
              "chainId": cid, "value": 0}
        try:
            w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction)
            nonce += 1
            sent += 1
        except Exception as e:  # pool full or nonce gap: resync and continue
            print("load:", repr(e)[:120], flush=True)
            nonce = w3.eth.get_transaction_count(acct.address, "pending")
        t_next += 1 / rate
        time.sleep(max(0.0, t_next - time.time()))
    print(f"load: sent {sent} txs", flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:5])
