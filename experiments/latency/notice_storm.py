"""NOTICE storm on the live Besu QBFT testbed: what a mass partition costs the ledger.

A gateway serving n devices is cut off; after nu its witnesses post one NOTICE per device (n NOTICEs, from k witness
accounts), and when the gateway reconnects O seconds after the storm began it must answer all n within the response
window. We measure, on the real chain, the inclusion delay of every NOTICE and answer, the throughput, and how many
answers land within W_resp. Two answer modes:
  a2r    one anchorAndRespond per notice from the gateway's account (the protocol's default answer)
  batch  the gateway anchors ONE Merkle root over all n noticed heads, then k helper accounts submit
         respondCoverage with each head's proof (anyone may submit a coverage proof)

Usage: python notice_storm.py --n 2000 --mode a2r --out ../results/notice_storm_v4.jsonl
"""
import argparse
import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "prototype"))

from eth_account import Account  # noqa: E402
from web3 import Web3  # noqa: E402
from web3.middleware import ExtraDataToPOAMiddleware  # noqa: E402

from provecps import crypto  # noqa: E402
from provecps.besu_rt import deploy, setup_batch  # noqa: E402
from provecps.ledger import load_artifact  # noqa: E402

GAS = 2_000_000


def w3_for(url):
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 10}))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


class Tracker:
    """Polls blocks and records the inclusion of every transaction to the registry."""

    def __init__(self, url, registry, abi):
        self.w3 = w3_for(url)
        self.c = self.w3.eth.contract(address=registry, abi=abi)
        self.registry = registry
        self.included = {}       # tx hash -> (block ts, status, gas)
        self.opened = {}         # deviceId -> (challenge id, block ts)
        self.blocks = []         # (number, ts, registry txs, gas)
        self.next = self.w3.eth.block_number + 1
        self.lock, self.stop = threading.Lock(), threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        topic = None
        while not self.stop.is_set():
            try:
                head = self.w3.eth.block_number
                while self.next <= head:
                    b = self.w3.eth.get_block(self.next, full_transactions=True)
                    mine = [t for t in b.transactions if t["to"] == self.registry]
                    gas = 0
                    for t in mine:
                        rc = self.w3.eth.get_transaction_receipt(t["hash"])
                        gas += rc.gasUsed
                        for ev in self.c.events.ChallengeOpened().process_receipt(rc):
                            with self.lock:
                                self.opened[ev["args"]["deviceId"]] = (ev["args"]["id"], b.timestamp)
                        with self.lock:
                            self.included[bytes(t["hash"])] = (b.timestamp, rc.status, rc.gasUsed)
                    self.blocks.append((self.next, b.timestamp, len(b.transactions), len(mine), gas))
                    self.next += 1
            except Exception:
                pass
            time.sleep(0.2)
        del topic


def pipeline(url, signer, registry, abi, calls, tracker, window, sent):
    """Send calls [(fn, args)] from one account with consecutive nonces, at most `window` unconfirmed."""
    w3 = w3_for(url)
    c = w3.eth.contract(address=registry, abi=abi)
    acct = Account.from_key(signer.key.to_bytes())
    nonce, cid = w3.eth.get_transaction_count(acct.address, "pending"), w3.eth.chain_id
    inflight = []
    for i, (fn, args, tag) in enumerate(calls):
        while len(inflight) >= window:
            with tracker.lock:
                inflight = [h for h in inflight if h not in tracker.included]
            if len(inflight) >= window:
                time.sleep(0.05)
        tx = {"to": registry, "data": c.encode_abi(fn, args=list(args)), "gas": GAS, "gasPrice": 0,
              "nonce": nonce + i, "chainId": cid}
        st = acct.sign_transaction(tx)
        t = time.time()
        w3.eth.send_raw_transaction(st.raw_transaction)
        sent.append((bytes(st.hash), fn, tag, t))
        inflight.append(bytes(st.hash))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--mode", choices=["a2r", "batch"], default="a2r")
    ap.add_argument("--k", type=int, default=8, help="witness (and helper) accounts")
    ap.add_argument("--cut", type=int, default=120, help="gateway offline O (s) from the start of the storm")
    ap.add_argument("--window", type=int, default=150, help="unconfirmed transactions per account")
    ap.add_argument("--W", type=int, default=300)
    ap.add_argument("--url", default="http://127.0.0.1:8545")
    ap.add_argument("--track", default="http://127.0.0.1:8547")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    abi, bytecode = load_artifact()
    tag = time.time_ns()
    S = lambda who: crypto.Signer.from_seed(f"provecps-storm/{tag}/{who}")  # noqa: E731
    admin, gw = S("admin"), S("gateway")
    wits = [S(f"witness{j}") for j in range(a.k)]
    devs = [crypto.Signer.from_seed(f"provecps-storm/dev{i}") for i in range(a.n)]

    t = time.time()
    reg = deploy(a.url, admin, abi, bytecode, a.W)
    calls = [("registerGateway", (gw.address,))] + [("registerDevice", (i + 1, d.address, gw.address))
                                                    for i, d in enumerate(devs)]
    setup_batch(a.url, admin, abi, reg, calls)
    dom = crypto.domain_separator(w3_for(a.url).eth.chain_id, reg)
    print(f"setup: {a.n} devices registered in {time.time() - t:.0f}s", flush=True)

    heads = []
    for i, d in enumerate(devs):
        head = Web3.keccak(text=f"storm-{tag}-{i}")
        heads.append((i + 1, 1, head, d.sign(crypto.checkpoint_digest(dom, i + 1, 1, head))))
    tracker = Tracker(a.track, reg, abi)

    # Storm: k witnesses post one NOTICE per device.
    sent = []
    t0 = time.time()
    shards = [[("notice", ((dev, c, h), sig), dev) for dev, c, h, sig in heads[j::a.k]] for j in range(a.k)]
    ths = [threading.Thread(target=pipeline, args=(a.url, wits[j], reg, abi, shards[j], tracker, a.window, sent))
           for j in range(a.k)]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    while True:
        with tracker.lock:
            done = sum(1 for h, fn, _, _ in sent if fn == "notice" and h in tracker.included)
        if done == a.n:
            break
        time.sleep(0.2)
    t_notices = time.time() - t0
    print(f"storm: {a.n} notices included {t_notices:.0f}s after the first was sent", flush=True)

    # The gateway reconnects O seconds after the storm began and answers every notice.
    time.sleep(max(0.0, t0 + a.cut - time.time()))
    t1 = time.time()
    with tracker.lock:
        opened = dict(tracker.opened)
    if a.mode == "a2r":
        ans = [("anchorAndRespond", (opened[dev][0], (crypto.leaf(dev, c, h), c, h, sig, []), [], b""), dev)
               for dev, c, h, sig in heads]
        ths = [threading.Thread(target=pipeline, args=(a.url, gw, reg, abi, ans, tracker, a.window, sent))]
    else:
        tree = crypto.MerkleTree([crypto.leaf(dev, c, h) for dev, c, h, _ in heads])
        anchor_sent = []
        pipeline(a.url, gw, reg, abi, [("anchor", (tree.root,), 0)], tracker, 1, anchor_sent)
        sent.extend(anchor_sent)
        while anchor_sent[0][0] not in tracker.included:
            time.sleep(0.2)
        ans = [("respondCoverage", (opened[dev][0], (tree.root, c, h, sig, tree.proof(i)), []), dev)
               for i, (dev, c, h, sig) in enumerate(heads)]
        helpers = [S(f"helper{j}") for j in range(a.k)]
        ths = [threading.Thread(target=pipeline, args=(a.url, helpers[j], reg, abi, ans[j::a.k], tracker, a.window,
                                                       sent)) for j in range(a.k)]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    fns = ("anchorAndRespond", "respondCoverage")
    while True:
        with tracker.lock:
            done = sum(1 for h, fn, _, _ in sent if fn in fns and h in tracker.included)
        if done == a.n:
            break
        time.sleep(0.2)
    time.sleep(3)
    tracker.stop.set()

    rows = {"notice": [], "answer": []}
    late = failed = 0
    for h, fn, dev, ts in sent:
        inc = tracker.included.get(h)
        if inc is None or fn == "anchor":
            continue
        bts, status, gas = inc
        kind = "notice" if fn == "notice" else "answer"
        rows[kind].append((bts - ts, gas))
        failed += status != 1
        if kind == "answer" and bts > opened[dev][1] + a.W:
            late += 1
    q = lambda xs, p: sorted(xs)[min(len(xs) - 1, int(p * len(xs)))]  # noqa: E731
    storm_blocks = [b for b in tracker.blocks if b[3] > 0]
    res = {
        "n": a.n, "mode": a.mode, "k": a.k, "cut": a.cut, "W": a.W, "window": a.window,
        "notice_dl": {"p50": q([d for d, _ in rows["notice"]], .5), "p99": q([d for d, _ in rows["notice"]], .99),
                      "max": max(d for d, _ in rows["notice"])},
        "answer_dl": {"p50": q([d for d, _ in rows["answer"]], .5), "p99": q([d for d, _ in rows["answer"]], .99),
                      "max": max(d for d, _ in rows["answer"])},
        "notices_included_s": round(t_notices, 1), "answers_included_s": round(time.time() - 3 - t1, 1),
        "last_answer_after_open_max": max(tracker.included[h][0] - opened[dev][1]
                                          for h, fn, dev, _ in sent if fn in fns),
        "answers_after_window": late, "failed_tx": failed,
        "gas_notice_mean": sum(g for _, g in rows["notice"]) / len(rows["notice"]),
        "gas_answer_mean": sum(g for _, g in rows["answer"]) / len(rows["answer"]),
        "max_registry_tx_per_block": max(b[3] for b in storm_blocks),
        "max_gas_per_block": max(b[4] for b in storm_blocks),
        "registry": reg, "measured_at": int(time.time()),
    }
    print(json.dumps(res), flush=True)
    with open(a.out, "a") as f:
        f.write(json.dumps(res) + "\n")


if __name__ == "__main__":
    main()
