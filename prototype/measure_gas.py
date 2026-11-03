"""Steady-state gas of every archetype's honest-path call, with real HAI payloads (Anvil, EVM paris).

Gas depends on the EVM revision, not the chain: Registry.anchor measured 47,825 on Besu QBFT, PureChain and
Anvil alike. Each call writes a fresh slot (new event / new root), as in a long-running deployment; we report
the median over N calls after the first (which pays one-time slot initialisation for B4).

Usage: python measure_gas.py [N=200] [out.json]
"""
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from eth_hash.auto import keccak  # noqa: E402

from provecps import crypto, hai  # noqa: E402
from provecps.ledger import ROOT, Anvil, SimLedger  # noqa: E402
from provecps.sim import Sim  # noqa: E402

BASE = ROOT / "contracts/out/Baselines.sol"


def deploy(chain, name, admin, *ctor):
    j = json.loads((BASE / f"{name}.json").read_text()) if name != "Registry" else \
        json.loads((ROOT / "contracts/out/Registry.sol/Registry.json").read_text())
    led = SimLedger(Sim(chain.last_ts), chain, [1.0], abi=j["abi"], bytecode=j["bytecode"]["object"])
    factory = chain.w3.eth.contract(abi=j["abi"], bytecode=j["bytecode"]["object"])
    h = chain.send(admin, None, factory.constructor(*ctor).data_in_transaction)
    chain.mine(chain.last_ts + 1)
    led.address = chain.receipt(h).contractAddress
    led.contract = chain.w3.eth.contract(address=led.address, abi=j["abi"])
    return led


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    out = sys.argv[2] if len(sys.argv) > 2 else None
    chain = Anvil(sys.argv[3] if len(sys.argv) > 3 else "http://127.0.0.1:8646")
    admin, gw = crypto.Signer.from_seed("gas-admin").address, crypto.Signer.from_seed("gas-gw").address
    rep = hai.build("test1")
    events = rep.events[:n]
    res = {}

    def run(label, led, fn, argsf):
        led.setup_tx(admin, "registerGateway", gw)
        gas = [led.setup_tx(gw, fn, *argsf(i)).gasUsed for i in range(n)]
        steady = gas[1:]
        res[label] = {"fn": fn, "median": int(statistics.median(steady)), "min": min(steady), "max": max(steady),
                      "first": gas[0]}
        print(f"{label:28s} {fn:12s} median={res[label]['median']:7d} min={min(steady)} max={max(steady)} first={gas[0]}")

    run("PROVE-CPS Registry.anchor", deploy(chain, "Registry", admin, 300), "anchor",
        lambda i: (keccak(b"root%d" % i),))
    run("B1 FullLog.logEvent", deploy(chain, "FullLog", admin), "logEvent",
        lambda i: (events[i][1], i + 1, 1_700_000_000 + events[i][0], list(events[i][2]), events[i][3]))
    run("B2 HashLog.anchorHash", deploy(chain, "HashLog", admin), "anchorHash", lambda i: (keccak(b"ev%d" % i),))
    run("B3/B5 MerkleLog.anchor", deploy(chain, "MerkleLog", admin), "anchor", lambda i: (keccak(b"r%d" % i),))
    run("B4 SequencedLog.append", deploy(chain, "SequencedLog", admin), "append", lambda i: (i + 1, keccak(b"s%d" % i)))
    res["payload_bytes_mean"] = statistics.fmean(len(e[3]) for e in events)
    if out:
        Path(out).write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
