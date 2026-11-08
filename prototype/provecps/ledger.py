"""The ledger in simulated time: the real Registry bytecode on Anvil, with block timestamps set by the simulator.

Every verdict (Dismissed / Late / Convicted) in the attack matrix comes from the deployed contract, not from a
model of it. Inclusion delays are drawn from the Delta_L distribution measured on a live chain, and a sender's
transactions are included in nonce order. Anvil runs with automine off; we mine each block at its timestamp.
"""
import csv
import json
import math
import random
from collections import defaultdict
from pathlib import Path

from eth_utils import event_abi_to_log_topic
from web3 import Web3

from .sim import Outages, Sim

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "contracts/out/Registry.sol/Registry.json"
GAS_LIMIT = 5_000_000


def load_artifact(path=ARTIFACT):
    j = json.loads(Path(path).read_text())
    return j["abi"], j["bytecode"]["object"]


def empirical_delays(csv_path, phase="warm"):
    """Delta_L samples in seconds from experiments/latency/measure_inclusion.py output."""
    with open(csv_path, newline="") as f:
        return [float(r["submit_to_receipt_ms"]) / 1000 for r in csv.DictReader(f) if r["phase"] == phase]


class Anvil:
    """Anvil with manual mining and auto-impersonation (protocol signatures are still real; only the
    transaction envelope is unsigned, which does not affect what the contract checks)."""

    def __init__(self, rpc="http://127.0.0.1:8645"):
        self.w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 120}))
        self.rpc("anvil_autoImpersonateAccount", [True])
        self.rpc("evm_setAutomine", [False])
        self.last_ts = self.w3.eth.get_block("latest").timestamp

    def rpc(self, method, params):
        r = self.w3.provider.make_request(method, params)
        if "error" in r:
            raise RuntimeError(f"{method}: {r['error']}")
        return r["result"]

    def send(self, sender, to, data, gas=GAS_LIMIT, value=0):
        tx = {"from": sender, "data": data, "gas": hex(gas), "gasPrice": "0x0", "value": hex(value)}
        if to:
            tx["to"] = to
        return self.rpc("eth_sendTransaction", [tx])

    def mine(self, ts: int) -> int:
        ts = max(int(ts), self.last_ts + 1)
        self.rpc("evm_setNextBlockTimestamp", [ts])
        self.rpc("evm_mine", [])
        self.last_ts = ts
        return ts

    def receipt(self, h):
        return self.w3.eth.get_transaction_receipt(h)


class SimLedger:
    def __init__(self, sim: Sim, chain: Anvil, delays, seed=0, abi=None, bytecode=None):
        self.sim, self.chain = sim, chain
        self.delays = list(delays)
        self.rng = random.Random(seed)
        self.abi, self.bytecode = abi or load_artifact()[0], bytecode or load_artifact()[1]
        self.contract = chain.w3.eth.contract(abi=self.abi)
        self._topics = {event_abi_to_log_topic(e): e["name"] for e in self.abi if e["type"] == "event"}
        self.address = None
        self._pending = defaultdict(list)
        self._sender_last = {}
        self.subscribers = []
        self.log = []      # (ts, sender, fn, args, status, gasUsed, events)
        self.events = []   # (ts, name, args) for every contract event, in order
        self.anchored = {} # (gateway, root) -> block ts, rebuilt from Anchored logs (mirrors anchoredAt)
        self.status = {}   # challenge id -> Registry.Status, rebuilt from ChallengeOpened/Resolved logs

    # -------------------------------------------------------------- setup (instant, before t0)

    def deploy(self, admin: str, response_window: int, bond: int = 0):
        factory = self.chain.w3.eth.contract(abi=self.abi, bytecode=self.bytecode)
        h = self.chain.send(admin, None, factory.constructor(response_window, bond).data_in_transaction)
        self.chain.mine(self.chain.last_ts + 1)
        rc = self.chain.receipt(h)
        assert rc.status == 1, "deploy failed"
        self.address = rc.contractAddress
        self.contract = self.chain.w3.eth.contract(address=self.address, abi=self.abi)
        return self.address

    def setup_tx(self, sender, fn, *args):
        """Synchronous transaction for configuration (registration, policy), mined immediately."""
        h = self.chain.send(sender, self.address, self.contract.encode_abi(fn, args=list(args)))
        self.chain.mine(self.chain.last_ts + 1)
        rc = self.chain.receipt(h)
        assert rc.status == 1, f"setup {fn} failed"
        return rc

    # -------------------------------------------------------------- simulated-time transactions

    def submit(self, sender, fn, args, cb=None, value=0):
        t = max(self.sim.now + self.rng.choice(self.delays), self._sender_last.get(sender, 0))
        sec = max(math.ceil(t), self.chain.last_ts + 1)
        self._sender_last[sender] = sec
        if sec not in self._pending:
            self.sim.at(sec, self._mine, sec)
        self._pending[sec].append((sender, fn, args, cb, value))

    def _mine(self, sec):
        batch = self._pending.pop(sec)
        hashes = [self.chain.send(s, self.address, self.contract.encode_abi(fn, args=list(a)), value=v)
                  for s, fn, a, _, v in batch]
        ts = self.chain.mine(sec)
        for (sender, fn, args, cb, _), h in zip(batch, hashes):
            rc = self.chain.receipt(h)
            evs = [(self._topics[lg["topics"][0]], self._decode(lg)) for lg in rc.logs if lg["topics"][0] in self._topics]
            self.log.append((ts, sender, fn, args, rc.status, rc.gasUsed, evs))
            for name, a in evs:
                self.events.append((ts, name, a))
                if name == "Anchored":
                    self.anchored.setdefault((a["gateway"], a["root"]), ts)  # the contract keeps the first time
                elif name == "ChallengeOpened":
                    self.status[a["id"]] = 1
                elif name == "ChallengeResolved":
                    self.status[a["id"]] = a["status"]
            if cb:
                cb(rc.status == 1, evs, ts)
            for sub in self.subscribers:
                sub(sender, fn, args, rc.status == 1, evs, ts)

    def _decode(self, lg):
        name = self._topics[lg["topics"][0]]
        return dict(getattr(self.contract.events, name)().process_log(lg)["args"])

    def view(self, fn, *args):
        return self.contract.functions[fn](*args).call()

    def anchored_at(self, gateway, root) -> int:
        """Registry.anchoredAt from the Anchored log index (what a production witness reads: logs, not calls)."""
        return self.anchored.get((gateway, root), 0)


class LedgerPort:
    """One party's access to the ledger. During an outage, submissions wait until the party is back and
    ledger notifications are seen only when it reconnects (a client that polls once it is online)."""

    def __init__(self, ledger: SimLedger, sender: str, outages: Outages | None = None):
        self.ledger, self.sender, self.outages = ledger, sender, outages or Outages()
        self.sim = ledger.sim

    def up(self) -> bool:
        return not self.outages.down(self.sim.now)

    def submit(self, fn, args, cb=None, value=0):
        t = self.outages.up_at(self.sim.now)
        if t > self.sim.now:
            self.sim.at(t, self.ledger.submit, self.sender, fn, args, cb, value)
        else:
            self.ledger.submit(self.sender, fn, args, cb, value)

    def subscribe(self, handler):
        def deliver(*a):
            t = self.outages.up_at(self.sim.now)
            if t > self.sim.now:
                self.sim.at(t, handler, *a)
            else:
                handler(*a)
        self.ledger.subscribers.append(deliver)

    def view(self, fn, *args):
        return self.ledger.view(fn, *args)

    def anchored_at(self, gateway, root) -> int:
        return self.ledger.anchored_at(gateway, root)
