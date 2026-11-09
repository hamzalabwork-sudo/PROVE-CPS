"""Real-time execution on a live chain (Hyperledger Besu QBFT): the same agents as the simulator, on the wall
clock, against the deployed Registry.

  RTSim     the simulator's event loop paced by the wall clock; other threads post work through an inbox
  ChainView one party's connection to the chain: its own RPC endpoint, a block poller that replays every Registry
            transaction to it in block order (as SimLedger does), and signing senders that retry while the endpoint
            is unreachable. It has the interface the agents use (submit, subscribers, view, anchored_at, status, log)

A party behind a cut uplink cannot submit or read the chain until the cut heals, and then catches up on the blocks
it missed, as a real client would. Transactions are signed locally (zero gas price on the private testnet).
"""
import heapq
import itertools
import queue
import threading
import time

from eth_abi import decode as abi_decode
from eth_account import Account
from eth_utils import event_abi_to_log_topic
from requests.exceptions import RequestException
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

from .sim import Sim

GAS = 5_000_000


class RTSim(Sim):
    def __init__(self):
        super().__init__(time.time())
        self.inbox = queue.Queue()
        self.max_lag = 0.0          # how far behind the wall clock a scheduled action ran

    def post(self, fn, *args):
        """Thread-safe: run fn(*args) on the event-loop thread as soon as possible."""
        self.inbox.put((fn, args))

    def run(self, until):
        q = self._q
        while True:
            now = time.time()
            if q and q[0][0] <= min(now, until):
                t, _, fn, args = heapq.heappop(q)
                self.max_lag = max(self.max_lag, now - t)
                self.now = max(now, t)
                fn(*args)
                continue
            if now >= until:
                break
            nxt = min(q[0][0] if q else until, until)
            try:
                fn, args = self.inbox.get(timeout=max(0.0, nxt - now))
            except queue.Empty:
                continue
            self.now = time.time()
            fn(*args)
        self.now = time.time()


def _type_str(inp):
    t = inp["type"]
    if t.startswith("tuple"):
        return "(" + ",".join(_type_str(c) for c in inp["components"]) + ")" + t[len("tuple"):]
    return t


class ChainView:
    def __init__(self, sim, url, abi, address, keys=None, name="", poll=0.25, timeout=3):
        self.sim, self.url, self.name, self.address = sim, url, name, Web3.to_checksum_address(address)
        self.w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": timeout}))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        self.contract = self.w3.eth.contract(address=self.address, abi=abi)
        self._topics = {event_abi_to_log_topic(e): e["name"] for e in abi if e["type"] == "event"}
        self._fns = {}
        for f in abi:
            if f["type"] == "function":
                types = [_type_str(i) for i in f["inputs"]]
                sel = Web3.keccak(text=f"{f['name']}({','.join(types)})")[:4]
                self._fns[bytes(sel)] = (f["name"], types)
        self.keys = keys or {}       # sender address -> crypto.Signer
        self.subscribers = []
        self.log, self.events, self.anchored, self.status = [], [], {}, {}
        self.pending = {}            # tx hash -> (sender, fn, args, cb, t_sent)
        self.inclusion = []          # (fn, sender, t_sent, block_ts): Delta_L = block_ts - t_sent
        self.errors = 0
        self.rejected = []           # (fn, reason) of transactions the node refused
        self.chain_id = self._retry(lambda: self.w3.eth.chain_id)
        self.next_block = self._retry(lambda: self.w3.eth.block_number) + 1
        self._queues, self._lock, self._stop = {}, threading.Lock(), threading.Event()
        threading.Thread(target=self._poll, args=(poll,), daemon=True).start()

    # -------------------------------------------------------------- plumbing

    def _retry(self, f, tries=None):
        for i in itertools.count():
            try:
                return f()
            except Exception:
                self.errors += 1
                if tries is not None and i + 1 >= tries:
                    raise
                time.sleep(0.5)

    def stop(self):
        self._stop.set()

    # -------------------------------------------------------------- reads

    def view(self, fn, *args):
        return self._retry(lambda: self.contract.functions[fn](*args).call())

    def anchored_at(self, gateway, root) -> int:
        return self.anchored.get((gateway, root), 0)

    def _poll(self, period):
        while not self._stop.is_set():
            try:
                head = self.w3.eth.block_number
                while self.next_block <= head and not self._stop.is_set():
                    self._replay_block(self.next_block)
                    self.next_block += 1
            except Exception:
                self.errors += 1     # endpoint unreachable (a cut uplink): catch up when it heals
            time.sleep(period)

    def _replay_block(self, n):
        blk = self.w3.eth.get_block(n, full_transactions=True)
        ts = blk.timestamp
        for tx in blk.transactions:
            if tx["to"] is None or Web3.to_checksum_address(tx["to"]) != self.address:
                continue
            rc = self.w3.eth.get_transaction_receipt(tx["hash"])
            data = bytes(tx["input"])
            fn, types = self._fns.get(data[:4], ("?", None))
            args = tuple(abi_decode(types, data[4:])) if types is not None else ()
            evs = [(self._topics[lg["topics"][0]],
                    dict(getattr(self.contract.events, self._topics[lg["topics"][0]])().process_log(lg)["args"]))
                   for lg in rc.logs if lg["topics"] and lg["topics"][0] in self._topics]
            sender = Web3.to_checksum_address(tx["from"])
            with self._lock:
                mine = self.pending.pop(bytes(tx["hash"]), None)
            self.sim.post(self._deliver, ts, sender, fn, args, rc.status, rc.gasUsed, evs, mine)

    def _deliver(self, ts, sender, fn, args, status, used, evs, mine):
        """On the event-loop thread, in block order: the same bookkeeping and callbacks as SimLedger._mine."""
        self.log.append((ts, sender, fn, args, status, used, evs))
        for name, a in evs:
            self.events.append((ts, name, a))
            if name == "Anchored":
                self.anchored.setdefault((a["gateway"], a["root"]), ts)
            elif name == "ChallengeOpened":
                self.status[a["id"]] = 1
            elif name == "ChallengeResolved":
                self.status[a["id"]] = a["status"]
        if mine is not None:
            _, mfn, _, cb, t_sent = mine
            self.inclusion.append((mfn, sender, t_sent, ts))
            if cb:
                cb(status == 1, evs, ts)
        for sub in self.subscribers:
            sub(sender, fn, args, status == 1, evs, ts)

    # -------------------------------------------------------------- writes

    def submit(self, sender, fn, args, cb=None, value=0):
        q = self._queues.get(sender)
        if q is None:
            q = self._queues[sender] = queue.Queue()
            threading.Thread(target=self._sender, args=(sender, q), daemon=True).start()
        q.put((fn, args, cb, value))

    def _sender(self, sender, q):
        acct = Account.from_key(self.keys[sender].key.to_bytes())
        nonce = self._retry(lambda: self.w3.eth.get_transaction_count(sender, "pending"))
        while not self._stop.is_set():
            fn, args, cb, value = q.get()
            data = self.contract.encode_abi(fn, args=list(args))
            tx = {"to": self.address, "data": data, "gas": GAS, "gasPrice": 0, "nonce": nonce,
                  "chainId": self.chain_id, "value": value}
            signed = acct.sign_transaction(tx)
            h = bytes(signed.hash)
            while True:
                t_sent = time.time()
                with self._lock:
                    self.pending[h] = (sender, fn, args, cb, t_sent)
                try:
                    self.w3.eth.send_raw_transaction(signed.raw_transaction)
                    break
                except RequestException:
                    self.errors += 1     # endpoint unreachable: the same transaction again once it heals
                    time.sleep(0.5)
                except Exception as e:
                    msg = str(e).lower()
                    if "known" in msg or "already" in msg or "nonce too low" in msg:
                        break        # the node got it before our request timed out
                    with self._lock:     # rejected by the node: record it, the nonce stays free
                        self.pending.pop(h, None)
                    self.rejected.append((fn, msg[:200]))
                    h = None
                    break
            if h is not None:
                nonce += 1


def deploy(url, admin, abi, bytecode, response_window, bond=0, timeout=10):
    """Deploy the Registry from `admin` (a crypto.Signer) and return its address."""
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": timeout}))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    acct = Account.from_key(admin.key.to_bytes())
    data = w3.eth.contract(abi=abi, bytecode=bytecode).constructor(response_window, bond).data_in_transaction
    tx = {"data": data, "gas": 8_000_000, "gasPrice": 0, "chainId": w3.eth.chain_id,
          "nonce": w3.eth.get_transaction_count(acct.address, "pending")}
    h = w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction)
    rc = w3.eth.wait_for_transaction_receipt(h, timeout=120, poll_latency=0.2)
    assert rc.status == 1, "deploy failed"
    return rc.contractAddress


def setup_batch(url, admin, abi, address, calls, timeout=10, window=150):
    """Send configuration calls [(fn, args)] from admin with consecutive nonces (at most `window` in flight) and
    wait until all are included. Returns the block timestamp of the last one."""
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": timeout}))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    acct = Account.from_key(admin.key.to_bytes())
    c = w3.eth.contract(address=address, abi=abi)
    nonce, cid = w3.eth.get_transaction_count(acct.address, "pending"), w3.eth.chain_id
    hashes = []
    last_ts = 0
    for i, (fn, args) in enumerate(calls):
        tx = {"to": address, "data": c.encode_abi(fn, args=list(args)), "gas": GAS, "gasPrice": 0,
              "nonce": nonce + i, "chainId": cid}
        hashes.append(w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction))
        if len(hashes) >= window or i == len(calls) - 1:
            for h in hashes:
                rc = w3.eth.wait_for_transaction_receipt(h, timeout=300, poll_latency=0.2)
                assert rc.status == 1, f"setup call failed: {h.hex()}"
                last_ts = max(last_ts, w3.eth.get_block(rc.blockNumber).timestamp)
            hashes = []
    return last_ts
