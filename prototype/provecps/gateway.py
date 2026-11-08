"""Gateway agent (design doc 6.2) and the adversarial strategies A1-A8 (design doc 7).

The honest gateway: verify device signature and chain link, issue a receipt with a policy deadline, replicate
FULL payloads, and anchor with the deadline-safe earliest-deadline stabbing rule (Prop 4): when the earliest
pending deadline minus (safety + reserve) arrives, close one batch containing the latest head of every device
with receipted-but-unanchored events. An attack is a Strategy that overrides individual decisions; everything
else, including how the gateway answers challenges, is the same code.

Disputes (v2): a challenge with no confirmed coverage is answered in ONE transaction, `anchorAndRespond`, over a
single-leaf batch holding the challenged device-signed head; a NOTICE-FULL answer also carries the payload, taken
from the gateway's custody or, for an event it never received, from the witness's copy in the evidence store.
"""
import heapq
import math
from collections import defaultdict

from eth_hash.auto import keccak

from . import crypto
from .messages import Receipt

CUSTODY, NOTICE, AVAILABILITY, NOTICE_FULL = 0, 1, 2, 3


# ====================================================================== strategies

class Honest:
    name = "honest"

    def drop(self, msg, now):                 # ignore a device message entirely (no custody, no receipt)
        return False

    def keep_payload(self, msg, full, now):   # retain and (if FULL) replicate the payload
        return True

    def cap(self, dev, st):                   # highest counter of `dev` the gateway is willing to anchor
        return None

    def hold_until(self, dev, st):            # earliest time the gateway is willing to anchor `dev`
        return -math.inf

    def answers(self, dev, kind):             # respond to a challenge about `dev`
        return True

    def published_receipt(self, r, msg, gw):  # the receipt it writes to the public custody log
        return r

    def receipt_delay(self, msg, now):        # how long it withholds the receipt
        return 0

    def deadline_stretch(self, msg, now):     # seconds added to the policy deadline (devices tolerate sigma)
        return 0


class _Targeted(Honest):
    def __init__(self, targets, t0, t1=math.inf):
        self.targets, self.t0, self.t1 = set(targets), t0, t1

    def _hit(self, dev, ts):
        return dev in self.targets and self.t0 <= ts < self.t1


class TailTruncation(_Targeted):
    """A1: keep receipting (so devices free their buffers) but never anchor target events from t0 on."""
    name = "A1-tail-truncation"

    def cap(self, dev, st):
        return st.last_before(self.t0) if dev in self.targets else None

    def answers(self, dev, kind):
        return dev not in self.targets


class MidStreamDrop(_Targeted):
    """A2: delete target events generated in [t0, t1) (payload and header), keep anchoring device heads
    because it cannot form a valid head without them (I1)."""
    name = "A2-mid-stream-drop"

    def keep_payload(self, msg, full, now):
        return not self._hit(msg.header.device_id, msg.header.timestamp)


class Stonewall(_Targeted):
    """A3 (and A7 when timed to a real partition): silently ignore target devices from t0 on."""
    name = "A3-stonewall"

    def drop(self, msg, now):
        return msg.header.device_id in self.targets and now >= self.t0

    def answers(self, dev, kind):
        return dev not in self.targets


class RefuseCustody(_Targeted):
    """A8: refuse custody of target devices (no receipt, hence no AVAILABILITY obligation) but answer every plain
    NOTICE by anchoring the head the witness posted, so every event ends up covered while FULL payloads never
    reach the evidence store. In v1 this suppression went unattributed; v2 answers it with NOTICE-FULL, which
    this gateway cannot answer without publishing the payload it wants to hide."""
    name = "A8-custody-refusal"

    def drop(self, msg, now):
        return msg.header.device_id in self.targets and now >= self.t0

    def answers(self, dev, kind):
        return not (dev in self.targets and kind == NOTICE_FULL)


class SlowWalk(_Targeted):
    """A9: the worst case for detection that Theorem 2 allows. Withhold each target receipt for just under the notice
    threshold (so no NOTICE fires), stretch its deadline by the clock tolerance the device accepts, then never anchor
    (truncation). Detection must then wait for the stretched deadline of a late receipt."""
    name = "A9-slow-walk"

    def __init__(self, targets, t0, hold, stretch):
        super().__init__(targets, t0)
        self.hold, self.stretch = hold, stretch

    def receipt_delay(self, msg, now):
        return self.hold if self._hit(msg.header.device_id, msg.header.timestamp) else 0

    def deadline_stretch(self, msg, now):
        return self.stretch if self._hit(msg.header.device_id, msg.header.timestamp) else 0

    def cap(self, dev, st):
        return st.last_before(self.t0) if dev in self.targets else None

    def answers(self, dev, kind):
        return dev not in self.targets


class Disguise(_Targeted):
    """A4: take custody of FULL target events, anchor them, but treat them as DIGEST: delete the payload."""
    name = "A4-disguised-suppression"

    def keep_payload(self, msg, full, now):
        return not (full and self._hit(msg.header.device_id, msg.header.timestamp))


class Equivocate(_Targeted):
    """A5: show the device one history and the public custody log another (same counter, different head)."""
    name = "A5-equivocation"

    def published_receipt(self, r, msg, gw):
        if not self._hit(msg.header.device_id, msg.header.timestamp):
            return r
        fake = keccak(b"forged" + r.head)
        digest = crypto.receipt_digest(gw.domain, r.device_id, r.counter, fake, r.deadline)
        return Receipt(r.device_id, r.counter, fake, r.deadline, gw.signer.sign(digest))


class Delay(_Targeted):
    """A6: anchor target events, but only `extra` seconds after their deadline (then answer, to avoid conviction)."""
    name = "A6-deadline-delay"

    def __init__(self, targets, t0, t1, extra):
        super().__init__(targets, t0, t1)
        self.extra = extra

    def hold_until(self, dev, st):
        # Rational delay: `extra` past the *earliest* pending deadline (a FULL event received after a DIGEST one
        # has the earlier deadline), so the gateway can still answer within W_resp and escape conviction.
        first = st.first_unanchored()
        if dev not in self.targets or first is None:
            return -math.inf
        pending = range(first, st.last_counter + 1)
        if not any(self.t0 <= st.ts[c] < self.t1 for c in pending):
            return -math.inf
        return min(st.deadline[c] for c in pending) + self.extra


# ====================================================================== gateway

class DevState:
    __slots__ = ("last_counter", "last_head", "heads", "hashes", "sigs", "ts", "deadline", "custody",
                 "last_receipt", "anchored_req", "pre")

    def __init__(self):
        self.last_counter, self.last_head = 0, crypto.ZERO32
        self.heads, self.hashes, self.sigs, self.ts, self.deadline = {}, {}, {}, {}, {}
        self.custody = {}           # counter -> payload (None if deleted)
        self.last_receipt = None
        self.anchored_req = 0       # highest counter included in a submitted batch

    def first_unanchored(self):
        c = self.anchored_req + 1
        return c if c <= self.last_counter else None

    def last_before(self, t):
        c = self.last_counter
        while c > 0 and self.ts[c] >= t:
            c -= 1
        return c


class Gateway:
    def __init__(self, sim, signer, port, domain, policy, device_keys, store, tau_full, tau_digest,
                 safety, reserve=0, strategy=None):
        self.sim, self.signer, self.port, self.domain = sim, signer, port, domain
        self.address = signer.address
        self.policy, self.device_keys, self.store = policy, device_keys, store
        self.tau_full, self.tau_digest, self.safety, self.reserve = tau_full, tau_digest, safety, reserve
        self.strategy = strategy or Honest()
        self.dev = defaultdict(DevState)
        self.heap = []                       # (deadline, dev, counter) of receipted, unanchored heads
        self.fire_at = None
        self.coverage = defaultdict(list)    # dev -> [(counter, head, sig, root, proof)] confirmed on ledger
        self.waiting = []                    # challenges to answer once coverage lands (see _respond)
        self.release = {}                    # (dev, counter) -> time a withheld receipt is released (A9)
        self.stats = {"events": 0, "receipts": 0, "rejected": 0, "batches": 0, "leaves": 0, "responses": 0}
        port.subscribe(self._on_ledger)

    # ------------------------------------------------------------------ device messages

    def on_event(self, msg):
        now = self.sim.now
        if self.strategy.drop(msg, now):
            return None
        h = msg.header
        st = self.dev[h.device_id]
        if h.counter <= st.last_counter:
            return st.last_receipt           # retransmission: the cumulative receipt covers it
        if h.counter != st.last_counter + 1:
            return None                      # out of order; the device retransmits from its oldest
        if not self._valid(msg, st):
            self.stats["rejected"] += 1
            return None
        full = self.policy.requires_full(h.features, h.timestamp)
        keep = self.strategy.keep_payload(msg, full, now)
        st.last_counter, st.last_head = h.counter, msg.head.head
        st.heads[h.counter], st.hashes[h.counter] = msg.head.head, h.hash()
        st.sigs[h.counter], st.ts[h.counter] = msg.head.sig, h.timestamp
        st.custody[h.counter] = msg.payload if keep else None
        if full and keep:
            self.store.put_payload(h.payload_hash, msg.payload)
        hold = self.strategy.receipt_delay(msg, now)
        deadline = (math.ceil(now + hold) + (self.tau_full if full else self.tau_digest)
                    + self.strategy.deadline_stretch(msg, now))
        if hold:
            self.release[(h.device_id, h.counter)] = now + hold
        st.deadline[h.counter] = deadline
        digest = crypto.receipt_digest(self.domain, h.device_id, h.counter, msg.head.head, deadline)
        r = Receipt(h.device_id, h.counter, msg.head.head, deadline, self.signer.sign(digest))
        st.last_receipt = r
        self.store.log_receipt(self.address, self.strategy.published_receipt(r, msg, self))
        self.stats["events"] += 1
        self.stats["receipts"] += 1
        heapq.heappush(self.heap, (deadline, h.device_id, h.counter))
        self._schedule()
        return r

    def release_time(self, r):
        """When the receipt `r` may leave the gateway (a strategy may withhold it, also on retransmission)."""
        return self.release.get((r.device_id, r.counter), -math.inf)

    def _valid(self, msg, st):
        h = msg.header
        if msg.head.device_id != h.device_id or msg.head.counter != h.counter or msg.prev_head != st.last_head:
            return False
        if keccak(msg.payload) != h.payload_hash or crypto.chain_step(st.last_head, h.hash()) != msg.head.head:
            return False
        digest = crypto.checkpoint_digest(self.domain, h.device_id, h.counter, msg.head.head)
        return crypto.recover(digest, msg.head.sig) == self.device_keys.get(h.device_id)

    # ------------------------------------------------------------------ scheduler (Prop 4)

    def _schedule(self):
        heap = self.heap
        while heap and heap[0][2] <= self.dev[heap[0][1]].anchored_req:
            heapq.heappop(heap)              # already covered by a submitted batch
        if not heap:
            return
        t = heap[0][0] - self.safety - self.reserve
        if self.fire_at is None or t < self.fire_at:
            self.fire_at = t
            self.sim.at(t, self._fire, t)

    def _fire(self, token=None, force=False):
        if not force and token != self.fire_at:
            return                           # superseded by an earlier firing
        self.fire_at = None
        now = self.sim.now
        horizon = now + self.safety + self.reserve
        entries, held = [], {}
        for dev in [d for d, st in self.dev.items() if st.anchored_req < st.last_counter]:
            st = self.dev[dev]
            hold = self.strategy.hold_until(dev, st)
            if hold - self.safety > now:
                held[dev] = hold
                continue
            cap = self.strategy.cap(dev, st)
            c = st.last_counter if cap is None else min(cap, st.last_counter)
            if c > st.anchored_req:
                entries.append((dev, c, st.heads[c], st.sigs[c]))
                st.anchored_req = c
            if cap is not None:              # the attacker abandons the rest of this device's heads
                st.anchored_req = st.last_counter
        # Due entries are now either covered by this batch (stale), abandoned by the strategy (stale), or held:
        # re-key held ones to the time the strategy is willing to anchor, so the scheduler does not spin.
        requeue = set()
        while self.heap and self.heap[0][0] <= horizon:
            _, dev, c = heapq.heappop(self.heap)
            if dev in held and c > self.dev[dev].anchored_req and dev not in requeue:
                requeue.add(dev)
                heapq.heappush(self.heap, (held[dev] + self.reserve, dev, c))
        if entries:
            self._anchor(entries)
        self._schedule()

    def _anchor(self, entries):
        tree = crypto.MerkleTree([crypto.leaf(d, c, h) for d, c, h, _ in entries])
        root = tree.root
        proved = [(d, c, h, s, tree.proof(i)) for i, (d, c, h, s) in enumerate(entries)]
        self.stats["batches"] += 1
        self.stats["leaves"] += len(entries)

        def done(ok, evs, ts):
            if not ok:
                return
            for d, c, h, s, p in proved:
                self.coverage[d].append((c, h, s, root, p))
            self.store.publish_manifest(self.address, root, ts, proved)
            self._answer_waiting()

        self.port.submit("anchor", (root,), done)

    # ------------------------------------------------------------------ disputes

    def _on_ledger(self, sender, fn, args, ok, evs, ts):
        for name, a in evs:
            if name == "ChallengeOpened" and a["gateway"] == self.address:
                self._respond(a["id"], a["kind"], a["deviceId"], a["counter"], fn, args)

    def _respond(self, cid, kind, dev, counter, fn, args):
        if not self.strategy.answers(dev, kind):
            return
        st = self.dev[dev]
        if kind == AVAILABILITY:
            payload = st.custody.get(counter)
            if payload is not None:
                self.port.submit("respondPayload", (cid, payload))
                self.stats["responses"] += 1
            return
        head = args[0][2]                    # challenged head, from the challenge transaction's calldata
        payload = b""
        if kind == NOTICE_FULL:
            payload = self._payload_for(dev, args[3])
            if payload is None:
                self.stats["unanswerable"] = self.stats.get("unanswerable", 0) + 1
                return
        if fn in ("notice", "noticeFull"):
            sig = args[1]                    # the device-signed head is in the challenge itself
        else:
            sig = st.sigs.get(counter) if st.heads.get(counter) == head else None
        item = (cid, kind, dev, counter, head, sig, payload)
        if self._answer_from_coverage(item):
            return
        if sig is None or self.strategy.hold_until(dev, st) - self.safety > self.sim.now:
            self.waiting.append(item)        # answered when the (strategy's) next batch lands
            self._fire(force=True)
            return
        self._anchor_and_respond(item)

    def _payload_for(self, dev, header):
        """Payload of the FULL event in a NOTICE-FULL: from custody if we hold it, else the witness's copy."""
        ph = bytes(header[4])
        p = self.dev[dev].custody.get(header[1])
        if p is not None and keccak(p) == ph:
            return p
        return self.store.witness_payloads.get(ph)

    def _anchor_and_respond(self, item):
        cid, kind, dev, counter, head, sig, payload = item
        root = crypto.leaf(dev, counter, head)   # a one-leaf batch: its root is the leaf, its proof is empty
        self.stats["batches"] += 1
        self.stats["leaves"] += 1
        self.stats["responses"] += 1

        def done(ok, evs, ts):
            if not ok:
                return
            self.coverage[dev].append((counter, head, sig, root, []))
            self.store.publish_manifest(self.address, root, ts, [(dev, counter, head, sig, [])])
            if payload:
                self.store.put_payload(keccak(payload), payload)   # now in calldata on the ledger

        self.port.submit("anchorAndRespond", (cid, (root, counter, head, sig, []), [], payload), done)

    def _answer_from_coverage(self, item):
        cid, kind, dev, counter, head, sig, payload = item
        cov = self._coverage_for(dev, counter, head)
        if cov is None:
            return False
        (c, h, s, root, proof), later = cov
        if kind == NOTICE_FULL:
            def done(ok, evs, ts):
                if ok:
                    self.store.put_payload(keccak(payload), payload)
            self.port.submit("respondNoticeFull", (cid, (root, c, h, s, proof), later, payload), done)
        else:
            self.port.submit("respondCoverage", (cid, (root, c, h, s, proof), later))
        self.stats["responses"] += 1
        return True

    def _answer_waiting(self):
        self.waiting = [item for item in self.waiting if not self._answer_from_coverage(item)]

    def _coverage_for(self, dev, counter, head):
        st = self.dev[dev]
        best = None
        for cov in self.coverage[dev]:
            c = cov[0]
            if c < counter:
                continue
            if c == counter and cov[1] == head:
                return cov, []
            if st.heads.get(counter) == head and all(k in st.hashes for k in range(counter + 1, c + 1)):
                if best is None or c < best[0][0]:
                    best = (cov, [st.hashes[k] for k in range(counter + 1, c + 1)])
        return best
