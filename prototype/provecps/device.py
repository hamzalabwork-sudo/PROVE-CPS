"""Device agent (design doc 6.1). Transport-agnostic: the caller delivers messages and drives the clock.

Runs unchanged on a Raspberry Pi; the only dependencies are keccak and secp256k1.
"""
from eth_hash.auto import keccak

from . import crypto
from .messages import AvailabilityEvidence, CheckpointMsg, EventMsg, Header, Receipt, SignedHead


class Device:
    def __init__(self, device_id: int, signer: crypto.Signer, gateway_addr: str, domain: bytes, policy,
                 tau_max: int, clock_slack: int = 5):
        self.id = device_id
        self.signer = signer
        self.gateway_addr = gateway_addr
        self.domain = domain
        self.policy = policy
        self.tau_max = tau_max            # longest deadline the policy allows; longer receipts are rejected
        self.clock_slack = clock_slack

        self.counter = 0
        self.head = crypto.ZERO32
        self.latest: SignedHead | None = None
        self.heads = {0: crypto.ZERO32}  # counter -> head, for counters not yet covered by a receipt
        self.ev_hashes = {}              # counter -> event hash, kept while a FULL event may need linking
        self.unreceipted = {}            # counter -> (EventMsg, generation time): the custody buffer
        self.receipt: Receipt | None = None
        self.full_wait = {}              # counter -> (Header, prev_head): FULL events awaiting custody
        self.receipts_out = []
        self.evidence_out = []
        self.conflicting = []
        self.stats = {"events": 0, "full": 0, "max_buffer": 0, "bad_receipts": 0}

    # ---------------------------------------------------------------- events

    def emit(self, ts: int, features: tuple, payload: bytes) -> EventMsg:
        c = self.counter + 1
        hdr = Header(self.id, c, ts, features, keccak(payload))
        eh = hdr.hash()
        prev = self.head
        head = crypto.chain_step(prev, eh)
        sig = self.signer.sign(crypto.checkpoint_digest(self.domain, self.id, c, head))
        self.counter, self.head = c, head
        self.latest = SignedHead(self.id, c, head, sig)
        self.heads[c] = head
        self.ev_hashes[c] = eh
        msg = EventMsg(hdr, payload, prev, self.latest)
        self.unreceipted[c] = (msg, ts)
        self.stats["events"] += 1
        if self.policy.requires_full(features, ts):
            self.full_wait[c] = (hdr, prev)
            self.stats["full"] += 1
        self.stats["max_buffer"] = max(self.stats["max_buffer"], len(self.unreceipted))
        return msg

    def pending(self):
        """Unreceipted messages, oldest first, for retransmission."""
        return [m for m, _ in self.unreceipted.values()]

    # ---------------------------------------------------------------- custody

    def on_receipt(self, r: Receipt, now: float) -> bool:
        if r.device_id != self.id:
            return False
        digest = crypto.receipt_digest(self.domain, r.device_id, r.counter, r.head, r.deadline)
        if crypto.recover(digest, r.sig) != self.gateway_addr:
            return False
        if self.receipt is not None and r.counter <= self.receipt.counter:
            if r.counter == self.receipt.counter and r.head != self.receipt.head:
                self._conflict(r)
            return r.counter == self.receipt.counter and r.head == self.receipt.head
        known = self.heads.get(r.counter)
        if known is None or known != r.head:
            # A gateway-signed statement about our chain that is false: keep it, it convicts (EQUIVOCATION).
            self._conflict(r)
            return False
        if r.deadline > now + self.tau_max + self.clock_slack:
            self.stats["bad_receipts"] += 1  # a stretched deadline would weaken the detection bound
            return False
        self.receipt = r
        self.receipts_out.append(r)
        for c in sorted(k for k in self.full_wait if k <= r.counter):
            hdr, prev = self.full_wait.pop(c)
            later = tuple(self.ev_hashes[k] for k in range(c + 1, r.counter + 1))
            self.evidence_out.append(AvailabilityEvidence(r, prev, hdr, later))
        for c in [k for k in self.unreceipted if k <= r.counter]:
            del self.unreceipted[c]
        floor = min(self.full_wait, default=r.counter)
        for d in (self.heads, self.ev_hashes):
            for c in [k for k in d if k < floor]:
                del d[c]
        return True

    def _conflict(self, r: Receipt):
        self.stats["bad_receipts"] += 1
        self.conflicting.append(r)

    # ---------------------------------------------------------------- witness path

    def checkpoint(self) -> CheckpointMsg | None:
        if self.latest is None:
            return None
        oldest = min((ts for _, ts in self.unreceipted.values()), default=None)
        msg = CheckpointMsg(self.latest, self.receipt, oldest, self.receipts_out, self.evidence_out, self.conflicting)
        self.receipts_out, self.evidence_out, self.conflicting = [], [], []
        return msg
