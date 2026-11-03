"""Witness and auditor (design doc 6.3).

The witness receives device checkpoints over a path that avoids the gateway and turns them into on-chain
disputes: CUSTODY (receipted, not covered by the deadline), NOTICE (never receipted), AVAILABILITY (FULL payload
missing), EQUIVOCATION (two gateway receipts disagree). It finalizes its own challenges when the response
window closes.

Two dispute policies (both measured in the evaluation):
  strict   one dispute per overdue latest receipt per checkpoint period. Every suppressed event is named by a
           dispute within its Theorem 3 bound, so Definition 3 holds per event and is checkable on the ledger.
           Cost O(devices x attack duration / p), independent of the event rate, paid only under attack.
  economy  at most one open CUSTODY/NOTICE dispute per device (a dispute on head c covers every earlier event,
           I1); re-check the newest overdue receipt when it resolves; stop once the gateway is convicted.
           Cost O(devices) per attack; attribution is per gateway rather than per event.

The auditor only reads the ledger and the evidence store; for devices without a witness it can raise nothing
stronger than an unattributed SILENCE alarm (Theorem 1).
"""
from . import crypto

OPEN, DISMISSED, LATE, CONVICTED = 1, 2, 3, 4


class Witness:
    def __init__(self, sim, port, domain, device_keys, gateway_of, store, grace=1, notice_after=15, economy=False):
        self.sim, self.port, self.domain = sim, port, domain
        self.economy = economy
        self.device_keys, self.gateway_of, self.store = device_keys, gateway_of, store
        self.grace, self.notice_after = grace, notice_after
        self.window = port.view("responseWindow")
        self.receipts = {}         # (gateway, dev, counter) -> Receipt seen from the device
        self.custody_checks = set()
        self.noticed = {}          # dev -> highest counter noticed
        self.open = {}             # dev -> challenge id (or "pending" while the challenge tx is in flight)
        self.deferred = {}         # dev -> newest receipt that became overdue while a dispute was open
        self.convicted = set()     # gateways with a conviction on the ledger
        self.proved = set()        # gateways we already submitted an equivocation proof against
        self.challenges = {}       # id -> (kind, dev, counter, opened_ts)
        self.stats = {"checkpoints": 0, "custody": 0, "notice": 0, "availability": 0, "equivocation": 0,
                      "finalize": 0, "invalid": 0}
        port.subscribe(self._on_ledger)

    # ------------------------------------------------------------------ checkpoints

    def on_checkpoint(self, cp):
        h = cp.head
        dev = h.device_id
        if crypto.recover(crypto.checkpoint_digest(self.domain, dev, h.counter, h.head), h.sig) != self.device_keys.get(dev):
            self.stats["invalid"] += 1
            return
        self.stats["checkpoints"] += 1
        gw = self.gateway_of[dev]
        for r in [*cp.receipts, *(e.receipt for e in cp.evidence), *cp.conflicting]:
            if self._gateway_signed(gw, r):
                self._record(gw, r)
        if cp.receipt is not None and self._gateway_signed(gw, cp.receipt):
            self._watch_custody(gw, cp.receipt)
        for e in cp.evidence:
            if self._gateway_signed(gw, e.receipt):
                self._watch_custody(gw, e.receipt)
                self.sim.at(e.receipt.deadline + self.grace, self._check_availability, gw, e)
        oldest = cp.oldest_unreceipted_ts
        if (oldest is not None and self.sim.now - oldest >= self.notice_after and h.counter > self.noticed.get(dev, 0)
                and not self._quiet(dev, gw)):
            self.noticed[dev] = h.counter
            self._open("notice", (h.abi(), h.sig), dev, h.counter)

    def _gateway_signed(self, gw, r):
        return crypto.recover(crypto.receipt_digest(self.domain, r.device_id, r.counter, r.head, r.deadline), r.sig) == gw

    def _record(self, gw, r):
        key = (gw, r.device_id, r.counter)
        prev = self.receipts.setdefault(key, r)
        logged = self.store.custody_log.get(key)
        for other in (prev, logged):
            if other is not None and other.head != r.head and gw not in self.proved \
                    and self._gateway_signed(gw, other):
                self.proved.add(gw)        # one proof suffices: it is self-contained and convicts on inclusion
                self.stats["equivocation"] += 1
                self.port.submit("proveEquivocation", (other.abi(), other.sig, r.abi(), r.sig))
                return

    # ------------------------------------------------------------------ custody and availability

    def _watch_custody(self, gw, r):
        key = (r.device_id, r.counter)
        if key not in self.custody_checks:
            self.custody_checks.add(key)
            self.sim.at(r.deadline + self.grace, self._check_custody, gw, r)

    def covered(self, gw, dev, counter, by_ts):
        """A device-signed head >= counter sits in a batch this gateway anchored at or before by_ts."""
        for c, root, head, sig, proof in self.store.by_device.get(dev, ()):
            if c < counter or self.store.manifests[root][0] != gw:
                continue
            at = self.port.anchored_at(gw, root)   # the manifest's timestamp is a claim; the ledger decides
            if 0 < at <= by_ts and crypto.verify_proof(proof, root, crypto.leaf(dev, c, head)) and \
                    crypto.recover(crypto.checkpoint_digest(self.domain, dev, c, head), sig) == self.device_keys[dev]:
                return True
        return False

    def _quiet(self, dev, gw):
        """Economy mode: hold back while a dispute on this device is open or the gateway is already convicted."""
        return self.economy and (dev in self.open or gw in self.convicted)

    def _check_custody(self, gw, r):
        dev = r.device_id
        if (self.economy and gw in self.convicted) or self.covered(gw, dev, r.counter, r.deadline):
            return
        if self._quiet(dev, gw):
            if r.counter > getattr(self.deferred.get(dev), "counter", 0):
                self.deferred[dev] = r
            return
        self._open("challengeCustody", (r.abi(), r.sig), dev, r.counter)

    def _check_availability(self, gw, e):
        if not self.store.has_payload(e.header.payload_hash) and not (self.economy and gw in self.convicted):
            self._open("challengeAvailability",
                       (e.receipt.abi(), e.receipt.sig, e.prev_head, e.header.abi(), list(e.later)),
                       e.header.device_id, e.header.counter)

    # ------------------------------------------------------------------ challenge lifecycle

    def _open(self, fn, args, dev, counter):
        kind = {"challengeCustody": "custody", "notice": "notice", "challengeAvailability": "availability"}[fn]
        self.stats[kind] += 1
        exclusive = self.economy and kind != "availability"
        if exclusive:
            self.open[dev] = "pending"

        def opened(ok, evs, ts):
            cid = next((a["id"] for name, a in evs if name == "ChallengeOpened"), None)
            if cid is None:
                if exclusive:
                    self.open.pop(dev, None)
                return
            self.challenges[cid] = (kind, dev, counter, ts)
            if exclusive:
                self.open[dev] = cid
            self.sim.at(ts + self.window + 1, self._finalize, cid)

        self.port.submit(fn, args, opened)

    def _finalize(self, cid):
        if self.port.ledger.status.get(cid) == OPEN:
            self.stats["finalize"] += 1
            self.port.submit("finalize", (cid,))

    def _on_ledger(self, sender, fn, args, ok, evs, ts):
        for name, a in evs:
            if name in ("Convicted", "EquivocationProven"):
                self.convicted.add(a["gateway"])
            elif name == "ChallengeResolved" and a["id"] in self.challenges:
                _, dev, _, _ = self.challenges[a["id"]]
                if self.open.get(dev) == a["id"]:
                    del self.open[dev]
                    r = self.deferred.pop(dev, None)
                    if r is not None and a["status"] != CONVICTED:
                        self._check_custody(self.gateway_of[dev], r)


class Auditor:
    """Reads only the ledger-confirmed evidence store. Raises an unattributed SILENCE alarm when a device's
    anchored head stops advancing for longer than its heartbeat allows."""

    def __init__(self, sim, store, devices, silence_after, period=10):
        self.sim, self.store, self.devices = sim, store, list(devices)
        self.silence_after, self.period = silence_after, period
        self.start = sim.now
        self.alarms = {}  # dev -> index into history of the alarm for the current stall
        self.history = []  # [dev, raised_ts, cleared_ts or None]: an auditor knows the device is silent meanwhile
        sim.after(period, self._tick)

    def _last_progress(self, dev):
        return self.store.progress.get(dev, (0, self.start))[1]

    def _tick(self):
        now = self.sim.now
        for dev in self.devices:
            stalled = now - self._last_progress(dev) > self.silence_after
            if stalled and dev not in self.alarms:
                self.alarms[dev] = len(self.history)
                self.history.append([dev, now, None])
            elif not stalled and dev in self.alarms:
                self.history[self.alarms.pop(dev)][2] = now
        self.sim.after(self.period, self._tick)
