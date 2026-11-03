"""Baseline archetypes B1-B6 on the same HAI traces and attack windows as PROVE-CPS.

Each archetype is reduced to the strongest auditor its evidence admits. To make failures structural rather
than an artefact of a weak implementation, every baseline is granted:
  - device-signed events (no forgery), integrity heartbeats, and an auditor that raises a SILENCE alarm when a
    device's committed stream stalls (same rule and threshold as the PROVE-CPS auditor);
  - in the '+W' variant, the same independent witness path PROVE-CPS uses (the device reports its own
    progress to the witness every p seconds).
What no baseline has is the combination PROVE-CPS adds: custody receipts (I2), an on-chain NOTICE with a
deadline (I4), and a committed selection policy (I3).

Outcome per suppressed event (same vocabulary as harness.score):
  attributed            evidence that convicts the gateway (adjudicated on-chain, or self-contained off-chain)
  flagged-unattributed  someone can tell something is wrong, but not prove who did it
  covered               the event's existence is committed; its content was lost without any violation
  undetected            nothing distinguishes the attack from honest operation
"""
from dataclasses import dataclass

BASELINES = {
    "B1": "full on-chain log (gateway posts every event)",
    "B2": "per-event hash anchoring",
    "B3": "Merkle batching (gateway-built batches of event hashes)",
    "B4": "gateway-sequenced batches",
    "B5": "device-signed hash chain anchored by the gateway (no receipts, no witness, no policy)",
    "B6": "transparency log with signed inclusion promises and gossip (no ledger)",
}


@dataclass
class Ctx:
    silence_after: float   # auditor stall threshold (same as PROVE-CPS auditor)
    p: float               # witness checkpoint period
    d_wit: float
    mmd: float             # B6 maximum merge delay (the log's inclusion promise)


def _truncating(attack):
    return attack in ("A1", "A3", "A7", "A1-unw", "A3-unw")


def outcome(base, witness, attack, ev, stream_gap, ctx):
    """Outcome and flag delay for one suppressed event.

    ev: dict with 'ts', 'full'. stream_gap: seconds the device's committed stream is silent around this event
    under the attack (inf for truncation, the window length for a mid-stream drop, 0 otherwise).
    """
    a = attack.removesuffix("-unw")
    silence = stream_gap > ctx.silence_after
    gw_signed_promise = base == "B6"
    if a == "A5":
        # A ledger gives one view by construction (equivocation is moot); a gossip log detects a split view
        # only if the device can gossip around the log, and then the two signed tree heads convict.
        return ("attributed", ctx.p + ctx.d_wit) if base == "B6" and witness else ("n/a", None)
    if a == "A6":
        # Late inclusion: only B6 has a promised deadline (MMD) whose violation is self-evident evidence. That
        # proves lateness, like a PROVE-CPS Late verdict; it is not a conviction for omission. (The auditor is
        # idealized: it sees every promise, whereas a PROVE-CPS witness samples receipts once per period p.)
        return ("late", ctx.mmd + ctx.p) if gw_signed_promise and witness else ("undetected", None)
    if a == "A4":
        # The payload of a FULL event is deleted. No baseline binds a selection policy, so nothing was violated.
        return ("covered", None) if base in ("B5", "B6") else ("undetected", None)
    if a == "A2":
        if base in ("B5", "B6"):
            return ("covered", None)          # a device chain/log entry commits to the event; content is lost
        return ("flagged-unattributed", ctx.silence_after) if silence else ("undetected", None)
    if _truncating(a):
        receipted = a == "A1"
        if base == "B6" and witness and receipted:
            # An inclusion promise plus a signed tree head without the entry after MMD: self-contained proof.
            return ("attributed", ctx.mmd + ctx.p)
        if witness:
            # The witness sees the device ahead of what was committed, but without custody receipts or an
            # on-chain notice the gateway can always claim it never received the events.
            return ("flagged-unattributed", ctx.p + ctx.d_wit)
        return ("flagged-unattributed", ctx.silence_after) if silence else ("undetected", None)
    raise ValueError(attack)


def evaluate(trial_rows, attack, window_s, ctx):
    """trial_rows: the per-event rows of a PROVE-CPS trial (same suppressed set) -> {(base, +W): counts}."""
    out = {}
    gap = float("inf") if _truncating(attack.removesuffix("-unw")) else window_s
    for base in BASELINES:
        for witness in (False, True):
            if base == "B6" and not witness:
                label = "B6-isolated"
            else:
                label = base + ("+W" if witness else "")
            counts = {}
            for r in trial_rows:
                # Theorem 1 regime: the '+W' path exists only for devices that have a witness
                o, _ = outcome(base, witness and r["witnessed"], attack, r, gap, ctx)
                counts[o] = counts.get(o, 0) + 1
            out[label] = counts
    return out
