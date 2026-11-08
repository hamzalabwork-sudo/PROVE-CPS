"""Batch scheduling in isolation (minimal-batch stabbing): the cost side of the cost-detection frontier.

The honest gateway's batch count depends only on receipt times and deadline classes, so it can be computed
exactly without running the protocol. `stabbing` replays the rule Gateway._schedule/_fire implements (it gave
the same batch count, 13 = 13, as the Gateway in a full honest trial on HAI test1 attack 0, 2026-10-31).
`fixed_interval` is what a Merkle-batching system (B3/B5) must use to give the same per-event deadline
guarantee without a committed policy: one batch every (tau_min - delta).
"""
import heapq
import math


def stabbing(receipts, tau, delta):
    """Greedy earliest-deadline interval stabbing.

    receipts: iterable of (receipt_time, class) in time order; tau: {class: deadline offset}.
    Returns the list of batch times. Optimal: no schedule meeting every deadline uses fewer batches.
    """
    batches = []
    pending = []                  # min-heap of deadlines of receipted, unanchored events
    for t, k in receipts:
        while pending and pending[0] - delta < t:
            fire = pending[0] - delta
            batches.append(fire)  # one batch covers every event receipted up to `fire`
            pending.clear()
        heapq.heappush(pending, math.ceil(t) + tau[k])
    if pending:
        batches.append(pending[0] - delta)
    return batches


def fixed_interval(t_start, t_end, tau_min, delta):
    period = tau_min - delta
    return math.ceil((t_end - t_start) / period)


def receipts_from_replay(rep, policy, t0=0, d_gw=0.005, start=0, end=None):
    """(receipt_time, 'full'|'digest') for every event of a replay segment, as the gateway sees them."""
    end = rep.duration if end is None else end
    out = []
    for off, dev, f, payload in rep.events:
        if start <= off < end:
            ts = t0 + (off - start)
            out.append((ts + d_gw, "full" if policy.requires_full(f, ts) else "digest"))
    return out
