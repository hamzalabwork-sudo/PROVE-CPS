"""Attack harness: replay one HAI attack window through devices -> gateway -> ledger, with a witness and an
auditor, under an honest or adversarial gateway, and score every suppressed event against Definition 3.

Each trial deploys a fresh Registry on Anvil; every verdict comes from the contract. Usage:
  python -m provecps.harness --split test1 --attacks all --strategies all --out ../experiments/results/attacks_test1.jsonl
"""
import argparse
import csv
import json
import math
import time
from dataclasses import asdict, dataclass, field

from . import crypto, hai
from .device import Device
from .gateway import (Delay, Disguise, Equivocate, Gateway, Honest, MidStreamDrop, RefuseCustody, SlowWalk,
                      Stonewall, TailTruncation)
from .ledger import ROOT, Anvil, LedgerPort, SimLedger, empirical_delays
from .policy import Policy
from .sim import Link, Outages, Sim
from .store import EvidenceStore
from .witness import Auditor, GriefWitness, Witness

PURECHAIN_CSV = ROOT / "experiments/results/inclusion_latency_purechain_s28.csv"
# Ledger delay profiles replayed by SimLedger. v2 profiles use Delta_L as the paper defines it: block timestamp of
# the inclusion minus the submission time (experiments/latency/measure_inclusion.py, column ts_minus_submit_s).
LAT2 = ROOT / "experiments/results/latency_v2"
LEDGERS = {
    "poa-v1": (PURECHAIN_CSV, None, "submit_to_receipt_ms"),            # v1: 50 samples, submit -> receipt
    "poa": (LAT2 / "purechain.csv", "purechain-warm", "ts_minus_submit_s"),             # 2,000 samples
    "besu": (LAT2 / "besu.csv", "besu-idle", "ts_minus_submit_s"),
    "besu-load": (LAT2 / "besu.csv", "besu-load-25tps-2KB", "ts_minus_submit_s"),
    "besu-fault": (LAT2 / "besu.csv", "besu-1-of-4-validators-down", "ts_minus_submit_s"),  # f = 1 of n = 4
}
_DELAYS = {}


def ledger_delays(name):
    """Delta_L samples (s) of a measured ledger profile, cached per process."""
    if name not in _DELAYS:
        path, label, col = LEDGERS[name]
        with open(path, newline="") as f:
            rows = [r for r in csv.DictReader(f) if r["phase"] not in ("first", "cold")
                    and (label is None or r.get("label") == label)]
        scale = 1000 if col.endswith("_ms") else 1
        _DELAYS[name] = [float(r[col]) / scale for r in rows]
        assert _DELAYS[name], name
    return _DELAYS[name]


class SilentPort:
    """Ledger access of a corrupt witness that colludes with the gateway: it reads the ledger like everyone else
    but never submits a challenge."""

    def __init__(self, port):
        self.port, self.suppressed = port, 0

    def view(self, *a):
        return self.port.view(*a)

    def subscribe(self, cb):
        self.port.subscribe(cb)

    def submit(self, fn, args, cb=None, value=0):
        self.suppressed += 1
KIND = {0: "custody", 1: "notice", 2: "availability", 3: "notice_full"}
STATUS = {2: "dismissed", 3: "late", 4: "convicted"}


@dataclass
class Params:
    tau_full: int = 30          # anchoring deadline for FULL events (s)
    tau_digest: int = 300       # anchoring deadline for DIGEST events (s)
    safety: float = 3.0         # scheduler safety margin delta >= p99 of measured Delta_L (2.55 s)
    reserve: float = 0.0        # extra scheduler slack reserved for gateway outages
    W: int = 300                # response window W_resp (s); deployed Registry uses 300
    p: float = 10.0             # checkpoint period device -> witness
    theta: float = 5.0          # device retransmission period
    notice_after: float = 15.0  # witness posts NOTICE once a head is unreceipted this long
    heartbeat: int = 60
    d_gw: float = 0.005         # device <-> gateway one-way delay (plant LAN)
    d_wit: float = 0.05         # device -> witness one-way delay (T_w without outages)
    grace: int = 1
    sigma: int = 5              # device clock tolerance on receipt deadlines (s)
    warmup: int = 600
    tail: int = 900
    O: int = 120                # partition length for A7 and its honest control (<= O_g)
    delay_extra: int = 60       # A6: how long after the deadline the attacker anchors
    economy: bool = False       # witness dispute policy: strict (per-event Def 3) or economy (per-gateway)
    notice_full: bool = True    # v2 NOTICE-FULL + second payload path; False = v1 (ablation)
    bond: int = 0               # challenge bond (wei); the griefing experiment sets it
    grief_period: float = 10.0  # griefing witness: replay period (s)
    ledger: str = "poa"         # measured Delta_L profile replayed by the ledger (see LEDGERS)
    witnesses: int = 1          # witnesses per witnessed device (diverse, e.g. controller + network monitor)
    silent_witnesses: int = 0   # how many of them are corrupt and collude with the gateway (never challenge)
    seed: int = 0


_SIGNERS = {}


def signer(name):
    if name not in _SIGNERS:
        _SIGNERS[name] = crypto.Signer.from_seed("provecps-sim/" + name)
    return _SIGNERS[name]


def strategies(P, targets, a0, a1, unwitnessed=frozenset()):
    """name -> (strategy, real partition at a0?, targeted devices)."""
    return {
        "honest": (Honest(), False, targets),
        "A1": (TailTruncation(targets, a0), False, targets),
        "A2": (MidStreamDrop(targets, a0, a1), False, targets),
        "A3": (Stonewall(targets, a0), False, targets),
        "A4": (Disguise(targets, a0, a1), False, targets),
        "A5": (Equivocate(targets, a0, a1), False, targets),
        "A6": (Delay(targets, a0, a1, P.delay_extra), False, targets),
        "A7": (Stonewall(targets, a0), True, targets),          # stonewall timed to a real partition
        "A8": (RefuseCustody(targets, a0), False, targets),     # refuse custody, answer plain notices
        "A8-v1": (RefuseCustody(targets, a0), False, targets),  # ablation: the same attack against v1 (no NOTICE-FULL)
        "A9": (SlowWalk(targets, a0, P.notice_after - 1, P.sigma - 1), False, targets),  # worst case for Theorem 2
        "honest-partition": (Honest(), True, targets),          # same partition, honest gateway
        "honest-grief": (Honest(), False, targets),             # honest gateway vs. a challenge-flooding witness
        # Theorem 1: an attacker who knows the witness topology suppresses only devices without a witness.
        "A1-unw": (TailTruncation(unwitnessed, a0), False, unwitnessed),
        "A3-unw": (Stonewall(unwitnessed, a0), False, unwitnessed),
        "A4-unw": (Disguise(unwitnessed, a0, a1), False, unwitnessed),
    }


def run_trial(rep, attack_idx, strat_name, P: Params, chain: Anvil, delays=None):
    if delays is None:
        delays = ledger_delays(P.ledger)
    w0, w1 = rep.attacks[attack_idx]
    seg0, seg1 = max(0, w0 - P.warmup), min(rep.duration, w1 + P.tail)
    sim = Sim(chain.last_ts)
    led = SimLedger(sim, chain, delays, seed=P.seed * 1000 + attack_idx)
    admin, gws, wit = signer("admin"), signer("gateway"), signer("witness")
    reg = led.deploy(admin.address, P.W, P.bond)
    dom = crypto.domain_separator(chain.w3.eth.chain_id, reg)
    led.setup_tx(admin.address, "registerGateway", gws.address)
    devices_ids = list(range(1, len(rep.tags) + 1))
    keys = {i: signer(f"dev{i}").address for i in devices_ids}
    for i in devices_ids:
        led.setup_tx(admin.address, "registerDevice", i, keys[i], gws.address)
    policy = Policy()
    act = chain.last_ts + 1
    led.setup_tx(admin.address, "setPolicy", [r.as_tuple() for r in hai.POLICY_RULES], act)
    policy.add(act, hai.POLICY_RULES)

    base = chain.last_ts + 10
    sim.now = base - 1
    T = lambda off: base + (off - seg0)  # noqa: E731  dataset offset -> ledger time
    A0, A1 = T(w0), T(w1)
    end_gen = T(seg1)
    end = end_gen + P.W + P.tau_digest + 120

    strategy, partition, targets = strategies(P, rep.boiler, A0, A1, frozenset(rep.boiler - rep.witnessed))[strat_name]
    outs = Outages([(A0, A0 + P.O)] if partition else [])
    store = EvidenceStore()
    gw = Gateway(sim, gws, LedgerPort(led, gws.address, outs), dom, policy, keys, store,
                 P.tau_full, P.tau_digest, P.safety, P.reserve, strategy)
    # Witness 0 is the paper's witness. With silent_witnesses = s, the first s witnesses are corrupt: they receive
    # every checkpoint but never challenge, and they keep their payload copies to themselves (private store).
    wits = []
    for k in range(P.witnesses):
        acct = wit if k == 0 else signer(f"witness{k}")
        corrupt = k < P.silent_witnesses
        port = LedgerPort(led, acct.address)
        wits.append(Witness(sim, SilentPort(port) if corrupt else port, dom, keys,
                            {i: gws.address for i in devices_ids}, EvidenceStore() if corrupt else store, P.grace,
                            P.notice_after, P.economy, P.notice_full and not strat_name.endswith("-v1"), P.bond))
        chain.rpc("anvil_setBalance", [acct.address, hex(10**30)])
    witness = next((w for k, w in enumerate(wits) if k >= P.silent_witnesses), wits[0])  # reported in "witness"
    chain.rpc("anvil_setBalance", [signer("griefer").address, hex(10**30)])
    griefer = (GriefWitness(sim, LedgerPort(led, signer("griefer").address), sorted(rep.witnessed), P.bond,
                            P.grief_period) if strat_name == "honest-grief" else None)
    auditor = Auditor(sim, store, devices_ids, silence_after=P.heartbeat + P.tau_digest + 2 * P.safety + 30)
    devs = {i: Device(i, signer(f"dev{i}"), gws.address, dom, policy, tau_max=P.tau_digest, tau_full=P.tau_full, clock_slack=P.sigma,
                      notice_after=int(P.notice_after)) for i in devices_ids}
    to_gw, to_dev, to_wit = Link(sim, P.d_gw, outs), Link(sim, P.d_gw, outs), Link(sim, P.d_wit)
    gen = {}        # (dev, counter) -> (ts, full)
    last_f0 = {}

    def gw_recv(m):
        r = gw.on_event(m)
        if r is not None:
            rel = gw.release_time(r)
            if rel > sim.now:
                sim.at(rel, to_dev.send, dev_recv, r)
            else:
                to_dev.send(dev_recv, r)

    def dev_recv(r):
        devs[r.device_id].on_receipt(r, sim.now)

    def emit(dev, f, payload):
        d = devs[dev]
        m = d.emit(int(sim.now), f, payload)
        gen[(dev, m.header.counter)] = (m.header.timestamp, policy.requires_full(f, m.header.timestamp),
                                        m.header.payload_hash)
        last_f0[dev] = (f[0], sim.now)
        to_gw.send(gw_recv, m)

    def retransmit():
        for d in devs.values():
            for m, ts in list(d.unreceipted.values()):
                if ts <= sim.now - P.theta:
                    to_gw.send(gw_recv, m)
        sim.after(P.theta, retransmit)

    def checkpoints():
        for i in rep.witnessed:
            cp = devs[i].checkpoint(sim.now)
            if cp is not None:
                for w in wits:
                    to_wit.send(w.on_checkpoint, cp)
                if griefer is not None:
                    to_wit.send(griefer.on_checkpoint, cp)
        sim.after(P.p, checkpoints)

    def heartbeats():           # after the replay ends, devices keep their integrity heartbeat
        for i in devices_ids:
            f0, t = last_f0.get(i, (0, 0))
            if sim.now - t >= P.heartbeat:
                emit(i, (f0, 0, 1), b"heartbeat")
        if sim.now < end:
            sim.after(1, heartbeats)

    for off, dev, f, payload in rep.events:
        if seg0 <= off < seg1:
            sim.at(T(off), emit, dev, f, payload)
    sim.at(end_gen, heartbeats)
    sim.at(base, retransmit)
    sim.at(base + 0.5, checkpoints)
    wall = time.perf_counter()
    sim.run(end)
    wall = time.perf_counter() - wall
    res = score(rep, strat_name, P, led, store, auditor, gen, targets, A0, A1, attack_idx, devs, gw, witness,
                delays, wall, partition)
    if griefer is not None:
        mine = [(fn, st, u) for _, snd, fn, _, st, u, _ in led.log if snd == gws.address and fn != "anchor"]
        res["grief"] = {**griefer.stats, "gateway_credit_wei": led.view("credit", gws.address),
                        "gateway_answers": sum(1 for _, st, _ in mine if st == 1),
                        "gateway_answer_gas": sum(u for _, st, u in mine if st == 1)}
    return res


def theorem_bounds(P, full, dl_max):
    """Theorem 2: Delta_d <= nu + p + tau_k + sigma + Delta_L + 3 and Delta_a <= Delta_d + W_resp + Delta_L + 2
    (integer block timestamps: ceil of the deadline, the strict deadline comparison, ceil of inclusion)."""
    tau = P.tau_full if full else P.tau_digest
    d = P.notice_after + P.p + tau + P.sigma + dl_max + 3
    return d, d + P.W + dl_max + 2


def _suppressed(strat_name, gen, targets, A0, A1):
    """The events the strategy hides or delays: target events in the attack window. A4 hides only FULL ones;
    A5 hides nothing (it is scored by time to the equivocation proof); honest runs score the same set as A1."""
    if strat_name == "A5":
        return []
    out = []
    for (dev, c), (ts, full, ph) in gen.items():
        if dev in targets and A0 <= ts < A1 and (not strat_name.startswith("A4") or full):
            out.append((dev, c, ts, full, ph))
    return out


def score(rep, strat_name, P, led, store, auditor, gen, targets, A0, A1, attack_idx, devs, gw, witness, delays,
          wall, partition):
    opened, resolved = {}, {}
    equivocation = []
    convicted_ts = None
    for ts, name, a in led.events:
        if name == "ChallengeOpened":
            opened[a["id"]] = (ts, a["kind"], a["deviceId"], a["counter"])
        elif name == "ChallengeResolved":
            resolved[a["id"]] = (ts, a["status"])
        elif name == "EquivocationProven":
            equivocation.append((ts, a["deviceId"], a["counter"]))
        if name in ("Convicted", "EquivocationProven") and convicted_ts is None:
            convicted_ts = ts
    by_dev = {}
    for cid, (ts, kind, dev, c) in opened.items():
        by_dev.setdefault(dev, []).append((ts, kind, c, cid))
    cov = {}
    for dev, entries in store.by_device.items():
        cov[dev] = sorted((c, store.manifests[root][1]) for c, root, *_ in entries)
    alarms = {}
    for dev, raised, cleared in auditor.history:
        alarms.setdefault(dev, []).append((raised, cleared))

    dl_max = max(delays)
    rows = []
    for dev, c, ts, full, ph in _suppressed(strat_name, gen, targets, A0, A1):
        tau = P.tau_full if full else P.tau_digest
        t_cov = min((t for cc, t in cov.get(dev, ()) if cc >= c), default=None)
        t_ch = t_conv = t_late = None
        for ots, kind, cc, cid in sorted(by_dev.get(dev, ())):
            if (kind == 2 and cc == c) or (kind != 2 and cc >= c):
                t_ch = ots if t_ch is None else t_ch
                st = resolved.get(cid)
                if st and st[1] == 4 and t_conv is None:
                    t_conv = st[0]
                if st and st[1] == 3 and t_late is None:
                    t_late = st[0]
        # flagged by a SILENCE alarm raised after the event, or by one still active when the event was generated
        t_alarm = min((max(raised, ts) for raised, cleared in alarms.get(dev, ()) if cleared is None or cleared >= ts),
                      default=None)
        rc = devs[dev].receipt
        flagged = min((t for t in (t_ch, t_alarm) if t is not None), default=None)
        detected = min((t for t in (t_cov, t_ch) if t is not None), default=None)  # Definition 3 detection
        # A FULL event counts as covered only if its payload reached the evidence store through the gateway's own
        # obligations (custody replication or a published answer); a witness's copy does not discharge them.
        payload_ok = (not full) or store.has_payload(ph)
        outcome = ("attributed" if t_conv else "late" if t_late
                   else ("covered" if payload_ok else "payload-lost") if t_cov
                   else "flagged-unattributed" if t_alarm else "undetected")
        d = lambda t: None if t is None else t - ts  # noqa: E731
        rows.append({
            "dev": dev, "witnessed": dev in rep.witnessed, "full": full, "outcome": outcome, "payload_ok": payload_ok,
            "receipted": rc is not None and rc.counter >= c,  # a gateway-signed custody receipt exists for e
            "d_det": d(detected), "d_flag": d(flagged), "d_ch": d(t_ch), "d_alarm": d(t_alarm),
            "d_attr": d(t_conv), "d_cov": d(t_cov),
            # Theorem 2 (achievability), exactly as stated: nu + p + tau_k + sigma + Delta_L + 3 s of rounding
            "bound_d": theorem_bounds(P, full, dl_max)[0],
            "bound_a": theorem_bounds(P, full, dl_max)[1],
        })
    gas = {}
    for ts, sender, fn, args, status, used, evs in led.log:
        g = gas.setdefault(fn, {"n": 0, "gas": 0, "reverted": 0})
        g["n"] += 1
        g["gas"] += used
        g["reverted"] += int(status != 1)
    n_events = len(gen)
    return {
        "attack": attack_idx, "window_s": A1 - A0, "strategy": strat_name, "partition": partition,
        "params": asdict(P), "events": n_events, "suppressed": len(rows), "rows": rows,
        "first_challenge_rel": (min(v[0] for v in opened.values()) - A0) if opened else None,
        "gateway_convicted": convicted_ts is not None, "convicted_at": None if convicted_ts is None else convicted_ts - A0,
        "equivocation_proofs": len(equivocation),
        "equivocation_at": min((e[0] for e in equivocation), default=A0 - 1) - A0 if equivocation else None,
        "challenges": {KIND[k]: sum(1 for v in opened.values() if v[1] == k) for k in KIND},
        "resolutions": {STATUS[s]: sum(1 for v in resolved.values() if v[1] == s) for s in STATUS},
        "alarms": len(auditor.history), "gas": gas, "batches": gw.stats["batches"], "leaves": gw.stats["leaves"],
        "device_max_buffer": max(d.stats["max_buffer"] for d in devs.values()),
        "witness": witness.stats, "wall_s": round(wall, 2),
    }


def summarize(res):
    rows = res["rows"]
    out = {}
    for w in (True, False):
        rs = [r for r in rows if r["witnessed"] == w]
        if not rs:
            continue
        cnt = {}
        for r in rs:
            cnt[r["outcome"]] = cnt.get(r["outcome"], 0) + 1
        mx = lambda k: max((r[k] for r in rs if r[k] is not None), default=None)  # noqa: E731
        out["witnessed" if w else "unwitnessed"] = {
            "n": len(rs), **cnt, "max_d_det": mx("d_det"), "max_d_flag": mx("d_flag"), "max_d_attr": mx("d_attr"),
        }
        if w:  # Theorem 3 makes a claim only for devices with a witness
            out["witnessed"]["within_bound"] = all(r["d_det"] <= r["bound_d"] for r in rs if r["d_det"] is not None)
            out["witnessed"]["within_bound_a"] = all(r["d_attr"] <= r["bound_a"] for r in rs if r["d_attr"] is not None)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test1")
    ap.add_argument("--attacks", default="all")
    ap.add_argument("--strategies", default="all")
    ap.add_argument("--out", required=True)
    ap.add_argument("--rpc", default="http://127.0.0.1:8645")
    ap.add_argument("--warmup", type=int, default=600)
    ap.add_argument("--tail", type=int, default=900)
    ap.add_argument("--economy", action="store_true")
    a = ap.parse_args()
    rep = hai.build(a.split)
    P = Params(warmup=a.warmup, tail=a.tail, economy=a.economy)
    chain = Anvil(a.rpc)
    delays = ledger_delays(P.ledger)
    idx = range(len(rep.attacks)) if a.attacks == "all" else [int(x) for x in a.attacks.split(",")]
    names = list(strategies(P, set(), 0, 0)) if a.strategies == "all" else a.strategies.split(",")
    with open(a.out, "a") as f:
        for i in idx:
            for s in names:
                res = run_trial(rep, i, s, P, chain, delays)
                res["split"] = a.split
                f.write(json.dumps(res) + "\n")
                f.flush()
                print(f"[{a.split} attack {i:2d} {s:16s}] events={res['events']:6d} suppressed={res['suppressed']:5d} "
                      f"convicted={res['gateway_convicted']!s:5} at={res['convicted_at']} equiv={res['equivocation_at']} "
                      f"chal={res['challenges']} res={res['resolutions']} alarms={res['alarms']} wall={res['wall_s']}s  "
                      f"{json.dumps(summarize(res))}", flush=True)


if __name__ == "__main__":
    main()
