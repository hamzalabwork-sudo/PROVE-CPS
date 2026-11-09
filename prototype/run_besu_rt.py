"""End-to-end trials in real time on the 4-validator Besu QBFT testbed, with real network faults.

Each lane is one trial: a fresh Registry, 65 devices replaying one HAI attack window at 1x speed, the gateway, a
witness and the auditor (the same agents as the simulator). Every party has its own RPC endpoint:
  gateway  -> relay container gw-uplink-<lane> (socat to validator 1); `tc netem loss 100%` inside the relay cuts
              the gateway's uplink for real, so it can neither submit nor read the chain until the cut heals
  witness  -> validator 2         ground truth (scoring) -> validator 3
Faults (scenario keys):
  cut=O        cut the gateway's uplink with netem at the start of the attack window for O s; its plant LAN
               link is cut in the same window (emulated: devices and gateway share this process)
  isolate4=1   validator 4 is isolated with netem for the whole trial (f = 1 of n = 4)
  wan=MS       every validator gets MS ms of netem delay (+-10%) for the whole trial
Delta_L is measured on every transaction (block timestamp minus the time it was sent), and the achievability bound
is evaluated with the largest Delta_L observed in the trial.

Usage: python run_besu_rt.py --out ../experiments/results/besu_rt_v4.jsonl --lanes "0:honest:3:cut=120" ...
  lane spec  <lane>:<strategy>:<split/attack, e.g. test1/3>:<scenario>
"""
import argparse
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from provecps import crypto, hai  # noqa: E402
from provecps.besu_rt import ChainView, RTSim, deploy, setup_batch  # noqa: E402
from provecps.device import Device  # noqa: E402
from provecps.gateway import Gateway  # noqa: E402
from provecps.harness import Params, score, strategies, summarize  # noqa: E402
from provecps.ledger import LedgerPort, load_artifact  # noqa: E402
from provecps.policy import Policy  # noqa: E402
from provecps.sim import Link, Outages  # noqa: E402
from provecps.store import EvidenceStore  # noqa: E402
from provecps.witness import Auditor, Witness  # noqa: E402

NODES = {1: "http://127.0.0.1:8545", 2: "http://127.0.0.1:8546", 3: "http://127.0.0.1:8547"}
VALIDATORS = ["besu-node1", "besu-node2", "besu-node3", "besu-node4"]
IMAGE = "provecps-netem:1"
NET = "provecps-besu_qbft"


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def netem_on_validator(name, spec):
    """Apply (spec) or clear (None) a netem qdisc in a validator's network namespace from a sidecar."""
    cmd = f"tc qdisc del dev eth0 root 2>/dev/null; {'tc qdisc add dev eth0 root netem ' + spec if spec else 'true'}"
    return sh("docker", "run", "--rm", "--net", f"container:{name}", "--cap-add", "NET_ADMIN", IMAGE, "sh", "-c", cmd)


def start_relay(lane):
    name, port = f"gw-uplink-{lane}", 18540 + lane
    sh("docker", "rm", "-f", name)
    r = sh("docker", "run", "-d", "--name", name, "--network", NET, "--cap-add", "NET_ADMIN", "-p",
           f"127.0.0.1:{port}:{port}", IMAGE, "socat", f"TCP-LISTEN:{port},fork,reuseaddr", "TCP:172.31.27.11:8545")
    assert r.returncode == 0, r.stderr
    time.sleep(2)
    return name, f"http://127.0.0.1:{port}"


def cut(relay, on):
    if on:
        return sh("docker", "exec", relay, "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "100%")
    return sh("docker", "exec", relay, "tc", "qdisc", "del", "dev", "eth0", "root")


def run_lane(lane, strat_name, split, attack, scenario, out, lock, stop_after=0):
    P = Params(warmup=120, tail=300)
    rep = hai.build(split)
    abi, bytecode = load_artifact()
    seed = lambda who: crypto.Signer.from_seed(f"provecps-rt/{lane}/{time.time_ns()}/{who}")  # noqa: E731
    admin, gws, wit = seed("admin"), seed("gateway"), seed("witness")
    reg = deploy(NODES[1], admin, abi, bytecode, P.W, P.bond)
    devices_ids = list(range(1, len(rep.tags) + 1))
    keys = {i: crypto.Signer.from_seed(f"provecps-sim/dev{i}").address for i in devices_ids}
    policy = Policy()
    act = int(time.time()) + 8
    calls = [("registerGateway", (gws.address,))] + [("registerDevice", (i, keys[i], gws.address)) for i in devices_ids]
    calls.append(("setPolicy", ([r.as_tuple() for r in hai.POLICY_RULES], act)))
    setup_batch(NODES[1], admin, abi, reg, calls)
    policy.add(act, hai.POLICY_RULES)
    dom = crypto.domain_separator(20271, reg)

    relay, relay_url = start_relay(lane)
    sim = RTSim()
    v_gw = ChainView(sim, relay_url, abi, reg, {gws.address: gws}, "gateway")
    v_wit = ChainView(sim, NODES[2], abi, reg, {wit.address: wit}, "witness")
    v_true = ChainView(sim, NODES[3], abi, reg, {}, "truth")

    w0, w1 = rep.attacks[attack]
    seg0, seg1 = max(0, w0 - P.warmup), min(rep.duration, w1 + P.tail)
    base = max(time.time() + 15, act + 2)
    T = lambda off: base + (off - seg0)  # noqa: E731
    A0, A1 = T(w0), T(w1)
    end_gen = T(seg1)
    end = end_gen + P.W + P.tau_digest + 120
    if stop_after:     # smoke test: stop early
        end = min(end, time.time() + stop_after)
    strategy, partition, targets = strategies(P, rep.boiler, A0, A1, frozenset(rep.boiler - rep.witnessed))[strat_name]
    O = int(scenario.get("cut", 0))
    lan = Outages([(A0, A0 + O)] if O else [])
    store = EvidenceStore()
    gw = Gateway(sim, gws, LedgerPort(v_gw, gws.address), dom, policy, keys, store, P.tau_full, P.tau_digest,
                 P.safety, P.reserve, strategy)
    witness = Witness(sim, LedgerPort(v_wit, wit.address), dom, keys, {i: gws.address for i in devices_ids}, store,
                      P.grace, P.notice_after, P.economy, P.notice_full, P.bond)
    auditor = Auditor(sim, store, devices_ids, silence_after=P.heartbeat + P.tau_digest + 2 * P.safety + 30)
    devs = {i: Device(i, crypto.Signer.from_seed(f"provecps-sim/dev{i}"), gws.address, dom, policy,
                      tau_max=P.tau_digest, tau_full=P.tau_full, clock_slack=P.sigma, notice_after=int(P.notice_after))
            for i in devices_ids}
    to_gw, to_dev, to_wit = Link(sim, P.d_gw, lan), Link(sim, P.d_gw, lan), Link(sim, P.d_wit)
    gen, last_f0 = {}, {}

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
        m = devs[dev].emit(int(sim.now), f, payload)
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
                to_wit.send(witness.on_checkpoint, cp)
        sim.after(P.p, checkpoints)

    def heartbeats():
        for i in devices_ids:
            f0, t = last_f0.get(i, (0, 0))
            if sim.now - t >= P.heartbeat:
                emit(i, (f0, 0, 1), b"heartbeat")
        if sim.now < end:
            sim.after(1, heartbeats)

    faults = []

    def fault(on):
        r = cut(relay, on)
        faults.append((round(time.time() - A0, 2), "cut" if on else "heal", r.returncode))

    def progress():
        print(f"[lane {lane}] t-A0={time.time() - A0:7.1f}s events={len(gen)} queue={len(sim._q)} "
              f"inbox={sim.inbox.qsize()} lag={sim.max_lag:.2f} blocks gw/wit/true={v_gw.next_block}/"
              f"{v_wit.next_block}/{v_true.next_block} rpc_err={v_gw.errors}/{v_wit.errors} "
              f"chal={sum(1 for _, n, _ in v_true.events if n == 'ChallengeOpened')}", flush=True)
        sim.after(30, progress)

    sim.at(base, progress)
    for off, dev, f, payload in rep.events:
        if seg0 <= off < seg1:
            sim.at(T(off), emit, dev, f, payload)
    sim.at(end_gen, heartbeats)
    sim.at(base, retransmit)
    sim.at(base + 0.5, checkpoints)
    if O:   # docker exec takes ~0.3 s: run it off the event loop
        sim.at(A0, lambda: threading.Thread(target=fault, args=(True,), daemon=True).start())
        sim.at(A0 + O, lambda: threading.Thread(target=fault, args=(False,), daemon=True).start())
    print(f"[lane {lane}] {strat_name} {split}/{attack} {scenario} window {A1 - A0}s, ends in {end - time.time():.0f}s",
          flush=True)
    wall = time.perf_counter()
    sim.run(end)
    wall = time.perf_counter() - wall
    for v in (v_gw, v_wit, v_true):
        v.stop()
    cut(relay, False)
    sh("docker", "rm", "-f", relay)

    incl = [(v.name, fn, ts - t) for v in (v_gw, v_wit) for fn, _, t, ts in v.inclusion]
    dl = [d for _, _, d in incl] or [0.0]
    res = score(rep, strat_name, P, v_true, store, auditor, gen, targets, A0, A1, attack, devs, gw.stats, witness,
                [max(dl)], wall, partition or bool(O))
    res.update(split=split, policy="strict", variant="", ledger="besu-rt", scenario=scenario, lane=lane,
               faults=faults, max_lag=round(sim.max_lag, 3), rpc_errors={v.name: v.errors for v in (v_gw, v_wit)},
               rejected={v.name: v.rejected for v in (v_gw, v_wit)},
               delta_l={"n": len(dl), "max": max(dl), "p50": sorted(dl)[len(dl) // 2],
                        "p99": sorted(dl)[int(0.99 * (len(dl) - 1))],
                        "by_party": {who: max([d for w, _, d in incl if w == who] or [0]) for who in ("gateway", "witness")}},
               registry=reg)
    with lock:
        with open(out, "a") as f:
            f.write(json.dumps(res) + "\n")
    print(f"[lane {lane}] done: convicted={res['gateway_convicted']} chal={res['challenges']} "
          f"res={res['resolutions']} dl_max={max(dl):.2f} lag={sim.max_lag:.2f} {json.dumps(summarize(res))}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--lanes", nargs="+", required=True)
    ap.add_argument("--isolate4", action="store_true", help="isolate validator 4 with netem during the run")
    ap.add_argument("--wan", type=int, default=0, help="netem delay (ms) on every validator during the run")
    ap.add_argument("--note", default="", help="extra scenario keys recorded with each trial, e.g. isolate4=1")
    ap.add_argument("--stop-after", type=int, default=0, help="smoke test: stop each lane after this many seconds")
    a = ap.parse_args()
    from web3 import Web3
    heights = [Web3(Web3.HTTPProvider(f"http://127.0.0.1:{8545 + k}", request_kwargs={"timeout": 5})).eth.block_number
               for k in range(4)]
    assert max(heights) - min(heights) <= 3, f"validators out of sync: {heights}"   # a stalled node skews Delta_L
    print("validator heights", heights, flush=True)
    if a.isolate4:
        print("isolate node4:", netem_on_validator("besu-node4", "loss 100%").returncode, flush=True)
    if a.wan:
        for v in VALIDATORS:
            print("wan", v, netem_on_validator(v, f"delay {a.wan}ms {a.wan // 10}ms").returncode, flush=True)
    lock = threading.Lock()
    threads = []
    try:
        for spec in a.lanes:
            lane, strat, sa, scen = spec.split(":")
            split, att = sa.split("/")
            scenario = dict(kv.split("=") for kv in (scen + "," + a.note).split(",") if kv)
            if a.isolate4:
                scenario["isolate4"] = "1"
            if a.wan:
                scenario["wan"] = str(a.wan)
            t = threading.Thread(target=run_lane, args=(int(lane), strat, split, int(att), scenario, a.out, lock,
                                                         a.stop_after))
            t.start()
            threads.append(t)
            time.sleep(5)
        for t in threads:
            t.join()
    finally:   # clear only the faults this process applied (a phase script may own a longer-lived fault)
        for v in VALIDATORS if a.wan else (["besu-node4"] if a.isolate4 else []):
            netem_on_validator(v, None)
    print("BESU_RT_DONE", flush=True)


if __name__ == "__main__":
    main()
