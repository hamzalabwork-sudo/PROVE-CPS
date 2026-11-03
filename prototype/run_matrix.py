"""Run the attack matrix in parallel: each worker owns a private Anvil (restarted every few trials to bound its
memory) and appends one JSON line per trial. Re-running skips trials already in the output (resumable).

Usage: python run_matrix.py --out results.jsonl [--splits test1,test2] [--strategies all] [--policies strict,economy]
                            [--workers 8] [--anvil ~/.local/foundry-v1.8.4/anvil]
"""
import argparse
import json
import multiprocessing as mp
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

RESTART_EVERY = 6
SLOW = {"A1": 0, "A3": 1, "A7": 2, "A1-unw": 3, "A3-unw": 4}  # schedule long trials first


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_anvil(binary):
    """Start a private Anvil on an OS-assigned free port and verify we are talking to *it* (on a shared server
    another service may already listen on any fixed port)."""
    import urllib.request
    for _ in range(5):
        port = free_port()
        p = subprocess.Popen([binary, "--host", "127.0.0.1", "--port", str(port), "--chain-id", "31337",
                              "--gas-price", "0", "--base-fee", "0", "--no-mining", "--order", "fifo", "--accounts", "1",
                              "--gas-limit", "1000000000", "--hardfork", "paris", "--silent"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        body = json.dumps({"jsonrpc": "2.0", "method": "web3_clientVersion", "params": [], "id": 1}).encode()
        for _ in range(200):
            if p.poll() is not None:
                break  # exited (port taken between probe and bind): try another port
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{port}", body, {"Content-Type": "application/json"})
                ver = json.loads(urllib.request.urlopen(req, timeout=1).read())["result"]
                if ver.startswith("anvil/") and p.poll() is None:
                    return p, port
                break
            except Exception:
                time.sleep(0.05)
        p.kill()
    raise RuntimeError("could not start a private anvil")


def parse_variant(v):
    """'O=240,W=300' -> {'O': 240, 'W': 300}; '' -> {}."""
    return {k: float(x) if "." in x else int(x) for k, x in (kv.split("=") for kv in v.split(",") if kv)}


def worker(wid, jobs, out, binary, lock):
    from provecps import hai
    from provecps.harness import PURECHAIN_CSV, Params, run_trial
    from provecps.ledger import Anvil, empirical_delays
    delays = empirical_delays(PURECHAIN_CSV)
    reps, proc, n, port = {}, None, 0, None
    for split, attack, strat, policy, variant in iter(jobs.get, None):
        if proc is None or n % RESTART_EVERY == 0:
            if proc:
                proc.terminate()
                proc.wait()
            proc, port = start_anvil(binary)
        n += 1
        rep = reps.get(split) or reps.setdefault(split, hai.build(split))
        try:
            P = Params(economy=policy == "economy", **parse_variant(variant))
            res = run_trial(rep, attack, strat, P, Anvil(f"http://127.0.0.1:{port}"), delays)
            res.update(split=split, policy=policy, variant=variant)
            line = json.dumps(res)
        except Exception as e:  # record and keep going; a crashed trial must be visible, not silently missing
            line = json.dumps({"split": split, "attack": attack, "strategy": strat, "policy": policy,
                               "variant": variant, "error": repr(e)})
        with lock:
            with open(out, "a") as f:
                f.write(line + "\n")
        print(f"[w{wid}] {split} attack {attack} {strat} {policy} {variant} done", flush=True)
    if proc:
        proc.terminate()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--splits", default="test1,test2")
    ap.add_argument("--strategies", default="all")
    ap.add_argument("--policies", default="strict,economy")
    ap.add_argument("--attacks", default="all")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--anvil", default=os.path.expanduser("~/.local/foundry-v1.8.4/anvil"))
    ap.add_argument("--variants", default="", help="';'-separated Params overrides, e.g. 'O=60,W=300;O=360,W=300'")
    a = ap.parse_args()
    from provecps import hai
    from provecps.harness import Params, strategies
    names = list(strategies(Params(), set(), 0, 0)) if a.strategies == "all" else a.strategies.split(",")
    done = set()
    if os.path.exists(a.out):
        for line in open(a.out):
            r = json.loads(line)
            if "error" not in r:
                done.add((r["split"], r["attack"], r["strategy"], r["policy"], r.get("variant", "")))
    todo = []
    for split in a.splits.split(","):
        n_att = len(hai.build(split).attacks)
        idx = range(n_att) if a.attacks == "all" else [int(x) for x in a.attacks.split(",")]
        for i in idx:
            for s in names:
                for pol in a.policies.split(","):
                    if pol == "economy" and s in ("honest", "honest-partition", "A5"):
                        continue  # the witness policy does not change these runs
                    for var in a.variants.split(";"):
                        if (split, i, s, pol, var) not in done:
                            todo.append((split, i, s, pol, var))
    todo.sort(key=lambda j: (SLOW.get(j[2], 9), j[0], j[1]))
    print(f"{len(done)} done, {len(todo)} to run on {a.workers} workers", flush=True)
    jobs, lock = mp.Queue(), mp.Lock()
    for j in todo:
        jobs.put(j)
    for _ in range(a.workers):
        jobs.put(None)
    ps = [mp.Process(target=worker, args=(w, jobs, a.out, a.anvil, lock)) for w in range(a.workers)]
    for p in ps:
        p.start()
    for p in ps:
        p.join()
    print("MATRIX DONE", flush=True)


if __name__ == "__main__":
    main()
