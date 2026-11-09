"""v4 numbers: component ablation, gateway crash with state loss, real-time Besu runs with real network faults,
the NOTICE storm, and the equal-guarantee cost sweeps. Every figure quoted in the paper for these experiments is
computed here from the logs in this directory (gzipped or not).

Usage: python numbers_v4.py [out.json]
"""
import gzip
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRUNC = {"A1", "A3", "A7", "A9"}


def load(name):
    for p in (HERE / name, HERE / (name + ".gz")):
        if p.exists():
            op = gzip.open if p.suffix == ".gz" else open
            with op(p, "rt") as f:
                return [r for r in map(json.loads, f) if "error" not in r]
    return []


def required(r, strat):
    """Events whose evidence the policy requires on witnessed devices (as in numbers_v3)."""
    return r["witnessed"] and (r["full"] or strat in TRUNC)


def gas_total(t):
    return sum(g["gas"] for g in t["gas"].values())


def txs(t):
    return sum(g["n"] for g in t["gas"].values())


def ablation(out):
    rows = load("ablation_v4.jsonl")
    ref = {(t["split"], t["attack"], t["strategy"]): t for t in load("matrix_v3.jsonl")
           if t.get("policy") == "strict" and t.get("variant", "") == ""}
    res = {}
    by = defaultdict(list)
    for t in rows:
        by[(t["variant"], t["strategy"])].append(t)
    for (var, strat), ts in sorted(by.items()):
        c = Counter(r["outcome"] for t in ts for r in t["rows"] if required(r, strat))
        c_ref = Counter(r["outcome"] for t in ts for r in ref[(t["split"], t["attack"], strat)]["rows"]
                        if required(r, strat))
        e = {"trials": len(ts), "outcomes": dict(c), "outcomes_full_protocol": dict(c_ref),
             "convicted_trials": sum(t["gateway_convicted"] for t in ts)}
        if strat == "honest":
            refs = [ref[(t["split"], t["attack"], "honest")] for t in ts]
            e.update(
                disputes=sum(sum(t["challenges"].values()) for t in ts),
                disputes_full_protocol=sum(sum(t["challenges"].values()) for t in refs),
                txs=sum(txs(t) for t in ts), txs_full_protocol=sum(txs(t) for t in refs),
                gas=sum(gas_total(t) for t in ts), gas_full_protocol=sum(gas_total(t) for t in refs),
                max_buffer=max(t["device_max_buffer"] for t in ts),
                max_buffer_full_protocol=max(t["device_max_buffer"] for t in refs),
                seconds=sum(t["window_s"] + t["params"]["warmup"] + t["params"]["tail"] for t in ts))
            e["tx_ratio"] = e["txs"] / e["txs_full_protocol"]
            e["gas_ratio"] = e["gas"] / e["gas_full_protocol"]
        if strat == "A9":
            rs = [r for t in ts for r in t["rows"] if r["witnessed"] and r["d_det"] is not None]
            e["max_over_bound_d"] = max(r["d_det"] - r["bound_d"] for r in rs)
            e["min_over_bound_d"] = min(r["d_det"] - r["bound_d"] for r in rs)
            e["max_over_bound_a"] = max((r["d_attr"] - r["bound_a"] for r in rs if r["d_attr"] is not None), default=None)
            e["events_over_bound_d"] = sum(r["d_det"] > r["bound_d"] for r in rs)
            e["events"] = len(rs)
        res[f"{var} {strat}"] = e
    out["ablation"] = res


def crash(out):
    res = {}
    by = defaultdict(list)
    for t in load("crash_v4.jsonl"):
        by[t["params"]["crash_dur"]].append(t)
    for dur, ts in sorted(by.items()):
        rs = [r for t in ts for r in t["rows"]]
        res[str(int(dur))] = {
            "trials": len(ts), "convicted_trials": sum(t["gateway_convicted"] for t in ts),
            "challenges": sum(sum(t["challenges"].values()) for t in ts),
            "dismissed": sum(t["resolutions"]["dismissed"] for t in ts),
            "late": sum(t["resolutions"]["late"] for t in ts),
            "convicted": sum(t["resolutions"]["convicted"] for t in ts),
            "outcomes": dict(Counter(r["outcome"] for r in rs)),
            "recovered_open": sum(t.get("gateway", {}).get("recovered_open", 0) for t in ts),
            "max_d_det_witnessed": max((r["d_det"] for r in rs if r["witnessed"] and r["d_det"] is not None),
                                       default=None),
        }
    out["crash"] = res


def besu_rt(out):
    res = []
    for t in load("besu_rt_v4.jsonl"):
        req = [r for r in t["rows"] if required(r, t["strategy"])]
        res.append({
            "strategy": t["strategy"], "split": t["split"], "attack": t["attack"], "scenario": t["scenario"],
            "convicted": t["gateway_convicted"], "challenges": t["challenges"], "resolutions": t["resolutions"],
            "required": len(req), "required_outcomes": dict(Counter(r["outcome"] for r in req)),
            "all_outcomes": dict(Counter(r["outcome"] for r in t["rows"])),
            "within_bound_d": all(r["d_det"] <= r["bound_d"] for r in t["rows"] if r["witnessed"] and r["d_det"] is not None),
            "within_bound_a": all(r["d_attr"] <= r["bound_a"] for r in t["rows"] if r["witnessed"] and r["d_attr"] is not None),
            "min_slack_d": min((r["bound_d"] - r["d_det"] for r in t["rows"] if r["witnessed"] and r["d_det"] is not None),
                               default=None),
            "delta_l": t["delta_l"], "max_lag": t["max_lag"], "faults": t["faults"], "rejected": t["rejected"],
        })
    out["besu_rt"] = res


def storm(out):
    out["notice_storm"] = load("notice_storm_v4.jsonl")


def cost(out):
    p = HERE / "cost_sweep_v4.json"
    if p.exists():
        c = json.loads(p.read_text())
        out["cost"] = {"policy": c["policy"],
                       "random": [(r["fraction"], round(r["saving_vs_B3_pct"], 1), round(r["vs_B7_pct"], 1))
                                  for r in c["random"]],
                       "envelope": [(r["margin_permille"], round(r["full_pct"], 2), round(r["saving_vs_B3_pct"], 1),
                                     round(r["vs_B7_pct"], 1)) for r in c["envelope"]]}


def main():
    out = {}
    for f in (ablation, crash, besu_rt, storm, cost):
        f(out)
    s = json.dumps(out, indent=1, default=str)
    print(s)
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(s)


if __name__ == "__main__":
    main()
