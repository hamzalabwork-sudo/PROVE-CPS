"""Aggregate attack-matrix trials into summary tables.

  T1  PROVE-CPS per strategy and witness regime: outcome shares, detection/attribution delays vs the bounds,
      gateway convictions, dispute count and gas (strict vs economy witness policy)
  T2  headline matrix: attack x system, share of suppressed events attributed / flagged / covered / undetected
  T3  non-frameability: convictions of honest gateways (all honest trials, incl. real partitions)

Usage: python analyze.py matrix.jsonl [out.json]
"""
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from provecps.baselines import Ctx, evaluate  # noqa: E402

OUTCOMES = ["attributed", "late", "covered", "flagged-unattributed", "undetected", "n/a"]
DL_MAX = 2.555  # max of the 50 warm PureChain Delta_L samples (2554.9 ms) that every trial draws from
DISPUTE_FNS = ("challengeCustody", "notice", "challengeAvailability", "respondCoverage", "respondPayload",
               "finalize", "proveEquivocation")


def pct(c, n):
    return round(100 * c / n, 2) if n else None


def q(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))] if xs else None


def load(path):
    rows, errors = [], []
    for line in open(path):
        r = json.loads(line)
        (errors if "error" in r else rows).append(r)
    return rows, errors


def bounds(P, full, dl_max):
    """The achievability bound (same formula as harness.theorem_bounds)."""
    tau = P["tau_full"] if full else P["tau_digest"]
    d = P["notice_after"] + P["p"] + tau + P.get("sigma", 5) + dl_max + 3
    return d, d + P["W"] + dl_max + 2


def table1(trials):
    out = {}
    groups = defaultdict(list)
    for t in trials:
        groups[(t["strategy"], t.get("policy", "strict"))].append(t)
    for (strat, pol), ts in sorted(groups.items()):
        g = {"trials": len(ts), "gateway_convicted": sum(t["gateway_convicted"] for t in ts)}
        for regime, w in (("witnessed", True), ("unwitnessed", False)):
            ev = [r for t in ts for r in t["rows"] if r["witnessed"] == w]
            if not ev:
                continue
            cnt = defaultdict(int)
            for r in ev:
                cnt[r["outcome"]] += 1
            det = [r["d_det"] for r in ev if r.get("d_det") is not None]
            att = [r["d_attr"] for r in ev if r["d_attr"] is not None]
            g[regime] = {
                "events": len(ev), **{o: pct(cnt[o], len(ev)) for o in OUTCOMES if cnt[o]},
                "d_det_p50": q(det, .5), "d_det_max": max(det, default=None),
                "d_attr_p50": q(att, .5), "d_attr_max": max(att, default=None),
            }
            # attribution at gateway level (what the economy witness guarantees): the custodian is convicted on the
            # ledger and a gateway-signed receipt proves it held the event; unreceipted events never left the device.
            conv_rows = [(r, t["gateway_convicted"]) for t in ts for r in t["rows"] if r["witnessed"] == w]
            g[regime]["receipt_backed_conviction"] = pct(sum(c and r.get("receipted", False) for r, c in conv_rows), len(ev))
            g[regime]["retained_by_device"] = pct(sum(c and not r.get("receipted", True) for r, c in conv_rows), len(ev))
            if w:
                ok_d = ok_a = 0
                for t in ts:
                    for r in t["rows"]:
                        if r["witnessed"]:
                            bd, ba = bounds(t["params"], r["full"], DL_MAX)
                            ok_d += r.get("d_det") is not None and r["d_det"] <= bd
                            ok_a += r["d_attr"] is not None and r["d_attr"] <= ba
                g[regime]["det_within_thm3"] = pct(ok_d, len(det))
                g[regime]["attr_within_thm3"] = pct(ok_a, len(att))
        disp = [sum(v["n"] for k, v in t["gas"].items() if k in DISPUTE_FNS) for t in ts]
        dgas = [sum(v["gas"] for k, v in t["gas"].items() if k in DISPUTE_FNS) for t in ts]
        g["dispute_txs_per_trial_p50"] = q(disp, .5)
        g["dispute_gas_per_trial_p50"] = q(dgas, .5)
        g["anchor_gas_per_trial_p50"] = q([t["gas"].get("anchor", {}).get("gas", 0) for t in ts], .5)
        if strat == "A5":
            eq = [t["equivocation_at"] for t in ts if t["equivocation_at"] is not None]
            g["equivocation_proven"] = f"{len(eq)}/{len(ts)}"
            g["equivocation_at_max_s"] = max(eq, default=None)
        out[f"{strat} [{pol}]"] = g
    return out


def table2(trials):
    """Attack x system. PROVE-CPS from the trials (strict policy); baselines evaluated on the same events."""
    agg = defaultdict(lambda: defaultdict(int))
    for t in trials:
        if t.get("policy", "strict") != "strict" or t["strategy"].startswith("honest"):
            continue
        P = t["params"]
        ctx = Ctx(silence_after=P["heartbeat"] + P["tau_digest"] + 2 * P["safety"] + 30, p=P["p"], d_wit=P["d_wit"],
                  mmd=P["tau_digest"])
        a = t["strategy"]
        if a == "A5":
            agg[(a, "PROVE-CPS")]["attributed" if t["equivocation_at"] is not None else "undetected"] += 1
            for base, cnt in evaluate([{"witnessed": True, "ts": 0, "full": False}], a, t["window_s"], ctx).items():
                for o, n in cnt.items():
                    agg[(a, base)][o] += n
            continue
        for r in t["rows"]:
            agg[(a, "PROVE-CPS")][r["outcome"]] += 1
        for base, cnt in evaluate(t["rows"], a, t["window_s"], ctx).items():
            for o, n in cnt.items():
                agg[(a, base)][o] += n
    out = defaultdict(dict)
    for (a, sysname), cnt in agg.items():
        n = sum(cnt.values())
        out[a][sysname] = {o: pct(c, n) for o, c in cnt.items()}
    return out


def table3(trials):
    hon = [t for t in trials if t["strategy"].startswith("honest")]
    return {
        "honest_trials": len(hon),
        "honest_convictions": sum(t["gateway_convicted"] for t in hon),
        "honest_resolutions": {k: sum(t["resolutions"].get(k, 0) for t in hon) for k in ("dismissed", "late", "convicted")},
        "honest_notices": sum(t["challenges"].get("notice", 0) for t in hon),
    }


def main():
    trials, errors = load(sys.argv[1])
    res = {"trials": len(trials), "errors": len(errors), "error_samples": [e["error"][:200] for e in errors[:3]],
           "T1": table1(trials), "T2": table2(trials), "T3": table3(trials)}
    print(json.dumps(res, indent=1))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
