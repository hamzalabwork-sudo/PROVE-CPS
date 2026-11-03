"""Cost-detection frontier (Proposition 4) on the full HAI test traces.

For each FULL-event deadline tau_full (the detection bound that matters for incident evidence):
  PROVE-CPS   greedy stabbing with two classes (FULL: tau_full, DIGEST: tau_digest)
  one-class   greedy stabbing with every event at tau_full (what deadline batching gives without a policy)
  B3/B5       fixed-interval Merkle batching that meets tau_full for every event: one batch per (tau_full - delta)
  B2 / B1     one transaction per event (cost independent of tau)
Gas per call from measure_gas.py (EVM paris; identical on Besu, PureChain and Anvil).

Usage: python pareto.py [out.json]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from provecps import hai  # noqa: E402
from provecps.policy import Policy  # noqa: E402
from provecps.schedule import fixed_interval, receipts_from_replay, stabbing  # noqa: E402

GAS = {"anchor": 47825, "merkle": 47762, "hash": 46166, "full": 95068}
DELTA = 3.0
TAU_DIGEST = 300
TAUS = [5, 10, 15, 20, 30, 45, 60, 90, 120, 180, 300]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else None
    pol = Policy()
    pol.add(0, hai.POLICY_RULES)
    rows = []
    for split in ("test1", "test2"):
        rep = hai.build(split)
        rc = receipts_from_replay(rep, pol)
        hours = rep.duration / 3600
        n_ev = len(rc)
        n_full = sum(k == "full" for _, k in rc)
        for tau in TAUS:
            two = len(stabbing(rc, {"full": tau, "digest": max(tau, TAU_DIGEST)}, DELTA))
            one = len(stabbing(rc, {"full": tau, "digest": tau}, DELTA))
            fixed = fixed_interval(0, rep.duration, tau, DELTA)
            rows.append({
                "split": split, "tau_full": tau, "hours": round(hours, 2), "events": n_ev, "full_events": n_full,
                "batches_per_h": {"provecps": two / hours, "one_class": one / hours, "fixed": fixed / hours},
                "gas_per_h": {"provecps": two * GAS["anchor"] / hours, "one_class": one * GAS["anchor"] / hours,
                              "B3_fixed": fixed * GAS["merkle"] / hours,
                              "B2": n_ev * GAS["hash"] / hours, "B1": n_ev * GAS["full"] / hours},
            })
            g = rows[-1]["gas_per_h"]
            print(f"{split} tau_full={tau:4d}s  batches/h: PROVE-CPS {two/hours:7.1f}  one-class {one/hours:7.1f}  "
                  f"fixed {fixed/hours:7.1f}  | gas/h: PROVE-CPS {g['provecps']/1e6:6.2f}M  B3 {g['B3_fixed']/1e6:6.2f}M  "
                  f"B2 {g['B2']/1e6:8.1f}M  B1 {g['B1']/1e6:8.1f}M  | saving vs B3 {100*(1-g['provecps']/g['B3_fixed']):5.1f}%")
    if out:
        Path(out).write_text(json.dumps({"delta": DELTA, "tau_digest": TAU_DIGEST, "gas": GAS, "rows": rows}, indent=1))


if __name__ == "__main__":
    main()
