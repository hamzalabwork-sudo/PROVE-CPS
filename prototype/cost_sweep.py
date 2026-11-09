"""Equal-guarantee cost comparisons on the full HAI test traces (both splits, 79 h).

1. Two-tier Merkle batching (B7). The gateway keeps two trees: a fast tier for the events it deems critical,
   anchored when the earliest of them nears tau_FULL, and a slow tier for the rest, anchored when the earliest nears
   tau_DIGEST. It meets the same per-class deadlines as PROVE-CPS, but the tier is the gateway's choice and nothing
   binds it, so putting a critical event in the slow tier and later dropping its payload is A4, undetectable.
   PROVE-CPS closes a single batch that also takes every pending DIGEST head, which saves slow-tier anchors.
2. The FULL share. The cost advantage over fixed-interval Merkle batching (B3) comes from policy selectivity, so it
   shrinks as more events are FULL. Two sweeps:
     random     each event is FULL with probability f, independently: FULL events spread evenly in time
                (the pessimistic case for batching)
     envelope   the committed policy with a narrower envelope margin: FULL events cluster in excursions, as in the
                plant (policy_sweep.py)
3. The FULL deadline tau_FULL under the committed policy (tau_sweep).
Gas per call from measure_gas.py: anchor 48,086 (PROVE-CPS), root-only Merkle contract 47,762 (B3, B7).

Usage: python cost_sweep.py [out.json]
"""
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from policy_sweep import is_full  # noqa: E402
from provecps import hai  # noqa: E402
from provecps.schedule import fixed_interval, stabbing  # noqa: E402

GAS_ANCHOR, GAS_MERKLE = 48086, 47762
TAU_FULL, TAU_DIGEST, DELTA = 30, 300, 3.0
FRACTIONS = [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2]
MARGINS = [200, 100, 50, 25, 0, -25, -50]   # permille beyond the envelope (default policy: 50)
STEP = 900
TAUS = [5, 10, 20, 30, 60, 120, 300]   # deadline sweep under the committed policy


def costs(reps, label_of, tau_full=TAU_FULL):
    """Batches of PROVE-CPS (one two-class stabbing schedule), of B7 (two independent tiers) and of B3."""
    two = b7 = b3 = n = full = 0
    hours = 0.0
    for rep in reps:
        rc = [(t + 0.005, "full" if label_of(rep, i, f) else "digest") for i, (t, _, f, _) in enumerate(rep.events)]
        two += len(stabbing(rc, {"full": tau_full, "digest": TAU_DIGEST}, DELTA))
        fast = [(t, k) for t, k in rc if k == "full"]
        slow = [(t, k) for t, k in rc if k == "digest"]
        b7 += len(stabbing(fast, {"full": tau_full}, DELTA)) + len(stabbing(slow, {"digest": TAU_DIGEST}, DELTA))
        b3 += fixed_interval(0, rep.duration, tau_full, DELTA)
        hours += rep.duration / 3600
        n += len(rc)
        full += sum(k == "full" for _, k in rc)
    g = {"provecps": two * GAS_ANCHOR / hours, "B7_two_tier": b7 * GAS_MERKLE / hours, "B3": b3 * GAS_MERKLE / hours}
    return {"full_pct": 100 * full / n, "gas_per_h": g, "batches_per_h": {"provecps": two / hours, "B7": b7 / hours,
            "B3": b3 / hours}, "saving_vs_B3_pct": 100 * (1 - g["provecps"] / g["B3"]),
            "vs_B7_pct": 100 * (g["provecps"] / g["B7_two_tier"] - 1)}


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else None
    reps = [hai.build(s) for s in ("test1", "test2")]
    res = {"tau_full": TAU_FULL, "tau_digest": TAU_DIGEST, "delta": DELTA}
    res["policy"] = costs(reps, lambda rep, i, f: is_full(f, 50, STEP))
    print("committed policy", json.dumps(res["policy"]))
    res["random"] = []
    for frac in FRACTIONS:
        rng = random.Random(7)
        marks = {id(rep): [rng.random() < frac for _ in rep.events] for rep in reps}
        r = costs(reps, lambda rep, i, f: marks[id(rep)][i])
        r["fraction"] = frac
        res["random"].append(r)
        print(f"random  f={100*frac:5.1f}%  saving vs B3 {r['saving_vs_B3_pct']:5.1f}%  vs B7 {r['vs_B7_pct']:+5.1f}%")
    res["envelope"] = []
    for m in MARGINS:
        r = costs(reps, lambda rep, i, f: is_full(f, m, STEP))
        r["margin_permille"] = m
        res["envelope"].append(r)
        print(f"margin {m:4d}  FULL {r['full_pct']:5.2f}%  saving vs B3 {r['saving_vs_B3_pct']:5.1f}%  "
              f"vs B7 {r['vs_B7_pct']:+5.1f}%")
    res["tau_sweep"] = []
    for tau in TAUS:
        r = costs(reps, lambda rep, i, f: is_full(f, 50, STEP), tau)
        r["tau_full"] = tau
        res["tau_sweep"].append(r)
        print(f"tau_full {tau:4d}  saving vs B3 {r['saving_vs_B3_pct']:5.1f}%  vs B7 {r['vs_B7_pct']:+5.1f}%")
    if out:
        Path(out).write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
