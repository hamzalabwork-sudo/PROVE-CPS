"""Policy sensitivity and the envelope-aware attacker (reviewer W8), on both HAI test splits (52 attacks).

For each committed policy (envelope margin m, step threshold s, both in permille of the commissioning envelope):
  full_pct      share of all events the policy marks FULL
  enrichment    FULL rate inside attack windows / FULL rate outside
  recall_*      attack windows with >= 1 FULL event on boiler devices (any / witnessed only): the windows in which
                a suppressing gateway must give up FULL content or be convicted
  gas_h         PROVE-CPS gas per hour with every FULL event anchored within 30 s (two-class stabbing);
                saving_pct is relative to fixed-interval Merkle batching with the same 30 s guarantee (B3/B5)
An *envelope-aware* attacker knows the public policy and keeps every observed signal inside the envelope; the
"steps only" row is what remains for him, and "none" is the fully stealthy case: no FULL event at all, so only the
DIGEST evidence remains (the existence of every event, and its signed header with the envelope position f0 at
1 permille resolution and 1% deadband).

Usage: python policy_sweep.py [out.json]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from provecps import hai  # noqa: E402
from provecps.schedule import fixed_interval, stabbing  # noqa: E402

GAS_ANCHOR, GAS_MERKLE = 48086, 47762
TAU_FULL, TAU_DIGEST, DELTA = 30, 300, 3.0
INF = 10**9
MARGINS = [0, 25, 50, 100, 200]   # permille beyond the envelope (paper policy: 50 = 5%)
STEPS = [500, 700, 900, INF]      # permille step (paper policy: 900)


def is_full(f, m, s):
    f0, f1, hb = f
    return (m < INF and (f0 >= 1000 + m or f0 <= -m)) or (s < INF and f1 >= s)


def evaluate(reps, m, s):
    ev = ev_in = full = full_in = 0
    windows = rec_any = rec_wit = 0
    gas = hours = fixed = 0.0
    for rep in reps:
        inside = lambda t: any(a <= t < b for a, b in rep.attacks)  # noqa: E731
        hit_any, hit_wit = set(), set()
        rc = []
        for t, dev, f, _ in rep.events:
            fl = is_full(f, m, s)
            ins = inside(t)
            ev += 1
            ev_in += ins
            full += fl
            full_in += fl and ins
            if fl and dev in rep.boiler:
                for k, (a, b) in enumerate(rep.attacks):
                    if a <= t < b:
                        hit_any.add(k)
                        if dev in rep.witnessed:
                            hit_wit.add(k)
            rc.append((t + 0.005, "full" if fl else "digest"))
        windows += len(rep.attacks)
        rec_any += len(hit_any)
        rec_wit += len(hit_wit)
        gas += len(stabbing(rc, {"full": TAU_FULL, "digest": TAU_DIGEST}, DELTA)) * GAS_ANCHOR
        fixed += fixed_interval(0, rep.duration, TAU_FULL, DELTA) * GAS_MERKLE
        hours += rep.duration / 3600
    out_rate = (full - full_in) / max(ev - ev_in, 1)
    return {"margin_permille": None if m >= INF else m, "step_permille": None if s >= INF else s,
            "full_pct": round(100 * full / ev, 3),
            "enrichment": round((full_in / max(ev_in, 1)) / out_rate, 1) if out_rate else None,
            "recall_any": f"{rec_any}/{windows}", "recall_witnessed": f"{rec_wit}/{windows}",
            "gas_h_M": round(gas / hours / 1e6, 3), "saving_pct": round(100 * (1 - gas / fixed), 1)}


def main():
    reps = [hai.build(s) for s in ("test1", "test2")]
    rows = [evaluate(reps, m, s) for m in MARGINS for s in STEPS]
    rows.append(evaluate(reps, INF, 900) | {"note": "envelope-aware attacker: steps only"})
    rows.append(evaluate(reps, INF, INF) | {"note": "fully stealthy attacker: no FULL event"})
    for r in rows:
        print(r)
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(json.dumps({"tau_full": TAU_FULL, "delta": DELTA, "rows": rows}, indent=1))


if __name__ == "__main__":
    main()
