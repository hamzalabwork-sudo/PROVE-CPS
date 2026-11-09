"""v3 evaluation numbers: robustness runs and seed confidence intervals (no hand copying).

Usage (from experiments/results, after gunzip -k *.jsonl.gz):
  python numbers_v3.py matrix_v3.jsonl robust_v3.jsonl seeds_v3.jsonl > numbers_v3.json

Required events: suppressed events on witnessed devices whose evidence the policy requires: every FULL event, and
DIGEST events under truncating strategies (A1, A3, A7, A9). Under A2 and A8 a suppressed DIGEST event ends up
covered, which is compliant. A required event succeeds when it is attributed (a conviction names it).
"""
import json
import math
import statistics as st
import sys
from collections import Counter, defaultdict

TRUNC = {"A1", "A3", "A7", "A9"}


def load(path):
    with open(path) as f:
        return [json.loads(line) for line in f]


def required(t, r):
    s = t["strategy"]
    return r["witnessed"] and (r["full"] or s in TRUNC)


def stats(trials):
    """Aggregate a set of trials of one strategy and variant."""
    req = att = 0
    det_ok = det_n = attr_ok = attr_n = 0
    slack_d, slack_a, det_max = [], [], []
    oc = Counter()
    for t in trials:
        for r in t["rows"]:
            if r["witnessed"]:
                oc[r["outcome"]] += 1
            if not required(t, r):
                continue
            req += 1
            att += r["outcome"] == "attributed"
            if r.get("d_det") is not None:
                det_n += 1
                det_ok += r["d_det"] <= r["bound_d"]
                slack_d.append(r["bound_d"] - r["d_det"])
                det_max.append(r["d_det"])
            if r["outcome"] == "attributed" and r.get("d_attr") is not None:
                attr_n += 1
                attr_ok += r["d_attr"] <= r["bound_a"]
                slack_a.append(r["bound_a"] - r["d_attr"])
    hon = [t for t in trials if t["strategy"].startswith("honest")]
    out = dict(trials=len(trials), convicted=sum(bool(t["gateway_convicted"]) for t in trials),
               required=req, attributed=att, witnessed_outcomes=dict(oc),
               det_within=f"{det_ok}/{det_n}", attr_within=f"{attr_ok}/{attr_n}",
               det_max=max(det_max) if det_max else None,
               min_slack_det=round(min(slack_d), 3) if slack_d else None,
               min_slack_attr=round(min(slack_a), 3) if slack_a else None,
               bound_d_full=max((r["bound_d"] for t in trials for r in t["rows"] if r["full"]), default=None))
    if hon:
        out["challenges"] = dict(sum((Counter(t["challenges"]) for t in hon), Counter()))
        out["resolutions"] = dict(sum((Counter(t["resolutions"]) for t in hon), Counter()))
    return out


def ci95(xs):
    """Mean and 95% t-interval half-width over seeds."""
    n = len(xs)
    m = st.mean(xs)
    if n < 2:
        return dict(n=n, mean=m, half=None)
    t975 = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776, 6: 2.571, 7: 2.447, 8: 2.365, 9: 2.306, 10: 2.262}.get(n, 1.96)
    return dict(n=n, mean=round(m, 4), half=round(t975 * st.stdev(xs) / math.sqrt(n), 4),
                min=round(min(xs), 4), max=round(max(xs), 4))


def main():
    matrix, robust, seeds = (load(p) for p in sys.argv[1:4])
    out = {"errors": sum("error" in t for t in matrix + robust + seeds)}

    # robustness: per strategy and variant
    g = defaultdict(list)
    for t in robust:
        g[(t["strategy"], t.get("variant", ""))].append(t)
    out["robust"] = {f"{s}|{v}": stats(T) for (s, v), T in sorted(g.items())}

    # seeds: seed 0 is the strict v3 matrix, seeds 1-9 the repeats
    by_seed = defaultdict(lambda: defaultdict(list))
    for t in matrix:
        if t.get("policy", "strict") == "strict":
            by_seed[0][t["strategy"]].append(t)
    for t in seeds:
        by_seed[int(t["variant"].split("=")[1])][t["strategy"]].append(t)
    per_seed = {}
    for seed, strat in sorted(by_seed.items()):
        per_seed[seed] = {s: stats(T) for s, T in strat.items()}
    metrics = defaultdict(list)
    for seed, S in per_seed.items():
        for s, v in S.items():
            if v["required"]:
                metrics[f"{s}.attr_rate"].append(v["attributed"] / v["required"])
                metrics[f"{s}.convicted"].append(v["convicted"])
            if v["min_slack_det"] is not None:
                metrics[f"{s}.min_slack_det"].append(v["min_slack_det"])
                metrics[f"{s}.det_max"].append(v["det_max"])
        hon = [t for s, T in by_seed[seed].items() if s.startswith("honest") for t in T]
        metrics["honest_all.convicted"].append(sum(bool(t["gateway_convicted"]) for t in hon))
        metrics["honest_all.late"].append(sum(t["resolutions"].get("late", 0) for t in hon))
    out["seeds"] = {k: ci95(v) for k, v in sorted(metrics.items())}
    out["seeds_count"] = len(per_seed)
    out["seed_trials"] = sum(len(T) for S in by_seed.values() for T in S.values())

    # non-frameability over every v3 honest trial
    hon = [t for t in matrix + robust + seeds if t["strategy"].startswith("honest")]
    n, c = len(hon), sum(bool(t["gateway_convicted"]) for t in hon)
    out["honest_all_v3"] = dict(trials=n, convicted=c, rule_of_three_pct=round(300 / n, 2) if not c else None)
    # every detected or attributed required event of a suppression strategy vs its bound, all v3 logs. The bounds
    # are per-event guarantees of the strict dispute policy; economy promises attribution per gateway (one open
    # dispute per device), so later events of a device under A6 can be detected after their own bound.
    ATT = {"A1", "A2", "A3", "A4", "A7", "A8", "A9"}
    d_ok = d_n = a_ok = a_n = 0
    for t in matrix + robust + seeds:
        if t["strategy"] not in ATT or t.get("policy", "strict") != "strict":
            continue
        for r in t["rows"]:
            if not required(t, r):
                continue
            if r.get("d_det") is not None:
                d_n += 1
                d_ok += r["d_det"] <= r["bound_d"]
            if r["outcome"] == "attributed" and r.get("d_attr") is not None:
                a_n += 1
                a_ok += r["d_attr"] <= r["bound_a"]
    out["bounds_all_v3"] = dict(detected_within=f"{d_ok}/{d_n}", attributed_within=f"{a_ok}/{a_n}")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
