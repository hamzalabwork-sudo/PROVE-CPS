"""Every headline number of the v2 evaluation, recomputed from matrix_v2.jsonl (no hand copying)."""
import json, sys
from collections import Counter, defaultdict
sys.path.insert(0, "../../prototype")
rows = [json.loads(l) for l in open(sys.argv[1])]
S = lambda s, pol="strict": [t for t in rows if t["strategy"] == s and t.get("policy", "strict") == pol]
q = lambda v, p: sorted(v)[min(len(v) - 1, int(p * len(v)))] if v else None
out = {"trials": len(rows), "errors": sum("error" in t for t in rows)}
# delays per strategy and class (strict, witnessed, outcome-relevant events)
tab = {}
for s in ("A1", "A2", "A3", "A4", "A7", "A8", "A9"):
    for full in (True, False):
        R = [r for t in S(s) for r in t["rows"] if r["witnessed"] and r["full"] == full]
        det = [r["d_det"] for r in R if r.get("d_det") is not None]
        att = [r["d_attr"] for r in R if r.get("outcome") == "attributed" and r.get("d_attr") is not None]
        if s == "A8" and not full:
            continue  # A8 is scored on FULL events (DIGEST events are answered and committed)
        if det:
            tab[f"{s}-{'F' if full else 'D'}"] = dict(n=len(R), det_p50=q(det, .5), det_max=max(det),
                attr_max=max(att) if att else None, bound_d=max(r["bound_d"] for r in R),
                bound_a=max(r["bound_a"] for r in R), det_ok=all(r["d_det"] <= r["bound_d"] for r in R if r.get("d_det") is not None),
                attr_ok=all(r["d_attr"] <= r["bound_a"] for r in R if r.get("outcome") == "attributed" and r.get("d_attr") is not None))
out["delays"] = tab
# totals over witnessed events, strict, A1-A4,A7,A8F,A9
tot_d = tot_a = 0
for s in ("A1", "A2", "A3", "A4", "A7", "A8", "A9"):
    for t in S(s):
        for r in t["rows"]:
            if not r["witnessed"] or (s == "A8" and not r["full"]): continue
            if r.get("d_det") is not None: tot_d += 1
            if r.get("outcome") == "attributed": tot_a += 1
out["events_det"], out["events_attr"] = tot_d, tot_a
# slack (min bound - observed)
out["min_slack_det"] = min(v["bound_d"] - v["det_max"] for v in tab.values())
# A5 equivocation
eq = [t["equivocation_at"] for t in S("A5") if t["equivocation_at"] is not None]
out["A5"] = dict(proven=len(eq), trials=len(S("A5")), max_s=max(eq) if eq else None)
# honest trials: never convicted
hon = [t for t in rows if t["strategy"].startswith("honest")]
out["honest"] = dict(trials=len(hon), convicted=sum(bool(t["gateway_convicted"]) for t in hon),
    challenges=dict(sum((Counter(t["challenges"]) for t in hon), Counter())),
    resolutions=dict(sum((Counter(t["resolutions"]) for t in hon), Counter())))
# conviction counts per strategy
out["convicted"] = {f"{t0}|{p}": f"{sum(bool(t['gateway_convicted']) for t in S(t0,p))}/{len(S(t0,p))}"
                    for t0, p in sorted({(t['strategy'], t.get('policy','strict')) for t in rows})}
# A8 / A8-v1 FULL fate
for s in ("A8", "A8-v1"):
    out[s] = dict(Counter(r["outcome"] for t in S(s) for r in t["rows"] if r["witnessed"] and r["full"]))
# A6 lateness
lat = [r for t in S("A6") for r in t["rows"] if r["witnessed"]]
out["A6"] = dict(Counter(r["outcome"] for r in lat))
# per-call gas (avg) over all trials
g = defaultdict(lambda: [0, 0])
for t in rows:
    for fn, v in t["gas"].items():
        if v["n"] - v.get("reverted", 0) > 0:
            g[fn][0] += v["gas"]; g[fn][1] += v["n"]
out["gas_per_call"] = {fn: round(a / n) for fn, (a, n) in g.items()}
# dispute cost per trial (strict vs economy, A1)
for p in ("strict", "economy"):
    T = S("A1", p)
    tx = sorted(sum(v["n"] for fn, v in t["gas"].items() if fn != "anchor") for t in T)
    gs = sorted(sum(v["gas"] for fn, v in t["gas"].items() if fn != "anchor") for t in T)
    out[f"A1_disputes_{p}"] = dict(tx_p50=q(tx, .5), gas_p50=q(gs, .5))
print(json.dumps(out, indent=1))
