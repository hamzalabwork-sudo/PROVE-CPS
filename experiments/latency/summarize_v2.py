"""Summarize the v2 latency campaigns (Delta_L = block timestamp - submission time; the registry's clock).

Usage: python summarize_v2.py experiments/results/latency_v2/besu.csv [purechain.csv ...]
Prints per-label n, p50/p99/max of Delta_L, the share of samples above 3 s (one QBFT block period + 1 s),
submit->receipt p50/p99/max, and the worst forward/backward block-timestamp skew seen by the client.
"""
import csv
import json
import sys


def q(v, p):
    return v[min(len(v) - 1, int(p * len(v)))]


out = {}
for f in sys.argv[1:]:
    rows = [r for r in csv.DictReader(open(f)) if r["phase"] not in ("first", "cold")]
    for lab in sorted({r["label"] for r in rows}):
        R = [r for r in rows if r["label"] == lab]
        d = sorted(float(r["ts_minus_submit_s"]) for r in R)
        s = sorted(float(r["submit_to_receipt_ms"]) / 1000 for r in R)
        ahead = max(float(r["ts_minus_receipt_s"]) for r in R)
        out[lab] = dict(n=len(d), dl_p50=round(q(d, .5), 2), dl_p99=round(q(d, .99), 2), dl_max=round(d[-1], 2),
                        dl_min=round(d[0], 2), over3s=sum(x > 3 for x in d),
                        s2r_p50=round(q(s, .5), 2), s2r_p99=round(q(s, .99), 2), s2r_max=round(s[-1], 2),
                        ts_ahead_of_receipt_max=round(ahead, 3))
print(json.dumps(out, indent=1))
