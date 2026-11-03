"""Device-side cost of PROVE-CPS on the real HAI event stream: runs the exact Device code a field device runs.

Measures, per event: emit (hash, chain step, EIP-712 digest, secp256k1 signature), receipt verification
(signature recovery + chain check), and checkpoint assembly; plus peak buffer and process RSS.
Receipts are produced by a co-located honest gateway, but only device-side work is timed.

Usage: python bench_device.py [n_events=20000] [out.json]
On a Raspberry Pi copy prototype/ and the cached replay (experiments/cache/hai_test1_*.pkl), or pass a
synthetic stream with --synthetic if the dataset is not on the device.
"""
import json
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from eth_hash.auto import keccak  # noqa: E402

from provecps import crypto  # noqa: E402
from provecps.device import Device  # noqa: E402
from provecps.messages import Receipt  # noqa: E402
from provecps.policy import Policy  # noqa: E402


def rss_mb():
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return r / 1024 if platform.system() == "Linux" else r / 2**20
    except ImportError:
        try:
            import psutil
            return psutil.Process().memory_info().peak_wset / 2**20
        except Exception:
            return None


def stream(n, synthetic):
    if synthetic:
        for i in range(n):
            yield i, 1, (500 + i % 7, i % 3, 0), b"P1_FT01Z,%d,1234.567890" % i
        return
    from provecps import hai
    rep = hai.build("test1")
    for k, e in enumerate(rep.events[:n]):
        yield e


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 20000
    out = next((a for a in sys.argv[1:] if a.endswith(".json")), None)
    synthetic = "--synthetic" in sys.argv
    from provecps import hai
    pol = Policy()
    pol.add(0, hai.POLICY_RULES)
    dom = crypto.domain_separator(31337, "0x" + "11" * 20)
    gw = crypto.Signer.from_seed("bench-gw")
    devs = {}
    t_emit, t_rcpt, t_cp = [], [], []
    for off, dev, f, payload in stream(n, synthetic):
        d = devs.get(dev)
        if d is None:
            d = devs[dev] = Device(dev, crypto.Signer.from_seed(f"bench-dev{dev}"), gw.address, dom, pol, tau_max=300)
        ts = 1_700_000_000 + off
        t0 = time.perf_counter_ns()
        m = d.emit(ts, f, payload)
        t1 = time.perf_counter_ns()
        dl = ts + 30
        r = Receipt(dev, m.head.counter, m.head.head, dl,
                    gw.sign(crypto.receipt_digest(dom, dev, m.head.counter, m.head.head, dl)))
        t2 = time.perf_counter_ns()
        ok = d.on_receipt(r, ts)
        t3 = time.perf_counter_ns()
        assert ok
        t_emit.append(t1 - t0)
        t_rcpt.append(t3 - t2)
        if m.head.counter % 10 == 0:
            t4 = time.perf_counter_ns()
            d.checkpoint()
            t_cp.append(time.perf_counter_ns() - t4)

    def q(xs):
        xs = sorted(xs)
        return {"p50_us": round(xs[len(xs) // 2] / 1e3, 1), "p99_us": round(xs[int(len(xs) * .99)] / 1e3, 1),
                "mean_us": round(statistics.fmean(xs) / 1e3, 1)}

    from eth_keys.backends import get_backend
    res = {
        "host": platform.node(), "machine": platform.machine(), "python": platform.python_version(),
        "ecc_backend": type(get_backend()).__name__, "events": len(t_emit), "devices": len(devs),
        "emit": q(t_emit), "receipt_verify": q(t_rcpt), "checkpoint": q(t_cp) if t_cp else None,
        "peak_rss_mb": rss_mb(), "synthetic": synthetic,
        "max_device_buffer": max(d.stats["max_buffer"] for d in devs.values()),
    }
    tot = res["emit"]["mean_us"] + res["receipt_verify"]["mean_us"]
    res["max_events_per_s_one_core"] = round(1e6 / tot)
    print(json.dumps(res, indent=2))
    if out:
        Path(out).write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
