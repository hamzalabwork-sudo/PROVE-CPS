"""HAI 23.05 replay: one device per non-constant gateway-view tag, report-by-exception with a heartbeat.

Signed policy features per event (integers, so the contract can evaluate them):
  f0  envelope position in permille: 0 = commissioning low, 1000 = commissioning high
  f1  step since the device's previous report, in permille of the envelope
  f2  1 for an integrity heartbeat (no change), else 0
The envelope is fixed at commissioning from training data (no information from the attack splits).
"""
import pickle
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from .policy import Op, Rule

ROOT = Path(__file__).resolve().parents[2]
HAI = ROOT / "data/hai/hai-23.05"
CACHE = ROOT / "experiments/cache"
PROFILE = ROOT / "experiments/data/profile_hai.json"

# FULL when a signal leaves its commissioning envelope by 5%, or steps across >= 90% of it in one report
# (in practice a discrete state change: pump trip, valve flip). On test1 this selects 0.33% of events,
# 16.6x more often inside attack windows than outside, and at least one event in every attack window.
# A 20% step threshold was rejected: noisy vibration channels cross it on almost every report.
POLICY_RULES = [Rule(0, Op.GE, 1050), Rule(0, Op.LE, -50), Rule(1, Op.GE, 900)]
TRAIN = ("train1", "train2", "train3", "train4")  # train1 alone gives a too-narrow envelope (17% FULL)


@dataclass
class Replay:
    tags: list            # device i (1-based id) is tags[i-1]
    witnessed: set        # device ids whose signal the controller (HAIEnd) also observes
    boiler: set           # device ids in the attacked process (P1 boiler + its DCS loops)
    events: list          # (offset_s, device_id, features tuple, payload bytes), time-ordered
    attacks: list         # [(start_offset_s, end_offset_s)] from the labels
    duration: int
    start: str


def _calibrate(train_files, q=(0.001, 0.999)):
    frames = [pd.read_csv(f, index_col=0) for f in train_files]
    df = pd.concat(frames)
    lo, hi = df.quantile(q[0]), df.quantile(q[1])
    active = [c for c in df.columns if df[c].std() > 0 and hi[c] > lo[c]]
    return active, lo[active], hi[active]


def build(split="test1", deadband=0.01, heartbeat=60, train=TRAIN, use_cache=True) -> Replay:
    key = CACHE / f"hai_{split}_db{deadband}_hb{heartbeat}_{'-'.join(train)}.pkl"
    if use_cache and key.exists():
        return Replay(**pickle.loads(key.read_bytes()))
    import json
    tags, lo, hi = _calibrate([HAI / f"hai-{t}.csv" for t in train])
    df = pd.read_csv(HAI / f"hai-{split}.csv", index_col=0)
    labels = pd.read_csv(HAI / f"label-{split}.csv", index_col=0)["label"].to_numpy()
    x = df[tags].to_numpy(dtype=float)
    span = (hi - lo).to_numpy()
    low = lo.to_numpy()
    n, m = x.shape
    events = []
    last_val = x[0].copy()
    last_t = np.full(m, -10**9)
    thr = deadband * span
    for t in range(n):
        row = x[t]
        moved = np.abs(row - last_val) > thr
        beat = (t - last_t) >= heartbeat
        fire = np.nonzero(moved | beat | (t == 0))[0]
        for j in fire:
            v = row[j]
            f0 = int(round(1000 * (v - low[j]) / span[j]))
            f1 = int(round(1000 * abs(v - last_val[j]) / span[j]))
            hb = int(not moved[j] and t > 0)
            payload = f"{tags[j]},{t},{v:.6f}".encode()
            events.append((t, int(j) + 1, (f0, f1, hb), payload))
            last_val[j], last_t[j] = v, t
    attacks, inside = [], False
    for t, lab in enumerate(labels):
        if lab and not inside:
            s, inside = t, True
        elif not lab and inside:
            attacks.append((s, t))
            inside = False
    if inside:
        attacks.append((s, n))
    prof = json.loads(PROFILE.read_text())
    witnessed_tags = {p["hai"] for p in prof["overlap"]["pairs"]}
    rep = Replay(
        tags=tags,
        witnessed={i + 1 for i, t in enumerate(tags) if t in witnessed_tags},
        boiler={i + 1 for i, t in enumerate(tags) if t.startswith("P1_") or t.startswith("x100")},
        events=events, attacks=attacks, duration=n, start=str(df.index[0]))
    CACHE.mkdir(parents=True, exist_ok=True)
    key.write_bytes(pickle.dumps(vars(rep)))
    return rep


if __name__ == "__main__":
    from .policy import Policy
    r = build()
    pol = Policy()
    pol.add(0, POLICY_RULES)
    full = [e for e in r.events if pol.requires_full(e[2], 1)]
    in_att = lambda t: any(s <= t < e for s, e in r.attacks)  # noqa: E731
    n_att = sum(in_att(e[0]) for e in r.events)
    f_att = sum(in_att(e[0]) for e in full)
    print(f"devices={len(r.tags)} witnessed={len(r.witnessed)} boiler={len(r.boiler)} "
          f"boiler&witnessed={len(r.boiler & r.witnessed)} duration={r.duration}s attacks={len(r.attacks)}")
    print(f"events={len(r.events)} ({len(r.events)/r.duration:.2f}/s), FULL={len(full)} ({100*len(full)/len(r.events):.2f}%)")
    print(f"attack-window events={n_att}, of which FULL={f_att} ({100*f_att/max(n_att,1):.1f}%); "
          f"FULL rate inside attacks {f_att/max(n_att,1):.3f} vs outside {(len(full)-f_att)/max(len(r.events)-n_att,1):.3f}")
    print("unwitnessed boiler devices:", sorted(r.tags[i - 1] for i in r.boiler - r.witnessed))
