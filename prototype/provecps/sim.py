"""Discrete-event simulation core: clock, event queue, lossy links with outage windows."""
import heapq
import itertools
from bisect import bisect_right


class Sim:
    def __init__(self, t0: float):
        self.now = t0
        self._q = []
        self._seq = itertools.count()

    def at(self, t: float, fn, *args):
        heapq.heappush(self._q, (max(t, self.now), next(self._seq), fn, args))

    def after(self, dt: float, fn, *args):
        self.at(self.now + dt, fn, *args)

    def run(self, until: float):
        q = self._q
        while q and q[0][0] <= until:
            t, _, fn, args = heapq.heappop(q)
            self.now = t
            fn(*args)
        self.now = until


class Outages:
    """Sorted, non-overlapping [start, end) windows during which a party or link is down."""

    def __init__(self, windows=()):
        self.windows = sorted(windows)
        self._starts = [s for s, _ in self.windows]

    def down(self, t: float) -> bool:
        i = bisect_right(self._starts, t) - 1
        return i >= 0 and t < self.windows[i][1]

    def up_at(self, t: float) -> float:
        """Earliest time >= t at which the party is up."""
        i = bisect_right(self._starts, t) - 1
        return self.windows[i][1] if i >= 0 and t < self.windows[i][1] else t


class Link:
    """One-way message path. Messages sent while the link is down are lost; senders retransmit."""

    def __init__(self, sim: Sim, delay: float, outages: Outages | None = None):
        self.sim, self.delay, self.outages = sim, delay, outages or Outages()
        self.sent = self.lost = 0

    def send(self, handler, *args) -> bool:
        self.sent += 1
        if self.outages.down(self.sim.now):
            self.lost += 1
            return False
        self.sim.after(self.delay, handler, *args)
        return True
