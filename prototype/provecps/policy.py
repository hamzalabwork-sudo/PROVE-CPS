"""Selection policy: the off-chain twin of Registry.requiresFull (insight I3).

A policy is a list of rules over device-signed integer features; an event is FULL if any rule matches.
Versions activate by the event's device-signed timestamp, so a gateway cannot pick the version.
"""
from dataclasses import dataclass
from enum import IntEnum


class Op(IntEnum):  # same order as Registry.Op
    GE = 0
    LE = 1
    EQ = 2
    NE = 3


@dataclass(frozen=True)
class Rule:
    feature: int
    op: Op
    threshold: int

    def matches(self, features) -> bool:
        if self.feature >= len(features):
            return False
        x = features[self.feature]
        return {Op.GE: x >= self.threshold, Op.LE: x <= self.threshold,
                Op.EQ: x == self.threshold, Op.NE: x != self.threshold}[self.op]

    def as_tuple(self):
        return (self.feature, int(self.op), self.threshold)


class Policy:
    """Ordered policy versions: [(activation_unix_s, [Rule, ...]), ...]."""

    def __init__(self):
        self.versions: list[tuple[int, list[Rule]]] = []

    def add(self, activation: int, rules: list[Rule]):
        if self.versions and activation <= self.versions[-1][0]:
            raise ValueError("policy activations must increase")
        self.versions.append((activation, list(rules)))

    def requires_full(self, features, timestamp: int) -> bool:
        for activation, rules in reversed(self.versions):
            if activation <= timestamp:
                return any(r.matches(features) for r in rules)
        return False
