"""Protocol messages exchanged off-chain (device -> gateway, gateway -> device, device -> witness)."""
from dataclasses import dataclass, field

from . import crypto


@dataclass(frozen=True, slots=True)
class Header:
    """Signed event header e_{i,c} = (i, c, t, f, h(payload)). Everything the policy reads is in here."""
    device_id: int
    counter: int
    timestamp: int
    features: tuple
    payload_hash: bytes

    def hash(self) -> bytes:
        return crypto.event_hash(self.device_id, self.counter, self.timestamp, self.features, self.payload_hash)

    def abi(self):
        return (self.device_id, self.counter, self.timestamp, list(self.features), self.payload_hash)


@dataclass(frozen=True, slots=True)
class SignedHead:
    """Device Checkpoint signature over (i, c, H_{i,c}); commits to the device's whole prefix (insight I1)."""
    device_id: int
    counter: int
    head: bytes
    sig: bytes

    def abi(self):
        return (self.device_id, self.counter, self.head)


@dataclass(frozen=True, slots=True)
class EventMsg:
    header: Header
    payload: bytes
    prev_head: bytes
    head: SignedHead


@dataclass(frozen=True, slots=True)
class Receipt:
    """Gateway-signed transfer of custody for every event of the device up to `counter` (insight I2)."""
    device_id: int
    counter: int
    head: bytes
    deadline: int
    sig: bytes

    def abi(self):
        return (self.device_id, self.counter, self.head, self.deadline)


@dataclass(frozen=True, slots=True)
class AvailabilityEvidence:
    """What a witness needs to call Registry.challengeAvailability for one FULL event."""
    receipt: Receipt
    prev_head: bytes
    header: Header
    later: tuple  # event hashes from header.counter + 1 up to receipt.counter


@dataclass(slots=True)
class CheckpointMsg:
    """Sent every p seconds from device to witness over a path that does not traverse the gateway."""
    head: SignedHead
    receipt: Receipt | None
    oldest_unreceipted_ts: int | None
    receipts: list = field(default_factory=list)     # every receipt accepted since the last checkpoint
    evidence: list = field(default_factory=list)     # AvailabilityEvidence for new FULL events
    conflicting: list = field(default_factory=list)  # gateway-signed receipts that contradict the device chain
