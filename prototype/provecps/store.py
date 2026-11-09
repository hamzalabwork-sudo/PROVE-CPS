"""Off-chain evidence store, replicated across operators: payloads of FULL events, batch manifests,
and the gateways' published custody logs. Auditors and witnesses read it; only the ledger is trusted."""
from collections import defaultdict


class EvidenceStore:
    def __init__(self):
        self.payloads = {}                   # payload hash -> bytes, published by the gateway (its obligation)
        self.witness_payloads = {}           # payload hash -> bytes, copies held by witnesses (second path, v2)
        self.witness_headers = {}            # (dev, counter) -> event hash, of headers held by witnesses (v3)
        self.gateway_headers = {}            # (dev, counter) -> event hash, of headers published by the gateway (v3)
        self.manifests = {}                  # root -> (gateway, anchored_ts, [(dev, counter, head, sig, proof)])
        self.by_device = defaultdict(list)   # dev -> [(counter, root, head, sig, proof)]
        self.custody_log = {}                # (gateway, dev, counter) -> Receipt
        self.progress = {}                   # dev -> (highest anchored counter, ts at which it was anchored)

    def put_payload(self, h: bytes, payload: bytes):
        self.payloads[h] = payload

    def has_payload(self, h: bytes) -> bool:
        return h in self.payloads

    def publish_manifest(self, gateway: str, root: bytes, ts: int, entries):
        self.manifests[root] = (gateway, ts, entries)
        for dev, counter, head, sig, proof in entries:
            self.by_device[dev].append((counter, root, head, sig, proof))
            if counter > self.progress.get(dev, (0, 0))[0]:
                self.progress[dev] = (counter, ts)

    def log_receipt(self, gateway: str, r):
        self.custody_log.setdefault((gateway, r.device_id, r.counter), r)
