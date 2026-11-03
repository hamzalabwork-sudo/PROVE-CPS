"""Cross-check every off-chain encoder against the deployed Registry bytecode (Anvil).

Run: .venv/Scripts/python prototype/tests/test_crypto_vs_contract.py   (Anvil on 127.0.0.1:8645)
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eth_hash.auto import keccak  # noqa: E402

from provecps import crypto  # noqa: E402
from provecps.ledger import Anvil, SimLedger  # noqa: E402
from provecps.policy import Op, Policy, Rule  # noqa: E402
from provecps.sim import Sim  # noqa: E402

rng = random.Random(20271)


def main():
    chain = Anvil()
    led = SimLedger(Sim(chain.last_ts), chain, [1.0])
    admin, gw, dev = (crypto.Signer.from_seed(s) for s in ("t-admin", "t-gateway", "t-device"))
    reg = led.deploy(admin.address, 60)
    cid = chain.w3.eth.chain_id
    dom = crypto.domain_separator(cid, reg)
    led.setup_tx(admin.address, "registerGateway", gw.address)
    led.setup_tx(admin.address, "registerDevice", 9, dev.address, gw.address)
    checks = 0

    # 1. EIP-712 digests
    for _ in range(20):
        d, c, h, dl = rng.getrandbits(64), rng.getrandbits(64), rng.randbytes(32), rng.getrandbits(64)
        assert led.view("receiptDigest", (d, c, h, dl)) == crypto.receipt_digest(dom, d, c, h, dl)
        assert led.view("checkpointDigest", (d, c, h)) == crypto.checkpoint_digest(dom, d, c, h)
        checks += 2

    # 2. event hash (incl. negative and extreme int256 features), chain step, leaf
    for n in (0, 1, 3, 8):
        feats = [rng.randint(-(1 << 255), (1 << 255) - 1) for _ in range(n)] + [-1, 0, 1050][:n]
        hdr = (rng.getrandbits(64), rng.getrandbits(64), rng.getrandbits(64), feats, rng.randbytes(32))
        assert led.view("eventHash", hdr) == crypto.event_hash(*hdr)
        a, b = rng.randbytes(32), rng.randbytes(32)
        assert led.view("chainStep", a, b) == crypto.chain_step(a, b)
        assert led.view("leafOf", hdr[0], hdr[1], a) == crypto.leaf(hdr[0], hdr[1], a)
        checks += 3

    # 3. Merkle proofs + device signatures + chain links, through a real dispute, at every leaf position
    #    of trees with 1..7 leaves (covers the odd-node promotion rule)
    head, heads, hashes = crypto.ZERO32, {}, {}
    for c in range(1, 8):
        eh = crypto.event_hash(9, c, 1000 + c, [c], keccak(b"p%d" % c))
        head = crypto.chain_step(head, eh)
        heads[c], hashes[c] = head, eh
    for n in range(1, 8):
        for idx in range(n):
            c = idx + 1                      # leaf idx carries the device head at counter c
            leaves_spec = [(9, k + 1, heads[k + 1]) if k == idx else (rng.getrandbits(64), k, rng.randbytes(32))
                           for k in range(n)]
            tree = crypto.MerkleTree([crypto.leaf(*s) for s in leaves_spec])
            assert crypto.verify_proof(tree.proof(idx), tree.root, crypto.leaf(9, c, heads[c]))
            led.setup_tx(gw.address, "anchor", tree.root)
            deadline = chain.last_ts + 1     # anchored at or before the deadline -> Dismissed, not Late
            r = (9, 1, heads[1], deadline)
            rsig = gw.sign(crypto.receipt_digest(dom, *r))
            chain.mine(deadline + 1)         # deadline passes
            rc = led.setup_tx(admin.address, "challengeCustody", r, rsig)
            ch = led.view("challengeCount")
            devsig = dev.sign(crypto.checkpoint_digest(dom, 9, c, heads[c]))
            later = [hashes[k] for k in range(2, c + 1)]
            led.setup_tx(admin.address, "respondCoverage", ch, (tree.root, c, heads[c], devsig, tree.proof(idx)), later)
            assert led.view("challenges", ch)[1] == 2, f"n={n} idx={idx}: expected Dismissed"
            checks += 1

    # 4. policy evaluation: requiresFull vs Policy.requires_full, including version selection by timestamp
    rules_v0 = [Rule(0, Op.GE, 1050), Rule(0, Op.LE, -50), Rule(1, Op.GE, 200)]
    rules_v1 = [Rule(2, Op.EQ, 1), Rule(0, Op.NE, 500)]
    t0 = chain.last_ts + 10
    pol = Policy()
    for t, rules in ((t0, rules_v0), (t0 + 100, rules_v1)):
        led.setup_tx(admin.address, "setPolicy", [r.as_tuple() for r in rules], t)
        pol.add(t, rules)
    for _ in range(300):
        feats = [rng.choice([-100, -50, -49, 0, 199, 200, 500, 1049, 1050, 2000, 1]) for _ in range(rng.randint(0, 3))]
        ts = rng.choice([t0 - 1, t0, t0 + 50, t0 + 99, t0 + 100, t0 + 1000])
        assert led.view("requiresFull", feats, ts) == pol.requires_full(feats, ts), (feats, ts)
        checks += 1

    # 5. signature recovery round trip and rejection of junk
    d = keccak(b"x")
    assert crypto.recover(d, gw.sign(d)) == gw.address
    assert crypto.recover(d, b"\x00" * 65) is None
    print(f"OK: {checks} contract cross-checks passed (chain {cid}, registry {reg})")


if __name__ == "__main__":
    main()
