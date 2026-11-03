"""Hashing, EIP-712 digests, signatures and Merkle trees, byte-compatible with contracts/src/Registry.sol.

Every function here has an on-chain twin; tests/test_crypto_vs_contract.py checks each pair against the
deployed bytecode. Hot-path encoders write ABI words by hand (all fields are static 32-byte words), which is
about 10x faster than eth_abi and matters when a device signs every event. Signing uses eth_keys, which picks
the libsecp256k1 (coincurve) backend when installed: the same library a constrained device would use.
"""
from eth_hash.auto import keccak
from eth_keys import keys

ZERO32 = b"\x00" * 32

EIP712_DOMAIN_TYPEHASH = keccak(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
RECEIPT_TYPEHASH = keccak(b"Receipt(uint64 deviceId,uint64 counter,bytes32 head,uint64 deadline)")
CHECKPOINT_TYPEHASH = keccak(b"Checkpoint(uint64 deviceId,uint64 counter,bytes32 head)")


def _w(x: int) -> bytes:
    """One ABI word for a non-negative integer (uint64 / uint256)."""
    return x.to_bytes(32, "big")


def domain_separator(chain_id: int, verifying_contract: str) -> bytes:
    addr = bytes.fromhex(verifying_contract.removeprefix("0x")).rjust(32, b"\x00")
    return keccak(EIP712_DOMAIN_TYPEHASH + keccak(b"ProveCPS") + keccak(b"1") + _w(chain_id) + addr)


def receipt_digest(domain: bytes, device_id: int, counter: int, head: bytes, deadline: int) -> bytes:
    struct = keccak(RECEIPT_TYPEHASH + _w(device_id) + _w(counter) + head + _w(deadline))
    return keccak(b"\x19\x01" + domain + struct)


def checkpoint_digest(domain: bytes, device_id: int, counter: int, head: bytes) -> bytes:
    struct = keccak(CHECKPOINT_TYPEHASH + _w(device_id) + _w(counter) + head)
    return keccak(b"\x19\x01" + domain + struct)


# ------------------------------------------------------------------ device chain

def features_hash(features) -> bytes:
    """keccak256(abi.encodePacked(int256[])): each element as a 32-byte two's-complement word."""
    return keccak(b"".join((x % (1 << 256)).to_bytes(32, "big") for x in features))


def event_hash(device_id: int, counter: int, timestamp: int, features, payload_hash: bytes) -> bytes:
    return keccak(_w(device_id) + _w(counter) + _w(timestamp) + features_hash(features) + payload_hash)


def chain_step(head: bytes, ev_hash: bytes) -> bytes:
    return keccak(head + ev_hash)  # abi.encode(bytes32, bytes32) is plain concatenation


def link(head: bytes, ev_hashes) -> bytes:
    for h in ev_hashes:
        head = chain_step(head, h)
    return head


def leaf(device_id: int, counter: int, head: bytes) -> bytes:
    """Double-hashed leaf (OpenZeppelin convention: rules out second preimages via inner nodes)."""
    return keccak(keccak(_w(device_id) + _w(counter) + head))


# ------------------------------------------------------------------ signatures

class Signer:
    __slots__ = ("key", "address")

    def __init__(self, key: keys.PrivateKey):
        self.key = key
        self.address = key.public_key.to_checksum_address()

    @classmethod
    def from_hex(cls, hex_key: str) -> "Signer":
        return cls(keys.PrivateKey(bytes.fromhex(hex_key.removeprefix("0x"))))

    @classmethod
    def from_seed(cls, seed: str) -> "Signer":
        """Deterministic test identity (simulation only; never for a deployment)."""
        return cls(keys.PrivateKey(keccak(seed.encode())))

    def sign(self, digest: bytes) -> bytes:
        """65-byte r || s || v with v in {27, 28}, the format OpenZeppelin ECDSA.recover expects."""
        s = self.key.sign_msg_hash(digest)
        return s.r.to_bytes(32, "big") + s.s.to_bytes(32, "big") + bytes([s.v + 27])


def recover(digest: bytes, sig: bytes) -> str | None:
    if len(sig) != 65 or sig[64] not in (27, 28):
        return None
    try:
        s = keys.Signature(vrs=(sig[64] - 27, int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")))
        return s.recover_public_key_from_msg_hash(digest).to_checksum_address()
    except Exception:  # invalid point / malformed signature: treat as invalid, never raise into an agent
        return None


# ------------------------------------------------------------------ Merkle tree

def _hash_pair(a: bytes, b: bytes) -> bytes:
    return keccak(a + b) if a < b else keccak(b + a)  # OpenZeppelin commutative hashing


class MerkleTree:
    """Commutative-hash Merkle tree whose proofs verify with OpenZeppelin MerkleProof.

    An odd node at the end of a level is promoted unchanged, so a proof simply has no sibling at that level.
    """

    def __init__(self, leaves):
        if not leaves:
            raise ValueError("empty batch")
        self.levels = [list(leaves)]
        while len(self.levels[-1]) > 1:
            cur = self.levels[-1]
            nxt = [_hash_pair(cur[i], cur[i + 1]) for i in range(0, len(cur) - 1, 2)]
            if len(cur) % 2:
                nxt.append(cur[-1])
            self.levels.append(nxt)

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def proof(self, index: int) -> list[bytes]:
        out = []
        for level in self.levels[:-1]:
            sib = index ^ 1
            if sib < len(level):
                out.append(level[sib])
            index //= 2
        return out


def verify_proof(proof, root: bytes, leaf_: bytes) -> bool:
    h = leaf_
    for p in proof:
        h = _hash_pair(h, p)
    return h == root
