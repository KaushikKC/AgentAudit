"""RFC 6962 Merkle tree with inclusion and consistency proofs.

This is the technical heart of AgentAudit. A Merkle tree lets us commit to the
entire state of an audit log in a single 32-byte root hash, and then prove two
things cheaply (both O(log n)):

  * **Inclusion**  -- "event #k really is in the log", by revealing only the
    sibling hashes on the path to the root. The verifier re-hashes upward and
    checks it lands on a root it already trusts. Nothing else about the log is
    disclosed.
  * **Consistency** -- "the log of size ``n`` is an append-only extension of the
    log of size ``m``" (m <= n). This is what proves history was never
    rewritten, only appended.

We follow RFC 6962 ("Certificate Transparency") exactly, including the
domain-separation prefixes that defend against second-preimage / node-vs-leaf
confusion attacks:

    leaf hash  = SHA256(0x00 || data)
    node hash  = SHA256(0x01 || left || right)

Generation uses the recursive definitions straight from the RFC (easy to read
and audit against the spec); verification uses the iterative algorithms from
RFC 6962-bis (what a lightweight verifier would run). We property-test that the
two agree for every tree size, which is the cheapest way to catch an off-by-one.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import List, Sequence

__all__ = [
    "LEAF_PREFIX",
    "NODE_PREFIX",
    "hash_leaf",
    "hash_node",
    "merkle_root",
    "inclusion_proof",
    "verify_inclusion",
    "consistency_proof",
    "verify_consistency",
    "IncrementalMerkleTree",
]

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

# Hash of the empty tree, per RFC 6962: MTH({}) = SHA256().
_EMPTY_ROOT = hashlib.sha256(b"").digest()


def hash_leaf(data: bytes) -> bytes:
    """Hash a single leaf: SHA256(0x00 || data)."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    """Hash an internal node: SHA256(0x01 || left || right)."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    """Largest power of two strictly less than n (n > 1). RFC 6962 'k'."""
    # e.g. n=5 -> 4, n=4 -> 2, n=2 -> 1
    return 1 << ((n - 1).bit_length() - 1)


