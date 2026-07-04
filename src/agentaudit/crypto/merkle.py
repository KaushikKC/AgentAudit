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


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Merkle Tree Hash (MTH) over already-hashed leaves.

    ``leaves`` are leaf *hashes* (output of :func:`hash_leaf`).
    """
    n = len(leaves)
    if n == 0:
        return _EMPTY_ROOT
    if n == 1:
        return leaves[0]
    k = _largest_power_of_two_below(n)
    return hash_node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> List[bytes]:
    """Audit path proving ``leaves[index]`` is committed by ``merkle_root(leaves)``.

    Returns the list of sibling hashes from the leaf up to (but excluding) the
    root -- RFC 6962 PATH(m, D[n]).
    """
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError(f"index {index} out of range for tree of size {n}")
    return _path(index, list(leaves))


def _path(m: int, leaves: List[bytes]) -> List[bytes]:
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if m < k:
        return _path(m, leaves[:k]) + [merkle_root(leaves[k:])]
    return _path(m - k, leaves[k:]) + [merkle_root(leaves[:k])]


