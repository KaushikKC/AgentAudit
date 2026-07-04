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


def verify_inclusion(
    index: int,
    tree_size: int,
    leaf_hash: bytes,
    proof: Sequence[bytes],
    root: bytes,
) -> bool:
    """Verify an inclusion proof (RFC 6962-bis 2.1.3.2), iteratively.

    Recomputes the root from ``leaf_hash`` + ``proof`` and compares to ``root``.
    """
    if index >= tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash
    for p in proof:
        if sn == 0:
            return False  # proof longer than the tree can justify
        if (fn & 1) or (fn == sn):
            r = hash_node(p, r)
            if not (fn & 1):
                while fn != 0 and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = hash_node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and _consteq(r, root)


def consistency_proof(m: int, leaves: Sequence[bytes]) -> List[bytes]:
    """Prove the tree of size ``m`` is a prefix of ``merkle_root(leaves)``.

    RFC 6962 PROOF(m, D[n]). ``m`` must satisfy 0 <= m <= len(leaves).
    An empty proof means the two roots are trivially consistent (m == n, or
    m == 0 which is consistent with anything).
    """
    n = len(leaves)
    if not 0 <= m <= n:
        raise ValueError(f"m={m} out of range for tree of size {n}")
    if m == 0 or m == n:
        return []
    return _subproof(m, list(leaves), True)


def _subproof(m: int, leaves: List[bytes], b: bool) -> List[bytes]:
    n = len(leaves)
    if m == n:
        # The subtree D[0:m] is fully contained. When it's the original whole
        # tree (b=True) its root is implicit; otherwise the verifier needs it.
        return [] if b else [merkle_root(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [merkle_root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]


