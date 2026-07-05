"""RFC 6962 Merkle tree tests, including the published reference vectors.

The reference hashes below are the canonical RFC 6962 test vectors (the
"D[0..7]" tree built from the bytes 0x00, 0x0010, 0x2021, ...). Matching them is
strong evidence our leaf/node hashing and tree shape are spec-correct, not just
internally consistent.
"""

import hashlib

import pytest

from agentaudit.crypto import merkle

# RFC 6962 test inputs: 8 leaves with these raw contents.
_INPUTS = [
    b"",
    bytes.fromhex("00"),
    bytes.fromhex("10"),
    bytes.fromhex("2021"),
    bytes.fromhex("3031"),
    bytes.fromhex("40414243"),
    bytes.fromhex("5051525354555657"),
    bytes.fromhex("606162636465666768696a6b6c6d6e6f"),
]

# Published RFC 6962 Merkle Tree Hashes for the first n inputs.
_KNOWN_ROOTS = {
    0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    2: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    3: "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    4: "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    5: "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    6: "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    7: "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    8: "5dc9da79a70659a9 ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328".replace(" ", ""),
}


def _leaves(n):
    return [merkle.hash_leaf(_INPUTS[i]) for i in range(n)]


@pytest.mark.parametrize("n,root", _KNOWN_ROOTS.items())
def test_known_rfc6962_roots(n, root):
    assert merkle.merkle_root(_leaves(n)).hex() == root


def test_leaf_and_node_domain_separation():
    # A leaf and a node with the same underlying bytes must differ.
    data = b"x"
    assert merkle.hash_leaf(data) != hashlib.sha256(b"\x01" + data).digest()
    assert merkle.hash_leaf(data) == hashlib.sha256(b"\x00" + data).digest()


@pytest.mark.parametrize("n", range(1, 17))
def test_inclusion_proof_roundtrip(n):
    leaves = [merkle.hash_leaf(bytes([i])) for i in range(n)]
    root = merkle.merkle_root(leaves)
    for i in range(n):
        path = merkle.inclusion_proof(i, leaves)
        assert merkle.verify_inclusion(i, n, leaves[i], path, root)


@pytest.mark.parametrize("n", range(2, 17))
def test_inclusion_proof_rejects_wrong_leaf(n):
    leaves = [merkle.hash_leaf(bytes([i])) for i in range(n)]
    root = merkle.merkle_root(leaves)
    path = merkle.inclusion_proof(0, leaves)
    wrong = merkle.hash_leaf(b"not-in-tree")
    assert not merkle.verify_inclusion(0, n, wrong, path, root)


@pytest.mark.parametrize("n", range(2, 20))
def test_consistency_proof_roundtrip(n):
    leaves = [merkle.hash_leaf(bytes([i % 256])) for i in range(n)]
    full_root = merkle.merkle_root(leaves)
    for m in range(1, n + 1):
        first_root = merkle.merkle_root(leaves[:m])
        proof = merkle.consistency_proof(m, leaves)
        assert merkle.verify_consistency(m, n, first_root, full_root, proof), (m, n)


def test_consistency_proof_detects_rewrite():
    leaves = [merkle.hash_leaf(bytes([i])) for i in range(8)]
    m = 5
    first_root = merkle.merkle_root(leaves[:m])
    # Rewrite history: change an *old* entry, then extend.
    tampered = list(leaves)
    tampered[2] = merkle.hash_leaf(b"rewritten")
    bad_root = merkle.merkle_root(tampered)
    proof = merkle.consistency_proof(m, tampered)
    # The old root no longer reconciles with the tampered tree.
    assert not merkle.verify_consistency(m, 8, first_root, bad_root, proof)


def test_empty_and_single():
    assert merkle.merkle_root([]).hex() == _KNOWN_ROOTS[0]
    one = merkle.hash_leaf(b"solo")
    assert merkle.merkle_root([one]) == one


def test_incremental_tree_matches_full_recompute():
    # The O(log n)/append frontier must produce the exact RFC 6962 root at every
    # size -- checked against the audited recursive merkle_root.
    tree = merkle.IncrementalMerkleTree()
    for n in range(0, 260):
        assert tree.root() == merkle.merkle_root(tree.leaves), n
        tree.append(merkle.hash_leaf(bytes([n % 256, (n // 256) % 256])))


def test_incremental_tree_matches_known_rfc_root():
    tree = merkle.IncrementalMerkleTree(_leaves(8))
    assert tree.root().hex() == _KNOWN_ROOTS[8]
    assert tree.size == 8


def test_incremental_tree_constructor_equivalence():
    leaves = [merkle.hash_leaf(bytes([i])) for i in range(13)]
    assert merkle.IncrementalMerkleTree(leaves).root() == merkle.merkle_root(leaves)
