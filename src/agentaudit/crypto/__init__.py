"""Cryptographic primitives: canonical serialization, Merkle trees, signing.

These are intentionally small and dependency-light so the offline verifier can
reuse them without importing the rest of AgentAudit.
"""

from agentaudit.crypto.canonical import CanonicalizationError, canonicalize
from agentaudit.crypto.merkle import (
    consistency_proof,
    hash_leaf,
    hash_node,
    inclusion_proof,
    merkle_root,
    verify_consistency,
    verify_inclusion,
)
from agentaudit.crypto.signing import SigningKey, VerifyingKey, verify_signature

__all__ = [
    "canonicalize",
    "CanonicalizationError",
    "hash_leaf",
    "hash_node",
    "merkle_root",
    "inclusion_proof",
    "verify_inclusion",
    "consistency_proof",
    "verify_consistency",
    "SigningKey",
    "VerifyingKey",
    "verify_signature",
]
