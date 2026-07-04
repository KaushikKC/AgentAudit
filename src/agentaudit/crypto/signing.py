"""Ed25519 signing for Merkle roots / sealed checkpoints.

Hash-chaining and Merkle trees make the log *tamper-evident*: if you have a
trusted root, you can detect any edit. Signing answers a different question --
*who* vouched for that root, and non-repudiably. We sign each sealed checkpoint
(a Merkle root + metadata) with an Ed25519 key so its origin is provable and the
signer cannot later deny it.

Ed25519 is chosen for small keys/signatures (32/64 bytes), deterministic
signatures (no RNG failure mode), and broad verifier support.

Important honesty (see the project threat model): local signing alone does not
stop whoever holds the key from re-signing a *rewritten* history going forward.
That gap is closed by external anchoring (Rekor / RFC-3161 TSA) and, later,
forward-secure key ratcheting -- both built on top of this module.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = ["SigningKey", "VerifyingKey", "verify_signature"]


@dataclass(frozen=True)
class VerifyingKey:
    """A public key that can verify signatures. Safe to publish/embed."""

    _key: Ed25519PublicKey

    @classmethod
    def from_pem(cls, pem: bytes) -> "VerifyingKey":
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("not an Ed25519 public key")
        return cls(key)

    @classmethod
    def from_raw(cls, raw: bytes) -> "VerifyingKey":
        return cls(Ed25519PublicKey.from_public_bytes(raw))

    def to_pem(self) -> bytes:
        return self._key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def to_raw(self) -> bytes:
        return self._key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._key.verify(signature, message)
            return True
        except InvalidSignature:
            return False


class SigningKey:
    """A private key that signs checkpoints. Keep this secret."""

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes, password: bytes | None = None) -> "SigningKey":
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("not an Ed25519 private key")
        return cls(key)

    def to_pem(self, password: bytes | None = None) -> bytes:
        enc = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def verifying_key(self) -> VerifyingKey:
        return VerifyingKey(self._key.public_key())


