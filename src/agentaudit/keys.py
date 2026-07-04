"""Signing-key management (production hardening).

By default an :class:`~agentaudit.log.AuditLog` generates an Ed25519 key in
process and holds it in memory -- fine for a demo, a liability in production. A
:class:`KeyProvider` decouples *how signing happens* from the engine, so the
private key can live encrypted on disk, or never leave a KMS/HSM at all.

The interface is intentionally ``sign`` + ``public_key_pem`` (not "give me the
private key"), because a KMS-backed provider *can't* export its key -- it signs
remotely. Two providers ship here:

  * :class:`LocalKeyProvider` -- an in-process Ed25519 key (the default).
  * :class:`EncryptedFileKeyProvider` -- a password-encrypted PKCS8 key at rest,
    loaded (or created) on disk; the password comes from an argument or an env var.

A KMS/HSM provider is just another subclass -- implement ``sign`` against your
KMS's asymmetric-sign API and ``public_key_pem`` from its public key. Example::

    class AwsKmsKeyProvider(KeyProvider):
        def __init__(self, key_id): self.key_id = key_id; self._c = boto3.client("kms")
        def sign(self, message):
            return self._c.sign(KeyId=self.key_id, Message=message,
                                 MessageType="RAW", SigningAlgorithm="...")["Signature"]
        def public_key_pem(self): ...   # from kms.get_public_key
"""

from __future__ import annotations

import abc
import os
import stat
from pathlib import Path
from typing import Optional

from agentaudit.crypto.signing import SigningKey

__all__ = ["KeyProvider", "LocalKeyProvider", "EncryptedFileKeyProvider"]

DEFAULT_KEY_PASSWORD_ENV = "AGENTAUDIT_KEY_PASSWORD"


class KeyProvider(abc.ABC):
    """Signs checkpoint bytes and exposes the matching public key (PEM)."""

    @abc.abstractmethod
    def sign(self, message: bytes) -> bytes:
        ...

    @abc.abstractmethod
    def public_key_pem(self) -> str:
        ...


class LocalKeyProvider(KeyProvider):
    """An in-process Ed25519 key. The default; simplest, least hardened."""

    def __init__(self, signing_key: Optional[SigningKey] = None) -> None:
        self._key = signing_key or SigningKey.generate()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def public_key_pem(self) -> str:
        return self._key.verifying_key().to_pem().decode()


