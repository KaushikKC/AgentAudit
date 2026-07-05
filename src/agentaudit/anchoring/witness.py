"""Witness-cosigning anchor -- offline-verifiable external attestation.

This is the RFC 6962 / C2SP "witness" model. An *independent* party (its own
Ed25519 key, its own append-only hash chain) observes a sealed root and signs a
statement: "I saw root X for session S at size N, at time T, as my witness entry
i." Because the witness is a separate trust domain from the operator, its
cosignature is meaningful evidence that the root existed and wasn't rewritten --
and it verifies **fully offline**, given the witness's public key.

Honest trust model (stated plainly, as everywhere in this project): a receipt
carries the witness's public key for convenience, but a key embedded in the
thing it's vouching for proves nothing on its own. Real assurance comes from
*pinning* the witness's independently-published key -- exactly how Rekor's
well-known log key works. :func:`verify_witness_receipt` supports that via
``trusted_keys``.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from agentaudit.anchoring.base import (
    AnchorBackend,
    AnchorReceipt,
    checkpoint_statement,
    statement_bytes,
)
from agentaudit.crypto.signing import SigningKey, VerifyingKey
from agentaudit.schema import GENESIS_HASH
from agentaudit.storage import Checkpoint

__all__ = ["WitnessLog", "verify_witness_receipt"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class WitnessLog(AnchorBackend):
    """An independent cosigning witness with its own append-only chain."""

    name = "witness"

    def __init__(self, signing_key: Optional[SigningKey] = None) -> None:
        # A fresh, independent key by default -- a real deployment runs this in a
        # separate trust domain and publishes the public key out-of-band.
        self.key = signing_key or SigningKey.generate()
        self._chain: List[str] = []      # witness entry hashes (own hash chain)
        self._prev = GENESIS_HASH

    @property
    def public_key_pem(self) -> str:
        return self.key.verifying_key().to_pem().decode()

    def submit(self, checkpoint: Checkpoint) -> AnchorReceipt:
        index = len(self._chain)
        statement = checkpoint_statement(checkpoint) | {
            "witnessed_at": _now(),
            "witness_index": index,
            "prev": self._prev,
        }
        body = statement_bytes(statement)
        signature = self.key.sign(body).hex()

        entry_hash = hashlib.sha256(body).hexdigest()
        self._chain.append(entry_hash)
        self._prev = entry_hash

        return AnchorReceipt(
            backend=self.name,
            root_hash=checkpoint.root_hash,
            anchored_at=statement["witnessed_at"],
            proof={
                "statement": statement,
                "signature": signature,
                "witness_public_key": self.public_key_pem,
            },
            offline_verifiable=True,
        )


def verify_witness_receipt(
    receipt: AnchorReceipt,
    trusted_keys: Optional[Iterable[str]] = None,
) -> bool:
    """Verify a witness receipt offline.

    Checks the receipt binds to its root and the witness signature is valid. If
    ``trusted_keys`` (PEM strings) is provided, additionally require that the
    witness key is one you trust -- without pinning, a valid signature only
    proves *someone* signed it, not that it was the real witness.
    """
    if receipt.backend != "witness":
        return False
    p = receipt.proof
    stmt = p.get("statement", {})
    if stmt.get("root_hash") != receipt.root_hash:
        return False
    pem = p.get("witness_public_key", "")
    if trusted_keys is not None and pem.strip() not in {k.strip() for k in trusted_keys}:
        return False
    try:
        vk = VerifyingKey.from_pem(pem.encode())
        return vk.verify(statement_bytes(stmt), bytes.fromhex(p["signature"]))
    except Exception:
        return False
