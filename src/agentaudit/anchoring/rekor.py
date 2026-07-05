"""Sigstore Rekor anchor -- commit roots to a public transparency log.

Rekor (https://rekor.sigstore.dev) is a free, public, append-only transparency
log. Anchoring a Merkle root there gives **provable time** (Rekor's
``integratedTime``) and a globally-visible, third-party record that the root
existed -- assurance no operator-held key can provide.

Scope & honesty:
  * The **read/verify** paths (log info, fetch entry, fetch log public key) work
    against live Rekor and are what the client is tested on.
  * :meth:`RekorAnchor.submit` performs a real, **permanent, public** write,
    validated against live Rekor (returns a ``logIndex`` + inclusion proof +
    signed entry timestamp). It uses the ``hashedrekord`` schema with an **ECDSA
    P-256** anchor key -- the canonical hashedrekord path. (Rekor's ed25519
    hashedrekord uses Ed25519ph, which ``cryptography`` doesn't expose; the anchor
    key is independent of the log's Ed25519 signing key regardless.) It is never
    called implicitly -- only when you pass ``seal(anchor=RekorAnchor(...))``.
  * Receipts capture the Signed Entry Timestamp (SET) + Rekor's log public key, so
    they verify **offline**: :func:`verify_set` checks Rekor's ECDSA signature over
    the canonicalized entry against the log key (pin it in production). An online
    re-fetch is the fallback when SET material is absent.

Networking note: some Python installs (notably the macOS framework build) ship
without a working system CA store and fail TLS to Rekor. We use ``certifi``'s CA
bundle when available, falling back to the default context.
"""

from __future__ import annotations

import base64
import hashlib
import json
import ssl
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from agentaudit.anchoring.base import (
    AnchorBackend,
    AnchorReceipt,
    checkpoint_statement,
    statement_bytes,
)
from agentaudit.storage import Checkpoint

__all__ = ["RekorClient", "RekorAnchor", "verify_rekor_receipt", "verify_set",
           "DEFAULT_REKOR_URL"]

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:  # pragma: no cover - depends on environment
        return ssl.create_default_context()


class RekorClient:
    """Thin REST client for the Rekor API (read paths are live-tested)."""

    def __init__(self, base_url: str = DEFAULT_REKOR_URL, timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._ctx = _ssl_context()

    def _request(self, method: str, path: str, body: Optional[bytes] = None) -> Any:
        req = urllib.request.Request(
            f"{self.base_url}{path}", data=body, method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
            return json.loads(resp.read())

    def get_log_info(self) -> Dict[str, Any]:
        return self._request("GET", "/api/v1/log")

    def get_entry_by_uuid(self, uuid: str) -> Dict[str, Any]:
        return self._request("GET", f"/api/v1/log/entries/{uuid}")

    def get_entry_by_index(self, log_index: int) -> Dict[str, Any]:
        return self._request("GET", f"/api/v1/log/entries?logIndex={log_index}")

    def get_public_key(self) -> str:
        req = urllib.request.Request(f"{self.base_url}/api/v1/log/publicKey")
        with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
            return resp.read().decode()

    def create_hashedrekord(self, digest_hex: str, signature: bytes,
                            public_key_pem: bytes) -> Dict[str, Any]:
        entry = {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": digest_hex}},
                "signature": {
                    "content": base64.b64encode(signature).decode(),
                    "publicKey": {"content": base64.b64encode(public_key_pem).decode()},
                },
            },
        }
        return self._request("POST", "/api/v1/log/entries", json.dumps(entry).encode())


class RekorAnchor(AnchorBackend):
    """Anchor sealed roots to a Rekor transparency log with an ECDSA anchor key.

    Generates a dedicated ECDSA P-256 key by default; pass ``private_key_pem`` to
    reuse a stable anchor identity across seals.
    """

    name = "rekor"

    def __init__(
        self,
        private_key_pem: Optional[bytes] = None,
        base_url: str = DEFAULT_REKOR_URL,
    ) -> None:
        if private_key_pem is not None:
            self.key = serialization.load_pem_private_key(private_key_pem, password=None)
        else:
            self.key = ec.generate_private_key(ec.SECP256R1())
        self.client = RekorClient(base_url)

    def private_key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def submit(self, checkpoint: Checkpoint) -> AnchorReceipt:
        statement = checkpoint_statement(checkpoint)
        digest = hashlib.sha256(statement_bytes(statement)).digest()
        # hashedrekord logs the digest; ECDSA over the prehashed digest is what
        # Rekor verifies against the logged sha256 value.
        signature = self.key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        public_pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        result = self.client.create_hashedrekord(digest.hex(), signature, public_pem)
        # Response is { "<uuid>": { body, logIndex, integratedTime, logID, verification, ... } }
        uuid, payload = next(iter(result.items()))
        integrated = payload.get("integratedTime")
        anchored_at = (
            datetime.fromtimestamp(integrated, tz=timezone.utc)
            .isoformat().replace("+00:00", "Z")
            if integrated else datetime.now(timezone.utc).isoformat()
        )
        set_b64 = (payload.get("verification") or {}).get("signedEntryTimestamp")
        # Capture the SET material + Rekor's log public key so the receipt is
        # OFFLINE-verifiable (no re-fetch needed).
        rekor_pub = None
        try:
            rekor_pub = self.client.get_public_key()
        except Exception:  # pragma: no cover - keep the receipt even if this fails
            pass
        return AnchorReceipt(
            backend=self.name,
            root_hash=checkpoint.root_hash,
            anchored_at=anchored_at,
            proof={
                "statement": statement,
                "digest": digest.hex(),
                "uuid": uuid,
                "body": payload.get("body"),
                "log_index": payload.get("logIndex"),
                "log_id": payload.get("logID"),
                "integrated_time": integrated,
                "signed_entry_timestamp": set_b64,
                "rekor_public_key": rekor_pub,
                "rekor_url": self.client.base_url,
            },
            # Offline-verifiable when we captured the SET + Rekor log key.
            offline_verifiable=bool(set_b64 and payload.get("body") and rekor_pub),
        )


def verify_set(body: str, integrated_time: int, log_id: str, log_index: int,
               set_b64: str, rekor_public_key_pem: str) -> bool:
    """Verify a Rekor Signed Entry Timestamp (SET) -- fully offline.

    The SET is Rekor's ECDSA(P-256) signature over the RFC 8785-canonicalized
    ``{body, integratedTime, logID, logIndex}``. Verifying it against Rekor's log
    public key is proof the entry was included, with no network round-trip.
    """
    payload = {"body": body, "integratedTime": integrated_time,
               "logID": log_id, "logIndex": log_index}
    canon = statement_bytes(payload)  # same canonical JSON Rekor signs
    pub = serialization.load_pem_public_key(rekor_public_key_pem.encode())
    try:
        pub.verify(base64.b64decode(set_b64), canon, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _body_digest(body_b64: str) -> Optional[str]:
    body = json.loads(base64.b64decode(body_b64))
    return body.get("spec", {}).get("data", {}).get("hash", {}).get("value")


def verify_rekor_receipt(
    receipt: AnchorReceipt,
    trusted_rekor_key: Optional[str] = None,
    online: bool = False,
    client: Optional[RekorClient] = None,
) -> bool:
    """Verify a Rekor receipt.

    Prefers **offline** verification: check the SET against Rekor's log public
    key and confirm the logged entry commits to our anchored digest -- no
    network. Pass ``trusted_rekor_key`` (PEM) to pin Sigstore's published log
    key rather than trusting the key embedded in the receipt (recommended; a
    key carried inside the thing it vouches for proves nothing on its own).

    Falls back to an online re-fetch when ``online=True`` or the SET material is
    absent.
    """
    if receipt.backend != "rekor":
        return False
    p = receipt.proof
    set_b64, body = p.get("signed_entry_timestamp"), p.get("body")
    pub_pem = trusted_rekor_key or p.get("rekor_public_key")

    if not online and set_b64 and body and pub_pem:
        if not verify_set(body, p["integrated_time"], p["log_id"], p["log_index"],
                          set_b64, pub_pem):
            return False
        # Bind the SET-verified entry to the root we anchored.
        return _body_digest(body) == p.get("digest")

    # Online fallback: re-fetch the entry and match the digest.
    uuid = p.get("uuid")
    if not uuid:
        return False
    client = client or RekorClient(p.get("rekor_url", DEFAULT_REKOR_URL))
    try:
        entry = client.get_entry_by_uuid(uuid)
    except Exception:
        return False
    _, payload = next(iter(entry.items()))
    return _body_digest(payload["body"]) == p.get("digest")
