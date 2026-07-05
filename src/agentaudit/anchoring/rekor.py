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


