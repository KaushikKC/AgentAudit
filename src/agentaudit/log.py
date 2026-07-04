"""The append-only, hash-chained, Merkle-committed audit log engine.

This is the object an instrumented agent talks to. It:

  * appends :class:`~agentaudit.schema.AuditEvent` records, stamping each with a
    sequence number, the previous entry's hash, a timestamp, and its own
    ``entry_hash`` (a hash *chain*);
  * builds a Merkle tree over the entry hashes and can **seal** a checkpoint --
    signing the current Merkle root with an Ed25519 key;
  * issues **inclusion proofs** for individual events and **consistency proofs**
    between two checkpoints.

Nothing here can rewrite history: entries go only to append-only storage, and
every integrity claim is recomputable from the raw entries by an independent
verifier.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence

if TYPE_CHECKING:
    from agentaudit.anchoring.base import AnchorBackend

from agentaudit.crypto import merkle
from agentaudit.crypto.signing import SigningKey
from agentaudit.keys import KeyProvider, LocalKeyProvider
from agentaudit.redaction import Sealed, flatten_fields, make_disclosure, seal_fields
from agentaudit.schema import (
    GENESIS_HASH,
    AuditEvent,
    EventType,
    LogEntry,
    compute_entry_hash,
)
from agentaudit.storage import Checkpoint, SQLiteStore, StorageBackend

__all__ = ["AuditLog", "InclusionProof", "SealPolicy"]

# Marker left in the visible entry body in place of a redacted field's raw value.
REDACTED_MARKER = {"__redacted__": True}


@dataclass
class SealPolicy:
    """When to seal a checkpoint automatically.

    ``every_n_events`` seals synchronously once that many events accumulate since
    the last seal; ``every_seconds`` runs a background timer that seals any
    outstanding entries on that cadence. Either or both may be set.
    """

    every_n_events: Optional[int] = None
    every_seconds: Optional[float] = None


def _utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class InclusionProof:
    """An inclusion proof plus the signed checkpoint it resolves against."""

    def __init__(self, seq: int, entry_hash: str, tree_size: int,
                 path: List[str], checkpoint: Checkpoint) -> None:
        self.seq = seq
        self.entry_hash = entry_hash
        self.tree_size = tree_size
        self.path = path
        self.checkpoint = checkpoint

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "entry_hash": self.entry_hash,
            "tree_size": self.tree_size,
            "path": self.path,
            "checkpoint": asdict(self.checkpoint),
        }


class AuditLog:
    """A single audit session backed by append-only storage."""

    def __init__(
        self,
        store: Optional[StorageBackend] = None,
        session_id: Optional[str] = None,
        signing_key: Optional[SigningKey] = None,
        key_provider: Optional["KeyProvider"] = None,
        seal_policy: Optional["SealPolicy"] = None,
        auto_anchor: Optional["AnchorBackend"] = None,
    ) -> None:
        self.store = store or SQLiteStore()
        self.session_id = session_id or str(uuid.uuid4())
        self.signing_key = signing_key
        # Signing is done through a KeyProvider so the private key can live in an
        # encrypted file or a KMS, not just in process. A bare signing_key is
        # wrapped for backward compatibility.
        if key_provider is not None:
            self._key_provider: Optional[KeyProvider] = key_provider
        elif signing_key is not None:
            self._key_provider = LocalKeyProvider(signing_key)
        else:
            self._key_provider = None

        # Operator-held secret material for redacted entries (D3). Kept in memory
        # here; in production this lives in an access-controlled secret store and
        # is never persisted alongside the (public) log.
        self._disclosures: Dict[str, Sealed] = {}

        # Cached incremental state so appends stay O(log n), not O(n). An
        # AuditLog instance assumes it is the sole writer of its session; the
        # cache is loaded once from the store (for a reopened log) then updated
        # in place. A lock serializes concurrent record()/seal() calls.
        self._lock = threading.RLock()
        self._loaded = False
        self._merkle = merkle.IncrementalMerkleTree()
        self._prev_hash = GENESIS_HASH
        self._size = 0

        # Automated sealing (production hardening): seal every N events and/or
        # every T seconds so checkpoints don't depend on a manual call.
        self.seal_policy = seal_policy
        self._auto_anchor = auto_anchor
        self._sealed_size = 0            # tree_size at the last seal
        self._seal_timer: Optional[threading.Thread] = None
        self._stop_timer = threading.Event()
        if seal_policy is not None and seal_policy.every_seconds:
            self._start_seal_timer()

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            entries = self.store.entries(self.session_id)
            self._merkle = merkle.IncrementalMerkleTree(
                merkle.hash_leaf(bytes.fromhex(e.entry_hash)) for e in entries
            )
            self._prev_hash = entries[-1].entry_hash if entries else GENESIS_HASH
            self._size = len(entries)
            cp = self.store.latest_checkpoint(self.session_id)
            self._sealed_size = cp.tree_size if cp else 0
            self._loaded = True

    # -- automated sealing (production hardening) --------------------------
    def _start_seal_timer(self) -> None:
        interval = self.seal_policy.every_seconds
        assert interval is not None

        def _loop() -> None:
            while not self._stop_timer.wait(interval):
                try:
                    self._ensure_loaded()
                    if self._size > self._sealed_size:   # only if there's new data
                        self.seal(anchor=self._auto_anchor)
                except Exception:  # pragma: no cover - never kill the timer thread
                    pass

        self._seal_timer = threading.Thread(target=_loop, daemon=True,
                                             name=f"agentaudit-seal-{self.session_id[:8]}")
        self._seal_timer.start()

    def close(self) -> None:
        """Stop the background sealer (if any) and seal any outstanding entries."""
        self._stop_timer.set()
        if self._seal_timer is not None:
            self._seal_timer.join(timeout=1.0)
        self._ensure_loaded()
        if self._key_provider is not None and self._size > self._sealed_size:
            self.seal(anchor=self._auto_anchor)

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- appending ---------------------------------------------------------
    def record(
        self,
        event: AuditEvent,
        redact_keys: Optional[Sequence[str]] = None,
    ) -> LogEntry:
        """Seal ``event`` into the chain and persist it. Returns the entry.

        ``redact_keys`` names top-level event fields (e.g. ``["input"]``) whose
        raw values must NOT enter the log. Those values are committed with a
        salted per-field Merkle root (``content_commitment``); the visible entry
        stores only a marker. The raw values + salts are retained in-memory so
        the operator can later issue a selective-disclosure excerpt.
        """
        self._ensure_loaded()

        redact = set(redact_keys or ())
        _REDACTABLE = {"input", "output"}
        if not redact <= _REDACTABLE:
            raise ValueError(f"redact_keys must be a subset of {_REDACTABLE}")

        body_input = event.input
        body_output = event.output
        content_commitment = None
        if redact:
            fields: Dict[str, object] = {}
            if "input" in redact and event.input is not None:
                fields.update(flatten_fields(event.input, "input"))
                body_input = dict(REDACTED_MARKER)
            if "output" in redact and event.output is not None:
                fields.update(flatten_fields(event.output, "output"))
                body_output = dict(REDACTED_MARKER)
            if fields:
                sealed = seal_fields(fields)
                content_commitment = sealed.content_root

        with self._lock:
            seq = self._size
            entry = LogEntry(
                session_id=self.session_id,
                seq=seq,
                prev_hash=self._prev_hash,
                timestamp=event.timestamp or _utc_now_rfc3339(),
                event_type=event.event_type.value
                if isinstance(event.event_type, EventType)
                else str(event.event_type),
                actor=asdict(event.actor),
                policy_ref=asdict(event.policy_ref) if event.policy_ref else None,
                input=body_input,
                output=body_output,
                reasoning_ref=event.reasoning_ref,
                control_mapping=list(event.control_mapping),
                event_id=event.event_id,
                content_commitment=content_commitment,
            )
            entry.entry_hash = compute_entry_hash(entry.signed_body())
            self.store.append_entry(entry)
            # Advance cached state incrementally (O(log n) for the Merkle update).
            if content_commitment is not None:
                self._disclosures[event.event_id] = sealed
            self._merkle.append(merkle.hash_leaf(bytes.fromhex(entry.entry_hash)))
            self._prev_hash = entry.entry_hash
            self._size += 1
            due = (self.seal_policy is not None
                   and self.seal_policy.every_n_events is not None
                   and self._size - self._sealed_size >= self.seal_policy.every_n_events)
        # Seal outside the lock so a network anchor doesn't stall other writers.
        if due:
            self.seal(anchor=self._auto_anchor)
        return entry

    # -- Merkle / checkpoints ---------------------------------------------
    def _leaf_hashes(self) -> List[bytes]:
        self._ensure_loaded()
        return self._merkle.leaves

    def merkle_root(self) -> str:
        self._ensure_loaded()
        return self._merkle.root().hex()

    def size(self) -> int:
        self._ensure_loaded()
        return self._size

    def seal(self, anchor: Optional["AnchorBackend"] = None) -> Checkpoint:
        """Compute the current Merkle root, sign it, optionally anchor, persist.

        If ``anchor`` is given, the signed root is committed to that external
        backend (a witness log or Sigstore Rekor) and the receipt is stored on
        the checkpoint -- adding provable time + third-party non-repudiation.
        """
        self._ensure_loaded()
        with self._lock:  # snapshot size+root atomically w.r.t. concurrent record()
            cp = Checkpoint(
                session_id=self.session_id,
                tree_size=self._size,
                root_hash=self._merkle.root().hex(),
                timestamp=_utc_now_rfc3339(),
            )
            if self._key_provider is not None:
                body = _checkpoint_signing_bytes(cp)
                cp.signature = self._key_provider.sign(body).hex()
                cp.public_key = self._key_provider.public_key_pem()
            self._sealed_size = cp.tree_size   # reset the auto-seal counter
        if anchor is not None:
            cp.anchor = anchor.submit(cp).to_json()   # may do network I/O; outside lock
        self.store.append_checkpoint(cp)
        return cp

    # -- proofs ------------------------------------------------------------
    def inclusion_proof(self, seq: int, checkpoint: Optional[Checkpoint] = None) -> InclusionProof:
        """Prove that entry ``seq`` is committed by ``checkpoint`` (or a fresh seal)."""
        cp = checkpoint or self.store.latest_checkpoint(self.session_id) or self.seal()
        leaves = self._leaf_hashes()[: cp.tree_size]
        path = merkle.inclusion_proof(seq, leaves)
        entry = self.store.entries(self.session_id)[seq]
        return InclusionProof(
            seq=seq,
            entry_hash=entry.entry_hash,
            tree_size=cp.tree_size,
            path=[h.hex() for h in path],
            checkpoint=cp,
        )

    def consistency_proof(self, first_size: int, second_size: Optional[int] = None) -> List[str]:
        """Prove the log at ``second_size`` is an append-only extension of ``first_size``."""
        leaves = self._leaf_hashes()
        second = second_size or len(leaves)
        return [h.hex() for h in merkle.consistency_proof(first_size, leaves[:second])]

    # -- selective disclosure (D3) ----------------------------------------
    def make_disclosure(
        self,
        seq: int,
        reveal_paths: Sequence[str],
        checkpoint: Optional[Checkpoint] = None,
    ) -> Dict[str, Any]:
        """Build a self-verifying excerpt that reveals only ``reveal_paths``.

        The excerpt proves, without exposing the hidden fields, that: the
        revealed values are authentic; they belong to a specific committed entry;
        and that entry is included in the signed log. Verify with
        :func:`agentaudit.verifier.verify_disclosure`.
        """
        entry = self.store.entries(self.session_id)[seq]
        sealed = self._disclosures.get(entry.event_id)
        if sealed is None:
            raise ValueError(
                f"entry[{seq}] has no redacted fields to disclose "
                "(record it with redact_keys=...)"
            )
        disclosure = make_disclosure(sealed, reveal_paths)
        inclusion = self.inclusion_proof(seq, checkpoint=checkpoint)
        return {
            "entry": entry.signed_body() | {"entry_hash": entry.entry_hash},
            "disclosure": disclosure.to_dict(),
            "inclusion": inclusion.to_dict(),
        }

    # -- integrity ---------------------------------------------------------
    def entries(self) -> List[LogEntry]:
        return self.store.entries(self.session_id)


def _checkpoint_signing_bytes(cp: Checkpoint) -> bytes:
    """The exact bytes an Ed25519 signature covers for a checkpoint.

    Kept explicit and minimal so the verifier can reproduce it byte-for-byte.
    """
    from agentaudit.crypto.canonical import canonicalize

    return canonicalize({
        "session_id": cp.session_id,
        "tree_size": cp.tree_size,
        "root_hash": cp.root_hash,
        "timestamp": cp.timestamp,
    })
