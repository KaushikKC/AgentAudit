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


