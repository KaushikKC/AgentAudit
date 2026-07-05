"""External anchoring -- pluggable backends + receipts.

Local Ed25519 signing makes the log tamper-*evident*, but whoever holds the key
can re-sign a *rewritten* history going forward. Anchoring closes that gap by
committing each sealed Merkle root to an *external* trusted location the operator
cannot backdate, yielding **provable time** and **third-party non-repudiation**.

A backend takes a sealed checkpoint and returns an :class:`AnchorReceipt` -- a
portable record of "this root existed, externally witnessed, at this time". The
receipt travels inside the evidence bundle so an auditor can check it later.

Backends:
  * :class:`~agentaudit.anchoring.witness.WitnessLog` -- an independent cosigning
    witness; the receipt is offline-verifiable (given a trusted witness key).
  * :class:`~agentaudit.anchoring.rekor.RekorAnchor` -- Sigstore Rekor public
    transparency log; provable time from a public good.
"""

from __future__ import annotations

import abc
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict

from agentaudit.crypto.canonical import canonicalize
from agentaudit.storage import Checkpoint

__all__ = ["AnchorReceipt", "AnchorBackend", "checkpoint_statement", "statement_bytes"]


def checkpoint_statement(cp: Checkpoint) -> Dict[str, Any]:
    """The minimal, binding description of a checkpoint that gets anchored.

    Binds the root to its session and size so a receipt can't be replayed onto a
    different log.
    """
    return {
        "session_id": cp.session_id,
        "tree_size": cp.tree_size,
        "root_hash": cp.root_hash,
    }


def statement_bytes(statement: Dict[str, Any]) -> bytes:
    """Canonical bytes an anchor commits to (signs / hashes)."""
    return canonicalize(statement)


@dataclass
class AnchorReceipt:
    """Portable proof that a Merkle root was externally anchored."""

    backend: str                       # "witness" | "rekor" | ...
    root_hash: str                     # the checkpoint root that was anchored
    anchored_at: str                   # external trusted time (RFC3339)
    proof: Dict[str, Any] = field(default_factory=dict)  # backend-specific
    offline_verifiable: bool = False   # True iff verifiable without a network

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "AnchorReceipt":
        d = json.loads(text)
        return cls(
            backend=d["backend"],
            root_hash=d["root_hash"],
            anchored_at=d["anchored_at"],
            proof=d.get("proof", {}),
            offline_verifiable=d.get("offline_verifiable", False),
        )


class AnchorBackend(abc.ABC):
    """A place to anchor sealed Merkle roots."""

    name: str = "anchor"

    @abc.abstractmethod
    def submit(self, checkpoint: Checkpoint) -> AnchorReceipt:
        """Anchor ``checkpoint``'s root externally and return a receipt."""
        raise NotImplementedError
