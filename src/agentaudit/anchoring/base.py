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


