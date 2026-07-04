"""The audit event data model.

An :class:`AuditEvent` is what a caller records -- the semantic content of one
agent decision, tool call, generation, retrieval, or human override. The log
engine (:mod:`agentaudit.log`) turns it into a :class:`LogEntry` by stamping the
chain fields (``seq``, ``prev_hash``, ``timestamp``, ``entry_hash``).

The single most important field is ``policy_ref``: recording *which policy
version* (id + version + content hash) the agent applied lets you later prove,
cryptographically, what governed a decision at the time it was made. That is the
exact question regulators ask and the exact thing "paper governance" cannot
answer.

We use plain dataclasses (not pydantic) so this model, and the offline verifier
that depends on it, stay dependency-light.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from agentaudit.crypto.canonical import canonicalize

__all__ = [
    "EventType",
    "PolicyRef",
    "Actor",
    "AuditEvent",
    "LogEntry",
    "GENESIS_HASH",
    "compute_entry_hash",
]

# The prev_hash of the very first entry in a session. 64 zero hex chars = the
# 32-byte all-zero digest, a conventional, unambiguous chain anchor.
GENESIS_HASH = "0" * 64


class EventType(str, Enum):
    TOOL_CALL = "tool_call"
    DECISION = "decision"
    LLM_GENERATION = "llm_generation"
    RETRIEVAL = "retrieval"
    HUMAN_OVERRIDE = "human_override"


@dataclass
class Actor:
    """Who/what produced the event."""

    agent_id: str
    framework: Optional[str] = None       # langchain | crewai | autogen | ...
    model: Optional[str] = None
    model_version: Optional[str] = None


@dataclass
class PolicyRef:
    """A pinned reference to the policy version in force at decision time."""

    policy_id: str
    version: str
    hash: Optional[str] = None            # content hash of the policy document


@dataclass
class AuditEvent:
    """Caller-supplied content for one audit event.

    Chain fields (seq/prev_hash/entry_hash) are added by the log, not here.
    """

    event_type: EventType
    actor: Actor
    policy_ref: Optional[PolicyRef] = None
    input: Optional[Dict[str, Any]] = None
    output: Optional[Dict[str, Any]] = None
    reasoning_ref: Optional[str] = None
    control_mapping: List[str] = field(default_factory=list)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: Optional[str] = None       # filled by the log if not provided


@dataclass
class LogEntry:
    """A fully sealed entry: content + chain fields + entry hash.

    ``entry_hash`` covers every field except itself (``prev_hash`` is included,
    which is what chains the entries), so recomputing it detects any edit.
    """

    session_id: str
    seq: int
    prev_hash: str
    timestamp: str
    event_type: str
    actor: Dict[str, Any]
    policy_ref: Optional[Dict[str, Any]]
    input: Optional[Dict[str, Any]]
    output: Optional[Dict[str, Any]]
    reasoning_ref: Optional[str]
    control_mapping: List[str]
    event_id: str
    # Set when one or more fields are redacted (D3): the salted per-field Merkle
    # root that a selective-disclosure excerpt proves against. The raw values are
    # NOT in the entry -- only this commitment is.
    content_commitment: Optional[str] = None
    entry_hash: str = ""

    def signed_body(self) -> Dict[str, Any]:
        """The dict that ``entry_hash`` commits to (everything but the hash)."""
        d = asdict(self)
        d.pop("entry_hash", None)
        return d

    def recompute_hash(self) -> str:
        return compute_entry_hash(self.signed_body())

    def is_intact(self) -> bool:
        """True iff the stored ``entry_hash`` matches the content."""
        return self.entry_hash == self.recompute_hash()

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LogEntry":
        return cls(
            session_id=d["session_id"],
            seq=d["seq"],
            prev_hash=d["prev_hash"],
            timestamp=d["timestamp"],
            event_type=d["event_type"],
            actor=d["actor"],
            policy_ref=d.get("policy_ref"),
            input=d.get("input"),
            output=d.get("output"),
            reasoning_ref=d.get("reasoning_ref"),
            control_mapping=d.get("control_mapping", []),
            event_id=d["event_id"],
            content_commitment=d.get("content_commitment"),
            entry_hash=d.get("entry_hash", ""),
        )


def compute_entry_hash(signed_body: Dict[str, Any]) -> str:
    """entry_hash = SHA256(canonical(signed_body)), as lowercase hex.

    ``signed_body`` must already contain ``prev_hash`` -- that inclusion is what
    makes the sequence a hash *chain*: editing entry i changes its hash, which
    was the ``prev_hash`` of entry i+1, cascading to the end.
    """
    return hashlib.sha256(canonicalize(signed_body)).hexdigest()
