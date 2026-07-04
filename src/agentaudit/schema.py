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


