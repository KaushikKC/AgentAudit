"""AgentAudit -- tamper-evident audit trails for AI agents.

Open-source middleware that records every agent decision, tool call, input, and
output into a cryptographically tamper-evident, signed, exportable record -- the
evidence a regulated firm can hand to a regulator or auditor.

Quick start::

    from agentaudit import AuditLog, AuditEvent, Actor, EventType, SigningKey

    log = AuditLog(signing_key=SigningKey.generate())
    log.record(AuditEvent(
        event_type=EventType.DECISION,
        actor=Actor(agent_id="kyc-checker-v3", framework="langchain"),
        output={"decision": "approve", "confidence": 0.83},
    ))
    checkpoint = log.seal()   # signed Merkle root

See :mod:`agentaudit.verifier` for offline, trust-nothing verification.
"""

from agentaudit.crypto.signing import SigningKey, VerifyingKey
from agentaudit.keys import EncryptedFileKeyProvider, KeyProvider, LocalKeyProvider
from agentaudit.log import AuditLog, InclusionProof, SealPolicy
from agentaudit.schema import Actor, AuditEvent, EventType, LogEntry, PolicyRef
from agentaudit.storage import Checkpoint, SQLiteStore, StorageBackend

__version__ = "0.1.0"

__all__ = [
    "AuditLog",
    "InclusionProof",
    "SealPolicy",
    "AuditEvent",
    "Actor",
    "PolicyRef",
    "EventType",
    "LogEntry",
    "SQLiteStore",
    "StorageBackend",
    "Checkpoint",
    "SigningKey",
    "VerifyingKey",
    "KeyProvider",
    "LocalKeyProvider",
    "EncryptedFileKeyProvider",
    "__version__",
]
