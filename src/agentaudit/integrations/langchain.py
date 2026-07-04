"""LangChain callback adapter (differentiator D1).

Drop this handler into any LangChain run and every LLM call, tool call, and
agent decision becomes a tamper-evident audit entry::

    from agentaudit import AuditLog, SigningKey
    from agentaudit.integrations.langchain import AuditCallbackHandler

    log = AuditLog(signing_key=SigningKey.generate())
    agent.invoke(inputs, config={"callbacks": [AuditCallbackHandler(log)]})
    checkpoint = log.seal()

LangChain is an *optional* dependency: if it's installed, this subclasses its
``BaseCallbackHandler`` and is a first-class handler; if not, the class is still
importable and its callbacks are directly callable, which is exactly what the
unit tests exercise. Prompt/tool content is hashed by default so auditing never
leaks PII.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional
from uuid import UUID

from agentaudit.log import AuditLog
from agentaudit.schema import Actor, AuditEvent, EventType, PolicyRef

__all__ = ["AuditCallbackHandler"]

try:  # optional dependency
    from langchain_core.callbacks import BaseCallbackHandler as _Base
except Exception:  # pragma: no cover - exercised only without LangChain
    _Base = object  # type: ignore


def _digest(text: str) -> Dict[str, Any]:
    return {"redacted": True, "hash": hashlib.sha256(text.encode()).hexdigest(),
            "chars": len(text)}


def _content(text: str, redact: bool) -> Dict[str, Any]:
    return _digest(text) if redact else {"text": text}


