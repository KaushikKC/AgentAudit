"""CrewAI adapter (differentiator D1).

CrewAI exposes two stable hook points -- ``step_callback`` (fired for each agent
step / tool use) and ``task_callback`` (fired when a task completes). This module
turns them into :class:`AuditEvent` records, so a CrewAI crew produces the same
tamper-evident audit format as a LangChain agent -- the whole point of D1::

    from agentaudit import AuditLog, SigningKey
    from agentaudit.integrations.crewai import make_step_callback, make_task_callback

    log = AuditLog(signing_key=SigningKey.generate())
    crew = Crew(
        agents=[...], tasks=[...],
        step_callback=make_step_callback(log),
        task_callback=make_task_callback(log),
    )
    crew.kickoff()
    log.seal()

We duck-type the callback payloads rather than importing CrewAI, so this works
across CrewAI versions and needs no CrewAI install to unit-test. Content is
hashed by default.
"""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Dict, Optional

from agentaudit.log import AuditLog
from agentaudit.schema import Actor, AuditEvent, EventType

__all__ = ["make_step_callback", "make_task_callback"]


def _content(text: str, redact: bool) -> Dict[str, Any]:
    if redact:
        return {"redacted": True, "hash": hashlib.sha256(text.encode()).hexdigest(),
                "chars": len(text)}
    return {"text": text}


def _first_attr(obj: Any, *names: str) -> Optional[Any]:
    for n in names:
        if hasattr(obj, n):
            val = getattr(obj, n)
            if val is not None:
                return val
    return None


