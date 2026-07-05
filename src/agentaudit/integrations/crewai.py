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


def make_step_callback(
    log: AuditLog,
    agent_id: str = "crewai-agent",
    redact_content: bool = True,
) -> Callable[[Any], None]:
    """Return a ``step_callback`` that records each agent step / tool use."""

    def _callback(step: Any) -> None:
        tool = _first_attr(step, "tool")
        if tool is not None:
            # An agent action invoking a tool.
            tool_input = _first_attr(step, "tool_input", "text") or ""
            log.record(AuditEvent(
                event_type=EventType.TOOL_CALL,
                actor=Actor(agent_id=agent_id, framework="crewai"),
                input={"tool": str(tool),
                       "args": _content(str(tool_input), redact_content)},
            ))
            return

        result = _first_attr(step, "result", "output", "return_values", "text")
        log.record(AuditEvent(
            event_type=EventType.DECISION,
            actor=Actor(agent_id=agent_id, framework="crewai"),
            output={"step": _content(str(result if result is not None else step),
                                     redact_content)},
        ))

    return _callback


def make_task_callback(
    log: AuditLog,
    agent_id: str = "crewai-agent",
    redact_content: bool = True,
) -> Callable[[Any], None]:
    """Return a ``task_callback`` that records each completed task's output."""

    def _callback(task_output: Any) -> None:
        raw = _first_attr(task_output, "raw", "result", "output")
        name = _first_attr(task_output, "name", "description")
        agent = _first_attr(task_output, "agent") or agent_id
        log.record(AuditEvent(
            event_type=EventType.DECISION,
            actor=Actor(agent_id=str(agent), framework="crewai"),
            input={"task": str(name)} if name is not None else None,
            output={"result": _content(str(raw if raw is not None else task_output),
                                       redact_content)},
        ))

    return _callback
