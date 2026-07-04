"""OpenTelemetry-native instrumentation (differentiator D1, the neutral core).

The research names the exact gap: there is no dominant standard for governance
across LangChain, CrewAI, AutoGen, and the OpenAI Agents SDK -- each ships its
own tracing format. AgentAudit's answer is to sit on **OpenTelemetry's GenAI
semantic conventions** (the ``gen_ai.*`` attributes). Any framework that emits
those spans -- directly or via its OTel instrumentation -- flows into one audit
format, so a mixed fleet is governed uniformly.

Two things live here:

  * :func:`span_to_event` -- a pure mapping from OTel span data (name +
    attributes + span events) to an :class:`~agentaudit.schema.AuditEvent`. It
    has no hard dependency on the OTel SDK, so it is trivially unit-testable.
  * :class:`AuditSpanExporter` -- a drop-in OTel ``SpanExporter`` that records
    each span into an :class:`~agentaudit.log.AuditLog`. Register it in any OTel
    tracer provider and your agent's spans become a tamper-evident audit trail.

Prompt/completion *content* is hashed by default (``redact_content=True``) so
turning on auditing never turns your traces into a PII liability; model,
operation, token, and finish-reason *metadata* stay in the clear.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Mapping, Optional, Sequence

from agentaudit.log import AuditLog
from agentaudit.schema import Actor, AuditEvent, EventType

__all__ = ["span_to_event", "AuditSpanExporter", "GEN_AI"]

# The subset of GenAI semantic-convention attribute keys we map.
GEN_AI = {
    "system": "gen_ai.system",
    "operation": "gen_ai.operation.name",
    "request_model": "gen_ai.request.model",
    "response_model": "gen_ai.response.model",
    "agent_name": "gen_ai.agent.name",
    "agent_id": "gen_ai.agent.id",
    "tool_name": "gen_ai.tool.name",
    "prompt": "gen_ai.prompt",
    "completion": "gen_ai.completion",
    "input_tokens": "gen_ai.usage.input_tokens",
    "output_tokens": "gen_ai.usage.output_tokens",
    "finish_reasons": "gen_ai.response.finish_reasons",
    "conversation_id": "gen_ai.conversation.id",
}

# gen_ai.operation.name -> our event taxonomy.
_OPERATION_EVENT = {
    "chat": EventType.LLM_GENERATION,
    "text_completion": EventType.LLM_GENERATION,
    "generate_content": EventType.LLM_GENERATION,
    "execute_tool": EventType.TOOL_CALL,
    "embeddings": EventType.RETRIEVAL,
    "invoke_agent": EventType.DECISION,
    "create_agent": EventType.DECISION,
}


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _content_field(text: Optional[str], redact: bool) -> Optional[Dict[str, Any]]:
    if text is None:
        return None
    if redact:
        return {"redacted": True, "hash": _hash(text), "chars": len(text)}
    return {"text": text}


def _classify(attrs: Mapping[str, Any]) -> EventType:
    op = attrs.get(GEN_AI["operation"])
    if op in _OPERATION_EVENT:
        return _OPERATION_EVENT[op]
    if attrs.get(GEN_AI["tool_name"]):
        return EventType.TOOL_CALL
    return EventType.LLM_GENERATION


