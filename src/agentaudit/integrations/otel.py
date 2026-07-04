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


def span_to_event(
    name: str,
    attributes: Mapping[str, Any],
    span_events: Optional[Sequence[Mapping[str, Any]]] = None,
    framework: Optional[str] = None,
    redact_content: bool = True,
) -> Optional[AuditEvent]:
    """Map one OTel GenAI span to an :class:`AuditEvent` (or None to skip).

    ``span_events`` is an optional list of ``{"attributes": {...}}`` (OTel span
    events), where prompt/completion content increasingly lives.
    """
    attrs = dict(attributes or {})
    # Only audit GenAI/agent spans; ignore unrelated infrastructure spans.
    is_gen_ai = any(k.startswith("gen_ai.") for k in attrs) or bool(framework)
    if not is_gen_ai:
        return None

    # Prompt/completion may be attributes or ride on span events.
    prompt = attrs.get(GEN_AI["prompt"])
    completion = attrs.get(GEN_AI["completion"])
    for ev in span_events or ():
        ev_attrs = ev.get("attributes", {}) if isinstance(ev, Mapping) else {}
        prompt = prompt or ev_attrs.get(GEN_AI["prompt"])
        completion = completion or ev_attrs.get(GEN_AI["completion"])

    model = attrs.get(GEN_AI["response_model"]) or attrs.get(GEN_AI["request_model"])
    agent_id = (
        attrs.get(GEN_AI["agent_name"])
        or attrs.get(GEN_AI["agent_id"])
        or attrs.get(GEN_AI["tool_name"])
        or name
    )

    input_field: Dict[str, Any] = {}
    if attrs.get(GEN_AI["tool_name"]):
        input_field["tool"] = attrs[GEN_AI["tool_name"]]
    content_in = _content_field(prompt, redact_content)
    if content_in:
        input_field["prompt"] = content_in
    if attrs.get(GEN_AI["input_tokens"]) is not None:
        input_field["input_tokens"] = attrs[GEN_AI["input_tokens"]]

    output_field: Dict[str, Any] = {}
    content_out = _content_field(completion, redact_content)
    if content_out:
        output_field["completion"] = content_out
    if attrs.get(GEN_AI["finish_reasons"]) is not None:
        output_field["finish_reasons"] = attrs[GEN_AI["finish_reasons"]]
    if attrs.get(GEN_AI["output_tokens"]) is not None:
        output_field["output_tokens"] = attrs[GEN_AI["output_tokens"]]

    return AuditEvent(
        event_type=_classify(attrs),
        actor=Actor(
            agent_id=str(agent_id),
            framework=framework or attrs.get(GEN_AI["system"]),
            model=model,
        ),
        input=input_field or None,
        output=output_field or None,
    )


# --- OTel SpanExporter ------------------------------------------------------
try:  # keep the SDK an optional dependency
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

    _HAVE_OTEL = True
except Exception:  # pragma: no cover - exercised only without the SDK
    SpanExporter = object  # type: ignore
    SpanExportResult = None  # type: ignore
    _HAVE_OTEL = False


class AuditSpanExporter(SpanExporter):  # type: ignore[misc]
    """An OTel ``SpanExporter`` that writes GenAI spans into an ``AuditLog``.

    Usage::

        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(AuditSpanExporter(log)))
    """

    def __init__(
        self,
        log: AuditLog,
        framework: Optional[str] = None,
        redact_content: bool = True,
    ) -> None:
        if not _HAVE_OTEL:  # pragma: no cover
            raise RuntimeError(
                "opentelemetry-sdk is required for AuditSpanExporter "
                "(pip install 'agentaudit[otel]')"
            )
        self.log = log
        self.framework = framework
        self.redact_content = redact_content
        self.recorded: List[str] = []  # event_ids recorded, for introspection/tests

    def export(self, spans: Sequence[Any]) -> Any:
        try:
            for span in spans:
                event = span_to_event(
                    name=getattr(span, "name", ""),
                    attributes=dict(getattr(span, "attributes", {}) or {}),
                    span_events=[
                        {"attributes": dict(getattr(e, "attributes", {}) or {})}
                        for e in getattr(span, "events", []) or []
                    ],
                    framework=self.framework,
                    redact_content=self.redact_content,
                )
                if event is None:
                    continue
                # Content is already hashed when redact_content; no extra keys.
                entry = self.log.record(event)
                self.recorded.append(entry.event_id)
            return SpanExportResult.SUCCESS
        except Exception:  # pragma: no cover - defensive; never crash the app
            return SpanExportResult.FAILURE

    def shutdown(self) -> None:  # noqa: D401
        return None

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return True
