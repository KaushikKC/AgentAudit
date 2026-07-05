"""Tests for the D1 framework integrations.

The OTel exporter is tested against the real SDK (installed). The LangChain and
CrewAI adapters are tested by calling their callbacks directly with duck-typed
payloads -- so the tests run without those frameworks installed, and still prove
the mapping logic.
"""

from types import SimpleNamespace
from uuid import uuid4

from agentaudit import AuditLog, SigningKey
from agentaudit.integrations.otel import span_to_event
from agentaudit.schema import EventType
from agentaudit.verifier import verify_chain


# --- OTel mapping (pure) ----------------------------------------------------
def test_span_to_event_chat():
    ev = span_to_event(
        "chat claude-sonnet-5",
        {
            "gen_ai.system": "anthropic",
            "gen_ai.operation.name": "chat",
            "gen_ai.request.model": "claude-sonnet-5",
            "gen_ai.prompt": "hello",
            "gen_ai.completion": "hi",
        },
    )
    assert ev.event_type == EventType.LLM_GENERATION
    assert ev.actor.model == "claude-sonnet-5"
    # Content hashed by default, not stored raw.
    assert ev.input["prompt"]["redacted"] is True
    assert "hello" not in str(ev.input)


def test_span_to_event_tool():
    ev = span_to_event(
        "execute_tool sanctions_lookup",
        {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "sanctions_lookup"},
    )
    assert ev.event_type == EventType.TOOL_CALL
    assert ev.input["tool"] == "sanctions_lookup"


def test_span_to_event_ignores_non_genai():
    assert span_to_event("GET /health", {"http.method": "GET"}) is None


def test_span_content_opt_in_raw():
    ev = span_to_event(
        "chat m", {"gen_ai.system": "x", "gen_ai.prompt": "secret"},
        redact_content=False,
    )
    assert ev.input["prompt"] == {"text": "secret"}


# --- OTel exporter against the real SDK ------------------------------------
def test_audit_span_exporter_end_to_end():
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    from agentaudit.integrations.otel import AuditSpanExporter

    log = AuditLog(signing_key=SigningKey.generate())
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(AuditSpanExporter(log, framework="crewai")))
    tracer = provider.get_tracer("t")

    with tracer.start_as_current_span("chat m") as s:
        s.set_attribute("gen_ai.operation.name", "chat")
        s.set_attribute("gen_ai.request.model", "claude-sonnet-5")
        s.set_attribute("gen_ai.completion", "ok")

    entries = log.entries()
    assert len(entries) == 1
    assert entries[0].actor["framework"] == "crewai"
    assert verify_chain(entries).ok


# --- LangChain adapter ------------------------------------------------------
def test_langchain_handler_records_llm_tool_and_finish():
    from agentaudit.integrations.langchain import AuditCallbackHandler

    log = AuditLog()
    h = AuditCallbackHandler(log, agent_id="kyc")

    rid = uuid4()
    h.on_llm_start({"name": "ChatAnthropic"}, ["classify"], run_id=rid)
    resp = SimpleNamespace(
        generations=[[SimpleNamespace(text="approve")]],
        llm_output={"model_name": "claude-sonnet-5"},
    )
    h.on_llm_end(resp, run_id=rid)

    tid = uuid4()
    h.on_tool_start({"name": "sanctions_lookup"}, "Jane", run_id=tid)
    h.on_tool_end("no match", run_id=tid)
    h.on_agent_finish(SimpleNamespace(return_values={"output": "approve"}), run_id=uuid4())

    types = [e.event_type for e in log.entries()]
    assert types == ["llm_generation", "tool_call", "decision"]
    assert log.entries()[0].actor["model"] == "claude-sonnet-5"
    # PII in the tool input is hashed.
    assert "Jane" not in str(log.entries()[1].input)


def test_langchain_handler_stamps_policy_and_controls():
    from agentaudit import PolicyRef
    from agentaudit.integrations.langchain import AuditCallbackHandler

    log = AuditLog()
    h = AuditCallbackHandler(
        log, agent_id="kyc", policy_ref=PolicyRef("kyc-uk-2026", "1.4.2"),
        control_mapping=["EU-AI-Act-Art13"],
    )
    tid = uuid4()
    h.on_tool_start({"name": "sanctions"}, "x", run_id=tid)
    h.on_tool_end("ok", run_id=tid)
    e = log.entries()[0]
    assert e.policy_ref == {"policy_id": "kyc-uk-2026", "version": "1.4.2", "hash": None}
    assert e.control_mapping == ["EU-AI-Act-Art13"]


def test_langchain_real_dispatch_records_events():
    """Drive the handler through LangChain's actual callback machinery."""
    import pytest

    pytest.importorskip("langchain_core")
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool

    from agentaudit.bundle import export_bundle, verify_bundle
    from agentaudit.integrations.langchain import AuditCallbackHandler

    log = AuditLog(signing_key=SigningKey.generate())
    handler = AuditCallbackHandler(log, agent_id="kyc")
    cfg = {"callbacks": [handler]}

    @tool
    def screen(name: str) -> str:
        """Sanctions screen."""
        return "no match"

    model = GenericFakeChatModel(messages=iter([AIMessage(content="approve")]))
    model.invoke("assess risk", config=cfg)
    screen.invoke({"name": "Jane"}, config=cfg)

    types = [e.event_type for e in log.entries()]
    assert types == ["llm_generation", "tool_call"]
    assert verify_bundle(export_bundle(log)).ok
    # Content hashed by default -> no PII leaks through LangChain.
    assert "Jane" not in str(log.entries())


# --- CrewAI adapter ---------------------------------------------------------
def test_crewai_callbacks():
    from agentaudit.integrations.crewai import make_step_callback, make_task_callback

    log = AuditLog()
    step = make_step_callback(log, agent_id="researcher")
    task = make_task_callback(log, agent_id="researcher")

    step(SimpleNamespace(tool="web_search", tool_input="uk sanctions list"))
    step(SimpleNamespace(result="3 hits"))
    task(SimpleNamespace(raw="cleared", name="screening", agent="researcher"))

    types = [e.event_type for e in log.entries()]
    assert types == ["tool_call", "decision", "decision"]
    assert verify_chain(log.entries()).ok
