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


class AuditCallbackHandler(_Base):  # type: ignore[misc]
    """Maps LangChain callbacks onto :class:`AuditEvent` records."""

    # LangChain inspects this to decide whether to serialize inputs to the handler.
    raise_error = True

    def __init__(
        self,
        log: AuditLog,
        agent_id: str = "langchain-agent",
        redact_content: bool = True,
        policy_ref: Optional[PolicyRef] = None,
        control_mapping: Optional[List[str]] = None,
    ) -> None:
        self.log = log
        self.agent_id = agent_id
        self.redact_content = redact_content
        # Optional governance context stamped onto every recorded event, so a
        # LangChain run produces policy-bound, control-mapped evidence.
        self.policy_ref = policy_ref
        self.control_mapping = list(control_mapping or [])
        # Per-run scratch so we can pair *_start payloads with *_end results.
        self._pending: Dict[str, Dict[str, Any]] = {}

    def _event(self, event_type: EventType, actor: Actor, **kw: Any) -> AuditEvent:
        return AuditEvent(event_type=event_type, actor=actor, policy_ref=self.policy_ref,
                          control_mapping=list(self.control_mapping), **kw)

    def _actor(self, model: Optional[str] = None) -> Actor:
        return Actor(agent_id=self.agent_id, framework="langchain", model=model)

    @staticmethod
    def _key(run_id: Optional[UUID]) -> str:
        return str(run_id) if run_id is not None else "-"

    # -- LLM ---------------------------------------------------------------
    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str],
                     *, run_id: Optional[UUID] = None, **kwargs: Any) -> None:
        self._pending[self._key(run_id)] = {
            "prompt": "\n".join(prompts),
            "model": (serialized or {}).get("name") or kwargs.get("invocation_params", {}).get("model"),
        }

    def on_chat_model_start(self, serialized: Dict[str, Any], messages: Any,
                            *, run_id: Optional[UUID] = None, **kwargs: Any) -> None:
        # Flatten chat messages to text for hashing/length only.
        flat = str(messages)
        self._pending[self._key(run_id)] = {
            "prompt": flat,
            "model": (serialized or {}).get("name"),
        }

    def on_llm_end(self, response: Any, *, run_id: Optional[UUID] = None,
                   **kwargs: Any) -> None:
        pend = self._pending.pop(self._key(run_id), {})
        text = _llm_result_text(response)
        # Prefer the concrete model reported in the result over the LLM class name.
        model = _llm_result_model(response) or pend.get("model")
        self.log.record(self._event(
            EventType.LLM_GENERATION,
            self._actor(model),
            input={"prompt": _content(pend.get("prompt", ""), self.redact_content)},
            output={"completion": _content(text, self.redact_content)},
        ))

    # -- Tools -------------------------------------------------------------
    def on_tool_start(self, serialized: Dict[str, Any], input_str: str,
                      *, run_id: Optional[UUID] = None, **kwargs: Any) -> None:
        self._pending[self._key(run_id)] = {
            "tool": (serialized or {}).get("name", "tool"),
            "input": input_str,
        }

    def on_tool_end(self, output: Any, *, run_id: Optional[UUID] = None,
                    **kwargs: Any) -> None:
        pend = self._pending.pop(self._key(run_id), {})
        self.log.record(self._event(
            EventType.TOOL_CALL,
            self._actor(),
            input={"tool": pend.get("tool", "tool"),
                   "args": _content(str(pend.get("input", "")), self.redact_content)},
            output={"result": _content(str(output), self.redact_content)},
        ))

    # -- Agent decisions ---------------------------------------------------
    def on_agent_action(self, action: Any, *, run_id: Optional[UUID] = None,
                        **kwargs: Any) -> None:
        self.log.record(self._event(
            EventType.DECISION,
            self._actor(),
            output={"tool": getattr(action, "tool", None),
                    "reasoning": _content(str(getattr(action, "log", "")),
                                          self.redact_content)},
        ))

    def on_agent_finish(self, finish: Any, *, run_id: Optional[UUID] = None,
                        **kwargs: Any) -> None:
        values = getattr(finish, "return_values", {}) or {}
        self.log.record(self._event(
            EventType.DECISION,
            self._actor(),
            output={"final": _content(str(values.get("output", values)),
                                      self.redact_content)},
        ))


def _llm_result_text(response: Any) -> str:
    """Best-effort extraction of generated text from a LangChain LLMResult."""
    try:
        gens = getattr(response, "generations", None)
        if gens:
            return " ".join(g.text for row in gens for g in row if getattr(g, "text", None))
    except Exception:  # pragma: no cover
        pass
    return str(response)


