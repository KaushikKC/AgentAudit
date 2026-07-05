"""Real LangChain KYC demo (differentiator D1, end-to-end).

Unlike ``kyc_demo.py`` (framework-neutral mock tools), this drives **genuine
LangChain primitives** -- a chat model and ``@tool`` functions invoked through
LangChain's real callback dispatch -- with :class:`AuditCallbackHandler`
attached. Every LLM call and tool call the framework makes becomes a
policy-bound, control-mapped, tamper-evident audit entry, with no changes to the
agent's own code beyond passing the callback.

By default it uses a deterministic fake chat model, so it runs offline with no
API key and is fully reproducible. Set ``ANTHROPIC_API_KEY`` (and
``pip install langchain-anthropic``) to run it against a real Claude model --
the instrumentation is identical.

Run it::

    pip install "agentaudit[langchain]"
    python examples/langchain_kyc_demo.py
"""

from __future__ import annotations

import os
import sys

from agentaudit import AuditLog, PolicyRef, SigningKey
from agentaudit.anchoring import WitnessLog
from agentaudit.bundle import export_bundle, verify_bundle

try:
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
except ImportError:
    print("This demo needs LangChain:  pip install 'agentaudit[langchain]'")
    raise SystemExit(1)

from agentaudit.integrations.langchain import AuditCallbackHandler

POLICY = PolicyRef(policy_id="kyc-uk-2026", version="1.4.2", hash="a1b2c3")


# --- real LangChain tools ---------------------------------------------------
@tool
def parse_documents(applicant: str) -> str:
    """Extract identity fields from an applicant's submitted documents."""
    return "identity_valid=true; documents=passport,utility_bill"


@tool
def sanctions_lookup(name: str) -> str:
    """Screen a name against UK-HMT / OFAC / EU sanctions lists."""
    return "match=false; lists=UK-HMT,OFAC,EU"


def _chat_model():
    """Real Claude when configured, else a deterministic fake (no API key)."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            from langchain_anthropic import ChatAnthropic

            print("model: ChatAnthropic(claude-sonnet-5)\n")
            return ChatAnthropic(model="claude-sonnet-5", temperature=0)
        except ImportError:
            print("(langchain-anthropic not installed; using fake model)\n")
    print("model: deterministic fake (set ANTHROPIC_API_KEY for real Claude)\n")
    return GenericFakeChatModel(messages=iter([
        AIMessage(content="Decision: approve. Identity valid, no sanctions match, "
                          "confidence 0.83 (>= 0.70 threshold).")
    ]))


def main() -> int:
    log = AuditLog(signing_key=SigningKey.generate())
    handler = AuditCallbackHandler(
        log, agent_id="kyc-checker-v3", policy_ref=POLICY,
        control_mapping=["EU-AI-Act-Art12", "EU-AI-Act-Art13"],
    )
    cfg = {"callbacks": [handler]}
    model = _chat_model()

    print("== Instrumented LangChain KYC run ==")
    parsed = parse_documents.invoke({"applicant": "Jane Applicant"}, config=cfg)
    print(f"  parse_documents  -> {parsed}")
    screen = sanctions_lookup.invoke({"name": "Jane Applicant"}, config=cfg)
    print(f"  sanctions_lookup -> {screen}")
    decision = model.invoke(
        f"Given {parsed} and {screen}, decide approve/route_to_human per KYC policy.",
        config=cfg,
    )
    print(f"  llm decision     -> {decision.content[:60]}...")

    checkpoint = log.seal(anchor=WitnessLog())
    print(f"\n== Evidence ==")
    print(f"  events recorded  {log.size()}  ({', '.join(e.event_type for e in log.entries())})")
    print(f"  every event bound to policy {POLICY.policy_id} v{POLICY.version}")
    print(f"  merkle root      {checkpoint.root_hash[:24]}…  (signed + witness-anchored)")

    bundle = export_bundle(log)
    print(f"  content in log   hashed (redact_content=True) — prompts/outputs never stored raw")
    result = verify_bundle(bundle)
    print(f"\n== Offline verification ==\n  {result.summary().splitlines()[0]}")

    # Tamper-evidence
    import json
    tampered = json.loads(json.dumps(bundle))
    tampered["entries"][0]["output"] = {"result": {"hash": "forged"}}
    caught = not verify_bundle(tampered).ok
    print(f"  tamper detected  {caught}")

    return 0 if result.ok and caught else 1


if __name__ == "__main__":
    sys.exit(main())
