# AgentAudit

**Tamper-evident, cryptographically verifiable audit trails for AI agents.**

> When a regulator or enterprise customer asks *"prove your agent applied the right
> policy at the time of this decision,"* the honest answer today is usually "we can't."
> AgentAudit makes the answer *"here — verify it yourself, offline, without trusting us."*

AgentAudit is open-source middleware that records every agent decision, tool call, input,
and output into a cryptographically **tamper-evident, signed, exportable** record — the
evidence a firm under the EU AI Act, FCA, or a customer security review can hand to an
auditor. It is the opposite of *"paper governance"* (a policy PDF nobody checks): live,
runtime, verifiable evidence generated as a byproduct of normal operation.

```
record ──▶ hash-chain ──▶ Merkle tree ──▶ Ed25519-sign ──▶ export ──▶ verify offline
 events     (per-entry     (32-byte        (who vouched     (self-      (trust nothing)
            integrity)     commitment)     for it)          contained)
```

---

## Why this exists

Existing agent logs fail three ways:

1. **Mutable** — a row in Postgres or a line in a file can be edited after the fact.
2. **Unstructured** — free-text traces don't tie a decision to the *policy version* that produced it.
3. **Framework-siloed** — LangChain, CrewAI, AutoGen, and the OpenAI Agents SDK each emit their own trace format.

AgentAudit fixes (1) with cryptography, (2) with a first-class `policy_ref` (id + version + hash),
and (3) by being framework-agnostic and OpenTelemetry-native.

## What it proves (and what it doesn't)

Honesty about scope is a trust multiplier in this market, so we state it plainly:

- ✅ **Detects** post-hoc edits, deletions, reordering, and silent truncation (via consistency proofs).
- ✅ **Proves** *which policy version* an agent applied at decision time, and *who* signed the record.
- ✅ **External anchoring** (independent witness cosigning + Sigstore Rekor) adds provable time and
  third-party non-repudiation, so a key-holder can't quietly re-sign a rewritten history — the gap
  local signing alone leaves. (Forward-secure key ratcheting is the remaining hardening step.)
- ⚠️ **Does not verify** that the agent's decision was *correct* — only that the record of it is
  *authentic and unaltered*. Correctness is the evaluation layer; we keep our scope honest.

## How the cryptography works

Three well-established primitives from the Certificate Transparency / Sigstore lineage — proven, not invented.

| Layer | Primitive | Gives you |
|---|---|---|
| **1. Hash chain** | `entry_hash[i] = SHA256(canonical(entry[i]))`, where `entry[i]` includes `prev_hash` | Per-session integrity + ordering; editing entry *i* breaks every hash after it |
| **2. Merkle tree** | RFC 6962 with domain separation (`0x00` leaf / `0x01` node) | A 32-byte root committing to the whole log; **inclusion** & **consistency** proofs, both O(log n) |
| **3. Signing + anchoring** | Ed25519 over each sealed root; (roadmap) Rekor / RFC-3161 anchor | Non-repudiation + provable time from a third party |

The Merkle engine matches the **published RFC 6962 test vectors** (see `tests/test_merkle.py`).

## Quickstart

```bash
pip install -e ".[dev]"     # or: pip install agentaudit  (once published)

agentaudit demo -o bundle.json   # record a session, seal a signed Merkle root, export
agentaudit verify bundle.json    # independently verify the bundle offline  ->  PASS
agentaudit tamper bundle.json    # flip one field and watch it get caught   ->  FAIL
```

### The dashboard

```bash
agentaudit serve      # → http://127.0.0.1:8000  (auto-seeds demo sessions on first run)
```

A self-contained local web app (stdlib only, no extra deps) to browse sessions, watch each
one verify live, see its signed checkpoint / external anchor / regulatory coverage, and hit
**Simulate tamper** to make the verdict flip green → red. Every status shown is a real
`verify_bundle` result, never a cached claim.

### The 2-minute "aha": a KYC agent that produces regulator-ready evidence

```bash
python examples/kyc_demo.py -o kyc.json
```

An agent runs Know-Your-Customer checks on two applicants under a *pinned policy version*,
records every step, and exports an offline-verifiable evidence bundle. PII never enters the
log in the clear; the decision, its confidence, and the governing policy version do. Flipping
the sanctioned applicant's `route_to_human` to `approve` is caught immediately. See
[`examples/`](examples/).

### In code

```python
from agentaudit import AuditLog, AuditEvent, Actor, PolicyRef, EventType, SigningKey

log = AuditLog(signing_key=SigningKey.generate())

log.record(AuditEvent(
    event_type=EventType.DECISION,
    actor=Actor(agent_id="kyc-checker-v3", framework="langchain", model="claude-sonnet-5"),
    policy_ref=PolicyRef(policy_id="kyc-uk-2026", version="1.4.2", hash="a1b2c3"),
    output={"decision": "approve", "confidence": 0.83},
    control_mapping=["EU-AI-Act-Art14", "NIST-MEASURE-2.3"],
))

checkpoint = log.seal()          # signed 32-byte Merkle root over the whole session

from agentaudit.bundle import export_bundle, verify_bundle
bundle = export_bundle(log)      # self-contained, offline-verifiable evidence
assert verify_bundle(bundle).ok  # anyone can re-derive every claim from scratch
```

## Framework-agnostic instrumentation (D1)

One audit format across a mixed agent fleet. Sit on OpenTelemetry's GenAI
semantic conventions (the neutral core), with thin adapters for popular frameworks:

```python
# Any framework, via OpenTelemetry — spans become audit entries automatically
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from agentaudit.integrations.otel import AuditSpanExporter

provider.add_span_processor(SimpleSpanProcessor(AuditSpanExporter(log)))

# LangChain — drop the handler into any run (optionally policy-bound)
from agentaudit.integrations.langchain import AuditCallbackHandler
handler = AuditCallbackHandler(log, policy_ref=policy, control_mapping=["EU-AI-Act-Art13"])
agent.invoke(inputs, config={"callbacks": [handler]})   # see examples/langchain_kyc_demo.py

# CrewAI — stable step/task hooks
from agentaudit.integrations.crewai import make_step_callback, make_task_callback
Crew(..., step_callback=make_step_callback(log), task_callback=make_task_callback(log))
```

Prompt/tool **content is hashed by default**, so switching on auditing never turns your
traces into a PII liability. Install only what you use: `pip install "agentaudit[otel]"`
(or `[langchain]`, `[crewai]`, `[all]`).

