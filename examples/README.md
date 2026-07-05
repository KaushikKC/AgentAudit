# Examples

## KYC document-checker (`kyc_demo.py`)

The flagship reference demo (differentiator **D4**). An agent runs Know-Your-Customer
checks on two applicants — one clean, one on a sanctions list — under a *pinned policy
version*, and produces a regulator-ready, offline-verifiable evidence bundle.

```bash
python examples/kyc_demo.py            # run, seal, verify, and show tamper-evidence
python examples/kyc_demo.py -o kyc.json
agentaudit verify kyc.json            # verify the exported bundle independently
```

What it demonstrates in ~2 seconds, no LLM or framework install required:

- **Every step is recorded** — document parse, sanctions screen, and the final decision —
  each chained, Merkle-committed, and Ed25519-signed.
- **PII never enters the log in the clear** — inputs are stored as a salted hash + a
  sensitivity class; the *decision*, *confidence*, and *policy version* stay fully auditable.
- **`policy_ref` proves which policy version governed the decision** (id + version + content hash).
- **The bundle self-describes its regulatory coverage** — EU AI Act / NIST AI RMF / ISO 42001.
- **Tampering is caught** — flipping the sanctioned applicant's `route_to_human` to `approve`
  makes offline verification fail and names the altered entry.

## Selective disclosure (`selective_disclosure_demo.py`)

Differentiator **D3**. An agent records a decision whose input is full of PII. The
tamper-evident log commits to that input **without storing it**; later the operator proves
one field (`document_id`) to an auditor while `full_name` and `date_of_birth` stay sealed
and unguessable. The exported bundle contains **no raw PII at all**, yet stays fully verifiable.

```bash
python examples/selective_disclosure_demo.py
```

## External anchoring (`anchoring_demo.py`)

Local signing proves *who* vouched for a Merkle root; anchoring proves it to a party the
operator can't overrule. This shows the offline **witness** backend (an independent cosigner
whose receipt verifies offline against its pinned key). The same `log.seal(anchor=...)` call
also takes `RekorAnchor` to write the root into Sigstore's public transparency log.

```bash
python examples/anchoring_demo.py
```

## Real LangChain KYC run (`langchain_kyc_demo.py`)

Differentiator **D1**, end-to-end. Drives **genuine LangChain primitives** (a chat model +
`@tool` functions) through LangChain's real callback dispatch with `AuditCallbackHandler`
attached — every LLM/tool call becomes a policy-bound, control-mapped, tamper-evident entry,
with no change to the agent's own code beyond passing the callback.

```bash
pip install "agentaudit[langchain]"
python examples/langchain_kyc_demo.py           # deterministic fake model, no API key
ANTHROPIC_API_KEY=... python examples/langchain_kyc_demo.py   # real Claude (needs langchain-anthropic)
```

## Production hardening (`production_hardening_demo.py`)

The operational features for actually running the engine: a signing key **encrypted at rest**
(or a KMS), **automatic sealing** on an event/time threshold (no manual `.seal()`), a background
witness anchor, and a context manager that flushes a final checkpoint on exit.

```bash
python examples/production_hardening_demo.py
```

## Framework instrumentation (D1)

The `log.record(...)` calls in `kyc_demo.py` are the manual form of what the framework
adapters do automatically. See `agentaudit.integrations`:

- **OpenTelemetry** (`integrations.otel.AuditSpanExporter`) — the neutral core; any stack
  emitting GenAI semantic-convention spans becomes an audit trail.
- **LangChain** (`integrations.langchain.AuditCallbackHandler`) — drop into any run's callbacks.
- **CrewAI** (`integrations.crewai.make_step_callback` / `make_task_callback`).

Content is hashed by default so instrumentation never leaks PII.
