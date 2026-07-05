# AgentAudit

**Tamper-evident, cryptographically verifiable audit trails for AI agents.**

![status](https://img.shields.io/badge/status-alpha-orange)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-Apache--2.0-green)
![tests](https://img.shields.io/badge/tests-146%20passing-brightgreen)

AgentAudit is open-source middleware that records every agent decision, tool call, input, and
output into a cryptographically tamper-evident, signed, and exportable record. It is the
evidence a regulated firm can hand to a regulator or an enterprise customer when they ask a
simple question: *"Prove what your agent did, and prove you did not change the record after the
fact."*

Today, for most teams, the honest answer to that question is "we cannot." AgentAudit changes the
answer to "here is the proof, and you can verify it yourself, offline, without trusting us."

> Scope, stated plainly: AgentAudit proves that a record is authentic and unaltered, and which
> policy version governed a decision. It does not prove that the decision was correct, and it is
> not a legal compliance certification. Honesty about scope is deliberate. See
> [What it proves and what it does not](#what-it-proves-and-what-it-does-not).

---

## Table of contents

1. [Why this exists](#why-this-exists)
2. [Why now](#why-now)
3. [Feature overview](#feature-overview)
4. [How the cryptography works](#how-the-cryptography-works)
5. [Architecture](#architecture)
6. [Installation](#installation)
7. [Quickstart](#quickstart)
8. [The live end-to-end flow](#the-live-end-to-end-flow)
9. [Framework instrumentation (D1)](#framework-instrumentation-d1)
10. [Selective disclosure (D3)](#selective-disclosure-d3)
11. [External anchoring](#external-anchoring)
12. [Running it in production](#running-it-in-production)
13. [The evidence bundle format](#the-evidence-bundle-format)
14. [Regulatory control mapping (D2)](#regulatory-control-mapping-d2)
15. [Performance](#performance)
16. [What it proves and what it does not](#what-it-proves-and-what-it-does-not)
17. [Package layout](#package-layout)
18. [Command line reference](#command-line-reference)
19. [Examples](#examples)
20. [Testing](#testing)
21. [Roadmap and what is missing for production](#roadmap-and-what-is-missing-for-production)
22. [Contributing](#contributing)
23. [License](#license)

---

## Why this exists

An AI agent calls an API, updates a record, sends an email, or triggers a downstream workflow,
usually with no durable, trustworthy record of what it decided and why. Existing logs fail in
three ways:

1. **They are mutable.** A row in Postgres or a line in a file can be edited afterward. A
   regulator cannot trust "we did not change it."
2. **They are unstructured.** Free-text traces do not tie a decision to the policy version, the
   inputs, or the model that produced it.
3. **They are framework-siloed.** LangChain, CrewAI, AutoGen, and the OpenAI Agents SDK each emit
   their own trace format, so a team running several of them cannot govern them uniformly.

The market's named failure mode is "paper governance": the governance framework lives in a PDF
that nobody checks, with no connection to the running system. AgentAudit is the opposite of
paper. It produces live, runtime, cryptographically verifiable evidence as a byproduct of the
agent doing its normal job.

```
record  ->  hash-chain  ->  Merkle tree  ->  Ed25519 sign  ->  external anchor  ->  export  ->  verify offline
events      per-entry       32-byte           who vouched       provable time        self          trust
            integrity       commitment         for it            and witness          contained     nothing
```

## Why now

Evaluation and observability are the single largest blocker to agents reaching production.
Enterprises have raised budgets specifically for this category. The EU AI Act's high-risk
obligations become enforceable on **2 August 2026**, with penalties reaching 35 million euros or
7 percent of global turnover. Agent oversight is a greenfield category with few established
players. AgentAudit targets exactly the evidence those obligations require.

## Feature overview

| Capability | What it gives you | Status |
| --- | --- | --- |
| Append-only hash chain | Per-session integrity and ordering | Done |
| RFC 6962 Merkle tree | 32-byte commitment plus O(log n) inclusion and consistency proofs | Done |
| Ed25519 signing | Non-repudiable checkpoints | Done |
| Offline verifier (D5) | "Trust nothing" verification of a self-contained evidence bundle | Done |
| Framework instrumentation (D1) | One audit format for LangChain, CrewAI, and any OpenTelemetry stack | Done |
| Regulation-mapped export (D2) | EU AI Act, NIST AI RMF, and ISO 42001 control mapping in the bundle | Done |
| Selective disclosure (D3) | Prove one field, keep the rest sealed and unguessable | Done |
| KYC reference demo (D4) | A runnable agent that produces a regulator-ready bundle | Done |
| External anchoring | Independent witness cosigning plus Sigstore Rekor, both offline-verifiable | Done |
| Live dashboard | Watch real sessions verify, and watch a tamper get caught | Done |
| Production hardening | Encrypted-at-rest keys, automated sealing, thread-safe pluggable storage | Done |

## How the cryptography works

Three well-established primitives from the Certificate Transparency and Sigstore lineage. These
are proven constructions, not invented ones.

**1. Append-only hash chain (per-session integrity).** Every event is serialized deterministically
(canonical JSON) and hashed with SHA-256. Each entry includes the hash of the previous entry, so
altering entry `i` changes every hash after it.

```
entry_hash[i] = SHA256( canonical(entry[i]) )     where entry[i] contains prev_hash = entry_hash[i-1]
```

**2. Merkle tree (efficient proofs and tamper-evidence).** A Merkle tree over the entry hashes
commits the entire log state in a single 32-byte root. We follow RFC 6962 exactly, including the
domain-separation prefixes (0x00 for leaves, 0x01 for internal nodes) that defend against
second-preimage and node-versus-leaf confusion attacks. Two proof types, both O(log n):

* **Inclusion proof:** prove that event number k is in the log by revealing only the sibling
  hashes on the path to the root. A log of 80 million events needs a proof of roughly 3 KB.
* **Consistency proof:** prove that the log at time T2 is an append-only extension of the log at
  time T1, so history was never rewritten, only appended.

The Merkle engine matches the published RFC 6962 known-answer test vectors, including the
canonical eight-leaf root `5dc9da79...`. See `tests/test_merkle.py`.

**3. Signing and external anchoring (non-repudiation and provable time).** Each sealed Merkle
root is signed with an Ed25519 key so its origin is provable and the signer cannot deny it.
Because local signing alone cannot stop a key-holder from re-signing a rewritten history, each
root is also anchored to an external location the operator cannot backdate: an independent witness
cosigner, or the Sigstore Rekor public transparency log. Anchoring provides provable time and
third-party non-repudiation.

**Performance detail.** Recording an event updates an incremental Merkle tree (a Merkle Mountain
Range frontier) that keeps the root in O(log n) per append, so ingestion is linear rather than
quadratic.

## Architecture

```
   Instrumented agent (any framework)                 AgentAudit SDK
   LangChain / CrewAI / AutoGen / OpenAI Agents  ->    (thin, in-process)
        emits spans via OpenTelemetry                       |
        GenAI semantic conventions                          | canonical serialize + hash-chain
                                                            v
   Storage (append-only, WORM style)  <----------  Audit Log Engine  ---------->  External Anchor
   SQLite triggers / Postgres /                     hash chain                    Witness cosigner
   object-lock object store                         Merkle builder (incremental)  or Sigstore Rekor
        |                                           Ed25519 signer                (provable time)
        |
        v
   Verifier, Exporter, and Dashboard
     verify inclusion and consistency proofs offline
     export a regulator-ready evidence bundle (events plus proofs plus anchor receipt)
     map events to EU AI Act, NIST AI RMF, and ISO 42001 controls
     live web dashboard to inspect and verify sessions
```

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/KaushikKC/AgentAudit.git
cd AgentAudit
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,all]"
```

Optional extras, install only what you use:

| Extra | Pulls in | For |
| --- | --- | --- |
| `dev` | pytest, ruff, mypy | development and tests |
| `otel` | opentelemetry-sdk | the OpenTelemetry exporter |
| `langchain` | langchain-core | the LangChain callback handler |
| `crewai` | crewai | the CrewAI callbacks |
| `rekor` | certifi | Sigstore Rekor anchoring over TLS |
| `all` | all of the above | everything |

> The `agentaudit` console script installs into your user scripts directory. Inside a virtual
> environment it is on your PATH automatically. Otherwise use `python3 -m agentaudit.cli ...` in
> place of `agentaudit`.

## Quickstart

Command line, the 60-second story:

```bash
agentaudit demo -o bundle.json      # record, sign, seal, and export
agentaudit verify bundle.json       # independently verify offline, prints PASS
agentaudit tamper bundle.json       # flip one field, verification fails and names the entry
```

In code:

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

checkpoint = log.seal()             # signed 32-byte Merkle root over the whole session

from agentaudit.bundle import export_bundle, verify_bundle
bundle = export_bundle(log)         # self-contained, offline-verifiable evidence
assert verify_bundle(bundle).ok     # anyone can re-derive every claim from scratch
```

## The live end-to-end flow

To see the system working on real data (not seeded demo data), run an agent that logs to disk in
one terminal, and watch the dashboard in another.

```bash
# terminal 1: a KYC agent processes applicants, writing real sessions to live.db
python examples/live_kyc_stream.py --db live.db --interval 3

# terminal 2: watch them appear, verify, and (if you tamper) fail
python -m agentaudit.cli serve --db live.db --no-seed
# then open http://127.0.0.1:8000
```

The sidebar auto-refreshes as new sessions land. Click any session to see its real events, signed
checkpoint, external anchor, and a live verification result. Use **Simulate tamper** to run a real
re-verification that fails and names the altered entry. The on-disk log is never mutated, which is
the point: a sealed record cannot actually be corrupted without detection.

Running `agentaudit serve` without `--no-seed` seeds two demo sessions so the dashboard is never
empty on first run.

## Framework instrumentation (D1)

One audit format across a mixed agent fleet. AgentAudit sits on OpenTelemetry's GenAI semantic
conventions (the `gen_ai.*` span attributes), so any stack that emits those spans flows into one
tamper-evident format. Thin native adapters cover the popular frameworks directly.

```python
# Any framework, via OpenTelemetry: spans become audit entries automatically
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from agentaudit.integrations.otel import AuditSpanExporter

provider.add_span_processor(SimpleSpanProcessor(AuditSpanExporter(log)))

# LangChain: drop the handler into any run, optionally policy-bound
from agentaudit.integrations.langchain import AuditCallbackHandler
handler = AuditCallbackHandler(log, policy_ref=policy, control_mapping=["EU-AI-Act-Art13"])
agent.invoke(inputs, config={"callbacks": [handler]})

# CrewAI: stable step and task hooks
from agentaudit.integrations.crewai import make_step_callback, make_task_callback
Crew(..., step_callback=make_step_callback(log), task_callback=make_task_callback(log))
```

Prompt and tool content is hashed by default, so turning on auditing never turns your traces into
a PII liability. See `examples/langchain_kyc_demo.py` for a full run against real LangChain, with a
deterministic fake model by default and real Claude when an API key is present.

## Selective disclosure (D3)

Real audit data is full of PII. AgentAudit commits each field under a salted per-field Merkle root,
so you can later reveal exactly one field and prove it is authentic and in the log, while every
other field stays sealed and unguessable.

```python
log.record(AuditEvent(..., input={"name": "Jane", "dob": "1990-05-01",
                                  "document_id": "P1234567"}), redact_keys=["input"])
log.seal()

excerpt = log.make_disclosure(seq=0, reveal_paths=["input.document_id"])

from agentaudit.verifier import verify_disclosure
verify_disclosure(excerpt).ok      # True: document_id proven, name and dob never revealed
```

The exported bundle contains no raw PII at all, only the commitment, yet remains fully verifiable.
This directly answers the enterprise objection "we cannot put customer data in your tool." The
honest scope: this hides field values, not the set of field paths (the shape of the record is
visible).

## External anchoring

Local signing proves who vouched for a root. Anchoring proves it to a party the operator cannot
overrule, adding provable time and third-party non-repudiation.

```python
from agentaudit.anchoring import WitnessLog        # independent, offline-verifiable cosigner
checkpoint = log.seal(anchor=WitnessLog())

# or the Sigstore Rekor public transparency log:
from agentaudit.anchoring.rekor import RekorAnchor
checkpoint = log.seal(anchor=RekorAnchor())        # writes a permanent public entry
```

The witness backend attests to each root with an independent key and verifies fully offline (pin
its published key). The Rekor backend records the root in Sigstore's public log, stamps it with
provable time, and its receipt verifies offline by checking the Signed Entry Timestamp against
Rekor's log key. Either receipt travels inside the evidence bundle. See
`examples/anchoring_demo.py`.

The Rekor path is validated against the live public log. A real AgentAudit anchor exists at
log index 2064169373.

## Running it in production

Operational hardening beyond the cryptography:

```python
from agentaudit import AuditLog, SealPolicy, EncryptedFileKeyProvider
from agentaudit.anchoring import WitnessLog

log = AuditLog(
    key_provider=EncryptedFileKeyProvider("signing.key.pem"),   # key encrypted at rest, or a KMS
    seal_policy=SealPolicy(every_n_events=1000, every_seconds=60),  # auto-seal, no manual call
    auto_anchor=WitnessLog(),                                   # each checkpoint externally anchored
)
with log:                      # background sealer runs, a final checkpoint flushes on exit
    ...                        # log.record(...) as events happen
```

* **Key management.** Signing is done through a `KeyProvider`, so the private key lives in a
  password-encrypted file (permissions 0600) or a KMS or HSM (subclass `KeyProvider.sign`), never
  hard-coded and never trapped in process memory only.
* **Automated sealing.** `SealPolicy` seals every N events and every T seconds on a background
  thread. The engine and the SQLite store are thread-safe.
* **Pluggable storage.** `StorageBackend` is a formal interface. `SQLiteStore` (append-only via
  triggers) is the reference implementation. A Postgres or object-lock (WORM) backend drops in
  without touching the engine.

See `examples/production_hardening_demo.py`.

## The evidence bundle format

An evidence bundle is a single self-verifying JSON file that a regulator or auditor can check
offline, without the AgentAudit service running and without trusting the operator. It contains
everything needed to re-derive every claim from scratch.

| Field | Contents |
| --- | --- |
| `manifest` | Format version, session id, entry count, and how to verify |
| `checkpoint` | The sealed, signed Merkle root, plus the anchor receipt |
| `entries` | The full hash-chained log entries (redacted fields carry only a commitment) |
| `inclusion` | An inclusion proof per entry, resolving to the sealed root |
| `controls` | The union of regulatory controls referenced, expanded with titles and framework |

`verify_bundle` reproduces the chain, the Merkle root, the signature, every inclusion proof, and
the offline anchor, and returns a structured pass or fail with per-check detail.

## Regulatory control mapping (D2)

A tamper-evident log proves integrity. A compliance team also needs to know which obligation each
event speaks to. Events carry short control identifiers (for example `EU-AI-Act-Art14`), and the
exporter expands them into human-readable titles and their source framework, so a bundle is
self-describing.

Frameworks currently mapped: EU AI Act (Articles 12, 13, 14, 15), NIST AI RMF (Govern, Measure,
Manage functions), and ISO/IEC 42001 (operation records). See `agentaudit/controls.py`. This maps
evidence to controls. It is not legal advice and not a certification.

## Performance

Recording events is linear, not quadratic. An incremental Merkle tree keeps the RFC 6962 root in
O(log n) per append, and cached chain state removes any per-append full-log rescan, so per-record
time stays flat as the log grows.

```
   events        per record          rate
    1,000           26.7 us      about 37,000 records/second
   50,000           26.8 us      about 37,000 records/second      (flat, so O(n) ingest)
```

Run `python examples/benchmark.py` to reproduce. The engine is thread-safe: concurrent `record`
calls serialize on a lock and still produce one valid, contiguous chain. Throughput is now bounded
by per-record durable storage, not by the cryptography.

## What it proves and what it does not

Stating this plainly earns trust in this market.

* **Detects:** post-hoc edits, deletions, reordering, and silent truncation (via consistency
  proofs).
* **Proves:** which policy version an agent applied at decision time, and who signed the record.
* **Adds, via anchoring:** provable time and third-party non-repudiation, so a key-holder cannot
  quietly re-sign a rewritten history, up to the trust of the witness or Rekor key.
* **Does not prevent:** an attacker who controls the signing key going forward, beyond what
  anchoring and (future) forward-secure ratcheting mitigate.
* **Does not verify:** that the agent's decision was correct. That is the evaluation layer. Only
  that the record of the decision is authentic and unaltered.
* **Is not:** a legal compliance certification.

## Package layout

| Module | Responsibility |
| --- | --- |
| `agentaudit.crypto.canonical` | Deterministic canonical JSON so hashes are reproducible |
| `agentaudit.crypto.merkle` | RFC 6962 Merkle tree, inclusion and consistency proofs, incremental tree |
| `agentaudit.crypto.signing` | Ed25519 sign and verify, key management |
| `agentaudit.schema` | `AuditEvent`, `LogEntry`, `PolicyRef`, the data model |
| `agentaudit.storage` | Thread-safe append-only SQLite plus the `StorageBackend` interface |
| `agentaudit.keys` | Pluggable `KeyProvider`: local, encrypted-file, KMS-ready |
| `agentaudit.log` | The `AuditLog` engine: record, seal, prove, auto-seal |
| `agentaudit.verifier` | Offline, trust-nothing verification |
| `agentaudit.bundle` | Self-contained evidence bundle: export and verify |
| `agentaudit.controls` | Regulatory control catalog and bundle enrichment |
| `agentaudit.redaction` | Selective disclosure: salted per-field Merkle commitments |
| `agentaudit.anchoring` | External anchoring: witness cosigning and Sigstore Rekor |
| `agentaudit.integrations` | Framework adapters: OpenTelemetry, LangChain, CrewAI |
| `agentaudit.dashboard` | Local web dashboard, backed by live verification |
| `agentaudit.cli` | The `agentaudit` command line |

## Command line reference

```
agentaudit demo   [-o BUNDLE] [--anchor witness]   record a demo session and seal it
agentaudit verify BUNDLE                            verify an evidence bundle offline
agentaudit tamper BUNDLE [--seq N]                  mutate a bundle and show it fail
agentaudit serve  [--db PATH] [--port N] [--no-seed]  launch the local dashboard
```

## Examples

| File | Shows |
| --- | --- |
| `examples/kyc_demo.py` | KYC reference demo that produces a regulator-ready bundle (D4) |
| `examples/live_kyc_stream.py` | A real agent stream feeding the live dashboard |
| `examples/selective_disclosure_demo.py` | Prove one field, hide the rest (D3) |
| `examples/anchoring_demo.py` | Witness anchoring and offline verification |
| `examples/langchain_kyc_demo.py` | Real LangChain instrumentation (D1) |
| `examples/production_hardening_demo.py` | Encrypted key, automated sealing, anchoring |
| `examples/benchmark.py` | Ingestion throughput benchmark |

## Testing

```bash
pytest -q                                     # 146 passing, 1 skipped
pytest --cov=agentaudit                        # with coverage
AGENTAUDIT_TEST_REKOR=1 pytest tests/test_anchoring.py   # also hit the live Rekor log
ruff check
mypy src/agentaudit
```

The suite covers RFC 6962 Merkle against published vectors, tamper detection (edit, delete,
reorder, truncate, and re-chained forgery), selective disclosure, witness and offline Rekor SET
verification, the framework adapters, the dashboard data layer and a live HTTP round-trip,
incremental-engine correctness and thread-safety, and the key, seal, and storage hardening. Tests
never write to the public Rekor log unless `AGENTAUDIT_TEST_REKOR=1` is set.

## Roadmap and what is missing for production

The cryptographic core, all five differentiators, external anchoring, the dashboard, the
performance work, and the operational hardening are done and tested. The following items remain
before this is a fully production-grade, deployable product.

**Storage and durability**
* Postgres backend with database-level immutability, and S3 Object Lock (WORM) for payloads.
* Backups, replication, retention and legal-hold policies, and cold archival.
* Right-to-erasure reconciliation: erase the PII payload while keeping the commitment.

**Ingestion at scale**
* An out-of-process collector service (HTTP or gRPC) with auth, batching, backpressure, and
  idempotency. Ingestion is in-process SDK only today.
* Batched commits, sharding by session, and multi-writer support.

**Key management and crypto hardening**
* Real KMS and HSM providers (AWS KMS, GCP KMS, Vault), automated key rotation, and forward-secure
  key ratcheting.
* Full offline Rekor inclusion-proof verification against a monitored signed tree head, plus log
  monitoring.

**Security and compliance**
* A formal threat-model document, dependency scanning, an SBOM, signed releases, parser fuzzing,
  and an external security review.
* Multi-tenancy, authentication and authorization, RBAC over who can read reasoning and PII, and
  access logging of the audit system itself.
* Deeper control mappings, per-regulation evidence templates, and exportable compliance reports.

**Operations and reliability**
* Self-observability: metrics, health and readiness endpoints, and alerting on seal or anchor
  failures.
* Retry and backoff with dead-letter handling for anchoring, graceful shutdown, and faster crash
  recovery.
* Dashboard hardening: authentication, TLS, pagination, and RBAC. It is a local dev tool today.

**Ecosystem and distribution**
* A PyPI release with semantic versioning, a changelog, and a versioned bundle format with
  migrations.
* A dependency-free standalone verifier binary (Rust or Go), a JS or TS SDK for Node agents, and
  native AutoGen and OpenAI Agents SDK adapters.
* A Docker image, a Helm chart, and a hosted documentation site.

A living, more detailed plan lives in [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md).

## Contributing

Issues and pull requests are welcome. Please run `pytest`, `ruff check`, and `mypy src/agentaudit`
before opening a pull request. New behavior should ship with tests. If you touch the cryptographic
core, add property tests and, where relevant, known-answer vectors: a fast implementation that
computes the wrong root is worse than a slow one.

## License

Apache-2.0. See [LICENSE](LICENSE).
