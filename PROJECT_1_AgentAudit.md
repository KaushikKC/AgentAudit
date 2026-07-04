# AgentAudit — Tamper-Evident Audit Trail for AI Agents
### Deep technical build & differentiation plan

**What it is (one line):** open-source middleware that records every agent decision, tool call, input, and output into a cryptographically tamper-evident, signed, exportable record — the evidence an FCA/EU-AI-Act-regulated firm hands to a regulator or auditor.

**Why now:** Evaluation + observability is the single largest blocker to agents reaching production (cited as the top blocker in the 12% of pilots that convert). 71% of enterprises raised 2026 budget for eval/observability specifically. The EU AI Act's full high-risk obligations become enforceable **August 2, 2026** (fines up to €35M or 7% of global turnover). Gartner calls agent-oversight ("Guardian Agents") a greenfield category with almost no established players, and predicts 9-figure acquisitions Q3-2026→Q1-2027. This is the rare project that scores maximum on BOTH "gets attention" and "lands a job."

---

## 1. The core problem, precisely

An AI agent calls an API, updates a record, sends an email, triggers a downstream workflow — with no durable, trustworthy record of *what it decided and why*. When a regulator or enterprise customer asks "prove your agent applied the right policy at the time of this decision," the honest answer today is usually "we can't." Existing logs fail three ways:

1. **Mutable.** A log in Postgres or a file can be edited after the fact. A regulator cannot trust "we didn't change it."
2. **Unstructured.** Free-text traces don't map decisions to the policy/version/inputs that produced them.
3. **Framework-siloed.** Each agent framework (LangChain, CrewAI, AutoGen, OpenAI Agents SDK) has its own trace format; enterprises running several can't govern them uniformly.

The market's named failure mode is **"Paper Governance"** — the governance framework lives in a PDF; the running system has no connection to it. **AgentAudit's entire wedge is being the opposite of paper: live, runtime, cryptographically verifiable evidence generated as a byproduct of normal operation.**

---

## 2. How the cryptography actually works (the technical heart)

This is the part that makes it *real* and not a logging wrapper. Three layers, each a well-established primitive from Certificate Transparency / Sigstore lineage — proven, not invented.

### 2.1 Append-only hash chain (per-session integrity)
Every audit event is serialized deterministically (canonical JSON) and hashed with SHA-256. Each entry includes the hash of the previous entry:

```
entry_hash[i] = SHA256( canonical(event[i]) || entry_hash[i-1] )
```

This chains entries so that altering event *i* changes every hash after it. Use domain-separation prefixes on leaves vs nodes (0x00 for leaf, 0x01 for internal node — the RFC 6962 construction) to block second-preimage/leaf-node-confusion attacks. This detail signals you actually read the crypto literature.

### 2.2 Merkle tree (efficient proofs + tamper-evidence)
Build a Merkle tree over entries. The **root hash** commits to the entire log state in 32 bytes. Two proof types, both O(log n):

- **Inclusion proof:** prove "event #3 was in the log" by revealing only the sibling hashes up the path to the root (log₂N × 32 bytes) — the verifier re-hashes upward and checks it lands on the known root. Nothing else about the log is revealed. (Same trick CT uses to prove a TLS cert is logged without downloading the log; a log of 80M events needs only ~3KB of proof.)
- **Consistency proof:** prove the log at time T2 is an append-only extension of the log at T1 — i.e., history was never rewritten, only appended.

### 2.3 Signing + external anchoring (non-repudiation + trusted time)
- **Sign** each Merkle root (or each sealed batch) with an Ed25519 key so the origin is provable and the signer can't deny it.
- **Anchor externally.** Local signing alone has a limit: whoever holds the key can re-sign a rewritten history. The fix is anchoring the root to an *external* trusted location the operator can't backdate: a public transparency log (Sigstore Rekor / a C2SP tlog-checkpoint), an RFC-3161 timestamp authority (TSA), or — optional, opt-in — a public blockchain. Anchoring gives you *provable time* and *third-party non-repudiation* without the cost/latency of putting every event on-chain.
- **Forward-secure key ratcheting (advanced, phase 3):** rotate/erase the per-segment signing key after each seal so a *future* key compromise can't forge *past* entries.

### 2.4 Honest threat model (state this explicitly — it earns trust)
- Detects: post-hoc edits, deletions, reordering, silent truncation (via consistency proofs).
- Does NOT prevent: an attacker who controls the signing key *going forward* (mitigated by external anchoring + forward-secure ratcheting).
- Does NOT verify the agent's decision was *correct* — only that the record of it is *authentic and unaltered*. (Correctness is the eval layer; keep the scope honest.)

---

## 3. System architecture

```
   ┌─────────────────────────────────────────────────────────────┐
   │  Instrumented Agent (any framework)                          │
   │  LangChain / CrewAI / AutoGen / OpenAI Agents SDK / custom   │
   │      │ emits spans via OpenTelemetry semantic conventions    │
   └──────┼──────────────────────────────────────────────────────┘
          ▼
   ┌─────────────────────┐   canonical serialize + hash-chain
   │  AgentAudit SDK      │──────────────────────────────┐
   │  (thin, in-process)  │                              ▼
   └─────────────────────┘                    ┌────────────────────┐
                                              │  Audit Log Engine  │
   ┌─────────────────────┐  append-only       │  - hash chain      │
   │  Collector service  │◄───────────────────│  - Merkle builder  │
   │  (OTel-compatible)   │                    │  - Ed25519 signer  │
   └──────────┬──────────┘                    └─────────┬──────────┘
              │                                          │ root every N events / T seconds
              ▼                                          ▼
   ┌─────────────────────┐                    ┌────────────────────┐
   │  Storage            │                    │  External Anchor   │
   │  Postgres + object   │                    │  Rekor / TSA /     │
   │  store (WORM-mode)   │                    │  (opt) chain       │
   └─────────────────────┘                    └────────────────────┘
              │
              ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  Verifier CLI + Exporter                                     │
   │  - verify inclusion/consistency proofs offline              │
   │  - export regulator-ready evidence bundle (JSON + proofs)   │
   │  - map events → policy version → EU AI Act / NIST controls  │
   └─────────────────────────────────────────────────────────────┘
```

### The audit event schema (the data model that matters)
```json
{
  "event_id": "uuid",
  "session_id": "uuid",
  "seq": 42,
  "prev_hash": "hex-sha256",
  "timestamp": "RFC3339",
  "actor": { "agent_id": "kyc-checker-v3", "framework": "langchain", "model": "llama-3.1-8b", "model_version": "..." },
  "event_type": "tool_call | decision | llm_generation | retrieval | human_override",
  "policy_ref": { "policy_id": "kyc-uk-2026", "version": "1.4.2", "hash": "hex" },
  "input": { "redacted": true, "hash": "hex", "pii_class": "high" },
  "output": { "value_or_hash": "...", "confidence": 0.83 },
  "reasoning_ref": "hash-of-chain-of-thought (stored separately, access-controlled)",
  "control_mapping": ["EU-AI-Act-Art13", "NIST-MEASURE-2.3"],
  "entry_hash": "hex-sha256"
}
```
The `policy_ref` with version+hash is the killer field: it lets you prove *which policy version* the agent applied *at the time* — exactly what regulators ask and what "paper governance" can't answer.

---

## 4. How to be DIFFERENT (this is the section that matters)

Competitors already exist: `agentnotary` (cryptographic seal + EU-AI-Act docs), `Nobulex` (Ed25519 receipts, hash-chained), `nono` (Merkle pre/post filesystem roots), Microsoft's agent-governance-toolkit (Merkle audit chain), plus enterprise governance suites (Fiddler, Credo AI, Holistic AI). **You cannot win on "I also hash-chain events."** Here is where you differentiate, ranked by leverage:

**D1 — Framework-agnostic, OpenTelemetry-native.** The research names the exact gap: *no dominant standard for governance across LangChain, CrewAI, AutoGen, ADK, OpenAI Agents SDK — each builds its own tracing format.* Be the neutral layer that instruments ALL of them via OTel semantic conventions, so one audit format spans a mixed fleet. Most competitors are single-framework or bolted to one vendor. This is the strongest wedge.

**D2 — Regulation-mapped evidence export, not just logs.** Don't stop at "here's a tamper-evident log." Ship an **evidence bundle exporter** that maps each event to specific EU AI Act articles / NIST AI RMF functions / ISO 42001 controls, and produces a self-verifying package (events + inclusion proofs + anchor receipts + a standalone verifier) a regulator can check *offline* without your service running. Competitors log; you produce *admissible evidence*.

**D3 — Selective disclosure / redaction-preserving proofs.** Real audit data is full of PII. Naive systems either leak it or can't prove anything without revealing everything. Support **verifiable excerpts**: prove an event is in the log and prove properties of it (e.g., "confidence < 0.7 → routed to human") while keeping the raw PII sealed/hashed. This is a genuine technical contribution (Hartung-style redactable Merkle proofs) and directly answers the enterprise objection "we can't put customer data in your tool."

**D4 — The KYC-agent reference demo as a product artifact.** Ship a complete, runnable demo: a KYC document-checker agent, fully instrumented, that produces a regulator-ready audit bundle you can open and verify. FCA-recognizable workflow, two-minute "aha," screenshot-friendly. This is what makes it spread and what makes an interviewer say "you built the thing our customers ask for."

**D5 — Offline, dependency-free verifier.** A tiny standalone binary/script that verifies an evidence bundle with zero network and zero trust in you. Auditors love this; it's the difference between "trust our dashboard" and "verify it yourself." Very few competitors ship this.

---

## 5. Tech stack (chosen for credibility + speed)
- **Language:** Python for the SDK/collector (matches the agent ecosystem); Rust or Go for the verifier + Merkle engine if you want performance cred (the IoT-edge Merkle paper hit >130k logs/s, <5MB RAM — cite as your perf bar).
- **Instrumentation:** OpenTelemetry SDK + emerging LLM/agent semantic conventions.
- **Crypto:** `cryptography` (Ed25519), `hashlib` (SHA-256); BLAKE3 optional for speed. Merkle tree hand-rolled (it's ~150 lines and you want to own it).
- **Storage:** Postgres (append-only table, WORM/immutable via triggers or object-lock storage) + object store for large payloads.
- **Anchor:** Sigstore Rekor (free public transparency log) as default; RFC-3161 TSA as alt; blockchain anchor opt-in only.
- **Demo agent:** LangChain KYC checker + a couple of mock tools (doc parse, sanctions-list lookup).

---

## 6. Build plan (6 weeks, build-in-public, timed to the Aug 2 EU AI Act deadline)

**Week 0 — stake the claim.** Post the thesis: "Agent governance today is a PDF nobody checks. I'm building runtime, cryptographically verifiable agent audit trails — in public — ahead of the Aug 2 EU AI Act deadline." Repo skeleton + a killer README first screen (one-line pitch, the KYC demo GIF placeholder, "verify it yourself" promise).

**Weeks 1–2 — the core engine (thin vertical slice).** Hash-chain + Merkle tree + Ed25519 signing + append-only storage. SDK that wraps a LangChain agent and emits events. Milestone: run the KYC agent, produce a signed log, tamper with one entry, show the verifier catching it. Write-up #1: "How tamper-evident audit logs work (Merkle trees, inclusion proofs) — and why AI agents need them."

**Weeks 3–4 — differentiation layer.** Add (a) OTel-native multi-framework instrumentation (at least LangChain + one more), (b) the regulation-mapped evidence-bundle exporter, (c) the offline verifier. Milestone: export a KYC evidence bundle, verify it offline with the standalone tool. Write-up #2: "I built a regulator-ready evidence exporter for AI agents — mapped to the EU AI Act."

**Week 5 — external anchoring + selective disclosure.** Anchor roots to Rekor; add redaction-preserving inclusion proofs (D3). Milestone: prove an event's existence and a property of it *without revealing the PII*. Write-up #3 (the flagship, technically deepest): "Proving what your AI agent did — without leaking the customer's data."

**Week 6 — sequenced launch.** Perfect README first screen (pitch + KYC GIF + "verify offline" + one-command install). Primary launch on Hacker News ("Show HN: tamper-evident audit trails for AI agents, EU AI Act–ready") OR r/LocalLLaMA + r/MachineLearning; ONE secondary channel next day. Answer every comment fast for 48h. Tie the timing to the Aug 2 deadline for a news hook.

**Ongoing:** weekly commits, fast issue replies (maintainer responsiveness keeps threads alive), one short write-up per interesting problem hit.

---

## 7. What "success" looks like
- A repo an engineer can clone and run the KYC demo in <10 min.
- Three evergreen technical write-ups that keep pulling search traffic.
- A verifiable evidence bundle you can attach to job applications: "here's cryptographic proof my system works, verify it yourself."
- Direct mappability to named buyers (Robin AI, Luminance, ComplyAdvantage, Arva, etc.) — you're building the feature their customers ask for in every sales call. That sentence in a cover letter gets interviews.

## 8. Honest risks
- Crypto correctness matters; a broken Merkle/signing impl is worse than none. Write property tests; the IoT paper found a double-counting metric bug and a redundant tree-rebuild — expect similar and audit yourself.
- Don't over-claim: you provide *tamper-evidence and admissible evidence*, not proof of decision correctness, and not legal compliance certification. Say so plainly. Honesty about scope is a trust multiplier in this specific market.
- The space is filling fast — your moat is D1+D2+D3 (multi-framework + regulation-mapped export + selective disclosure) executed cleanly, not being first.
