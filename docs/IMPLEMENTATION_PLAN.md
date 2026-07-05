# AgentAudit — Implementation Plan & Roadmap

Living document tracking what's built and what's next. See `PROJECT_1_AgentAudit.md` for the
original thesis and `README.md` for the product overview.

---

## Status legend
✅ done & tested · 🚧 in progress · ⏳ planned · ⚠️ known debt

---

## Done (108 tests passing, CI green)

**Phase 1 — cryptographic core**
- ✅ `crypto/canonical.py` — deterministic JSON (RFC 8785-style)
- ✅ `crypto/merkle.py` — RFC 6962 Merkle tree, inclusion + consistency proofs; matches published RFC test vectors
- ✅ `crypto/signing.py` — Ed25519 sign/verify + PEM/raw key handling
- ✅ `schema.py` — `AuditEvent` / `LogEntry` / `PolicyRef` / `Actor`; hash chain via `entry_hash`
- ✅ `storage.py` — append-only SQLite (UPDATE/DELETE triggers = WORM-style)
- ✅ `log.py` — `AuditLog` engine: record → chain → Merkle → seal(sign) → proofs
- ✅ `verifier.py` + `bundle.py` — offline, trust-nothing verification + self-contained evidence bundle
- ✅ `cli.py` — `agentaudit demo | verify | tamper`

**Differentiators**
- ✅ **D1** framework instrumentation — `integrations/otel.py` (neutral OTel GenAI exporter, tested vs real SDK), `integrations/langchain.py`, `integrations/crewai.py`
- ✅ **D2 (partial)** regulation-mapped export — `controls.py` catalog (EU AI Act / NIST AI RMF / ISO 42001) + self-describing bundle
- ✅ **D3** selective disclosure — `redaction.py` salted per-field Merkle commitments + `verify_disclosure`
- ✅ **D4** KYC reference demo — `examples/kyc_demo.py`
- ✅ **D5** offline verifier — `agentaudit verify` / `verify_bundle`
- ✅ `examples/selective_disclosure_demo.py`

---

## External anchoring (Phase 3) — ✅ witness (offline) + ✅ Rekor (write path validated live)

**Shipped:** `anchoring/base.py` (receipt + backend ABC), `anchoring/witness.py`
(`WitnessLog` — independent cosigner, fully offline-verifiable, tested), `anchoring/rekor.py`
(`RekorClient` + `RekorAnchor`), `AuditLog.seal(anchor=...)`, `verifier.verify_anchor` +
`verify_bundle` integration, CLI `demo --anchor witness`, `examples/anchoring_demo.py`,
tests (`tests/test_anchoring.py`, offline + 1 opt-in live read).

**Rekor validated live** (2026-07-03): `seal(anchor=RekorAnchor())` wrote a real public entry
at **logIndex 2064169373** (integratedTime + inclusion proof + signed entry timestamp returned);
`verify_rekor_receipt` re-fetch and `verify_anchor(online=True)` both pass. Key finding: Rekor's
ed25519 hashedrekord uses **Ed25519ph** (SHA-512 prehash) which `cryptography` doesn't expose, so
`RekorAnchor` uses a dedicated **ECDSA P-256** key (canonical hashedrekord path) — independent of
the log's Ed25519 signing key.

**Remaining on anchoring:**
- ✅ Full **offline** Rekor verification — DONE. `rekor.verify_set` checks the Signed Entry
  Timestamp (ECDSA over RFC 8785-canonicalized `{body,integratedTime,logID,logIndex}`) against
  Rekor's log key; receipts now capture the SET + log key (`offline_verifiable=True`).
  `verify_anchor` prefers it (no network); pin the key via `trusted_rekor_key`. Validated against
  a real entry (logIndex 2064169373), tested deterministically via `tests/fixtures/rekor_entry.json`.
- ⏳ **RFC-3161 TSA** backend and **blockchain** anchor (documented follow-ups; RFC-3161 needs
  correct ASN.1/CMS — do it right or not at all).

**Why anchoring mattered:** local Ed25519 signing is tamper-*evident* but whoever holds the key
can re-sign a rewritten history going forward. Anchoring each sealed Merkle root to an *external*
location the operator can't backdate gives **provable time + third-party non-repudiation**.

<details><summary>Original design notes (kept for reference)</summary>

**Design (resume here):**

- `anchoring/base.py`
  - `AnchorReceipt` dataclass: `backend`, `root_hash`, `anchored_at` (external time), `proof: dict`, `offline_verifiable: bool`; `to_json()` / `from_json()`.
  - `AnchorBackend` ABC: `name`; `submit(checkpoint) -> AnchorReceipt`.
  - `checkpoint_statement(cp) -> dict` bound fields: `{session_id, tree_size, root_hash}` (reuse canonical form from `log._checkpoint_signing_bytes`).

- `anchoring/witness.py` — **`WitnessLog`** (default, fully offline-verifiable). The RFC 6962 /
  C2SP witness-cosigning model: an *independent* party (its own Ed25519 key + own append-only
  hash chain) attests "I saw root X at time T at witness index i" and signs it.
  - `submit`: build statement `{session_id, tree_size, root_hash, witnessed_at, witness_index, prev}`, sign with the witness key, append to witness chain, return receipt (statement + signature + witness public key), `offline_verifiable=True`.
  - `verify_witness_receipt(receipt, trusted_keys: set[pem] | None)`: check `statement.root_hash == receipt.root_hash`, verify signature; **if `trusted_keys` given, require the witness key ∈ trusted** (honest trust model — a receipt-embedded key alone proves nothing; real trust needs a pinned/published witness key, exactly like Rekor's well-known log key).

- `anchoring/rekor.py` — **`RekorAnchor`** (production default the spec names; network).
  - Submit a `hashedrekord` (apiVersion 0.0.1) to `https://rekor.sigstore.dev/api/v1/log/entries`:
    `spec.data.hash = sha256(statement bytes)`, `spec.signature.content = base64(Ed25519 sig)`, `spec.signature.publicKey.content = base64(PEM)`.
  - Store receipt: `logIndex`, `uuid`, `integratedTime` (= provable time), `logID`, `signedEntryTimestamp` (SET), `inclusionProof`. `offline_verifiable=False`.
  - `verify`: re-fetch `GET /entries/{uuid}`, confirm body matches. (Rigorous offline path = verify the SET/inclusionProof against Rekor's log public key from `/log/publicKey` — implement as a follow-up; document current depth honestly.)
  - **Networking note:** the macOS framework Python's default cert store fails TLS to Rekor; use `certifi.where()` CA bundle if importable, else default `ssl` context. Confirmed Rekor reachable this way.
  - ⚠️ **Live submission = permanent public write.** Do NOT submit to the real Rekor unprompted. It's the product's purpose (a hash + ephemeral pubkey + sig, no PII) but it's outward-facing — get user consent before a live anchor. Reads (log info, fetch entry, fetch public key) are fine to test live.

- **Integration:**
  - `AuditLog.seal(anchor: AnchorBackend | None = None)`: after signing, `receipt = anchor.submit(cp); cp.anchor = receipt.to_json()` before `append_checkpoint`. (Signature covers root only; `anchor` is external metadata — fine.)
  - `verifier.verify_anchor(anchor_json, trusted_keys=None) -> VerificationResult`; call it from `verify_bundle` when `checkpoint.anchor` is present and offline-verifiable. For Rekor, mark "externally anchored (verify online)".
  - CLI: optional `agentaudit demo --anchor witness`.

- **Tests:** witness anchoring fully offline (submit → verify, tamper root → fail, untrusted key rejected when pinning). Rekor test `@pytest.mark.network`, skipped by default.

- **Docs:** update README threat model — anchoring closes the "re-sign rewritten history" gap up to the trust of the witness/Rekor key; add a roadmap row flip.

- **Decision to keep scope tight:** ship **witness + Rekor** solidly; **RFC-3161 TSA** and **blockchain anchor** are documented follow-ups (RFC-3161 needs correct ASN.1/CMS — better late than broken).

</details>

---

## Tier 1 — highest leverage next

- ✅ **Visual dashboard / web UI** — DONE. `agentaudit.dashboard` (`serve` CLI): stdlib http
  server + self-contained SPA, backed by the real `verify_bundle` engine; sessions rail, live
  verdict banner, checkpoint/anchor/coverage cards, and a non-destructive **Simulate tamper**
  that flips the verdict red. Tests in `tests/test_dashboard.py` (data layer + live round-trip).
  A shareable static snapshot was also published as a Claude Artifact for pitching.
- ✅ **Performance debt** — FIXED. `crypto/merkle.IncrementalMerkleTree` (Merkle Mountain Range
  frontier) keeps the RFC 6962 root in O(log n)/append; `AuditLog` caches chain state
  (`_prev_hash`, `_size`, `_merkle`, loaded once via `_ensure_loaded`) and guards record/seal with
  an `RLock`. Result: **flat ~26 µs/record (~37k rec/s)** from n=1k→50k — the old code did a
  185 ms full-scan *per append* at n=50k (~7,000× slower; ~77 min to ingest 50k vs ~1.3 s now).
  Tests: `test_engine_perf.py` (cached-root == recompute, reopen-continuity, thread-safety) +
  `test_merkle.py` incremental property tests. Demo: `examples/benchmark.py`.
- ✅ **Real LangChain + LLM KYC demo** — DONE. `examples/langchain_kyc_demo.py` drives genuine
  LangChain primitives (chat model + `@tool`) through LangChain's real callback dispatch with
  `AuditCallbackHandler` (now supports `policy_ref` + `control_mapping` stamping). Deterministic
  fake model by default (no API key, reproducible); swaps to `ChatAnthropic(claude-sonnet-5)`
  when `ANTHROPIC_API_KEY` is set. Validated against real langchain-core 1.4.8; tests in
  `test_integrations.py` (real-dispatch, `importorskip`) + `test_demo_and_controls.py`.

## Tier 2 — production hardening

- ✅ **Key management / KMS** — DONE. `agentaudit.keys.KeyProvider` (sign + public_key_pem, so a
  KMS that can't export its key still works): `LocalKeyProvider`, `EncryptedFileKeyProvider`
  (password-encrypted PKCS8 at rest, 0600, password from arg/env), documented KMS subclass path.
  `AuditLog(key_provider=...)` routes all signing through it.
- ✅ **Automated sealing policy** — DONE. `SealPolicy(every_n_events, every_seconds)`;
  synchronous threshold seal + background timer thread; `AuditLog` is a context manager that
  flushes a final checkpoint on exit. `auto_anchor` anchors each auto-seal.
- ✅ **Thread-safe storage + formal interface** — DONE. `StorageBackend` ABC; `SQLiteStore` now
  has an internal lock + `check_same_thread=False`, safe for background sealers and the dashboard.
  Demo: `examples/production_hardening_demo.py`. Tests: `test_hardening.py`.
- ⏳ **Postgres + object-store backend** with true WORM (object-lock). Interface is ready
  (`StorageBackend`) — additive; can't validate here without a live DB.
- ⏳ **Collector service + HTTP/gRPC API** — architecture diagram shows an out-of-process
  collector; today it's in-process SDK only. (Dashboard server is a starting point.)
- ⏳ **Forward-secure key ratcheting** — rotate/erase per-segment key after each seal so a future
  key compromise can't forge past entries. (KeyProvider interface is the hook.)

## ⏳ Tier 3 — breadth & polish

- **Standalone Rust/Go verifier binary** — the spec's zero-dependency "verify-it-yourself" artifact + perf cred.
- **JS/TS SDK** for Node agents.
- **Deeper D2** — more control mappings, per-regulation evidence templates, per-session coverage report.
- **Docs site** + the 3 evergreen write-ups; **PyPI publish** + versioned releases.
- **AutoGen / OpenAI Agents SDK** native adapters (OTel exporter already covers them generically).
- **Retention / legal-hold** semantics; standalone threat-model doc.

---

## Known technical debt (⚠️)
- Key *rotation* still manual (encrypted-at-rest + KMS path now exist via `KeyProvider`); forward-secure ratcheting not yet built.
- SQLite triggers are app-level WORM only; real immutability needs object-lock storage.
- Per-record SQLite commit is now the ingest bottleneck (crypto is O(log n)); batched commits would raise throughput further.
- Reopened `AuditLog` loads all entries once (O(n)) to rebuild cached state; fine, but not incremental across process restarts.
- Rekor offline verify checks the SET (Rekor's inclusion promise), not the full inclusion-proof-vs-STH path; production verifiers should pin Sigstore's published Rekor log key rather than the receipt-embedded one.

## Housekeeping
- No git commit made yet (per standing preference — commit when the user asks).
- `agentaudit` console script installs to `~/Library/Python/3.12/bin` (not on PATH here) — user-env, not a packaging bug.
- Build-in-public posts drafted through #8 (thesis, Merkle/CT, honest-scope, D1, D3, meta-lesson,
  Rekor Ed25519ph→ECDSA debugging, O(n²)→MMR perf fix).
