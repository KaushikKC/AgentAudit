"""Adversarial tests: every class of tampering must be caught.

These are the tests that matter for the pitch -- they demonstrate the core
claim (edit / delete / reorder / truncate are all detectable) as executable
proof, not marketing copy.
"""

import copy

from agentaudit import Actor, AuditEvent, AuditLog, EventType, SigningKey
from agentaudit.bundle import export_bundle, verify_bundle
from agentaudit.verifier import verify_chain


def _bundle(n=5):
    log = AuditLog(signing_key=SigningKey.generate())
    for i in range(n):
        log.record(AuditEvent(
            event_type=EventType.DECISION,
            actor=Actor(agent_id="agent-x"),
            output={"i": i, "decision": "approve"},
        ))
    log.seal()
    return export_bundle(log)


def test_clean_bundle_verifies():
    assert verify_bundle(_bundle()).ok


def test_edit_is_detected():
    b = _bundle()
    b["entries"][2]["output"]["decision"] = "deny"   # flip a decision
    assert not verify_bundle(b).ok


def test_deletion_is_detected():
    b = _bundle()
    del b["entries"][2]                               # drop an entry
    res = verify_bundle(b)
    assert not res.ok


def test_reorder_is_detected():
    b = _bundle()
    b["entries"][1], b["entries"][2] = b["entries"][2], b["entries"][1]
    assert not verify_bundle(b).ok


def test_truncation_is_detected_via_merkle_root():
    b = _bundle()
    b["entries"] = b["entries"][:-1]                  # silently drop the tail
    # Chain alone might still look linear; the sealed Merkle root won't match.
    assert not verify_bundle(b).ok


def test_forged_hash_without_key_is_detected():
    # Attacker edits content AND recomputes the entry_hash to hide the edit,
    # but cannot re-sign the Merkle root -> signature/root check fails.
    b = _bundle()
    from agentaudit.schema import LogEntry, compute_entry_hash

    e = LogEntry.from_dict(b["entries"][1])
    e.output = {"i": 1, "decision": "FORGED"}
    b["entries"][1] = e.signed_body() | {"entry_hash": compute_entry_hash(e.signed_body())}
    # The forged entry now self-verifies, but its hash differs from the one the
    # Merkle root committed to, so the root no longer matches.
    assert not verify_bundle(b).ok


def test_prev_hash_relink_still_fails_root():
    # Even relinking prev_hash across a forged chain won't reproduce the signed root.
    b = _bundle()
    entries = copy.deepcopy(b["entries"])
    entries[0]["output"] = {"i": 0, "decision": "FORGED"}
    # Recompute the whole chain to make it internally consistent.
    from agentaudit.schema import GENESIS_HASH, LogEntry, compute_entry_hash

    prev = GENESIS_HASH
    fixed = []
    for d in entries:
        e = LogEntry.from_dict(d)
        e.prev_hash = prev
        e.entry_hash = compute_entry_hash(e.signed_body())
        prev = e.entry_hash
        fixed.append(e.signed_body() | {"entry_hash": e.entry_hash})
    b["entries"] = fixed
    # Chain is now internally valid...
    assert verify_chain(fixed).ok
    # ...but the sealed, signed Merkle root exposes the rewrite.
    assert not verify_bundle(b).ok
