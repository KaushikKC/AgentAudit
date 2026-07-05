from agentaudit import Actor, AuditEvent, AuditLog, EventType, PolicyRef, SigningKey
from agentaudit.verifier import verify_chain


def _make_log(n=5, sign=True):
    log = AuditLog(signing_key=SigningKey.generate() if sign else None)
    for i in range(n):
        log.record(AuditEvent(
            event_type=EventType.DECISION,
            actor=Actor(agent_id="kyc-checker-v3", framework="langchain"),
            policy_ref=PolicyRef(policy_id="kyc-uk-2026", version="1.4.2", hash="abc"),
            output={"decision": "approve", "confidence": 0.5 + i / 100},
        ))
    return log


def test_chain_links_and_genesis():
    log = _make_log(4)
    entries = log.entries()
    assert entries[0].prev_hash == "0" * 64
    for i in range(1, len(entries)):
        assert entries[i].prev_hash == entries[i - 1].entry_hash
        assert entries[i].seq == i


def test_verify_chain_passes_on_clean_log():
    log = _make_log(6)
    result = verify_chain(log.entries())
    assert result.ok, result.summary()


def test_merkle_root_matches_after_seal():
    log = _make_log(7)
    cp = log.seal()
    result = verify_chain(log.entries(), expected_root=cp.root_hash)
    assert result.ok, result.summary()


def test_inclusion_proof_for_every_entry():
    from agentaudit.verifier import verify_inclusion_proof

    log = _make_log(9)
    log.seal()
    for e in log.entries():
        proof = log.inclusion_proof(e.seq).to_dict()
        assert verify_inclusion_proof(proof).ok


def test_consistency_between_seals():
    from agentaudit.verifier import verify_consistency_proof

    log = _make_log(3)
    cp1 = log.seal()
    # append more, seal again
    for i in range(4):
        log.record(AuditEvent(
            event_type=EventType.TOOL_CALL,
            actor=Actor(agent_id="kyc-checker-v3"),
        ))
    cp2 = log.seal()
    path = log.consistency_proof(cp1.tree_size, cp2.tree_size)
    assert verify_consistency_proof(
        cp1.tree_size, cp2.tree_size, cp1.root_hash, cp2.root_hash, path
    ).ok
