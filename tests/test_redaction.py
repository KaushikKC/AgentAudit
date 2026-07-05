import json

from agentaudit import Actor, AuditEvent, AuditLog, EventType, SigningKey
from agentaudit.redaction import (
    flatten_fields,
    make_disclosure,
    seal_fields,
    verify_disclosure,
)
from agentaudit.verifier import verify_disclosure as verify_excerpt


def test_flatten_nested_and_lists():
    f = flatten_fields({"a": {"b": 1}, "c": [10, 20]}, "input")
    assert f == {"input.a.b": 1, "input.c[0]": 10, "input.c[1]": 20}


def test_seal_and_full_roundtrip():
    fields = {"input.name": "Jane", "input.dob": "1990-05-01"}
    sealed = seal_fields(fields)
    sd = make_disclosure(sealed, reveal_paths=["input.dob"])
    ok, revealed = verify_disclosure(sd)
    assert ok
    assert revealed == {"input.dob": "1990-05-01"}


def test_hidden_value_and_salt_not_in_excerpt():
    fields = {"input.name": "Jane", "input.dob": "1990-05-01"}
    sealed = seal_fields(fields)
    sd = make_disclosure(sealed, reveal_paths=["input.dob"])
    blob = json.dumps(sd.to_dict())
    assert "Jane" not in blob                     # hidden value absent
    assert sealed.salts["input.name"] not in blob  # its salt absent -> unguessable


def test_forged_revealed_value_fails():
    sealed = seal_fields({"input.name": "Jane", "input.dob": "1990-05-01"})
    sd = make_disclosure(sealed, reveal_paths=["input.name"])
    sd.revealed["input.name"]["value"] = "Attacker"
    ok, _ = verify_disclosure(sd)
    assert not ok


def test_tampered_hidden_leaf_fails():
    sealed = seal_fields({"input.name": "Jane", "input.dob": "1990-05-01"})
    sd = make_disclosure(sealed, reveal_paths=["input.name"])
    # Flip the hidden leaf hash -> root won't reconstruct.
    (k,) = sd.hidden.keys()
    sd.hidden[k] = "00" * 32
    assert not verify_disclosure(sd)[0]


def _redacted_log():
    log = AuditLog(signing_key=SigningKey.generate())
    log.record(AuditEvent(
        event_type=EventType.DECISION,
        actor=Actor(agent_id="kyc"),
        input={"name": "Jane Applicant", "dob": "1990-05-01", "document_id": "P1234567"},
        output={"decision": "approve", "confidence": 0.83},
    ), redact_keys=["input"])
    log.seal()
    return log


def test_log_disclosure_verifies_against_signed_log():
    log = _redacted_log()
    excerpt = log.make_disclosure(0, reveal_paths=["input.document_id"])
    res = verify_excerpt(excerpt)
    assert res.ok, res.summary()


def test_redacted_entry_carries_no_pii():
    log = _redacted_log()
    entry = log.entries()[0]
    assert entry.input == {"__redacted__": True}
    assert entry.content_commitment is not None
    assert "Jane" not in json.dumps(entry.signed_body())


def test_excerpt_hides_unrevealed_fields():
    log = _redacted_log()
    excerpt = log.make_disclosure(0, reveal_paths=["input.document_id"])
    blob = json.dumps(excerpt)
    assert "P1234567" in blob          # the field we chose to reveal
    assert "Jane Applicant" not in blob  # the field we chose to hide
    assert "1990-05-01" not in blob


def test_disclosure_detects_swapped_entry_hash():
    log = _redacted_log()
    excerpt = log.make_disclosure(0, reveal_paths=["input.document_id"])
    excerpt["entry"]["entry_hash"] = "00" * 32
    assert not verify_excerpt(excerpt).ok
