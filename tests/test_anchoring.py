"""External anchoring tests.

Witness anchoring is fully offline and always runs. Rekor *read* paths hit the
live public log and only run when AGENTAUDIT_TEST_REKOR=1 (kept out of CI by
default so the suite is deterministic and offline). No test ever writes to the
public Rekor log.
"""

import os
import base64
import json
import pathlib

import pytest

from agentaudit import Actor, AuditEvent, AuditLog, EventType, SigningKey
from agentaudit.anchoring import WitnessLog, verify_witness_receipt
from agentaudit.anchoring.base import AnchorReceipt
from agentaudit.bundle import export_bundle, verify_bundle
from agentaudit.verifier import verify_anchor


def _sealed_with_witness():
    witness = WitnessLog()
    log = AuditLog(signing_key=SigningKey.generate())
    log.record(AuditEvent(event_type=EventType.DECISION,
                          actor=Actor(agent_id="kyc"), output={"decision": "approve"}))
    cp = log.seal(anchor=witness)
    return log, witness, cp


def test_witness_receipt_is_offline_verifiable():
    _, witness, cp = _sealed_with_witness()
    r = AnchorReceipt.from_json(cp.anchor)
    assert r.backend == "witness" and r.offline_verifiable
    assert verify_witness_receipt(r)


def test_witness_pinned_key_required_for_trust():
    _, witness, cp = _sealed_with_witness()
    r = AnchorReceipt.from_json(cp.anchor)
    assert verify_witness_receipt(r, trusted_keys=[witness.public_key_pem])
    assert not verify_witness_receipt(r, trusted_keys=["-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----"])


def test_witness_receipt_tamper_detected():
    _, _, cp = _sealed_with_witness()
    r = AnchorReceipt.from_json(cp.anchor)
    r.proof["statement"]["root_hash"] = "00" * 32
    assert not verify_witness_receipt(r)          # root no longer binds
    r2 = AnchorReceipt.from_json(cp.anchor)
    r2.proof["signature"] = "00" * 64
    assert not verify_witness_receipt(r2)         # signature invalid


def test_witness_binds_root_to_receipt():
    _, _, cp = _sealed_with_witness()
    r = AnchorReceipt.from_json(cp.anchor)
    assert r.proof["statement"]["root_hash"] == cp.root_hash == r.root_hash


def test_witness_chain_increments():
    witness = WitnessLog()
    log = AuditLog(signing_key=SigningKey.generate())
    idxs = []
    for i in range(3):
        log.record(AuditEvent(event_type=EventType.TOOL_CALL, actor=Actor(agent_id="a")))
        cp = log.seal(anchor=witness)
        idxs.append(AnchorReceipt.from_json(cp.anchor).proof["statement"]["witness_index"])
    assert idxs == [0, 1, 2]


def test_bundle_includes_and_verifies_anchor():
    log, _, _ = _sealed_with_witness()
    bundle = export_bundle(log)
    assert bundle["checkpoint"]["anchor"] is not None
    res = verify_bundle(bundle)
    assert res.ok
    assert any("witness anchor cosignature valid" in c for c in res.checks)


def test_verify_anchor_dispatch_rekor_offline():
    # A rekor receipt is reported as present without a network call.
    receipt = AnchorReceipt(
        backend="rekor", root_hash="ab" * 32, anchored_at="2026-07-03T00:00:00Z",
        proof={"uuid": "deadbeef", "log_index": 42, "integrated_time": 1750000000},
        offline_verifiable=False,
    )
    res = verify_anchor(receipt.to_json(), online=False)
    assert res.ok
    assert any("rekor anchor present" in c for c in res.checks)


def test_verify_anchor_unknown_backend_fails():
    receipt = AnchorReceipt(backend="bogus", root_hash="00", anchored_at="t")
    assert not verify_anchor(receipt.to_json()).ok


# --- offline Rekor SET verification (deterministic, no network) ------------
# A real Rekor entry AgentAudit wrote (logIndex 2064169373). The SET is Rekor's
# ECDSA signature over the canonicalized entry; verifying it against Rekor's log
# public key proves inclusion offline.
with open(pathlib.Path(__file__).parent / "fixtures" / "rekor_entry.json") as _f:
    _REKOR_FIXTURE = json.load(_f)


def _rekor_receipt_from_fixture():
    f = _REKOR_FIXTURE
    return AnchorReceipt(backend="rekor", root_hash="n/a", anchored_at="t", proof={
        "digest": f["digest"], "uuid": f["uuid"], "body": f["body"],
        "log_index": f["log_index"], "log_id": f["log_id"],
        "integrated_time": f["integrated_time"], "signed_entry_timestamp": f["set"],
        "rekor_public_key": f["pub"],
    }, offline_verifiable=True)


def test_rekor_set_verifies_offline():
    from agentaudit.anchoring.rekor import verify_rekor_receipt, verify_set

    f = _REKOR_FIXTURE
    assert verify_set(f["body"], f["integrated_time"], f["log_id"], f["log_index"],
                      f["set"], f["pub"])
    r = _rekor_receipt_from_fixture()
    assert verify_rekor_receipt(r)                             # offline, no network
    assert verify_rekor_receipt(r, trusted_rekor_key=f["pub"])  # pinned key


def test_rekor_offline_detects_tamper():
    from agentaudit.anchoring.rekor import verify_rekor_receipt

    bad_digest = _rekor_receipt_from_fixture()
    bad_digest.proof["digest"] = "00" * 32          # entry no longer binds our root
    assert not verify_rekor_receipt(bad_digest)

    bad_set = _rekor_receipt_from_fixture()
    bad_set.proof["signed_entry_timestamp"] = base64.b64encode(b"x" * 72).decode()
    assert not verify_rekor_receipt(bad_set)


def test_verify_anchor_rekor_offline_from_fixture():
    res = verify_anchor(_rekor_receipt_from_fixture().to_json())
    assert res.ok
    assert any("rekor SET verified offline" in c for c in res.checks)


# --- live Rekor reads (opt-in only) ----------------------------------------
@pytest.mark.skipif(os.environ.get("AGENTAUDIT_TEST_REKOR") != "1",
                    reason="set AGENTAUDIT_TEST_REKOR=1 to hit the live Rekor log")
def test_rekor_read_paths_live():
    from agentaudit.anchoring.rekor import RekorClient

    c = RekorClient()
    info = c.get_log_info()
    assert int(info["treeSize"]) > 0
    assert "BEGIN PUBLIC KEY" in c.get_public_key()
