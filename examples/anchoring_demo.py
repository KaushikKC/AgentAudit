"""External anchoring demo (Phase 3).

Local signing proves *who* vouched for a Merkle root, but the key-holder could
re-sign a rewritten history going forward. Anchoring commits the root to an
*independent* party so that can't go unnoticed. This demo uses the offline
witness backend (an independent cosigner); the same `seal(anchor=...)` call works
with the Sigstore Rekor backend for a public transparency-log anchor.

Run it::

    python examples/anchoring_demo.py
"""

from __future__ import annotations

from agentaudit import Actor, AuditEvent, AuditLog, EventType, SigningKey
from agentaudit.anchoring import WitnessLog, verify_witness_receipt
from agentaudit.anchoring.base import AnchorReceipt
from agentaudit.bundle import export_bundle, verify_bundle


def main() -> int:
    # The witness runs in a separate trust domain with its own key. In production
    # its public key is published out-of-band so verifiers can pin it.
    witness = WitnessLog()
    published_witness_key = witness.public_key_pem

    log = AuditLog(signing_key=SigningKey.generate())
    log.record(AuditEvent(
        event_type=EventType.DECISION,
        actor=Actor(agent_id="kyc-checker-v3", framework="langchain"),
        output={"decision": "approve", "confidence": 0.83},
    ))

    checkpoint = log.seal(anchor=witness)
    receipt = AnchorReceipt.from_json(checkpoint.anchor)

    print("== Sealed + externally anchored ==")
    print(f"  merkle root     {checkpoint.root_hash}")
    print(f"  operator signed {'yes' if checkpoint.signature else 'no'}")
    print(f"  anchored by     {receipt.backend} at {receipt.anchored_at}")
    print(f"  witness index   {receipt.proof['statement']['witness_index']}")

    print("\n== Offline verification (auditor pins the witness's published key) ==")
    ok = verify_witness_receipt(receipt, trusted_keys=[published_witness_key])
    print(f"  witness cosignature valid (pinned key): {ok}")
    imposter = verify_witness_receipt(receipt, trusted_keys=[
        "-----BEGIN PUBLIC KEY-----\nMCowBQ==\n-----END PUBLIC KEY-----"])
    print(f"  rejected when pinned to a different key: {not imposter}")

    print("\n== The anchor rides inside the evidence bundle ==")
    res = verify_bundle(export_bundle(log))
    print("  " + res.summary().replace("\n", "\n  "))

    return 0 if ok and res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
