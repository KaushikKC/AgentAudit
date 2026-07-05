"""Selective-disclosure demo (differentiator D3).

The enterprise objection to any audit tool is: *"we can't put customer PII in
it."* This shows the answer. An agent records a decision whose input is full of
PII; the tamper-evident log commits to that input **without storing it**, and
later the operator proves one specific field to an auditor while every other
field stays sealed and unguessable.

Run it::

    python examples/selective_disclosure_demo.py
"""

from __future__ import annotations

import json

from agentaudit import Actor, AuditEvent, AuditLog, EventType, PolicyRef, SigningKey
from agentaudit.bundle import export_bundle
from agentaudit.verifier import verify_disclosure


def main() -> int:
    log = AuditLog(signing_key=SigningKey.generate())

    # An onboarding decision whose *input* is sensitive PII.
    log.record(
        AuditEvent(
            event_type=EventType.DECISION,
            actor=Actor(agent_id="kyc-checker-v3", framework="langchain"),
            policy_ref=PolicyRef(policy_id="kyc-uk-2026", version="1.4.2"),
            input={
                "full_name": "Jane Q. Applicant",
                "date_of_birth": "1990-05-01",
                "document_id": "P1234567",
                "nationality": "GB",
            },
            output={"decision": "approve", "confidence": 0.83},
            control_mapping=["EU-AI-Act-Art13", "EU-AI-Act-Art14"],
        ),
        redact_keys=["input"],   # PII is committed, never stored in the clear
    )
    log.seal()

    print("== What the exported evidence bundle actually contains ==")
    bundle = export_bundle(log)
    entry = bundle["entries"][0]
    print(f"  input in log:          {entry['input']}")
    print(f"  content_commitment:    {entry['content_commitment'][:24]}...")
    leaked = [p for p in ("Jane", "1990-05-01", "P1234567") if p in json.dumps(bundle)]
    print(f"  raw PII present:       {leaked or 'NONE'}")

    print("\n== Disclose ONE field to an auditor (document_id) ==")
    excerpt = log.make_disclosure(0, reveal_paths=["input.document_id"])
    res = verify_disclosure(excerpt)
    print("  " + res.summary().replace("\n", "\n  "))

    blob = json.dumps(excerpt)
    print("\n== Privacy of the excerpt ==")
    print(f"  reveals document_id:   {'P1234567' in blob}")
    print(f"  reveals full_name:     {'Jane' in blob}")
    print(f"  reveals date_of_birth: {'1990-05-01' in blob}")

    print("\n== Attacker forges the revealed value ==")
    forged = log.make_disclosure(0, reveal_paths=["input.document_id"])
    forged["disclosure"]["revealed"]["input.document_id"]["value"] = "P0000000"
    print(f"  forged excerpt caught: {not verify_disclosure(forged).ok}")

    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
