"""KYC document-checker reference demo (differentiator D4).

A realistic, FCA-recognizable workflow: an agent performs Know-Your-Customer
checks on an applicant -- parse identity documents, screen against a sanctions
list, then make an onboarding decision under a *pinned policy version*. Every
step is recorded through the AgentAudit SDK, so the run produces a
regulator-ready, offline-verifiable evidence bundle as a byproduct.

Deliberately framework-neutral and dependency-light (no LangChain/LLM install)
so it runs out of the box in seconds. The instrumentation points are exactly
where a LangChain/CrewAI callback adapter would sit -- that adapter is the D1
follow-up; the audit semantics shown here do not change.

Run it::

    python examples/kyc_demo.py            # run, seal, verify, show tamper-evidence
    python examples/kyc_demo.py -o kyc.json

Notice how PII never enters the log in the clear: inputs are recorded as a
salted hash + a sensitivity class, while the *decision*, its *confidence*, and
the *policy version* that governed it are fully auditable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from agentaudit import Actor, AuditEvent, AuditLog, EventType, PolicyRef, SigningKey
from agentaudit.bundle import export_bundle, verify_bundle

# ---------------------------------------------------------------------------
# The policy in force. In production this is a versioned document; here we hash
# its text so the log can prove *which* wording governed the decision.
# ---------------------------------------------------------------------------
KYC_POLICY_TEXT = (
    "UK KYC onboarding policy v1.4.2: approve when identity documents are valid, "
    "the applicant is absent from all sanctions lists, and model confidence >= 0.70; "
    "otherwise route to a human reviewer."
)
CONFIDENCE_THRESHOLD = 0.70

POLICY = PolicyRef(
    policy_id="kyc-uk-2026",
    version="1.4.2",
    hash=hashlib.sha256(KYC_POLICY_TEXT.encode()).hexdigest(),
)

ACTOR = Actor(agent_id="kyc-checker-v3", framework="reference", model="claude-sonnet-5")

# A tiny mock sanctions list (real deployments hit an external screening API).
_SANCTIONS = {"IVAN SANCTIONOV", "ACME SHELL CO"}


@dataclass
class Applicant:
    name: str
    dob: str
    document_id: str
    address: str


def _redact(obj: Dict[str, str], pii_class: str) -> Dict[str, str]:
    """Record only a salted hash + sensitivity class -- never raw PII."""
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    salt = b"demo-static-salt"  # per-tenant secret salt in production
    return {
        "redacted": True,
        "hash": hashlib.sha256(salt + canonical).hexdigest(),
        "pii_class": pii_class,
    }


# --- mock agent tools -------------------------------------------------------
def parse_documents(applicant: Applicant) -> Dict[str, object]:
    """Pretend-OCR: extract structured fields from the submitted documents."""
    return {
        "documents_found": 2,
        "identity_valid": bool(applicant.document_id),
        "fields_extracted": ["name", "dob", "document_id", "address"],
    }


def sanctions_screen(applicant: Applicant) -> Dict[str, object]:
    hit = applicant.name.upper() in _SANCTIONS
    return {"lists_checked": ["UK-HMT", "EU", "OFAC"], "match": hit}


def score_risk(parsed: Dict[str, object], screen: Dict[str, object]) -> float:
    """A stand-in for a model call; returns a confidence in [0, 1]."""
    if screen["match"] or not parsed["identity_valid"]:
        return 0.10
    return 0.83


# --- the instrumented agent -------------------------------------------------
def run_kyc(log: AuditLog, applicant: Applicant) -> str:
    # 1. Parse documents (input is PII -> redacted).
    parsed = parse_documents(applicant)
    log.record(AuditEvent(
        event_type=EventType.RETRIEVAL,
        actor=ACTOR,
        policy_ref=POLICY,
        input=_redact({"name": applicant.name, "document_id": applicant.document_id}, "high"),
        output=parsed,
        control_mapping=["EU-AI-Act-Art12", "NIST-MEASURE-2.3"],
    ))

    # 2. Sanctions screening.
    screen = sanctions_screen(applicant)
    log.record(AuditEvent(
        event_type=EventType.TOOL_CALL,
        actor=ACTOR,
        policy_ref=POLICY,
        input=_redact({"name": applicant.name}, "high"),
        output=screen,
        control_mapping=["EU-AI-Act-Art13", "ISO-42001-8.4"],
    ))

    # 3. Risk-scored decision under the pinned policy version.
    confidence = score_risk(parsed, screen)
    if confidence >= CONFIDENCE_THRESHOLD:
        decision, event_type, controls = "approve", EventType.DECISION, ["EU-AI-Act-Art13"]
    else:
        decision, event_type, controls = (
            "route_to_human", EventType.HUMAN_OVERRIDE, ["EU-AI-Act-Art14", "NIST-MANAGE-4.1"],
        )
    log.record(AuditEvent(
        event_type=event_type,
        actor=ACTOR,
        policy_ref=POLICY,
        output={"decision": decision, "confidence": confidence,
                "threshold": CONFIDENCE_THRESHOLD},
        control_mapping=controls,
    ))
    return decision


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="AgentAudit KYC reference demo")
    p.add_argument("-o", "--out", help="write the evidence bundle to this path")
    args = p.parse_args(argv)

    log = AuditLog(signing_key=SigningKey.generate())

    # Two applicants: one clean (approved), one on a sanctions list (human review).
    approved = Applicant("Jane Applicant", "1990-05-01", "P1234567", "1 High St, London")
    flagged = Applicant("Ivan Sanctionov", "1980-01-01", "P7654321", "Nowhere")

    print("== Running instrumented KYC agent ==")
    for applicant in (approved, flagged):
        outcome = run_kyc(log, applicant)
        print(f"  {applicant.name:<18} -> {outcome}")

    checkpoint = log.seal()
    print(f"\n== Sealed evidence ==")
    print(f"  entries       {log.size()}")
    print(f"  merkle root   {checkpoint.root_hash}")
    print(f"  signed        {'yes (Ed25519)' if checkpoint.signature else 'no'}")
    print(f"  policy hash   {POLICY.hash[:16]}...  (proves policy v{POLICY.version} applied)")

    bundle = export_bundle(log)
    frameworks = sorted({c["framework"] for c in bundle["controls"]})
    print(f"  covers        {', '.join(frameworks)}")

    print("\n== Independent offline verification ==")
    result = verify_bundle(bundle)
    print("  " + result.summary().replace("\n", "\n  "))

    print("\n== Tamper-evidence check ==")
    tampered = json.loads(json.dumps(bundle))  # deep copy
    # Flip the sanctioned applicant's decision from human-review to approve --
    # the exact after-the-fact edit an auditor must be able to catch.
    victim = next(i for i, e in enumerate(tampered["entries"])
                  if e.get("output", {}).get("decision") == "route_to_human")
    tampered["entries"][victim]["output"]["decision"] = "approve"
    bad = verify_bundle(tampered)
    print(f"  flipped entry[{victim}] decision 'route_to_human' -> 'approve'")
    print(f"  re-verification: {'DETECTED (FAIL)' if not bad.ok else 'MISSED (bug!)'}")

    if args.out:
        Path(args.out).write_text(json.dumps(bundle, indent=2))
        print(f"\nEvidence bundle written to {args.out}")
        print(f"Verify it yourself:  agentaudit verify {args.out}")

    return 0 if result.ok and not bad.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
