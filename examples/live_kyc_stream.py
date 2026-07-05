"""Live agent stream — real audit trails written to disk as an agent works.

This is the "real working flow": a KYC agent processes a stream of applicants,
and each run is recorded through the actual engine into a **file-backed** store.
Point the dashboard at the same DB and watch real sessions appear, verify, and
(if you tamper) fail — none of it seeded.

Two terminals:

    # terminal 1 — the agent keeps working, logging to live.db
    python examples/live_kyc_stream.py --db live.db --interval 3

    # terminal 2 — watch it live (auto-refreshes)
    python -m agentaudit.cli serve --db live.db --no-seed
    #   then open http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import time

from agentaudit import Actor, AuditEvent, AuditLog, EventType, PolicyRef, SigningKey
from agentaudit.anchoring import WitnessLog
from agentaudit.storage import SQLiteStore

POLICY = PolicyRef(policy_id="kyc-uk-2026", version="1.4.2",
                   hash=hashlib.sha256(b"kyc-uk-2026/1.4.2").hexdigest()[:12])
_SANCTIONS = {"IVAN SANCTIONOV", "ACME SHELL CO", "VICTOR ROGUE"}

APPLICANTS = [
    ("Jane Applicant", "P1234567"),
    ("Ivan Sanctionov", "P7654321"),
    ("Wei Chen", "P2223334"),
    ("Maria Garcia", "P9087651"),
    ("Victor Rogue", "P5551212"),
    ("Aisha Khan", "P4041000"),
    ("Tom Baker", "P3120099"),
]


def process_applicant(store: SQLiteStore, name: str, doc_id: str, signer: SigningKey) -> str:
    """One KYC run = one audit session, recorded and sealed to disk."""
    log = AuditLog(store=store, signing_key=signer)
    actor = Actor(agent_id="kyc-checker-v3", framework="langchain", model="claude-sonnet-5")

    # 1) parse documents — PII input is redacted (committed, not stored raw)
    log.record(AuditEvent(
        event_type=EventType.RETRIEVAL, actor=actor, policy_ref=POLICY,
        input={"name": name, "document_id": doc_id},
        output={"identity_valid": True, "documents_found": 2},
        control_mapping=["EU-AI-Act-Art12", "NIST-MEASURE-2.3"],
    ), redact_keys=["input"])

    # 2) sanctions screen
    hit = name.upper() in _SANCTIONS
    log.record(AuditEvent(
        event_type=EventType.TOOL_CALL, actor=actor, policy_ref=POLICY,
        output={"lists_checked": ["UK-HMT", "OFAC", "EU"], "match": hit},
        control_mapping=["EU-AI-Act-Art13", "ISO-42001-8.4"],
    ))

    # 3) decision under the pinned policy version
    if hit:
        decision, etype, controls = "route_to_human", EventType.HUMAN_OVERRIDE, \
            ["EU-AI-Act-Art14", "NIST-MANAGE-4.1"]
        conf = 0.12
    else:
        decision, etype, controls = "approve", EventType.DECISION, ["EU-AI-Act-Art13"]
        conf = 0.83
    log.record(AuditEvent(
        event_type=etype, actor=actor, policy_ref=POLICY,
        output={"decision": decision, "confidence": conf, "threshold": 0.70},
        control_mapping=controls,
    ))

    log.seal(anchor=WitnessLog())   # signed + externally anchored
    return decision


def main() -> int:
    p = argparse.ArgumentParser(description="Stream real KYC audit sessions to a DB")
    p.add_argument("--db", default="live.db", help="SQLite file the dashboard reads")
    p.add_argument("--interval", type=float, default=3.0, help="seconds between applicants")
    p.add_argument("--count", type=int, default=0, help="stop after N (0 = run forever)")
    args = p.parse_args()

    store = SQLiteStore(args.db)
    signer = SigningKey.generate()
    print(f"logging real KYC sessions to {args.db}  (Ctrl+C to stop)\n")

    seq = itertools.count(1)
    try:
        for name, doc_id in itertools.cycle(APPLICANTS):
            n = next(seq)
            decision = process_applicant(store, name, doc_id, signer)
            total = len(store.sessions())
            print(f"  [{n:>3}] {name:<18} -> {decision:<15} ({total} sessions in {args.db})")
            if args.count and n >= args.count:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
