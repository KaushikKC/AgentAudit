"""``agentaudit`` command-line interface.

Small, scriptable surface over the engine and verifier so the "aha" is one
command away:

    agentaudit demo                 # record a session, seal it, print the root
    agentaudit verify BUNDLE.json   # verify an exported evidence bundle offline
    agentaudit tamper BUNDLE.json   # flip one byte and show the verifier catch it
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentaudit import (
    Actor,
    AuditEvent,
    AuditLog,
    EventType,
    PolicyRef,
    SigningKey,
)
from agentaudit.bundle import export_bundle, verify_bundle


def _cmd_demo(args: argparse.Namespace) -> int:
    log = AuditLog(signing_key=SigningKey.generate())
    log.record(AuditEvent(
        event_type=EventType.RETRIEVAL,
        actor=Actor(agent_id="kyc-checker-v3", framework="langchain", model="claude-sonnet-5"),
        policy_ref=PolicyRef(policy_id="kyc-uk-2026", version="1.4.2", hash="a1b2c3"),
        input={"redacted": True, "hash": "deadbeef", "pii_class": "high"},
        output={"documents_found": 2},
        control_mapping=["EU-AI-Act-Art13", "NIST-MEASURE-2.3"],
    ))
    log.record(AuditEvent(
        event_type=EventType.DECISION,
        actor=Actor(agent_id="kyc-checker-v3", framework="langchain", model="claude-sonnet-5"),
        policy_ref=PolicyRef(policy_id="kyc-uk-2026", version="1.4.2", hash="a1b2c3"),
        output={"decision": "approve", "confidence": 0.83},
        control_mapping=["EU-AI-Act-Art14"],
    ))
    anchor = None
    if args.anchor == "witness":
        from agentaudit.anchoring import WitnessLog
        anchor = WitnessLog()
    cp = log.seal(anchor=anchor)
    print(f"session   {log.session_id}")
    print(f"entries   {log.size()}")
    print(f"root      {cp.root_hash}")
    print(f"signed    {'yes' if cp.signature else 'no'}")
    print(f"anchored  {args.anchor if cp.anchor else 'no'}")

    if args.out:
        bundle = export_bundle(log)
        Path(args.out).write_text(json.dumps(bundle, indent=2))
        print(f"bundle    written to {args.out}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    bundle = json.loads(Path(args.bundle).read_text())
    result = verify_bundle(bundle)
    print(result.summary())
    return 0 if result.ok else 1


def _cmd_tamper(args: argparse.Namespace) -> int:
    """Demonstrate tamper-evidence: mutate a bundle, re-verify, expect FAIL."""
    bundle = json.loads(Path(args.bundle).read_text())
    entries = bundle["entries"]
    target = min(args.seq, len(entries) - 1)
    before = entries[target].get("output")
    entries[target]["output"] = {"decision": "TAMPERED", "confidence": 0.0}
    print(f"tampered entry[{target}] output {before} -> {entries[target]['output']}\n")
    result = verify_bundle(bundle)
    print(result.summary())
    # Exit 0 when tamper is *detected* (the demo succeeded at its point).
    return 0 if not result.ok else 1


