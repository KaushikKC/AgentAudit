"""Self-contained evidence bundle: export + offline verification.

A competitor ships "a log". AgentAudit ships *admissible evidence*: a single
self-verifying JSON package a regulator or auditor can check offline, without
our service running and without trusting us.

A bundle contains everything needed to re-derive every claim from scratch:

  * ``entries``      -- the full hash-chained log entries;
  * ``checkpoint``   -- the sealed, signed Merkle root (with the public key);
  * ``inclusion``    -- an inclusion proof per entry, resolving to that root;
  * ``controls``     -- the union of regulatory control mappings referenced,
                        so the reader sees which EU AI Act / NIST / ISO controls
                        this evidence speaks to;
  * ``manifest``     -- format version + how to verify.

:func:`verify_bundle` reproduces the chain, the Merkle root, the signature, and
every inclusion proof, and returns a structured pass/fail with per-check detail.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List

from agentaudit.controls import enrich
from agentaudit.log import AuditLog
from agentaudit.storage import Checkpoint
from agentaudit.verifier import (
    VerificationResult,
    verify_anchor,
    verify_chain,
    verify_inclusion_proof,
    verify_signed_checkpoint,
)

__all__ = ["BUNDLE_FORMAT", "export_bundle", "verify_bundle"]

BUNDLE_FORMAT = "agentaudit/evidence-bundle/v1"


def export_bundle(log: AuditLog) -> Dict[str, Any]:
    """Produce a self-contained, offline-verifiable evidence bundle for ``log``."""
    checkpoint = log.store.latest_checkpoint(log.session_id) or log.seal()
    entries = log.entries()

    inclusion = [
        log.inclusion_proof(e.seq, checkpoint=checkpoint).to_dict()
        for e in entries
    ]

    control_ids = sorted({c for e in entries for c in (e.control_mapping or [])})

    return {
        "manifest": {
            "format": BUNDLE_FORMAT,
            "session_id": log.session_id,
            "entry_count": len(entries),
            "how_to_verify": "agentaudit verify <this-file>  (or verify_bundle())",
        },
        "checkpoint": asdict(checkpoint),
        "entries": [
            (e.signed_body() | {"entry_hash": e.entry_hash}) for e in entries
        ],
        "inclusion": inclusion,
        # Self-describing regulatory coverage (D2): ids expanded to titles +
        # source framework so the bundle is readable without AgentAudit.
        "controls": enrich(control_ids),
    }


def verify_bundle(bundle: Dict[str, Any]) -> VerificationResult:
    """Independently verify every claim in an evidence bundle."""
    result = VerificationResult(ok=True)

    fmt = bundle.get("manifest", {}).get("format")
    result._add(fmt == BUNDLE_FORMAT, f"bundle format is {BUNDLE_FORMAT}")

    checkpoint = bundle["checkpoint"]
    entries = bundle["entries"]

    # 1. Chain integrity + Merkle root matches the sealed checkpoint.
    chain = verify_chain(entries, expected_root=checkpoint["root_hash"])
    _merge(result, chain)

    # 2. Signature over the checkpoint (if present).
    if checkpoint.get("signature"):
        _merge(result, verify_signed_checkpoint(checkpoint))

    # 3. Every inclusion proof resolves to the sealed root.
    for proof in bundle.get("inclusion", []):
        _merge(result, verify_inclusion_proof(proof))

    # 4. External anchor, if the root was anchored (offline-verifiable ones only).
    if checkpoint.get("anchor"):
        _merge(result, verify_anchor(checkpoint["anchor"]))

    return result


