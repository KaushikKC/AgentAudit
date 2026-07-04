"""Regulatory control catalog + evidence enrichment (differentiator D2).

A tamper-evident log proves *integrity*. What a compliance team actually needs
is to know *which obligation* each recorded event speaks to. This module maps
the short control identifiers used on events (e.g. ``"EU-AI-Act-Art14"``) to
human-readable titles and their source framework, so an exported evidence
bundle is self-describing: a reader who has never seen AgentAudit can see that
"this log covers EU AI Act record-keeping and human-oversight obligations."

The catalog is intentionally small and curated to the controls that a runtime
agent audit trail can genuinely provide evidence *for*. It is not legal advice
and not a certification -- it maps evidence to controls, honestly scoped.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

__all__ = ["Control", "CONTROL_CATALOG", "describe", "enrich"]


@dataclass(frozen=True)
class Control:
    id: str
    framework: str
    title: str
    relevance: str   # why an audit trail is evidence for this control


CONTROL_CATALOG: Dict[str, Control] = {
    c.id: c
    for c in [
        Control(
            "EU-AI-Act-Art12", "EU AI Act",
            "Record-keeping (automatic logging over the system's lifetime)",
            "Tamper-evident event logs are the record this article requires.",
        ),
        Control(
            "EU-AI-Act-Art13", "EU AI Act",
            "Transparency and provision of information to deployers",
            "Signed inputs/outputs + policy version make agent behaviour inspectable.",
        ),
        Control(
            "EU-AI-Act-Art14", "EU AI Act",
            "Human oversight",
            "Recording low-confidence routing to a human proves oversight was applied.",
        ),
        Control(
            "EU-AI-Act-Art15", "EU AI Act",
            "Accuracy, robustness and cybersecurity",
            "Cryptographic integrity of the record supports the security requirement.",
        ),
        Control(
            "NIST-GOVERN-1.2", "NIST AI RMF",
            "Govern: accountability structures and traceability",
            "Non-repudiable, signed records establish who/what decided and when.",
        ),
        Control(
            "NIST-MEASURE-2.3", "NIST AI RMF",
            "Measure: system performance monitored in deployment",
            "A durable per-decision record is the substrate for measurement.",
        ),
        Control(
            "NIST-MANAGE-4.1", "NIST AI RMF",
            "Manage: post-deployment monitoring and incident response",
            "An append-only trail supports investigation of a specific decision.",
        ),
        Control(
            "ISO-42001-8.4", "ISO/IEC 42001",
            "Operation: records of AI system operation",
            "Immutable operation records satisfy the documented-information clause.",
        ),
    ]
}


def describe(control_id: str) -> Optional[Dict[str, str]]:
    """Return a serializable description of ``control_id`` (or None if unknown)."""
    c = CONTROL_CATALOG.get(control_id)
    if c is None:
        return None
    return {
        "id": c.id,
        "framework": c.framework,
        "title": c.title,
        "relevance": c.relevance,
    }


def enrich(control_ids: List[str]) -> List[Dict[str, str]]:
    """Expand a list of control ids into full, self-describing entries.

    Unknown ids are still surfaced (with ``framework: "unmapped"``) rather than
    silently dropped -- an auditor should see everything the log referenced.
    """
    out: List[Dict[str, str]] = []
    for cid in control_ids:
        d = describe(cid)
        if d is None:
            d = {"id": cid, "framework": "unmapped", "title": cid, "relevance": ""}
        out.append(d)
    return out
