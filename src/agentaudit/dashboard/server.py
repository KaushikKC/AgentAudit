"""Local dashboard server -- stdlib http.server, no extra runtime deps.

``serve()`` opens (and, if empty, seeds) a SQLite-backed store, then serves the
single-page app plus a small read-only JSON API backed by :class:`DashboardData`.
The route handlers are deliberately thin; all logic lives in the data layer so it
can be tested without a socket.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from agentaudit import Actor, AuditEvent, AuditLog, EventType, PolicyRef, SigningKey
from agentaudit.anchoring import WitnessLog
from agentaudit.dashboard.data import DashboardData
from agentaudit.dashboard.page import INDEX_HTML
from agentaudit.storage import SQLiteStore

__all__ = ["serve", "seed_demo", "make_handler"]


def seed_demo(store: SQLiteStore) -> None:
    """Populate a couple of realistic sessions so the dashboard is never empty."""
    # A KYC checker: PII input redacted (D3), root anchored to an offline witness.
    log = AuditLog(store=store, signing_key=SigningKey.generate())
    policy = PolicyRef(policy_id="kyc-uk-2026", version="1.4.2", hash="a1b2c3")
    actor = Actor(agent_id="kyc-checker-v3", framework="langchain", model="claude-sonnet-5")
    log.record(AuditEvent(event_type=EventType.RETRIEVAL, actor=actor, policy_ref=policy,
                          input={"name": "Jane Applicant", "document_id": "P1234567"},
                          output={"documents_found": 2, "identity_valid": True},
                          control_mapping=["EU-AI-Act-Art12", "NIST-MEASURE-2.3"]),
               redact_keys=["input"])
    log.record(AuditEvent(event_type=EventType.TOOL_CALL, actor=actor, policy_ref=policy,
                          output={"lists_checked": ["UK-HMT", "OFAC"], "match": False},
                          control_mapping=["EU-AI-Act-Art13", "ISO-42001-8.4"]))
    log.record(AuditEvent(event_type=EventType.DECISION, actor=actor, policy_ref=policy,
                          output={"decision": "approve", "confidence": 0.83},
                          control_mapping=["EU-AI-Act-Art13"]))
    log.seal(anchor=WitnessLog())

    # A support agent that escalates to a human on low confidence.
    log2 = AuditLog(store=store, signing_key=SigningKey.generate())
    a2 = Actor(agent_id="support-triage-v2", framework="crewai", model="claude-sonnet-5")
    log2.record(AuditEvent(event_type=EventType.LLM_GENERATION, actor=a2,
                           output={"intent": "refund_request", "confidence": 0.46}))
    log2.record(AuditEvent(event_type=EventType.HUMAN_OVERRIDE, actor=a2,
                           output={"decision": "route_to_human", "reason": "low_confidence"},
                           control_mapping=["EU-AI-Act-Art14", "NIST-MANAGE-4.1"]))
    log2.seal()


def make_handler(data: DashboardData):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # quiet by default
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj: Any, code: int = 200) -> None:
            self._send(code, json.dumps(obj).encode(), "application/json")

        def do_GET(self) -> None:
            u = urlparse(self.path)
            q = parse_qs(u.query)
            try:
                if u.path == "/" or u.path == "/index.html":
                    self._send(200, INDEX_HTML.encode(), "text/html; charset=utf-8")
                elif u.path == "/api/sessions":
                    self._json(data.sessions())
                elif u.path == "/api/session":
                    self._json(data.session(q["id"][0]))
                elif u.path == "/api/tamper":
                    self._json(data.simulate_tamper(q["id"][0], int(q.get("seq", ["0"])[0])))
                elif u.path == "/api/verify":
                    self._json(data.verify(q["id"][0]))
                else:
                    self._json({"error": "not found"}, 404)
            except KeyError:
                self._json({"error": "missing 'id' parameter"}, 400)
            except Exception as exc:  # surface, don't crash the server
                self._json({"error": str(exc)}, 500)

    return Handler


