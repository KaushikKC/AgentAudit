"""Dashboard data layer -- read-only views over stored audit sessions.

All the logic the UI needs, decoupled from HTTP so it's unit-testable without a
socket. Every verification here runs the *real* engine (`export_bundle` /
`verify_bundle`) -- the dashboard shows the same result an auditor would get
offline, never a cached "trust me" status.
"""

from __future__ import annotations

import copy
import threading
from typing import Any, Dict, List, Optional

from agentaudit.anchoring.base import AnchorReceipt
from agentaudit.bundle import export_bundle, verify_bundle
from agentaudit.log import AuditLog
from agentaudit.storage import SQLiteStore

__all__ = ["DashboardData"]


class DashboardData:
    def __init__(self, store: SQLiteStore) -> None:
        self.store = store
        # Serialize store access: a shared SQLite connection is read from
        # multiple HTTP worker threads.
        self._lock = threading.Lock()

    def _log(self, session_id: str) -> AuditLog:
        # No signing key needed: reads the already-sealed, signed checkpoint.
        return AuditLog(store=self.store, session_id=session_id)

    def _anchor_summary(self, anchor_json: Optional[str]) -> Optional[Dict[str, Any]]:
        if not anchor_json:
            return None
        r = AnchorReceipt.from_json(anchor_json)
        return {"backend": r.backend, "anchored_at": r.anchored_at,
                "log_index": r.proof.get("log_index")}

    # -- collection --------------------------------------------------------
    def sessions(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        with self._lock:
            sids = self.store.sessions()
            snapshot = [(sid, self.store.entries(sid), self.store.latest_checkpoint(sid))
                        for sid in sids]
        for sid, entries, cp in snapshot:
            actor = entries[0].actor if entries else {}
            out.append({
                "session_id": sid,
                "agent_id": actor.get("agent_id", "unknown"),
                "framework": actor.get("framework"),
                "event_count": len(entries),
                "root_hash": cp.root_hash if cp else None,
                "signed": bool(cp and cp.signature),
                "anchor": self._anchor_summary(cp.anchor if cp else None),
                "started_at": entries[0].timestamp if entries else None,
            })
        out.sort(key=lambda s: s.get("started_at") or "", reverse=True)
        return out

    # -- detail ------------------------------------------------------------
    def session(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            bundle = export_bundle(self._log(session_id))
        result = verify_bundle(bundle)
        return {
            "session_id": session_id,
            "checkpoint": bundle["checkpoint"],
            "anchor": self._anchor_summary(bundle["checkpoint"].get("anchor")),
            "entries": bundle["entries"],
            "controls": bundle["controls"],
            "verification": self._result(result),
        }

    def verify(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            bundle = export_bundle(self._log(session_id))
        return self._result(verify_bundle(bundle))

    def simulate_tamper(self, session_id: str, seq: int) -> Dict[str, Any]:
        """Non-destructive: flip a field on a copy and re-verify to show the catch."""
        with self._lock:
            bundle = copy.deepcopy(export_bundle(self._log(session_id)))
        entries = bundle["entries"]
        seq = max(0, min(seq, len(entries) - 1))
        target = entries[seq]
        before = copy.deepcopy(target.get("output"))
        # Flip an output field (or synthesize one) to a bogus value.
        if isinstance(target.get("output"), dict) and target["output"]:
            key = next(iter(target["output"]))
            target["output"][key] = "TAMPERED"
        else:
            target["output"] = {"tampered": True}
        result = verify_bundle(bundle)
        return {
            "tampered_seq": seq,
            "before": before,
            "after": target.get("output"),
            "verification": self._result(result),
        }

    @staticmethod
    def _result(result) -> Dict[str, Any]:
        return {"ok": result.ok, "checks": result.checks, "errors": result.errors,
                "passed": len(result.checks), "failed": len(result.errors)}
