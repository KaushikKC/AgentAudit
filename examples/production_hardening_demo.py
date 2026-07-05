"""Production hardening demo.

Shows the operational features that turn the engine from a demo into something
you'd actually run: a signing key encrypted at rest (not generated in-process),
automatic sealing on a threshold (no manual ``.seal()``), and a background witness
anchor -- all behind a context manager that flushes a final checkpoint on exit.

Run it::

    python examples/production_hardening_demo.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agentaudit import (
    Actor,
    AuditEvent,
    AuditLog,
    EncryptedFileKeyProvider,
    EventType,
    SealPolicy,
)
from agentaudit.anchoring import WitnessLog
from agentaudit.bundle import export_bundle, verify_bundle


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="agentaudit-"))
    key_path = workdir / "signing.key.pem"

    # 1. Signing key encrypted at rest (password from arg or $AGENTAUDIT_KEY_PASSWORD).
    key_provider = EncryptedFileKeyProvider(key_path, password=b"correct horse battery")
    print("== Key management ==")
    print(f"  signing key encrypted at rest: {key_path.name} "
          f"(perms {oct(key_path.stat().st_mode)[-3:]})")

    # 2. Auto-seal every 5 events + a background time-based seal, witness-anchored.
    log = AuditLog(
        store=None,
        key_provider=key_provider,
        seal_policy=SealPolicy(every_n_events=5, every_seconds=30),
        auto_anchor=WitnessLog(),
    )

    print("\n== Automated sealing (every 5 events) ==")
    with log:  # context manager seals any remainder on exit
        for i in range(12):
            log.record(AuditEvent(
                event_type=EventType.TOOL_CALL,
                actor=Actor(agent_id="triage-agent", framework="langchain"),
                output={"i": i},
            ))
        checkpoints = log.store.checkpoints(log.session_id)
        print(f"  after 12 events: {len(checkpoints)} auto-checkpoints at sizes "
              f"{[c.tree_size for c in checkpoints]}")

    final = log.store.checkpoints(log.session_id)
    print(f"  after close():   {len(final)} checkpoints, last covers {final[-1].tree_size} events")
    print(f"  every checkpoint signed + anchored: "
          f"{all(c.signature and c.anchor for c in final)}")

    print("\n== Verification ==")
    result = verify_bundle(export_bundle(log))
    print(f"  {result.summary().splitlines()[0]}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
