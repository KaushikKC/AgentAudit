"""Ingestion throughput benchmark.

Demonstrates that recording events is now **linear**: the incremental Merkle
tree (a Merkle Mountain Range frontier) keeps the RFC 6962 root in O(log n) per
append, and cached chain state removes the old per-append full-log rescan. The
per-record time stays flat as the log grows -- the signature of an O(n) ingest,
not the O(n^2) it was before.

Run it::

    python examples/benchmark.py
"""

from __future__ import annotations

import time

from agentaudit import Actor, AuditEvent, AuditLog, EventType


def _record_n(n: int) -> float:
    log = AuditLog()  # in-memory store; measures the record() hot path
    actor = Actor(agent_id="bench", framework="benchmark")
    t0 = time.perf_counter()
    for i in range(n):
        log.record(AuditEvent(event_type=EventType.TOOL_CALL, actor=actor, output={"i": i}))
    return time.perf_counter() - t0


def main() -> int:
    print("Ingestion throughput (flat per-record time == linear, not quadratic)\n")
    print(f"  {'events':>8}  {'total':>10}  {'per record':>12}  {'rate':>16}")
    print("  " + "-" * 50)
    for n in (1_000, 5_000, 20_000, 50_000):
        dt = _record_n(n)
        print(f"  {n:>8,}  {dt*1000:>8.0f} ms  {dt/n*1e6:>9.1f} µs  {n/dt:>12,.0f} rec/s")

    print("\nWhy it's flat: appending updates O(log n) Merkle frontier nodes and")
    print("O(1) cached chain state — no full-log rescan. The old code re-read and")
    print("re-hashed the entire log on every append (O(n) per record → O(n²) total).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
