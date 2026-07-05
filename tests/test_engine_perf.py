"""Engine correctness under the incremental-Merkle / cached-state rewrite.

These lock in the behaviours the O(n^2) fix must preserve: the cached root still
equals a from-scratch recompute, a reopened log continues the chain, and
concurrent writers still produce one valid contiguous chain.
"""

import threading

from agentaudit import Actor, AuditEvent, AuditLog, EventType, SigningKey
from agentaudit.crypto import merkle
from agentaudit.storage import SQLiteStore
from agentaudit.verifier import verify_chain


def _ev(i):
    return AuditEvent(event_type=EventType.TOOL_CALL, actor=Actor(agent_id="bench"),
                      output={"i": i})


def test_cached_root_matches_full_recompute():
    log = AuditLog(signing_key=SigningKey.generate())
    for i in range(200):
        log.record(_ev(i))
    # Independent recompute from the raw stored entries.
    leaves = [merkle.hash_leaf(bytes.fromhex(e.entry_hash)) for e in log.entries()]
    assert log.merkle_root() == merkle.merkle_root(leaves).hex()
    assert verify_chain(log.entries(), expected_root=log.seal().root_hash).ok


def test_reopened_log_continues_chain():
    store = SQLiteStore(":memory:")
    sid = None
    log = AuditLog(store=store)
    sid = log.session_id
    for i in range(10):
        log.record(_ev(i))

    # A fresh AuditLog over the same store loads cached state and continues.
    reopened = AuditLog(store=store, session_id=sid)
    assert reopened.size() == 10
    entry = reopened.record(_ev(10))
    assert entry.seq == 10
    assert entry.prev_hash == store.entries(sid)[9].entry_hash
    assert verify_chain(reopened.entries()).ok


def test_incremental_matches_after_each_append():
    log = AuditLog()
    for i in range(64):
        log.record(_ev(i))
        leaves = [merkle.hash_leaf(bytes.fromhex(e.entry_hash)) for e in log.entries()]
        assert log.merkle_root() == merkle.merkle_root(leaves).hex()


def test_concurrent_records_produce_valid_chain():
    store = SQLiteStore(":memory:", check_same_thread=False)
    log = AuditLog(store=store)
    n_threads, per = 8, 50

    def worker():
        for i in range(per):
            log.record(_ev(i))

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    entries = log.entries()
    assert len(entries) == n_threads * per
    # Sequence numbers are contiguous and the chain links -- no lost/dup appends.
    assert [e.seq for e in entries] == list(range(n_threads * per))
    assert verify_chain(entries).ok
