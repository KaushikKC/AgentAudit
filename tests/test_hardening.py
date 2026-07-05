"""Production-hardening tests: key providers, automated sealing, storage iface."""

import threading
import time

import pytest

from agentaudit import (
    Actor,
    AuditEvent,
    AuditLog,
    EncryptedFileKeyProvider,
    EventType,
    LocalKeyProvider,
    SealPolicy,
    SigningKey,
    SQLiteStore,
    StorageBackend,
)
from agentaudit.bundle import export_bundle, verify_bundle


def _ev(i=0):
    return AuditEvent(event_type=EventType.TOOL_CALL, actor=Actor(agent_id="a"), output={"i": i})


# --- key providers ----------------------------------------------------------
def test_local_key_provider_signs_and_verifies():
    log = AuditLog(key_provider=LocalKeyProvider())
    log.record(_ev())
    assert verify_bundle(export_bundle(log)).ok


def test_encrypted_file_key_provider_roundtrip(tmp_path):
    path = tmp_path / "signing.pem"
    kp = EncryptedFileKeyProvider(path, password=b"s3cret")
    assert path.exists()
    pub = kp.public_key_pem()

    # Reopen with the same password -> same key; signed bundle verifies.
    kp2 = EncryptedFileKeyProvider(path, password=b"s3cret")
    assert kp2.public_key_pem() == pub

    log = AuditLog(key_provider=kp2)
    log.record(_ev())
    assert verify_bundle(export_bundle(log)).ok


def test_encrypted_file_key_wrong_password_fails(tmp_path):
    path = tmp_path / "k.pem"
    EncryptedFileKeyProvider(path, password=b"right")
    with pytest.raises(Exception):
        EncryptedFileKeyProvider(path, password=b"wrong")


def test_encrypted_file_key_password_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTAUDIT_KEY_PASSWORD", "envpw")
    path = tmp_path / "k.pem"
    kp = EncryptedFileKeyProvider(path)          # password from env
    assert path.exists() and kp.public_key_pem()


def test_missing_password_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTAUDIT_KEY_PASSWORD", raising=False)
    with pytest.raises(ValueError):
        EncryptedFileKeyProvider(tmp_path / "k.pem")


# --- automated sealing ------------------------------------------------------
def test_seal_every_n_events():
    log = AuditLog(signing_key=SigningKey.generate(),
                   seal_policy=SealPolicy(every_n_events=5))
    for i in range(12):
        log.record(_ev(i))
    cps = log.store.checkpoints(log.session_id)
    # Seals fired at 5 and 10 events (12th hasn't reached the next threshold).
    assert [c.tree_size for c in cps] == [5, 10]
    assert all(c.signature for c in cps)


def test_seal_on_close_flushes_remaining():
    log = AuditLog(signing_key=SigningKey.generate(),
                   seal_policy=SealPolicy(every_n_events=10))
    for i in range(3):
        log.record(_ev(i))
    assert log.store.checkpoints(log.session_id) == []   # below threshold
    log.close()
    cps = log.store.checkpoints(log.session_id)
    assert cps and cps[-1].tree_size == 3                # flushed on close


def test_seal_every_seconds_background():
    log = AuditLog(signing_key=SigningKey.generate(),
                   seal_policy=SealPolicy(every_seconds=0.1))
    try:
        for i in range(3):
            log.record(_ev(i))
        time.sleep(0.35)                                  # let the timer fire
        cps = log.store.checkpoints(log.session_id)
        assert cps and cps[-1].tree_size == 3
    finally:
        log.close()


def test_context_manager_seals_on_exit():
    store = SQLiteStore(":memory:")
    with AuditLog(store=store, signing_key=SigningKey.generate(),
                  seal_policy=SealPolicy(every_n_events=100)) as log:
        sid = log.session_id
        for i in range(4):
            log.record(_ev(i))
    assert store.checkpoints(sid)[-1].tree_size == 4


# --- storage interface ------------------------------------------------------
def test_sqlite_store_is_a_storage_backend():
    assert issubclass(SQLiteStore, StorageBackend)
    assert isinstance(SQLiteStore(":memory:"), StorageBackend)
