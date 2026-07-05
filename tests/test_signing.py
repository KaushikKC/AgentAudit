import pytest

from agentaudit.crypto.signing import SigningKey, VerifyingKey, verify_signature


def test_sign_and_verify_roundtrip():
    sk = SigningKey.generate()
    vk = sk.verifying_key()
    msg = b"merkle-root-bytes"
    sig = sk.sign(msg)
    assert vk.verify(msg, sig)


def test_wrong_message_fails():
    sk = SigningKey.generate()
    sig = sk.sign(b"original")
    assert not sk.verifying_key().verify(b"tampered", sig)


def test_wrong_key_fails():
    sk1, sk2 = SigningKey.generate(), SigningKey.generate()
    sig = sk1.sign(b"msg")
    assert not sk2.verifying_key().verify(b"msg", sig)


def test_pem_roundtrip():
    sk = SigningKey.generate()
    pem = sk.to_pem()
    sk2 = SigningKey.from_pem(pem)
    sig = sk2.sign(b"data")
    assert sk.verifying_key().verify(b"data", sig)


def test_public_pem_and_raw_roundtrip():
    vk = SigningKey.generate().verifying_key()
    assert VerifyingKey.from_pem(vk.to_pem()).to_raw() == vk.to_raw()
    assert VerifyingKey.from_raw(vk.to_raw()).to_pem() == vk.to_pem()


def test_encrypted_pem():
    sk = SigningKey.generate()
    pem = sk.to_pem(password=b"s3cret")
    with pytest.raises(Exception):
        SigningKey.from_pem(pem)  # no password
    sk2 = SigningKey.from_pem(pem, password=b"s3cret")
    assert sk2.verifying_key().to_raw() == sk.verifying_key().to_raw()


def test_module_level_verify_signature():
    sk = SigningKey.generate()
    sig = sk.sign(b"hello")
    assert verify_signature(sk.verifying_key().to_pem(), b"hello", sig)
