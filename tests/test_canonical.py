import pytest

from agentaudit.crypto.canonical import CanonicalizationError, canonicalize


def test_key_order_is_stable():
    a = canonicalize({"b": 1, "a": 2})
    b = canonicalize({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


def test_no_insignificant_whitespace():
    assert canonicalize({"x": [1, 2, 3]}) == b'{"x":[1,2,3]}'


def test_nested_determinism():
    obj = {"z": {"y": 1, "x": 2}, "a": [{"c": 3, "b": 4}]}
    assert canonicalize(obj) == b'{"a":[{"b":4,"c":3}],"z":{"x":2,"y":1}}'


def test_utf8_not_escaped():
    assert canonicalize({"name": "Müller"}) == '{"name":"Müller"}'.encode("utf-8")


def test_rejects_nan_and_inf():
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(CanonicalizationError):
            canonicalize({"v": bad})


def test_rejects_non_string_keys():
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "a"})
