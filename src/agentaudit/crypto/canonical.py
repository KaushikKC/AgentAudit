"""Deterministic (canonical) serialization of audit events.

Two independent parties must be able to hash the *same* event and get the
*same* bytes, forever. That rules out ordinary ``json.dumps`` (key order,
whitespace, and float formatting are all implementation-defined). We follow
the JSON Canonicalization Scheme (RFC 8785 / JCS) closely enough for our
schema: sorted keys, minimal separators, UTF-8, and rejection of values that
have no canonical form (``NaN``, ``Infinity``).

Keeping this tiny and dependency-free is deliberate: the offline verifier must
be able to reproduce these exact bytes without pulling in our whole stack.
"""

from __future__ import annotations

import json
import math
from typing import Any

__all__ = ["canonicalize", "CanonicalizationError"]


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonically serialized."""


def _check(value: Any) -> None:
    """Reject values that have no single canonical representation."""
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError(
                f"non-finite float {value!r} has no canonical form"
            )
    elif isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalizationError(
                    f"object keys must be strings, got {type(k).__name__}"
                )
            _check(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _check(v)


