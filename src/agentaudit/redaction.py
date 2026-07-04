"""Redaction-preserving selective disclosure (differentiator D3).

Real audit data is full of PII. The naive options are both bad: log the PII (and
now your audit tool is a breach waiting to happen), or log nothing useful (and
you can't prove anything). D3 is the third way -- **prove a property of an event,
and prove that event is in the tamper-evident log, without revealing the raw
data.**

The mechanism is a per-field *salted Merkle commitment*. Instead of hashing a
value's whole subtree as one blob, we:

  1. flatten it into individual ``(path, value)`` fields;
  2. give each field a random salt and hash it into a Merkle leaf
     ``H(canonical({path, value, salt}))``;
  3. commit to all leaves with a Merkle root -- the ``content_commitment`` that
     the tamper-evident log seals and signs.

To disclose, the operator reveals ``(value, salt)`` for the chosen fields and
only the *leaf hash* for the rest. A verifier recomputes the revealed leaves,
combines them with the hidden leaf hashes, and checks the Merkle root matches
the committed one. Consequences:

  * A revealed value can't be faked -- a wrong value yields a wrong leaf and the
    root won't match.
  * A hidden value stays hidden *and unguessable* -- the per-field salt defeats
    dictionary attacks even on low-entropy fields like ``decision in {approve, deny}``.

This is a Hartung-style redactable proof, scoped honestly: it hides field
*values*, not the *set of field paths* (the shape of the record is revealed).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Tuple

from agentaudit.crypto import merkle
from agentaudit.crypto.canonical import canonicalize

__all__ = [
    "flatten_fields",
    "Sealed",
    "SelectiveDisclosure",
    "seal_fields",
    "make_disclosure",
    "verify_disclosure",
    "leaf_hash",
]

_SALT_BYTES = 16


def flatten_fields(obj: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten a JSON value into ``{dotted.path: scalar}`` leaves.

    Dicts recurse by key, lists by index. Empty containers are themselves leaves
    (so the shape round-trips). ``prefix`` namespaces the paths (e.g. "input").
    """
    out: Dict[str, Any] = {}
    if isinstance(obj, dict) and obj:
        for k, v in obj.items():
            out.update(flatten_fields(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list) and obj:
        for i, v in enumerate(obj):
            out.update(flatten_fields(v, f"{prefix}[{i}]" if prefix else f"[{i}]"))
    else:
        out[prefix] = obj
    return out


def leaf_hash(path: str, value: Any, salt: str) -> bytes:
    """The Merkle leaf for one field: H(0x00 || canonical({path,value,salt}))."""
    return merkle.hash_leaf(canonicalize({"path": path, "value": value, "salt": salt}))


@dataclass
class Sealed:
    """Operator-held secret material for a committed field set.

    ``content_root`` is public (it goes in the log). ``salts`` are secret -- they
    are what lets the operator later disclose specific fields.
    """

    content_root: str                 # hex Merkle root over the field leaves
    order: List[str]                  # canonical field ordering (sorted paths)
    fields: Dict[str, Any]            # path -> raw value  (SECRET)
    salts: Dict[str, str]             # path -> hex salt   (SECRET)


def seal_fields(fields: Dict[str, Any]) -> Sealed:
    """Commit to ``fields`` with a salted per-field Merkle root."""
    order = sorted(fields)
    salts = {p: secrets.token_hex(_SALT_BYTES) for p in order}
    leaves = [leaf_hash(p, fields[p], salts[p]) for p in order]
    root = merkle.merkle_root(leaves).hex()
    return Sealed(content_root=root, order=order, fields=dict(fields), salts=salts)


@dataclass
class SelectiveDisclosure:
    """A verifiable excerpt: some fields revealed, the rest committed-but-hidden."""

    content_root: str
    order: List[str]
    revealed: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # path -> {value, salt}
    hidden: Dict[str, str] = field(default_factory=dict)              # path -> leaf hash hex

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content_root": self.content_root,
            "order": self.order,
            "revealed": self.revealed,
            "hidden": self.hidden,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SelectiveDisclosure":
        return cls(
            content_root=d["content_root"],
            order=list(d["order"]),
            revealed=dict(d.get("revealed", {})),
            hidden=dict(d.get("hidden", {})),
        )


def make_disclosure(sealed: Sealed, reveal_paths: Sequence[str]) -> SelectiveDisclosure:
    """Produce an excerpt revealing ``reveal_paths`` and hiding everything else."""
    reveal = set(reveal_paths)
    unknown = reveal - set(sealed.order)
    if unknown:
        raise KeyError(f"unknown field paths: {sorted(unknown)}")

    revealed: Dict[str, Dict[str, Any]] = {}
    hidden: Dict[str, str] = {}
    for p in sealed.order:
        if p in reveal:
            revealed[p] = {"value": sealed.fields[p], "salt": sealed.salts[p]}
        else:
            hidden[p] = leaf_hash(p, sealed.fields[p], sealed.salts[p]).hex()
    return SelectiveDisclosure(
        content_root=sealed.content_root, order=sealed.order,
        revealed=revealed, hidden=hidden,
    )


def verify_disclosure(sd: SelectiveDisclosure) -> Tuple[bool, Dict[str, Any]]:
    """Verify an excerpt against its ``content_root``.

    Returns ``(ok, revealed_values)``. ``ok`` is True iff the revealed fields and
    hidden leaf hashes reconstruct exactly the committed Merkle root -- i.e. the
    revealed values are authentic and provably part of the committed record.
    """
    leaves: List[bytes] = []
    for p in sd.order:
        if p in sd.revealed:
            r = sd.revealed[p]
            leaves.append(leaf_hash(p, r["value"], r["salt"]))
        elif p in sd.hidden:
            leaves.append(bytes.fromhex(sd.hidden[p]))
        else:
            return False, {}  # a field neither revealed nor accounted for
    root = merkle.merkle_root(leaves).hex()
    if root != sd.content_root:
        return False, {}
    return True, {p: sd.revealed[p]["value"] for p in sd.revealed}
