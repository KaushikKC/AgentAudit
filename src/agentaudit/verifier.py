"""Offline verifier -- checks an audit log or evidence bundle from raw data.

The whole value proposition is "don't trust our dashboard, verify it yourself".
So this module deliberately depends only on the crypto primitives and the
schema -- no storage, no network, no service. Point it at a list of entries (or
a self-contained evidence bundle) and it will independently:

  1. **Chain integrity**  -- each ``entry_hash`` recomputes from its content, and
     each entry's ``prev_hash`` equals the previous entry's ``entry_hash``
     (catches edits, reordering, and gaps).
  2. **Merkle commitment** -- the Merkle root over the entry hashes matches the
     root the operator sealed and signed.
  3. **Signature**        -- the sealed root was signed by the claimed key.
  4. **Proofs**           -- inclusion and consistency proofs check out.

Every failure is reported with the sequence number and reason, so a tampered
log tells you exactly which entry was touched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from agentaudit.crypto import merkle
from agentaudit.crypto.signing import VerifyingKey
from agentaudit.redaction import SelectiveDisclosure
from agentaudit.redaction import verify_disclosure as _verify_sd
from agentaudit.schema import GENESIS_HASH, LogEntry, compute_entry_hash

__all__ = ["VerificationResult", "verify_chain", "verify_inclusion_proof",
           "verify_consistency_proof", "verify_signed_checkpoint",
           "verify_disclosure", "verify_anchor"]


@dataclass
class VerificationResult:
    """Outcome of a verification, with human-readable detail."""

    ok: bool
    checks: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def _add(self, ok: bool, msg: str) -> bool:
        (self.checks if ok else self.errors).append(msg)
        if not ok:
            self.ok = False
        return ok

    def __bool__(self) -> bool:
        return self.ok

    def summary(self) -> str:
        head = "PASS" if self.ok else "FAIL"
        lines = [f"[{head}] {len(self.checks)} checks passed, {len(self.errors)} failed"]
        lines += [f"  ok  {c}" for c in self.checks]
        lines += [f"  !!  {e}" for e in self.errors]
        return "\n".join(lines)


def _to_entries(raw: Sequence[Any]) -> List[LogEntry]:
    out: List[LogEntry] = []
    for item in raw:
        out.append(item if isinstance(item, LogEntry) else LogEntry.from_dict(item))
    return out


def verify_chain(
    entries: Sequence[Any],
    expected_root: Optional[str] = None,
) -> VerificationResult:
    """Verify hash-chain integrity over ``entries`` (dicts or LogEntry objects).

    If ``expected_root`` is given, also check the Merkle root matches it.
    """
    res = VerificationResult(ok=True)
    items = _to_entries(entries)

    if not items:
        res._add(False, "no entries to verify")
        return res

    prev = GENESIS_HASH
    for i, e in enumerate(items):
        res._add(e.seq == i, f"seq[{i}] is contiguous (got {e.seq})")
        recomputed = compute_entry_hash(e.signed_body())
        res._add(
            e.entry_hash == recomputed,
            f"entry[{e.seq}] hash matches content",
        )
        res._add(
            e.prev_hash == prev,
            f"entry[{e.seq}] prev_hash links to entry[{e.seq - 1}]",
        )
        prev = e.entry_hash

    if expected_root is not None:
        leaves = [merkle.hash_leaf(bytes.fromhex(e.entry_hash)) for e in items]
        root = merkle.merkle_root(leaves).hex()
        res._add(root == expected_root, "Merkle root matches sealed checkpoint")

    return res


