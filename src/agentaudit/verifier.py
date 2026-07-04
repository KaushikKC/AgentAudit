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


def verify_signed_checkpoint(
    checkpoint: Dict[str, Any],
) -> VerificationResult:
    """Verify an Ed25519 signature over a checkpoint body (root + metadata)."""
    from agentaudit.crypto.canonical import canonicalize

    res = VerificationResult(ok=True)
    sig = checkpoint.get("signature")
    pem = checkpoint.get("public_key")
    if not sig or not pem:
        res._add(False, "checkpoint is unsigned")
        return res
    body = canonicalize({
        "session_id": checkpoint["session_id"],
        "tree_size": checkpoint["tree_size"],
        "root_hash": checkpoint["root_hash"],
        "timestamp": checkpoint["timestamp"],
    })
    vk = VerifyingKey.from_pem(pem.encode() if isinstance(pem, str) else pem)
    res._add(
        vk.verify(body, bytes.fromhex(sig)),
        f"checkpoint signature valid (tree_size={checkpoint['tree_size']})",
    )
    return res


def verify_inclusion_proof(proof: Dict[str, Any]) -> VerificationResult:
    """Verify an inclusion proof dict (as produced by AuditLog.inclusion_proof)."""
    res = VerificationResult(ok=True)
    cp = proof["checkpoint"]
    ok = merkle.verify_inclusion(
        index=proof["seq"],
        tree_size=proof["tree_size"],
        leaf_hash=merkle.hash_leaf(bytes.fromhex(proof["entry_hash"])),
        proof=[bytes.fromhex(h) for h in proof["path"]],
        root=bytes.fromhex(cp["root_hash"]),
    )
    res._add(ok, f"inclusion proof for entry[{proof['seq']}] resolves to sealed root")
    return res


def verify_anchor(
    anchor_json: str,
    trusted_witness_keys: Optional[Sequence[str]] = None,
    trusted_rekor_key: Optional[str] = None,
    online: bool = False,
) -> VerificationResult:
    """Verify an external anchor receipt (as stored on a checkpoint).

    Witness receipts verify offline (optionally pinned to ``trusted_witness_keys``).
    Rekor receipts verify **offline** too when the SET material is present -- the
    signed entry timestamp is checked against Rekor's log key (pin it via
    ``trusted_rekor_key``); ``online=True`` forces a re-fetch instead.
    """
    from agentaudit.anchoring.base import AnchorReceipt
    from agentaudit.anchoring.witness import verify_witness_receipt

    res = VerificationResult(ok=True)
    receipt = AnchorReceipt.from_json(anchor_json)
    p = receipt.proof

    if receipt.backend == "witness":
        ok = verify_witness_receipt(receipt, trusted_keys=trusted_witness_keys)
        note = "" if trusted_witness_keys is not None else " (key not pinned)"
        res._add(ok, f"witness anchor cosignature valid{note}")
    elif receipt.backend == "rekor":
        from agentaudit.anchoring.rekor import verify_rekor_receipt

        has_set = bool(p.get("signed_entry_timestamp") and p.get("body")
                       and (p.get("rekor_public_key") or trusted_rekor_key))
        if has_set and not online:
            ok = verify_rekor_receipt(receipt, trusted_rekor_key=trusted_rekor_key)
            note = "" if trusted_rekor_key else " (Rekor key not pinned)"
            res._add(ok, f"rekor SET verified offline against log key{note} "
                         f"(logIndex={p.get('log_index')})")
        elif online:
            res._add(verify_rekor_receipt(receipt, online=True),
                     f"rekor entry re-fetched and matches (logIndex={p.get('log_index')})")
        else:
            res.checks.append(
                f"rekor anchor present (logIndex={p.get('log_index')}); "
                "no SET material to verify offline")
    else:
        res._add(False, f"unknown anchor backend: {receipt.backend}")
    return res


def verify_disclosure(excerpt: Dict[str, Any]) -> VerificationResult:
    """Verify a selective-disclosure excerpt (D3) end-to-end, offline.

    Chains four checks so the revealed fields are trustworthy without exposing
    the hidden ones:
      1. the disclosure reconstructs the entry's committed ``content_commitment``;
      2. the entry's ``entry_hash`` recomputes from its visible body;
      3. that entry is included in the sealed Merkle root (inclusion proof);
      4. the checkpoint signature is valid (if the checkpoint is signed).

    On success, the revealed field values are attached to the result message.
    """
    res = VerificationResult(ok=True)
    entry = excerpt["entry"]
    sd = SelectiveDisclosure.from_dict(excerpt["disclosure"])

    # 1. Disclosure reconstructs the committed content root.
    ok_sd, revealed = _verify_sd(sd)
    res._add(ok_sd, "selective disclosure reconstructs the committed field root")
    res._add(
        sd.content_root == entry.get("content_commitment"),
        "disclosed content_root matches the entry's content_commitment",
    )

    # 2. Entry hash recomputes from the visible body (no PII needed).
    le = LogEntry.from_dict(entry)
    res._add(le.entry_hash == compute_entry_hash(le.signed_body()),
             "entry hash matches its visible content")

    # 3. Inclusion proof resolves to the sealed root.
    _merge_into(res, verify_inclusion_proof(excerpt["inclusion"]))

    # 4. Signature over the checkpoint, if signed.
    cp = excerpt["inclusion"]["checkpoint"]
    if cp.get("signature"):
        _merge_into(res, verify_signed_checkpoint(cp))

    if res.ok and revealed:
        res.checks.append(f"revealed (authenticated) fields: {revealed}")
    return res


def _merge_into(into: VerificationResult, other: VerificationResult) -> None:
    into.checks.extend(other.checks)
    into.errors.extend(other.errors)
    if not other.ok:
        into.ok = False


def verify_consistency_proof(
    first_size: int,
    second_size: int,
    first_root: str,
    second_root: str,
    path: Sequence[str],
) -> VerificationResult:
    """Verify the log grew append-only from ``first_size`` to ``second_size``."""
    res = VerificationResult(ok=True)
    ok = merkle.verify_consistency(
        first=first_size,
        second=second_size,
        first_root=bytes.fromhex(first_root),
        second_root=bytes.fromhex(second_root),
        proof=[bytes.fromhex(h) for h in path],
    )
    res._add(ok, f"log is an append-only extension ({first_size} -> {second_size})")
    return res
