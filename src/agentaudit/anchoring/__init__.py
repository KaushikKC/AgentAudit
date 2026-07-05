"""External anchoring of sealed Merkle roots (Phase 3).

Anchoring commits each signed root to an external trusted location the operator
cannot backdate, adding provable time + third-party non-repudiation on top of
local signing.

  * :class:`~agentaudit.anchoring.witness.WitnessLog` -- independent cosigning
    witness; receipts verify **offline** (with a pinned witness key).
  * :class:`~agentaudit.anchoring.rekor.RekorAnchor` -- Sigstore Rekor public
    transparency log; provable time, verify by re-fetch.

The Rekor backend is imported lazily so this package needs no network stack to
import; ``AnchorBackend`` / ``AnchorReceipt`` / ``WitnessLog`` are always here.
"""

from agentaudit.anchoring.base import AnchorBackend, AnchorReceipt
from agentaudit.anchoring.witness import WitnessLog, verify_witness_receipt

__all__ = ["AnchorBackend", "AnchorReceipt", "WitnessLog", "verify_witness_receipt"]
