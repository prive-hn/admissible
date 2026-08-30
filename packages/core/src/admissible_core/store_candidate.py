"""The persistence a candidate-side run is allowed to reach.

Evaluating a commit produces observations: which commands ran and what they
exited with, which attempt they belonged to, which dependency was seen, what
may be reused next time.  All of it is description.  None of it is an
assertion, and the difference is the whole point of the split -- a description
becomes binding when a receipt is issued over it, and issuing receipts is the
Trust distribution's capability, not this one's.

So this facade is exactly the read surface plus those observation writes.  It
is not "the store minus a few dangerous methods": the reachable set is
enumerated, so a capability added to the backend tomorrow is unreachable here
until somebody deliberately lists it.
"""
from __future__ import annotations

from .store_base import CANDIDATE_WRITE_CAPABILITIES
from .store_read import ReadStore

__all__ = ["CandidateStore"]


class CandidateStore(ReadStore):
    """Reads, plus the writes that only ever record an observation."""

    CAPABILITIES = ReadStore.CAPABILITIES | CANDIDATE_WRITE_CAPABILITIES

    __slots__ = ()
