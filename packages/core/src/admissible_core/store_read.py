"""A read-only view of a durable Admissible home.

This is the surface for every consumer whose question is "what does this home
already say?" -- an inspection command, a standing query, a projection that
renders what was recorded.  None of those has any business writing, and the way
to say so is to hand out an object that cannot.

Reading a receipt, a defect or the trusted-policy baseline is included on
purpose.  Those records are facts about what an authority already did; the
authority is in *making* them, and every method that makes one is withheld in
:mod:`admissible_core.store_base`.  A reader that could not see receipts would
not be safer, it would just be unable to tell anyone what was admitted.
"""
from __future__ import annotations

from .store_base import READ_CAPABILITIES, CapabilityFacade

__all__ = ["ReadStore"]


class ReadStore(CapabilityFacade):
    """Every read the durable store offers, and not one write.

    The backend is injected rather than opened here: which object satisfies
    these methods -- the durable SQLite store, a replica, a fixture -- is the
    caller's decision, and Core's decision is only which methods are reachable
    through this object at all.
    """

    CAPABILITIES = READ_CAPABILITIES

    __slots__ = ()
