"""The sealed-line sentence: measured only where a ledger realized the floor."""

from __future__ import annotations


class FloorSentence:
    """Renders the consumer sentence for a mediated seal.

    `power_min` is sort-honest. Calling every floor "measured" was the defect:
    a claim attacked only by declarations clears its floor by declaration, and
    the seal's floor witness is what says which.
    """

    def render(self, seal) -> str:
        claim = min(seal.claims, key=lambda c: c.floor_basis)
        basis = claim.floor_witness or "declared"
        strength = "measured" if basis.startswith("ledger") else "declared"
        return (
            f"Sealed: survived the pinned refuter at {strength} power "
            f"{seal.power_min:g} ({basis}); "
            f"concordance is ({claim.agreeing}, {seal.k}) — unmeasured at k=1."
        )
