"""A journaled Admission-position cut. A root on replay: bounded, not trusted."""

from __future__ import annotations


class RecordedCut:
    """`as_of` naming an Admission journal position.

    Live transitions write the current position. Rebuild treats the journaled
    value as a root: an integer, inside the scrutiny journal, at or after a
    per-event floor, and never earlier than a prior recorded cut of any event
    type that carries one. That converts a forged cut from a free choice into
    a coherent rewrite of the surrounding record.
    """

    TYPES = frozenset({"cal_run", "cal_exclude", "cal_install", "cal_close"})

    def __init__(self, as_of: object, previous: int, ceiling: int, floor: int = 0):
        self.as_of = as_of
        self.previous = previous
        self.ceiling = ceiling
        self.floor = floor

    def check(self) -> None:
        if not isinstance(self.as_of, int) or isinstance(self.as_of, bool):
            raise ValueError("recorded cut must be an integer journal position")
        if self.as_of < self.floor:
            raise ValueError("recorded cut precedes its lower bound")
        if self.as_of > self.ceiling:
            raise ValueError("recorded cut is beyond the scrutiny journal")
        if self.as_of < self.previous:
            raise ValueError("recorded cuts move backwards")
