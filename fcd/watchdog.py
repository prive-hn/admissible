"""Portable death watchdog (A2/A9).

`alive_fn` is injected: on macOS it can wrap os.kill(pid, 0); on iOS a
heartbeat flag or task-state callback. The watchdog only ever CLOSES a
stage via death_observed; it has no path to Pass or Accept. Failing
alive (EPERM etc.) closes too — over-closing is the safe direction.
"""
from __future__ import annotations

from typing import Callable


def poll(pc: str, alive_fn: Callable[[], bool], on_death: Callable[[], None]) -> None:
    """Call on_death() iff the stage is Running and the worker is dead."""
    if pc == "Running" and not alive_fn():
        on_death()
