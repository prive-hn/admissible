"""Compatibility shim. Canonical watchdog: `fcd.watchdog.poll`.

Old signature poll(pid, pc, on_death) is kept for historical tests.
New code should inject alive_fn so the core stays portable.
"""
from __future__ import annotations

from typing import Callable

from fcd.watchdog import poll as fcd_poll


def pid_alive(pid: int) -> bool:
    try:
        import os

        os.kill(pid, 0)
        return True
    except OSError:
        return False


def poll(pid: int, pc: str, on_death: Callable[[], None]) -> None:
    fcd_poll(pc=pc, alive_fn=lambda: pid_alive(pid), on_death=on_death)
