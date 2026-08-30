"""Portable watchdog. Written first (TDD RED).

No os.kill: `alive_fn` is injected, so this runs on any platform,
including iOS sandboxes. The watchdog only closes; it never passes.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fcd.watchdog import poll  # noqa: F401
from fcd.core import Enforcer, Policy  # noqa: F401


class WatchdogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = Policy(
            allow={"impl": {"alice"}},
            deny={"impl": set()},
            phi={"alice": "model-a"},
            required={"impl": [("write", "w1")]},
        )
        self.e = Enforcer(self.policy)
        self.e.open("w", "impl", "hash1")

    def _running(self):
        self.e.admit("w", "alice")
        self.e.bind("w", True)

    def test_dead_worker_closes_published(self):
        self._running()
        poll(pc="Running", alive_fn=lambda: False,
             on_death=lambda: self.e.death_observed("w"))
        st = self.e.items["w"].stages[0]
        self.assertEqual(st.pc, "Closed")
        self.assertTrue(st.pub)

    def test_alive_worker_untouched(self):
        self._running()
        poll(pc="Running", alive_fn=lambda: True,
             on_death=lambda: self.e.death_observed("w"))
        self.assertEqual(self.e.items["w"].stages[0].pc, "Running")

    def test_not_running_ignored(self):
        poll(pc="Passed", alive_fn=lambda: False,
             on_death=lambda: self.e.death_observed("w"))
        self.assertNotIn("w", self.e.store)

    def test_watchdog_never_accepts(self):
        self._running()
        poll(pc="Running", alive_fn=lambda: False,
             on_death=lambda: self.e.death_observed("w"))
        self.assertNotIn("w", self.e.store)
        self.assertNotEqual(self.e.items["w"].status, "accepted")


if __name__ == "__main__":
    unittest.main()
