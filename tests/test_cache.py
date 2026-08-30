"""Stage-scoped prefix cache. Written first (TDD RED).

A cache is legal only when it cannot change who ran the stage:
key = (specialist, phi(a) after norm, prefix_hash). It is cleared on
Close/Admit. A hit never skips Observe.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fcd.cache import StageCache  # noqa: F401
from fcd.core import Enforcer, Policy  # noqa: F401


class StageCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = Policy(
            allow={"impl": {"alice", "bob"}},
            deny={"impl": set()},
            phi={"alice": "model-a", "bob": "model-b"},
            required={"impl": [("write", "w1")]},
        )
        self.e = Enforcer(self.policy)
        self.e.open("w", "impl", "hash1")

    def test_hit_within_same_stage_and_specialist(self):
        c = StageCache()
        k1 = c.key("alice", "model-a", "prefix-1")
        c.put(k1, "cached-body")
        self.assertTrue(c.get(k1))
        self.assertEqual(c.stats["hit"], 1)

    def test_miss_across_specialists(self):
        c = StageCache()
        c.put(c.key("alice", "model-a", "prefix-1"), "cached-body")
        k2 = c.key("bob", "model-b", "prefix-1")
        self.assertFalse(c.get(k2))
        self.assertEqual(c.stats["miss"], 1)

    def test_clear_on_stage_boundary(self):
        c = StageCache()
        k = c.key("alice", "model-a", "prefix-1")
        c.put(k, "cached-body")
        c.clear()
        self.assertFalse(c.get(k))

    def test_prefix_mutation_is_a_miss(self):
        c = StageCache()
        c.put(c.key("alice", "model-a", "prefix-1"), "cached-body")
        self.assertFalse(c.get(c.key("alice", "model-a", "prefix-2")))

    def test_hit_does_not_skip_observe(self):
        # Even on a cache hit, the machine must Observe and may refuse.
        c = StageCache()
        k = c.key("alice", "model-a", "prefix-1")
        c.put(k, "cached-body")
        self.e.admit("w", "alice")
        self.e.bind("w", True)
        self.assertTrue(c.get(k))
        self.e.observe("w", "model-B")  # wrong executed model
        self.e.decide_pass("w")
        st = self.e.items["w"].stages[0]
        self.assertEqual((st.pc, st.fault), ("Closed", "F1"))


if __name__ == "__main__":
    unittest.main()
