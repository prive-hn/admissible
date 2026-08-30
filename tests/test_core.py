"""Tests for the portable fcd core. Written first (TDD RED)."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fcd.core import Enforcer, Policy, norm  # noqa: F401  (must fail first)


def make_policy() -> Policy:
    return Policy(
        allow={"impl": {"alice", "bob", "carol"}},
        deny={"impl": set()},
        phi={"alice": "vendorA:model-a", "bob": "vendorB:model-b", "carol": "vendorC:model-c"},
        required={"impl": [("write", "w1"), ("check", "c1")]},
    )


class CoreMachineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.e = Enforcer(make_policy())
        self.e.open("w", "impl", "hash1")

    def _pass_stage0(self, who="alice", ran="vendorA:model-a"):
        self.e.admit("w", who)
        self.e.bind("w", True)
        self.e.observe("w", ran)
        self.e.decide_pass("w")

    def test_i1_mismatch_closes_with_f1(self):
        self._pass_stage0(ran="vendorB:model-b")
        st = self.e.items["w"].stages[0]
        self.assertEqual((st.pc, st.fault), ("Closed", "F1"))
        self.assertNotIn("w", self.e.store)

    def test_i1_vendor_prefix_collision_detected(self):
        # norm strips vendor: different vendors with same bare name must NOT pass
        self.e.admit("w", "alice")
        self.e.bind("w", True)
        self.e.observe("w", "vendorX:model-a")
        self.e.decide_pass("w")
        self.assertEqual(self.e.items["w"].stages[0].fault, "F1")

    def test_i6_check_excludes_author(self):
        self._pass_stage0()
        with self.assertRaises(ValueError):
            self.e.admit("w", "alice")
        self.e.admit("w", "carol")

    def test_i7_no_retry_of_tried(self):
        self.e.admit("w", "alice")
        self.e.bind("w", False)
        with self.assertRaises(ValueError):
            self.e.admit("w", "alice")

    def test_i8_store_only_via_accept(self):
        with self.assertRaises(PermissionError):
            self.e.store_put("w")

    def test_observe_before_bind_rejected(self):
        self.e.admit("w", "alice")
        with self.assertRaises(ValueError):
            self.e.observe("w", "vendorA:model-a")

    def test_accept_requires_all_stages(self):
        self._pass_stage0()
        self.assertEqual(self.e.items["w"].status, "open")
        self.e.admit("w", "carol")
        self.e.bind("w", True)
        self.e.observe("w", "vendorC:model-c")
        self.e.decide_pass("w")
        self.assertEqual(self.e.items["w"].status, "accepted")
        self.assertIn("w", self.e.store)


if __name__ == "__main__":
    unittest.main()


class KernelIdentityGuards(unittest.TestCase):
    """Two guards added after the RGA round-1 review found their absence
    broke I4 and I8 as state invariants (paper/RGA/PREMISE.md §4)."""

    def setUp(self) -> None:
        self.e = Enforcer(make_policy())
        self.e.open("w", "impl", "hash1")

    def _accept(self):
        for who, ran in (("alice", "vendorA:model-a"), ("carol", "vendorC:model-c")):
            self.e.admit("w", who)
            self.e.bind("w", True)
            self.e.observe("w", ran)
            self.e.decide_pass("w")

    def test_open_refuses_an_existing_id(self):
        with self.assertRaises(ValueError):
            self.e.open("w", "impl", "hash2")
        self.assertEqual(self.e.items["w"].body, "hash1")
        self._accept()
        with self.assertRaises(ValueError):
            self.e.open("w", "impl", "hash3")   # a stored id keeps its body (I4)
        self.assertEqual(self.e.items["w"].body, "hash1")

    def test_no_admit_refuses_a_passed_stage_of_an_accepted_item(self):
        self._accept()
        self.assertEqual(self.e.items["w"].status, "accepted")
        with self.assertRaises(ValueError):
            self.e.no_admit("w")                # was reachable: wrote status="failed" with id in S
        self.assertEqual(self.e.items["w"].status, "accepted")
        self.assertIn("w", self.e.store)

    def test_no_admit_still_fires_on_an_exhausted_open_stage(self):
        for who in ("alice", "bob", "carol"):
            self.e.admit("w", who)
            self.e.bind("w", False)             # every bind dead
        self.e.no_admit("w")
        self.assertEqual(self.e.items["w"].status, "failed")
        self.assertTrue(self.e.items["w"].stages[0].pub)
