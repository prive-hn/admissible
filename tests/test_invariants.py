"""Executable proofs of I1–I9 on the Python machine."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fcd.core import Enforcer, Policy, norm
from fcd.watchdog import poll


def policy() -> Policy:
    return Policy(
        allow={"impl": {"alice", "bob", "carol"}},
        deny={"impl": set(), "rev": set()},
        phi={"alice": "model-a", "bob": "model-b", "carol": "model-c"},
        required={"impl": [("write", "w1"), ("check", "c1")]},
    )


class InvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.e = Enforcer(policy())
        self.e.open("w", "impl", "hash1")

    def _write_ok(self, who: str = "alice", ran: str = "model-a") -> None:
        self.e.admit("w", who)
        self.e.bind("w", True)
        self.e.observe("w", ran)
        self.e.decide_pass("w")

    def test_i1_pass_requires_observe_match(self) -> None:
        self.e.admit("w", "alice")
        self.e.bind("w", True)
        st = self.e.items["w"].stages[0]
        self.assertIsNone(st.m_exec)
        self.assertEqual(st.m_decl, "model-a")
        self.e.observe("w", "model-other")
        self.e.decide_pass("w")
        self.assertEqual(st.pc, "Closed")
        self.assertEqual(st.fault, "F1")
        self.assertNotIn("w", self.e.store)

    def test_i1_pass_when_exec_equals_decl(self) -> None:
        self._write_ok()
        st = self.e.items["w"].stages[0]
        self.assertEqual(st.pc, "Passed")
        self.assertEqual(norm(st.m_exec), norm(st.m_decl))

    def test_i2_i6_check_excludes_author(self) -> None:
        self._write_ok("alice")
        with self.assertRaises(ValueError):
            self.e.admit("w", "alice")
        self.e.admit("w", "carol")
        self.assertEqual(self.e.items["w"].stages[1].a, "carol")

    def test_i3_no_pass_on_foreign_model(self) -> None:
        self.e.admit("w", "alice")
        self.e.bind("w", True)
        self.e.observe("w", "model-b")
        self.e.decide_pass("w")
        self.assertNotEqual(self.e.items["w"].stages[0].pc, "Passed")

    def test_i4_class_frozen(self) -> None:
        cls = self.e.items["w"].cls
        self._write_ok()
        self.assertEqual(self.e.items["w"].cls, cls)

    def test_i5_i8_accept_only_when_all_passed(self) -> None:
        with self.assertRaises(ValueError):
            self.e.accept("w")
        self._write_ok()
        self.e.admit("w", "carol")
        self.e.bind("w", True)
        self.e.observe("w", "model-c")
        self.e.decide_pass("w")
        self.assertEqual(self.e.items["w"].status, "accepted")
        self.assertIn("w", self.e.store)

    def test_i7_cannot_retry_tried(self) -> None:
        self.e.admit("w", "alice")
        self.e.bind("w", False)
        with self.assertRaises(ValueError):
            self.e.admit("w", "alice")
        self.e.admit("w", "bob")

    def test_i8_bypass_forbidden(self) -> None:
        with self.assertRaises(PermissionError):
            self.e.store_put("w")
        self.assertNotIn("w", self.e.store)

    def test_i9_retry_same_class(self) -> None:
        self.e.admit("w", "alice")
        self.e.bind("w", False)
        cls = self.e.items["w"].cls
        self.e.admit("w", "bob")
        self.assertEqual(self.e.items["w"].cls, cls)

    def test_bindfail_does_not_observe(self) -> None:
        self.e.admit("w", "alice")
        self.e.bind("w", False)
        with self.assertRaises(ValueError):
            self.e.observe("w", "model-a")

    def test_watchdog_close_on_dead_pid(self) -> None:
        self.e.admit("w", "alice")
        self.e.bind("w", True)
        poll(pc="Running", alive_fn=lambda: False, on_death=lambda: self.e.death_observed("w"))
        self.assertEqual(self.e.items["w"].stages[0].pc, "Closed")
        self.assertTrue(self.e.items["w"].stages[0].pub)


if __name__ == "__main__":
    unittest.main()
