"""Scale machinery: replay, version pin, DAG gate. TDD RED first."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fcd.core import Enforcer, Policy


def pol(version="v1", allow=None) -> Policy:
    return Policy(
        allow={"impl": allow or {"alice", "carol"}},
        deny={"impl": set()},
        phi={"alice": "model-a", "carol": "model-c", "bob": "model-b"},
        required={"impl": [("write", "w1"), ("check", "c1")]},
        version=version,
    )


def finish_item(e: Enforcer, item_id: str, writer="alice", checker="carol") -> None:
    e.admit(item_id, writer)
    e.bind(item_id, True)
    e.observe(item_id, e.policy_for(item_id).phi[writer])
    e.decide_pass(item_id)
    e.admit(item_id, checker)
    e.bind(item_id, True)
    e.observe(item_id, e.policy_for(item_id).phi[checker])
    e.decide_pass(item_id)


class ReplayTests(unittest.TestCase):
    def test_from_events_rebuilds_store_and_status(self):
        e = Enforcer(pol())
        e.open("w", "impl", "hash1")
        finish_item(e, "w")
        journal = list(e.events)
        rebuilt = Enforcer.from_events(journal, pol())
        self.assertIn("w", rebuilt.store)
        self.assertEqual(rebuilt.items["w"].status, "accepted")
        self.assertEqual(rebuilt.items["w"].body, "hash1")
        self.assertEqual(len(rebuilt.events), len(journal))

    def test_replay_refuses_a_tampered_journal(self):
        """Replay that re-derives state and then trusts the file is a state
        loader, not an authenticated record. A review demonstrated inconsistent
        forged, duplicated, deleted and derived-field-altered events rebuilding
        clean before field comparison was added. Coherent root-input rewrites
        remain another valid history and are covered by authenticated-head tests."""
        e = Enforcer(pol())
        e.open("w", "impl", "body")
        finish_item(e, "w")
        journal = [dict(ev) for ev in e.events]
        Enforcer.from_events([dict(ev) for ev in journal], pol())   # honest: accepted

        def refused(tampered, what):
            with self.assertRaises(ValueError, msg=f"accepted {what}") as caught:
                Enforcer.from_events(tampered, pol())
            self.assertIn("replay diverged", str(caught.exception))

        forged = journal + [{"type": "handwave", "work_item_id": "w"}]
        refused(forged, "a forged event of unknown type")

        accepts = [i for i, ev in enumerate(journal) if ev.get("type") == "accept"]
        if accepts:
            refused(journal[:accepts[0]] + [dict(journal[accepts[0]])] + journal[accepts[0]:],
                    "a duplicated accept")
            refused([ev for i, ev in enumerate(journal) if i != accepts[0]], "a deleted accept")

        for field, value in (("on_bind", False), ("declared_model", "model-b"), ("tried", [])):
            altered = [dict(ev, **{field: value}) if field in ev else dict(ev) for ev in journal]
            if altered != journal:
                refused(altered, f"an altered {field}")

    def test_from_events_does_not_emit(self):
        e = Enforcer(pol())
        e.open("w", "impl", "hash1")
        e.admit("w", "alice")
        e.bind("w", True)
        journal = list(e.events)
        rebuilt = Enforcer.from_events(journal, pol())
        self.assertEqual(rebuilt.events, tuple(journal))
        self.assertEqual(rebuilt.items["w"].stages[0].pc, "Running")

    def test_from_events_mismatch_stays_closed(self):
        e = Enforcer(pol())
        e.open("w", "impl", "hash1")
        e.admit("w", "alice")
        e.bind("w", True)
        e.observe("w", "model-other")
        e.decide_pass("w")
        rebuilt = Enforcer.from_events(list(e.events), pol())
        st = rebuilt.items["w"].stages[0]
        self.assertEqual((st.pc, st.fault), ("Closed", "F1"))
        self.assertNotIn("w", rebuilt.store)


class VersionPinTests(unittest.TestCase):
    def test_in_flight_item_keeps_v1_after_install_v2(self):
        e = Enforcer(pol("v1", allow={"alice", "carol"}))
        e.open("w", "impl", "hash1")
        e.install(pol("v2", allow={"carol"}))  # alice gone
        e.admit("w", "alice")  # still legal: item pinned v1
        self.assertEqual(e.items["w"].policy_version, "v1")
        self.assertEqual(e.policy.version, "v2")

    def test_new_item_uses_v2(self):
        e = Enforcer(pol("v1", allow={"alice", "carol"}))
        e.install(pol("v2", allow={"carol"}))
        e.open("n", "impl", "hash2")
        with self.assertRaises(ValueError):
            e.admit("n", "alice")
        e.admit("n", "carol")

    def test_cannot_mutate_policy_object_under_a_live_item(self):
        p = pol("v1")
        e = Enforcer(p)
        e.open("w", "impl", "hash1")
        with self.assertRaises(ValueError):
            e.install(pol("v1", allow={"carol"}))  # same version, different sets


class ReplayCurrentPolicyTests(unittest.TestCase):
    """Replay re-drives historical Opens under the version each pinned, then
    must leave the LAST supplied policy live. A machine running at v2 whose
    last historical Open pinned v1 must not rebuild pinned to v1: existing
    items stay on their pin, but work opened after recovery uses v2."""

    def test_from_events_restores_current_policy_after_replay(self):
        e = Enforcer(pol("v1", allow={"alice", "carol"}))
        e.open("w", "impl", "hash1")            # last (only) historical Open pins v1
        e.install(pol("v2", allow={"bob", "carol"}))  # live version is now v2
        finish_item(e, "w")                     # writer alice / checker carol, both in v1
        journal = list(e.events)

        rebuilt = Enforcer.from_events(journal, pol("v1", allow={"alice", "carol"}),
                                       pol("v2", allow={"bob", "carol"}))

        # historical item remains pinned to v1
        self.assertEqual(rebuilt.items["w"].policy_version, "v1")
        self.assertEqual(rebuilt.policy_for("w").version, "v1")
        # rebuilt current policy is the LAST supplied policy, v2 (RED before fix)
        self.assertEqual(rebuilt.policy.version, "v2")
        # new item after rebuild opens under v2: bob (v2-only) admits, alice (v1-only) refused
        rebuilt.open("n", "impl", "hash2")
        self.assertEqual(rebuilt.items["n"].policy_version, "v2")
        with self.assertRaises(ValueError):
            rebuilt.admit("n", "alice")
        rebuilt.admit("n", "bob")


class DagGateTests(unittest.TestCase):
    def test_open_refuses_missing_dependency(self):
        e = Enforcer(pol())
        with self.assertRaises(ValueError) as ctx:
            e.open("b", "impl", "hash-b", depends_on=("a",))
        self.assertIn("a", str(ctx.exception))
        self.assertNotIn("b", e.items)

    def test_open_after_dependency_accepted(self):
        e = Enforcer(pol())
        e.open("a", "impl", "hash-a")
        finish_item(e, "a")
        e.open("b", "impl", "hash-b", depends_on=("a",))
        self.assertEqual(e.items["b"].depends_on, ("a",))

    def test_open_refuses_unaccepted_open_dependency(self):
        e = Enforcer(pol())
        e.open("a", "impl", "hash-a")  # open but not accepted
        with self.assertRaises(ValueError):
            e.open("b", "impl", "hash-b", depends_on=("a",))


if __name__ == "__main__":
    unittest.main()
