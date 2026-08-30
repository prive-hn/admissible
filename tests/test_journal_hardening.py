"""Regression tests for immutable journals and hostile replay ingress.

These tests are intentionally written against the public dictionary-shaped event
contract.  Immutability must not require consumers to learn Red Admissible's
separate ``{kind, seq, body}`` representation.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from types import MappingProxyType
from unittest.mock import patch

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

from fcd.core import Enforcer, Policy  # noqa: E402
from test_rga_calibration import CalHarness  # noqa: E402


def policy() -> Policy:
    return Policy(
        allow={"impl": {"alice"}},
        deny={"impl": set()},
        phi={"alice": "vendor:model"},
        required={"impl": [("write", "w1")]},
        version="v1",
    )


def journal_api():
    try:
        from fcd.journal import (  # type: ignore[attr-defined]
            JournalEvent,
            ReplayError,
            to_plain_json,
        )
    except ImportError:
        return None, None, None
    return JournalEvent, ReplayError, to_plain_json


class HostileStr(str):
    calls = 0

    @classmethod
    def reset(cls):
        cls.calls = 0

    def _boom(self):
        type(self).calls += 1
        raise RuntimeError("hostile string method executed")

    def __eq__(self, other):
        return self._boom()

    def __hash__(self):
        return self._boom()

    def startswith(self, *args, **kwargs):
        return self._boom()

    def strip(self, *args, **kwargs):
        return self._boom()

    def __repr__(self):
        return self._boom()


class ImmutableJournalEventTests(unittest.TestCase):
    def test_event_is_deeply_immutable_without_changing_json_shape(self):
        JournalEvent, _, to_plain_json = journal_api()
        self.assertIsNotNone(JournalEvent, "fcd.journal.JournalEvent is missing")
        source = {
            "type": "open",
            "work_item_id": "w",
            "nested": {"labels": ["a", "b"]},
            "ts": 1.5,
        }
        event = JournalEvent(source)
        source["work_item_id"] = "source-mutated"
        source["nested"]["labels"].append("source-mutated")

        self.assertEqual(event["work_item_id"], "w")
        self.assertEqual(event["nested"]["labels"], ["a", "b"])
        for mutation in (
            lambda: event.__setitem__("work_item_id", "changed"),
            lambda: event.update({"work_item_id": "changed"}),
            lambda: event.pop("work_item_id"),
            lambda: event["nested"].__setitem__("labels", ()),
            lambda: event["nested"]["labels"].__setitem__(0, "changed"),
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises((TypeError, AttributeError)):
                    mutation()

        expected = {
            "type": "open",
            "work_item_id": "w",
            "nested": {"labels": ["a", "b"]},
            "ts": 1.5,
        }
        self.assertEqual(to_plain_json(event), expected)
        self.assertEqual(json.loads(json.dumps(to_plain_json(event))), expected)
        with self.assertRaises(TypeError):
            dict.__setitem__(event, "work_item_id", "base-descriptor-bypass")
        before = to_plain_json(event)
        with self.assertRaises((AttributeError, TypeError)):
            object.__setattr__(
                event, "_FrozenJSONDict__data",
                MappingProxyType({"type": "tampered"}))
        type(event).__init__(event, {"type": "tampered"})
        self.assertEqual(to_plain_json(event), before)

    def test_mapping_and_sequence_equality_have_consistent_negation(self):
        from collections import UserList
        from fcd.journal import FrozenJSONList

        JournalEvent, _, _ = journal_api()
        event = JournalEvent({"type": "x", "values": [1, 2]})
        values = event["values"]
        self.assertTrue(event == {"type": "x", "values": [1, 2]})
        self.assertFalse(event != {"type": "x", "values": [1, 2]})
        self.assertIs(type(values), FrozenJSONList)
        for equivalent in ([1, 2], (1, 2), UserList([1, 2])):
            with self.subTest(equivalent=type(equivalent).__name__):
                self.assertTrue(values == equivalent)
                self.assertFalse(values != equivalent)
                self.assertTrue(equivalent == values)
                self.assertFalse(equivalent != values)

    def test_forged_exact_frozen_types_are_revalidated(self):
        from fcd.journal import FrozenJSONList

        JournalEvent, _, _ = journal_api()
        hostile_list = tuple.__new__(FrozenJSONList, (object(),))
        with self.assertRaises(ValueError) as caught:
            JournalEvent({"type": "x", "values": hostile_list})
        self.assertEqual(str(caught.exception),
                         "journal event must contain canonical JSON values")

    def test_noncanonical_scalar_is_rejected_before_virtual_access(self):
        JournalEvent, _, _ = journal_api()
        self.assertIsNotNone(JournalEvent, "fcd.journal.JournalEvent is missing")
        HostileStr.reset()
        with self.assertRaises((TypeError, ValueError)) as caught:
            JournalEvent({"type": HostileStr("open"), "work_item_id": "w"})
        self.assertEqual(HostileStr.calls, 0)
        self.assertEqual(str(caught.exception), "journal event must contain canonical JSON values")

    def test_bytes_and_nonfinite_numbers_are_not_journal_values(self):
        JournalEvent, _, to_plain_json = journal_api()
        self.assertIsNotNone(JournalEvent, "fcd.journal.JournalEvent is missing")
        for value in (b"secret", float("nan"), float("inf"), float("-inf"), "\ud800"):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises((TypeError, ValueError)) as caught:
                    JournalEvent({"type": "x", "value": value})
                self.assertEqual(str(caught.exception),
                                 "journal event must contain canonical JSON values")
        with self.assertRaises(ValueError) as caught:
            JournalEvent({"\ud800": "value"})
        self.assertEqual(str(caught.exception),
                         "journal event must contain canonical JSON values")
        deep = []
        for _ in range(sys.getrecursionlimit() + 10):
            deep = [deep]
        with self.assertRaises(ValueError) as caught:
            to_plain_json(deep)
        self.assertEqual(str(caught.exception),
                         "journal event must contain canonical JSON values")

    def test_cyclic_values_are_rejected_with_the_fixed_value_error(self):
        JournalEvent, _, _ = journal_api()
        cycle = {}
        cycle["self"] = cycle
        with self.assertRaises((TypeError, ValueError)) as caught:
            JournalEvent({"type": "x", "cycle": cycle})
        self.assertEqual(str(caught.exception),
                         "journal event must contain canonical JSON values")

    def test_all_three_authorities_emit_immutable_events(self):
        JournalEvent, _, _ = journal_api()
        self.assertIsNotNone(JournalEvent, "fcd.journal.JournalEvent is missing")
        h = CalHarness()
        h.declare_tests()
        h.seal_line()
        for name, events in (("fcd", h.e.events), ("rga", h.a.events),
                             ("calibration", h.cal.events)):
            self.assertIs(type(events), tuple)
            self.assertTrue(events, name)
            for event in events:
                with self.subTest(authority=name, kind=event.get("type")):
                    self.assertIs(type(event), JournalEvent)
                    with self.assertRaises(TypeError):
                        event["type"] = "tampered"
        for authority in (h.e, h.a, h.cal):
            with self.assertRaises(AttributeError):
                authority.events.append(JournalEvent({"type": "forged"}))
            with self.assertRaises(AttributeError):
                authority.events = ()

    def test_failed_event_encoding_rolls_back_all_authority_state(self):
        from fcd.journal import JournalValueError
        from rga.core import Refuter

        e = Enforcer(policy(), clock=lambda: float("nan"))
        with self.assertRaises(JournalValueError):
            e.open("w", "impl", "body")
        self.assertEqual(e.items, {})
        self.assertEqual(e.events, ())

        deep = []
        for _ in range(sys.getrecursionlimit() + 10):
            deep = [deep]
        e = Enforcer(policy(), clock=lambda: deep)
        with self.assertRaises(JournalValueError):
            e.open("deep", "impl", "body")
        self.assertEqual(e.items, {})
        self.assertEqual(e.events, ())

        h = CalHarness()
        h.a.clock = lambda: float("nan")
        with self.assertRaises(JournalValueError):
            h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        self.assertEqual(h.a.refuters, {})
        self.assertEqual(h.a.events, ())

        h = CalHarness()
        with self.assertRaises(JournalValueError):
            h.a.declare(Refuter("deep", "v1", deep, "ledger"))
        self.assertEqual(h.a.refuters, {})
        self.assertEqual(h.a.events, ())

        h = CalHarness()
        h.declare_tests()
        h.seal_line()
        before_runs = tuple(h.cal.runs)
        before_events = h.cal.events
        h.cal.clock = lambda: float("nan")
        with self.assertRaises(JournalValueError):
            h.tier_a_escape(replay=False)
        self.assertEqual(tuple(h.cal.runs), before_runs)
        self.assertEqual(h.cal.events, before_events)

        h.cal.clock = lambda: deep
        with self.assertRaises(JournalValueError):
            h.tier_a_escape(nonce="deep-clock", replay=False)
        self.assertEqual(tuple(h.cal.runs), before_runs)
        self.assertEqual(h.cal.events, before_events)

        e = Enforcer(policy(), clock=lambda: 0.0)
        e.open("w", "impl", "body")
        e.admit("w", "alice")
        e.bind("w", True)
        before = e.events
        with self.assertRaises(AttributeError):
            e.observe("w", float("nan"))
        self.assertIsNone(e.items["w"].stages[0].m_exec)
        self.assertEqual(e.events, before)

        h = CalHarness()
        h.declare_tests()
        h.fcd_open()
        h.cal.open("w", "gen", "temp=0.7")
        h.fcd_write()
        before = h.a.events
        with self.assertRaises(TypeError):
            h.a.sample("w", b"artifact", ("contract", 1), "temp=0.7")
        self.assertEqual(h.a.lines["w"].samples, [])
        self.assertEqual(h.a.events, before)

        class BadOrder(str):
            def __lt__(self, other):
                raise ValueError("preparation comparator failed")

        with self.assertRaises(ValueError):
            h.a.sample("w", b"artifact", (BadOrder("a"), BadOrder("b")),
                       "temp=0.7")
        self.assertEqual(h.a.lines["w"].samples, [])
        self.assertEqual(h.a.events, before)

        old_fcd = e.policy
        new_fcd = Policy(
            allow=old_fcd.allow, deny=old_fcd.deny, phi=old_fcd.phi,
            required=old_fcd.required, version="v2")
        e.install(new_fcd)
        e.install(old_fcd)
        with self.assertRaises(AttributeError):
            e.observe("w", float("nan"))
        self.assertIs(e.policy, old_fcd)

        old_rga = h.a.policy
        from dataclasses import replace
        new_rga = replace(old_rga, version="r2")
        h.a.install(new_rga)
        h.a.install(old_rga)
        with self.assertRaises(JournalValueError):
            h.a.declare(Refuter("deep-policy", "v1", deep, "ledger"))
        self.assertIs(h.a.policy, old_rga)

    def test_successful_registry_rows_do_not_snapshot_prior_registry(self):
        from rga.core import Admission, Refuter

        class NoDeepcopyDict(dict):
            def __deepcopy__(self, memo):
                raise AssertionError("successful transition copied prior registry")

        h = CalHarness()
        h.a.refuters = NoDeepcopyDict()
        h.a.declared_at = NoDeepcopyDict()
        for index in range(100):
            h.a.declare(Refuter(f"r{index}", "v1", "tester", "bounded"))
        self.assertEqual(len(h.a.refuters), 100)
        self.assertIs(Admission, type(h.a))

        class NoDeepcopySet(set):
            def __deepcopy__(self, memo):
                raise AssertionError("successful transition copied prior set")

        h = CalHarness()
        h.declare_tests()
        h.seal_line()
        run = h.tier_a_escape(replay=False)
        h.cal.discredited = NoDeepcopySet()
        h.cal.replay_run(run.index, run.verdict, run.witness_hash)
        self.assertTrue(h.cal.runs[run.index].established)

    def test_failed_nested_accept_event_rolls_back_the_outer_decision(self):
        from fcd.journal import JournalValueError

        e = Enforcer(policy(), clock=lambda: 0.0)
        e.open("w", "impl", "body")
        e.admit("w", "alice")
        e.bind("w", True)
        e.observe("w", "vendor:model")
        before = e.events
        ticks = iter((0.0, float("nan")))
        e.clock = lambda: next(ticks)
        with self.assertRaises(JournalValueError):
            e.decide_pass("w")
        self.assertEqual(e.events, before)
        self.assertEqual(e.items["w"].stages[0].pc, "Running")
        self.assertEqual(e.items["w"].status, "open")
        self.assertNotIn("w", e.store)


class ReplayIngressTests(unittest.TestCase):
    def test_fcd_replay_accepts_legacy_dicts_and_stores_frozen_events(self):
        JournalEvent, _, to_plain_json = journal_api()
        self.assertIsNotNone(JournalEvent, "fcd.journal.JournalEvent is missing")
        e = Enforcer(policy())
        e.open("w", "impl", "body")
        legacy = [to_plain_json(event) for event in e.events]
        self.assertIs(type(legacy[0]), dict)

        rebuilt = Enforcer.from_events(legacy, policy())
        self.assertIs(type(rebuilt.events[0]), JournalEvent)
        with self.assertRaises(TypeError):
            rebuilt.events[0]["body_hash"] = "tampered"

    def test_hostile_discriminator_is_refused_without_calling_it(self):
        _, ReplayError, _ = journal_api()
        self.assertIsNotNone(ReplayError, "fcd.journal.ReplayError is missing")
        HostileStr.reset()
        journal = [{"type": HostileStr("open"), "work_item_id": "w"}]
        with self.assertRaises(ReplayError) as caught:
            Enforcer.from_events(journal, policy())
        self.assertEqual(HostileStr.calls, 0)
        self.assertEqual(str(caught.exception),
                         "replay refused: journal must contain canonical events")

    def test_forged_exact_event_is_refused_without_virtual_access(self):
        JournalEvent, ReplayError, _ = journal_api()
        HostileStr.reset()
        forged = tuple.__new__(JournalEvent, (
            ("type", HostileStr("open")),
            ("work_item_id", "w"),
        ))
        with self.assertRaises(ReplayError) as caught:
            Enforcer.from_events((forged,), policy())
        self.assertEqual(HostileStr.calls, 0)
        self.assertEqual(str(caught.exception),
                         "replay refused: journal must contain canonical events")

    def test_replay_does_not_alias_legacy_input(self):
        JournalEvent, _, to_plain_json = journal_api()
        self.assertIsNotNone(JournalEvent, "fcd.journal.JournalEvent is missing")
        e = Enforcer(policy())
        e.open("w", "impl", "body")
        legacy = [to_plain_json(event) for event in e.events]
        rebuilt = Enforcer.from_events(legacy, policy())
        legacy[0]["body_hash"] = "changed-after-replay"
        self.assertEqual(rebuilt.events[0]["body_hash"], "body")
        self.assertEqual(rebuilt.items["w"].body, "body")

    def test_calibration_replay_does_not_copy_public_snapshot_per_event(self):
        from rga.calibration import CalibrationAuthority

        h = CalHarness()
        h.declare_tests()
        h.seal_line()
        for index in range(3):
            h.tier_a_escape(nonce=f"escape-{index}", replay=False)
        calls = 0
        original = CalibrationAuthority.events

        def counted(authority):
            nonlocal calls
            calls += 1
            return original.fget(authority)

        with patch.object(CalibrationAuthority, "events", property(counted)):
            CalibrationAuthority.from_events(h.cal.events, h.a, h.cal.policy)
        self.assertLessEqual(calls, 1)


if __name__ == "__main__":
    unittest.main()
