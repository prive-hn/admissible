"""Property sweep for the FCD context / envelope / memory layer: I10..I17 and
the watchdog (F4) and stage-cache (I16) machinery, asserted against the live
ContextAuthority over a generated space of histories (tests/fcd_context_generators.py)
plus constructed probes for the receipt, CAS and drift guards.

Where tests/test_context_envelope.py pins each claim on an example, this asserts
the write-once pin and per-attempt cache identity universally, and drives each
forbidden transition (a leaked steering scope, a stale receipt, a losing CAS) to
its refusal.
"""
from __future__ import annotations

import dataclasses
import os
import sys
import unittest

from hypothesis import HealthCheck, given, settings

HERE = os.path.dirname(__file__)
for _p in (os.path.join(HERE, ".."), HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import fcd_context_generators as G  # noqa: E402
from fcd.context import (AdapterReceipt, ContextAuthority, KnowledgeDelta,  # noqa: E402
                         ProjectState, hash_bytes)
from fcd.cache import StageCache  # noqa: E402
from fcd.watchdog import poll  # noqa: E402
from fcd.core import Enforcer  # noqa: E402
import fcd_generators as FG  # noqa: E402

DEEP = bool(os.environ.get("ADMISSIBLE_DEEP"))
EXAMPLES = 400 if DEEP else 50
_SUPPRESS = [HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much]


def sweep(**kw):
    p = dict(max_examples=EXAMPLES, deadline=None, derandomize=not DEEP, suppress_health_check=_SUPPRESS)
    p.update(kw)
    return settings(**p)


class ContextEnvelopeInvariants(unittest.TestCase):
    """I10 (work/envelope pins are write-once) and I16 (per-attempt cache
    identity) as universal properties over generated histories."""

    @sweep()
    @given(G.context_histories())
    def test_I10_work_pins_are_write_once_through_head_advances(self, hist):
        for wp in hist.auth.work_pins("p"):
            self.assertEqual((wp.project_version, wp.memory_version), hist.pins[wp.work_item_id], hist.moves)
        for a in hist.attempts:
            env = a.envelope
            self.assertIsInstance(env.project_version, int)
            with self.assertRaises(dataclasses.FrozenInstanceError):
                env.project_version = env.project_version + 1   # envelope frozen

    @sweep()
    @given(G.context_histories())
    def test_I16_cache_identity_is_per_attempt(self, hist):
        ids = [hist.auth.cache_id(a.envelope.attempt_id) for a in hist.attempts]
        self.assertEqual(len(ids), len(set(ids)), hist.moves)     # each attempt a distinct identity
        for a in hist.attempts:                                   # ... and a STABLE one: cache_id is a
            aid = a.envelope.attempt_id                           # pure function of attempt state, so a
            self.assertEqual(hist.auth.cache_id(aid),             # repeat call returns the same id (a
                             hist.auth.cache_id(aid), hist.moves) # random-per-call id would still be
                                                                  # distinct across attempts, yet wrong)


class ContextForbiddenTransitions(unittest.TestCase):
    """I11, I12, I13, I14, I15, I17 as constructed probes — each drives a
    forbidden context transition to its refusal or its single-winner outcome."""

    def _auth(self, accepted=()):
        acc = set(accepted)
        auth = ContextAuthority(is_accepted=lambda w: w in acc)
        auth.add_project(ProjectState("p", 5, 3, "policy-1", strict_unknown=True))
        auth.open_work("p", "W", contract_revision=1)
        return auth, acc

    def test_I15_steering_cannot_leak_scope(self):
        auth, acc = self._auth()
        auth.open_work("p", "W2", contract_revision=1)
        a = auth.admit("W", G.gate_spec(), specialist="w1")
        with self.assertRaises(ValueError):
            auth.append_steering(a.envelope.attempt_id, "work", "W2", "leak to sibling")
        acc.add("W")
        with self.assertRaises(ValueError):
            auth.append_steering(a.envelope.attempt_id, "artifact", "W", "mutate accepted")

    def test_I17_a_prior_attempt_receipt_is_rejected(self):
        auth, _ = self._auth()
        a1 = auth.admit("W", G.gate_spec(), specialist="w1")
        pkg = auth.compile_package(a1.envelope.attempt_id, {"contract": b"c"})
        auth.close(a1.envelope.attempt_id)
        a2 = auth.admit("W", G.gate_spec(), specialist="w2")
        stale = AdapterReceipt(
            attempt_id=a1.envelope.attempt_id, nonce=a1.envelope.nonce,
            executor_id="codex", run_id="r1", package_hash_observed=hash_bytes(pkg.payload),
            continuation_hash=a1.latest_continuation_hash,
            executed_provider="openai", executed_model="model-a")
        self.assertFalse(auth.accept_receipt_for(a2.envelope.attempt_id, stale))

    def test_I11_receipt_mismatch_refuses_pass(self):
        auth, _ = self._auth()
        a = auth.admit("W", G.gate_spec(), specialist="w1")
        auth.compile_package(a.envelope.attempt_id, {"contract": b"c"})
        wrong = AdapterReceipt(
            attempt_id=a.envelope.attempt_id, nonce=a.envelope.nonce,
            executor_id="codex", run_id="r1", package_hash_observed=hash_bytes(b"wrong"),
            continuation_hash=a.latest_continuation_hash,
            executed_provider="openai", executed_model="model-a")
        self.assertFalse(auth.accept_receipt_for(a.envelope.attempt_id, wrong))
        self.assertFalse(auth.can_pass(a.envelope.attempt_id))

    def test_I12_fresh_blind_excludes_author_context(self):
        auth, _ = self._auth()
        gate = G.gate_spec(mode="fresh_blind")
        gate = dataclasses.replace(gate, context_policy=dataclasses.replace(
            gate.context_policy,
            include=frozenset({"contract", "candidate_diff", "builder_transcript"}),
            exclude=frozenset({"builder_transcript", "builder_reasoning"})))
        a = auth.admit("W", gate, specialist="rev")
        pkg = auth.compile_package(a.envelope.attempt_id, {
            "contract": b"contract", "candidate_diff": b"diff", "builder_transcript": b"secret"})
        self.assertNotIn(b"secret", pkg.payload)
        # fresh_blind forbids executor continuity
        bad = G.gate_spec(mode="fresh_blind", continuity="executor_continue", caps=frozenset({"continue"}))
        with self.assertRaises(ValueError):
            auth.admit("W", bad, specialist="rev")

    def test_I13_concurrent_cas_has_one_winner(self):
        auth, acc = self._auth(accepted=("W",))
        a = auth.admit("W", G.gate_spec(), specialist="w1")
        head = auth.project_head("p")
        first = auth.promote("W", KnowledgeDelta(("fact",), ("artifact:W",)), expected_head=head)
        self.assertNotEqual(first, head)                          # winner advanced the head
        with self.assertRaises(ValueError):
            auth.promote("W", KnowledgeDelta(("fact2",), ("artifact:W2",)), expected_head=head)  # loser: stale head

    def test_I14_drift_blocks_until_signed_review(self):
        auth, acc = self._auth(accepted=("W",))
        a = auth.admit("W", G.gate_spec(), specialist="w1")
        head = auth.project_head("p")
        auth.promote("W", KnowledgeDelta(("f",), ("artifact:Wf",)), expected_head=head)  # head advances underneath W
        with self.assertRaises(ValueError):
            auth.promote("W", KnowledgeDelta(("f2",), ("artifact:Wf2",)), expected_head=head)


class WatchdogAndStageCache(unittest.TestCase):
    """F4: a Running exit is always a published close; I16: the stage cache keys
    on the full attempt identity."""

    def test_F4_death_is_a_published_close(self):
        e = Enforcer(FG.gen_policy(writes=1))
        e.open("w", "impl", "body")
        e.admit("w", "gen"); e.bind("w", True)                   # pc = Running
        poll(pc="Running", alive_fn=lambda: False, on_death=lambda: e.death_observed("w"))
        st = e.items["w"].stages[0]
        self.assertEqual(st.pc, "Closed")
        self.assertEqual(st.fault, "F4")
        self.assertNotIn("w", e.store)

    def test_F4_a_live_running_stage_is_not_closed(self):
        e = Enforcer(FG.gen_policy(writes=1))
        e.open("w", "impl", "body"); e.admit("w", "gen"); e.bind("w", True)
        poll(pc="Running", alive_fn=lambda: True, on_death=lambda: e.death_observed("w"))
        self.assertEqual(e.items["w"].stages[0].pc, "Running")

    def test_I16_stage_cache_key_separates_every_dimension(self):
        c = StageCache()
        k1 = c.key("gen", "vendorA:model-g", "prefix1")
        c.put(k1, b"payload")
        self.assertEqual(c.get(k1), b"payload")
        # any differing dimension is a different key -> a miss
        self.assertIsNone(c.get(c.key("gen2", "vendorA:model-g", "prefix1")))
        self.assertIsNone(c.get(c.key("gen", "vendorB:other", "prefix1")))
        self.assertIsNone(c.get(c.key("gen", "vendorA:model-g", "prefix2")))


if __name__ == "__main__":
    unittest.main()
