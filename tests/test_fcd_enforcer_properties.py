"""Property sweep for the FCD identity layer: I1..I9 and the forbidden
transitions F1, F3, F6, F7, F8, F10, asserted against the live Enforcer over a
generated space of histories with fault injection (tests/fcd_generators.py).
Two guards the generated space does not reach on its own are added as constructed
probes: a bare decide with no Observe (I1) and a direct Accept while a required
stage is still Open (I5/I8).

Where tests/test_invariants.py pins each claim on one example, this asserts it
universally: for every history the generator grows, the identity invariants hold
of every reachable state, and each forbidden transition is refused wherever it
could be attempted. F2 (needs a runtime-instance field), F4 (watchdog; covered in
test_fcd_context_properties.py::WatchdogAndStageCache), F5 (phi(a) not an API
identity; its malformed-identity path is subsumed by bind's usability guard) and
F9 (a silent stop — a chat stop with status not accepted) are example-only or
covered elsewhere, per tests/THEOREM_PROPERTY_MAP.md.
"""
from __future__ import annotations

import os
import sys
import unittest

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

HERE = os.path.dirname(__file__)
for _p in (os.path.join(HERE, ".."), HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import fcd_generators as G  # noqa: E402
from fcd.core import Enforcer, norm  # noqa: E402

DEEP = bool(os.environ.get("ADMISSIBLE_DEEP"))
EXAMPLES = 400 if DEEP else 50
_SUPPRESS = [HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much]


def sweep(**kw):
    p = dict(max_examples=EXAMPLES, deadline=None, derandomize=not DEEP, suppress_health_check=_SUPPRESS)
    p.update(kw)
    return settings(**p)


def _stage_events(e: Enforcer):
    return [ev for ev in e.events if ev.get("type") == "stage"]


class FcdIdentityInvariants(unittest.TestCase):
    """I1..I9 as universal properties over generated Enforcer histories."""

    @sweep()
    @given(G.fcd_histories())
    def test_I1_bind_integrity(self, h):
        """pc=Passed => norm(m_exec)=norm(m_decl)=norm(phi(a))."""
        for item in h.e.items.values():
            phi = h.e.policy_for(item.id).phi
            for stg in item.stages:
                if stg.pc == "Passed":
                    self.assertIsNotNone(stg.m_exec)
                    self.assertEqual(norm(stg.m_exec), norm(stg.m_decl), (item.id, h.moves))
                    self.assertEqual(norm(stg.m_decl), norm(phi[stg.a]), (item.id, h.moves))
        # journal form: every passing decide sat on a matching call (on_bind True)
        for ev in h.e.events:
            if ev.get("type") == "decide" and ev.get("result") == "pass":
                sid = ev["stage_id"]
                calls = [c for c in h.e.events if c.get("type") == "call" and c.get("stage_id") == sid]
                self.assertTrue(calls and calls[-1]["on_bind"], (sid, h.moves))

    @sweep()
    @given(G.fcd_histories())
    def test_I2_class_admission(self, h):
        """Every admitted specialist lay in the pi* recorded at its admit."""
        for ev in _stage_events(h.e):
            self.assertIn(ev["assigned_specialist_id"], set(ev["pi_star"]), (ev["stage_id"], h.moves))

    @sweep()
    @given(G.fcd_histories())
    def test_I3_no_unbound_hop(self, h):
        """A Passed stage's executed model is the identity of some admissible
        specialist — never a leftover hop."""
        by_stage = {ev["stage_id"]: ev for ev in _stage_events(h.e)}
        phi = h.policy.phi
        for item in h.e.items.values():
            for i, stg in enumerate(item.stages):
                if stg.pc == "Passed":
                    sid = f"{item.id}.{i}"
                    admissible_models = {norm(phi[x]) for x in by_stage[sid]["pi_star"]}
                    self.assertIn(norm(stg.m_exec), admissible_models, (sid, h.moves))

    @sweep()
    @given(G.fcd_histories())
    def test_I4_class_and_body_frozen(self, h):
        """cls and body equal the Open event and never change; a re-open is refused."""
        opens = {ev["work_item_id"]: ev for ev in h.e.events if ev.get("type") == "open"}
        for item in h.e.items.values():
            self.assertEqual(item.cls, opens[item.id]["class"], h.moves)
            self.assertEqual(item.body, opens[item.id]["body_hash"], h.moves)
            with self.assertRaises(ValueError):
                h.e.open(item.id, "impl", "different-body")     # F10: same id, different body

    @sweep()
    @given(G.fcd_histories())
    def test_I5_accept_coverage(self, h):
        """status=accepted => every stage Passed."""
        for item in h.e.items.values():
            if item.status == "accepted":
                self.assertTrue(all(s.pc == "Passed" for s in item.stages), (item.id, h.moves))

    @sweep()
    @given(G.fcd_histories())
    def test_I6_dual_control_on_check_stages(self, h):
        """A check-stage admit never bound a prior author of the same item."""
        for ev in _stage_events(h.e):
            if ev["stage_kind"] == "check":
                self.assertNotIn(ev["assigned_specialist_id"], set(ev["authors"]), (ev["stage_id"], h.moves))

    @sweep()
    @given(G.fcd_histories())
    def test_I7_bounded_admits_and_no_retried(self, h):
        """A stage admits at most |pi*| distinct specialists, and re-admitting a
        tried specialist is refused."""
        for item in h.e.items.values():
            allow = set(h.policy.allow["impl"]) - set(h.policy.deny["impl"])
            for stg in item.stages:
                self.assertLessEqual(len(stg.tried), len(allow), (item.id, h.moves))
                if stg.tried and stg.pc in ("Open", "Closed"):
                    a = sorted(stg.tried)[0]
                    with self.assertRaises(ValueError):
                        h.e.admit(item.id, a)                   # F10 / I7: retry of a in tried

    @sweep()
    @given(G.fcd_histories())
    def test_I8_store_only_accepted(self, h):
        """id in store => accepted, and the store has no writer but Accept."""
        for iid in h.e.store:
            self.assertEqual(h.e.items[iid].status, "accepted", (iid, h.moves))
        for iid in h.e.items:
            with self.assertRaises(PermissionError):
                h.e.store_put(iid)                              # I8 bypass forbidden

    @sweep()
    @given(G.fcd_histories())
    def test_I9_retry_preserves_class(self, h):
        """Every stage event for an item carries the item's frozen class."""
        for ev in _stage_events(h.e):
            self.assertEqual(ev["class"], h.e.items[ev["work_item_id"]].cls, h.moves)


class FcdForbiddenTransitions(unittest.TestCase):
    """F1, F3, F6, F7, F8 as constructed forbidden-transition refusals — each a
    fresh scenario proving the guard fires (complementing the generated sweep)."""

    def _fresh(self, deny=()):
        e = Enforcer(G.gen_policy(deny=deny, writes=1))
        e.open("w", "impl", "body")
        return e

    def test_F1_foreign_model_never_passes(self):
        e = self._fresh()
        e.admit("w", "gen"); e.bind("w", True); e.observe("w", "vendorZ:rogue")
        e.decide_pass("w")
        st = e.items["w"].stages[0]
        self.assertEqual(st.pc, "Closed")
        self.assertEqual(st.fault, "F1")
        self.assertNotIn("w", e.store)

    def test_F3_bind_failure_closes_and_forbids_observe(self):
        e = self._fresh()
        e.admit("w", "gen"); e.bind("w", False)               # u=0 -> F3 close
        st = e.items["w"].stages[0]
        self.assertEqual(st.pc, "Closed")
        with self.assertRaises(ValueError):
            e.observe("w", "vendorA:model-g")                 # no call after u=0 without fail-closed

    def test_F6_denied_specialist_cannot_be_admitted(self):
        e = self._fresh(deny=("gen",))
        with self.assertRaises(ValueError):
            e.admit("w", "gen")                               # a in delta(c)

    def test_F7_check_admit_of_an_author_is_refused(self):
        e = Enforcer(G.gen_policy(writes=1))
        e.open("w", "impl", "body")
        e.admit("w", "gen"); e.bind("w", True)
        e.observe("w", "vendorA:model-g"); e.decide_pass("w")  # write passes; gen becomes an author
        self.assertEqual(e.items["w"].stages[0].pc, "Passed")
        with self.assertRaises(ValueError):
            e.admit("w", "gen")                               # check stage: gen in authors

    def test_F8_no_run_without_a_well_formed_stage(self):
        e = self._fresh()
        with self.assertRaises(ValueError):
            e.bind("w", True)                                 # not Admitted
        with self.assertRaises(ValueError):
            e.observe("w", "vendorA:model-g")                 # not Running
        with self.assertRaises(ValueError):
            e.decide_pass("w")                                # not Running

    def test_I1_decide_pass_requires_a_provider_observe(self):
        """I1 (journal form): a Pass must rest on a provider Observe. decide_pass
        with pc=Running but no Observe (m_exec is None) is refused. The generator
        always pairs observe with decide, so test_I1's journal clause never sees a
        bare decide; this drives the guard the round-3 finding hardened (Bind must
        not write m_exec, or the Pass check goes tautological)."""
        e = self._fresh()
        e.admit("w", "gen"); e.bind("w", True)                # Running, m_exec still None
        self.assertIsNone(e.items["w"].stages[0].m_exec)
        with self.assertRaisesRegex(ValueError, "Observe"):
            e.decide_pass("w")                                # no observe -> refused

    def test_I5_I8_accept_requires_all_stages_passed(self):
        """I5/I8: Accept's own guard — a direct accept while a required stage is
        still Open is refused, so the store (written only by Accept) admits only
        fully-passed items. Generated histories reach 'accepted' only via
        decide_pass after every stage Passed, so this guard is otherwise never
        exercised on its own."""
        e = self._fresh()                                     # stages [write, check]
        e.admit("w", "gen"); e.bind("w", True)
        e.observe("w", "vendorA:model-g"); e.decide_pass("w")  # write Passed; check still Open
        self.assertEqual([s.pc for s in e.items["w"].stages], ["Passed", "Open"])
        with self.assertRaisesRegex(ValueError, "all stages Passed"):
            e.accept("w")
        self.assertNotIn("w", e.store)


if __name__ == "__main__":
    unittest.main()
