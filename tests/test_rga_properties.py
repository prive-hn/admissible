"""Property sweep for the RGA scrutiny layer: R1..R13 and the V-faults,
asserted against the live Admission machine over a generated space of histories
with fault injection (tests/rga_generators.py).

Where tests/test_rga_invariants.py pins each claim on an example trace, this
asserts it universally: for every history the generator grows, the scrutiny
invariants hold of every sealed line, refuted/inconclusive/discordant/divergent
paths close rather than seal, and the write-once and refusal guards hold wherever
they could be attempted. Each TestCase names the invariant it exercises.
"""
from __future__ import annotations

import copy
import os
import sys
import unittest

from hypothesis import HealthCheck, given, settings

HERE = os.path.dirname(__file__)
for _p in (os.path.join(HERE, ".."), HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import rga_generators as G  # noqa: E402
from fcd.core import norm  # noqa: E402
from rga.core import DefectModel, LedgerEntry, Refuter  # noqa: E402
from test_rga_invariants import D1, K, TESTS, Harness, ledger  # noqa: E402

DEEP = bool(os.environ.get("ADMISSIBLE_DEEP"))
EXAMPLES = 400 if DEEP else 50
_SUPPRESS = [HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much]


def sweep(**kw):
    p = dict(max_examples=EXAMPLES, deadline=None, derandomize=not DEEP, suppress_health_check=_SUPPRESS)
    p.update(kw)
    return settings(**p)


class RgaSealInvariants(unittest.TestCase):
    """R1, R4, R6, R7, R8, R9, R13 as universal properties over sealed lines."""

    @sweep()
    @given(G.rga_histories())
    def test_R1_no_admission_without_survival(self, hist):
        a = hist.h.a
        for iid in hist.sealed:
            line = a.lines[iid]
            self.assertEqual(line.pc, "Sealed", hist.moves)
            for t in line.trials:
                self.assertEqual(t.verdict, "survived", (iid, hist.moves))
        # a line that ever recorded a refuted/inconclusive trial never sealed
        for iid in hist.lines:
            line = a.lines.get(iid)
            if line and any(t.verdict in ("refuted", "inconclusive") for t in line.trials):
                self.assertNotIn(iid, hist.sealed, (iid, hist.moves))

    @sweep()
    @given(G.rga_histories())
    def test_R4_concordance_precondition(self, hist):
        a = hist.h.a
        for iid in hist.sealed:
            seal = a.sealed[iid]
            for cs in seal.claims:
                self.assertGreaterEqual(cs.agreeing / cs.k, seal.theta - 1e-9, (iid, hist.moves))
            self.assertEqual(seal.artifact_hash, a.lines[iid].samples[0].artifact_hash, (iid, hist.moves))

    @sweep()
    @given(G.rga_histories())
    def test_R6_replay_exercised(self, hist):
        a = hist.h.a
        for iid in hist.sealed:
            line = a.lines[iid]
            pinned = {r for c in line.claims for r in c.refuters}   # (id, version) keys
            for key in pinned:
                self.assertTrue(
                    any((t.refuter_id, t.refuter_version) == key and t.replays >= 1 for t in line.trials),
                    (iid, key, hist.moves))

    @sweep()
    @given(G.rga_histories())
    def test_R7_sample_integrity_inherited(self, hist):
        a = hist.h.a
        for iid in hist.sealed:
            line = a.lines[iid]
            item = a.fcd.items[iid]
            for s in line.samples:
                stage = item.stages[s.index]
                self.assertEqual(stage.pc, "Passed", (iid, s.index, hist.moves))
                self.assertEqual(norm(s.m_exec), norm(stage.m_decl), (iid, s.index, hist.moves))

    @sweep()
    @given(G.rga_histories())
    def test_R8_seal_implies_accept(self, hist):
        a = hist.h.a
        for iid in hist.sealed:
            self.assertIn(iid, a.fcd.store, (iid, hist.moves))
            self.assertEqual(a.fcd.items[iid].status, "accepted", (iid, hist.moves))

    @sweep()
    @given(G.rga_histories())
    def test_R9_artifact_binding_by_seed(self, hist):
        a = hist.h.a
        for iid in hist.sealed:
            line = a.lines[iid]
            for t in line.trials:
                expected = a.seed_for(iid, t.sample_index, t.refuter_id, t.refuter_version, t.claim_id)
                self.assertEqual(t.seed, expected, (iid, hist.moves))

    @sweep()
    @given(G.rga_histories())
    def test_R13_bounded(self, hist):
        a = hist.h.a
        for iid in hist.lines:
            line = a.lines.get(iid)
            if not line:
                continue
            self.assertLessEqual(len(line.samples), line.k, (iid, hist.moves))
            cells = [(t.refuter_id, t.refuter_version, t.claim_id, t.sample_index) for t in line.trials]
            self.assertEqual(len(cells), len(set(cells)), (iid, hist.moves))       # <=1 trial per cell


class RgaPowerAndFrozen(unittest.TestCase):
    """R2 (power carried from P, never inferred; write-once) and R12 (frozen line)."""

    @sweep()
    @given(G.rga_histories())
    def test_R2_power_is_carried(self, hist):
        a = hist.h.a
        for iid in hist.sealed:
            seal = a.sealed[iid]
            for cs in seal.claims:
                for rs in cs.refuters:
                    if rs.mode == "ledger":
                        rec = a.power.get((rs.id, rs.version, rs.defect_model_hash))
                        self.assertIsNotNone(rec, (iid, rs.id, hist.moves))
                        self.assertAlmostEqual(rs.power, rec.kills / rec.size, places=9)

    @sweep()
    @given(G.rga_histories())
    def test_R12_frozen_line_matches_seal(self, hist):
        a = hist.h.a
        for iid in hist.sealed:
            line, seal = a.lines[iid], a.sealed[iid]
            self.assertEqual(seal.k, line.k, hist.moves)
            self.assertEqual(seal.theta, line.theta, hist.moves)
            self.assertEqual(seal.generator, line.generator, hist.moves)
            self.assertEqual(seal.policy_version, line.policy_version, hist.moves)


class RgaRefusalAndNonInterference(unittest.TestCase):
    """R5 (nondeterminism refuses, monotone) and R11 (RGA writes no FCD field),
    as constructed probes complementing the generated sweep."""

    def test_R5_divergent_replay_refuses_and_is_monotone(self):
        h = Harness(); h.declare_tests()
        h.run_to_seal_ready("w")
        h.a.replay("w", 0, "refuted", "w-flip")               # diverges from the survived trial
        self.assertIn(TESTS, h.a.refused)
        # refused is monotone: it cannot be measured, bounded, or pinned again
        with self.assertRaises(ValueError):
            h.a.measure("tests", "v1", DefectModel(D1, "mutator2"), ledger(9, 10))
        with self.assertRaises(ValueError):
            h.a.bound("tests", "v1", 0.9, 5)
        # and a line that pinned it, still open at refusal, was closed
        self.assertNotEqual(h.a.lines["w"].pc, "Sealed")

    def test_R11_rga_writes_no_fcd_field(self):
        h = Harness(); h.declare_tests()
        h.fcd_open("w"); h.rga_open("w")
        before = None

        def snap():
            e = h.a.fcd
            return (copy.deepcopy(e.items), set(e.store), len(e.events), e.policy)

        # snapshot the FCD projection across each RGA transition
        for i in range(h.k):
            h.fcd_write("w")
            before = snap(); h.sample("w", f"b{i}".encode())
            self.assertEqual(snap()[0], before[0])             # RGA writes NO FCD item field (full items, not just keys)
            self.assertEqual(snap()[1], before[1]); self.assertEqual(snap()[2], before[2])
            before = snap(); h.trial("w", i)
            self.assertEqual(snap()[0], before[0])             # a trial leaves every FCD item byte-identical
            self.assertEqual(snap()[1], before[1]); self.assertEqual(snap()[2], before[2])
        before = snap(); h.replay_all("w")
        self.assertEqual(snap()[0], before[0])                 # replay writes only the RGA line
        self.assertEqual(snap()[1], before[1]); self.assertEqual(snap()[2], before[2])
        h.fcd_check("w")
        before = snap(); h.a.seal("w")
        self.assertEqual(snap()[0], before[0])                 # Seal writes S_R, not any FCD item
        self.assertEqual(snap()[1], before[1])                 # Seal writes S_R, not S
        self.assertEqual(snap()[2], before[2])                 # no FCD event emitted


class RgaSeparationOfDuty(unittest.TestCase):
    """R3: a refuter authored by the generator, or a defect model authored by an
    interested party, cannot reach a seal (constructed refusals)."""

    def test_R3_generator_authored_refuter_cannot_pin(self):
        h = Harness(refuters=frozenset({("evil", "v1")}))
        h.a.declare(Refuter("evil", "v1", "gen", "ledger"))    # author == generator
        with self.assertRaises(ValueError):
            h.fcd_open("w"); h.rga_open("w")                   # pinning refuses at open

    def test_R3_defect_model_author_is_fixed_by_first_record(self):
        h = Harness(); h.declare_tests()               # first record fixes D1's author to "mutator"
        h.a.declare(Refuter("audit", "v1", "auditor", "ledger"))
        # A fresh refuter clears the write-once power guard (_guard_power_once runs
        # first), so execution actually reaches the author-fixity guard this test is
        # named for: re-declaring D1's model under a different author than its first
        # record is refused there. Pin the message so a green run is evidence for
        # THAT guard, not the incidental duplicate-power refusal.
        with self.assertRaises(ValueError) as cm:
            h.a.measure("audit", "v1", DefectModel(D1, "someone-else"), ledger(9, 10))
        self.assertIn("author differs", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
