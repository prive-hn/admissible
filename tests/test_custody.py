"""Executable checks of the custody-theory companion (paper/custody/DRAFT.md
§8) against real three-layer runs. Each test names the theorem it exercises.
These are research checks beside the paper, not gate checks: they prove the
companion computes what the paper says over the kernels as they are.
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "paper", "custody"))
sys.path.insert(0, HERE)

import custody  # noqa: E402
from fcd.core import Enforcer  # noqa: E402
from fcd.journal import JournalValueError  # noqa: E402
from rga.calibration import CalibrationAuthority, CalibrationClass, CalibrationPolicy  # noqa: E402
from rga.core import Admission, ClaimSpec, DefectModel, LedgerEntry, Refuter  # noqa: E402
from test_rga_calibration import CalHarness  # noqa: E402
from test_rga_invariants import D1, K, TESTS, PBT, Harness, admission_policy, fcd_policy, ledger  # noqa: E402


def rebuild(h, claims=None):
    """Rebuild all three machines from their journals, as a verifier would."""
    fcd2 = Enforcer.from_events(list(h.e.events), fcd_policy())
    adm2 = Admission.from_events(list(h.a.events), fcd2, admission_policy(claims=claims))
    return CalibrationAuthority.from_events(list(h.cal.events), adm2, h.cal.policy)


class PolarityD6(unittest.TestCase):
    """D6/T3: seal raises, escape lowers, discredit raises second-order."""

    def test_seal_raises_escape_lowers_discredit_raises_second_order(self):
        h = CalHarness(); h.declare_tests()
        self.assertFalse(h.cal.admissible("w"))
        h.seal_line()                                           # rga_seal + cal_stamp: '+'
        self.assertTrue(h.cal.admissible("w"))
        run = h.tier_a_escape(nonce="e1")                       # establishing cal_replay: '-'
        self.assertFalse(h.cal.admissible("w"))
        second = h.tier_a_escape(nonce="e2", replay=False)
        h.cal.replay_run(second.index, "refuted", "other")      # cal_discredit: '±'
        self.assertTrue(h.cal.admissible("w"))                  # validity of the first degraded
        self.assertEqual(custody.polarity_of("cal_stamp"), "+")       # the event at which admissible flips
        self.assertEqual(custody.polarity_of("rga_seal"), "e")        # enabling: never lowers, never the flip
        self.assertEqual(custody.polarity_of("cal_replay"), "-")
        self.assertEqual(custody.polarity_of("cal_discredit"), "+")   # never lowers; raises second-order
        self.assertEqual(custody.polarity_of("rga_refuse"), "±")
        self.assertEqual(run.tier, "A")

    def test_every_journaled_event_type_is_classified(self):
        h = CalHarness(); h.declare_tests(); h.seal_line(); h.tier_a_escape()
        seen = {e.get("type") for e in h.e.events} | {e.get("type") for e in h.a.events} \
            | {e.get("type") for e in h.cal.events}
        for t in seen:
            self.assertNotEqual(custody.polarity_of(t), "?", t)


class DeletionSurfaceT4(unittest.TestCase):
    """T4.1: the surface enumerates exactly the witnesses of negated demonstrations."""

    def test_surface_is_empty_for_a_clean_seal_and_names_the_escape(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        self.assertEqual(custody.deletion_surface(h.cal), ())
        run = h.tier_a_escape()
        surface = custody.deletion_surface(h.cal)
        self.assertEqual({(s.journal, s.type) for s in surface}, {("cal", "cal_run"), ("cal", "cal_replay")})
        self.assertTrue(all(s.line_id == "w" and s.reason == "escape" for s in surface))
        self.assertEqual(h.cal.events[run.position].get("type"), "cal_run")

    def test_surface_names_a_tainting_refusal_and_its_diverged_replay(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.fcd_open("z"); h.a.open("z", "gen", "temp=0.7")
        h.fcd_write("z"); h.sample("z", b"z0"); h.trial("z")
        h.a.replay("z", 0, "refuted", "w-same")                 # diverges: refuses `tests`
        self.assertTrue(h.a.tainted("w"))
        surface = custody.deletion_surface(h.cal, "w")
        self.assertEqual({s.type for s in surface}, {"rga_refuse", "rga_replay", "rga_close"})   # z's V4 close
        self.assertTrue(all(s.reason == "taint" for s in surface))
        at = h.a.refused_at[TESTS]
        self.assertEqual({s.index for s in surface}, {at - 1, at, at + 1})

    def test_deleting_the_surface_raises_standing_and_the_certificate_catches_it(self):
        """T4(a) then T11: deletion flips admissible to true; the line-scoped
        certificate refuses the deleted custody on demonstrations and length."""
        h = CalHarness(); h.declare_tests(); h.seal_line(); h.tier_a_escape()
        cert = custody.standing_certificate(h.cal, "w")
        self.assertFalse(cert.standing)
        self.assertEqual(cert.demonstrations, 2)
        self.assertEqual(custody.verify_certificate(h.cal, cert), [])
        pruned = [e for e in h.cal.events if e.get("type") not in ("cal_run", "cal_replay")]
        forged = CalibrationAuthority.from_events(pruned, h.a, h.cal.policy)
        self.assertTrue(forged.admissible("w"))                 # deletion raised standing
        self.assertEqual(custody.verify_certificate(forged, cert), ["demonstrations", "lengths"])

    def test_a_coherent_root_rewrite_changes_the_roots_hash(self):
        """T4(c)/T11: a rewrite that replay accepts moves the roots component."""
        h = CalHarness(); h.declare_tests(); h.seal_line()
        cert = custody.standing_certificate(h.cal, "w")
        g = CalHarness(); g.declare_tests(); g.seal_line(bodies=[b"other-0", b"other-1", b"other-2"])
        other = custody.standing_certificate(g.cal, "w")
        self.assertEqual(cert.lengths, other.lengths)
        self.assertEqual(cert.demonstrations, other.demonstrations)
        self.assertNotEqual(cert.roots_hash, other.roots_hash)


class JointReadingT7(unittest.TestCase):
    """T7/K3: power_min is the upper bound of the joint reading; Bonferroni is the lower."""

    def test_two_claims_power_min_and_joint(self):
        claims = (ClaimSpec("tests_pass", "spec-1", frozenset({TESTS}), D1),
                  ClaimSpec("props_hold", "spec-2", frozenset({PBT}), "d2-hash"))
        h = CalHarness(claims=claims)
        h.declare_tests(kills=9, size=10)
        h.a.declare(Refuter("pbt", "v1", "prop-author", "ledger"))
        h.a.measure("pbt", "v1", DefectModel("d2-hash", "mutator2"),
                    [LedgerEntry(f"q{i}", "killed" if i < 7 else "survived") for i in range(10)])
        h.fcd_open("w"); h.cal.open("w", "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write("w"); h.sample("w", f"w-{i}".encode())
            h.trial("w", i); h.trial("w", i, refuter=PBT, claim="props_hold", witness="p-same")
        h.replay_all("w"); h.fcd_check("w")
        seal = h.cal.seal("w")
        self.assertAlmostEqual(seal.power_min, 0.7)
        self.assertAlmostEqual(custody.seal_joint(seal), 0.6)
        lo, hi = custody.frechet_bounds([0.9, 0.7], "intersection")
        self.assertAlmostEqual(lo, 0.6); self.assertAlmostEqual(hi, 0.7)

    def test_bonferroni_horizon(self):
        self.assertEqual(custody.bonferroni_horizon(0.9), 10)
        self.assertEqual(custody.power_joint([0.9] * 10), 0.0)
        self.assertAlmostEqual(custody.power_joint([0.9] * 3), 0.7)
        self.assertIsNone(custody.bonferroni_horizon(1.0))

    def test_union_bounds_contain_the_kernels_composite(self):
        """T6: the kernel's labelled max is the lower Fréchet bound across models."""
        lo, hi = custody.frechet_bounds([0.9, 0.5], "union")
        self.assertAlmostEqual(lo, 0.9); self.assertAlmostEqual(hi, 1.0)
        self.assertGreater(1 - (1 - 0.9) * (1 - 0.5), lo)     # the banned product exceeds max


class KillContextT8(unittest.TestCase):
    def test_unique_kills_uncovered_and_redundancy(self):
        h = CalHarness(refuters=frozenset({TESTS, PBT}))
        h.declare_tests(kills=6, size=10)                       # kills m0..m5
        h.a.declare(Refuter("pbt", "v1", "prop-author", "ledger"))
        h.a.measure("pbt", "v1", DefectModel(D1, "mutator"),
                    [LedgerEntry(f"m{i}", "killed" if i in (4, 5, 6, 7) else "survived") for i in range(10)])
        h.fcd_open("w"); h.cal.open("w", "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write("w"); h.sample("w", f"w-{i}".encode())
            h.trial("w", i); h.trial("w", i, refuter=PBT, witness="p-same")
        h.replay_all("w"); h.fcd_check("w")
        seal = h.cal.seal("w")
        ctx = custody.kill_context(h.a, "w", "tests_pass")
        self.assertEqual((ctx.size, ctx.union, ctx.uncovered), (10, 8, 2))
        self.assertEqual(ctx.unique_kills, {TESTS: 4, PBT: 2})
        self.assertEqual(ctx.redundant, ())
        self.assertAlmostEqual(seal.claims[0].composite, 0.8)   # union = top extent's density
        self.assertEqual(seal.claims[0].composition, "union")


class HereditaryStandingT7_1(unittest.TestCase):
    def _chain(self):
        h = CalHarness(); h.declare_tests()
        h.seal_line("w")
        h.e.open("x", "impl", "body-hash", depends_on=("w",))
        h.cal.open("x", "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write("x"); h.sample("x", f"x-{i}".encode()); h.trial("x", i)
        h.replay_all("x"); h.fcd_check("x"); h.cal.seal("x")
        h.e.open("y", "impl", "body-hash", depends_on=("x",))
        h.cal.open("y", "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write("y"); h.sample("y", f"y-{i}".encode()); h.trial("y", i)
        h.replay_all("y"); h.fcd_check("y"); h.cal.seal("y")
        return h

    def test_impeached_grandparent_is_invisible_to_admissible_and_suspect_but_not_to_provenance(self):
        h = self._chain()
        self.assertEqual(custody.ancestors(h.a, "y"), ("x", "w"))
        self.assertTrue(custody.hereditary_admissible(h.cal, "y"))
        h.tier_a_escape("w")
        self.assertFalse(h.cal.admissible("w"))
        self.assertTrue(h.cal.admissible("y"))                  # today: unchanged (documented)
        self.assertFalse(h.cal.suspect("y"))                    # one hop: x is fine
        self.assertTrue(h.cal.suspect("x"))
        prov = custody.provenance(h.cal, "y")
        self.assertTrue(prov["w"].impeached and not prov["x"].impeached)
        self.assertFalse(custody.hereditary_admissible(h.cal, "y"))

    def test_joint_closure_is_bonferroni_over_the_chain(self):
        h = self._chain()
        self.assertAlmostEqual(h.a.sealed["y"].power_min, 0.9)
        self.assertAlmostEqual(custody.power_joint_closure(h.cal, "y"), 0.7)   # three seals at 0.9


class ExposureT16(unittest.TestCase):
    def test_attempt_index_and_published_refutations_on_one_bind_key(self):
        h = CalHarness(); h.declare_tests()
        h.fcd_open("w1"); h.cal.open("w1", "gen", "temp=0.7")
        h.fcd_write("w1"); h.sample("w1", b"w1-0")
        h.trial("w1", 0, verdict="refuted", witness="kill")       # V1: published
        self.assertEqual(h.a.lines["w1"].fault, "V1")
        h.seal_line("w2")
        ex = custody.exposure(h.a, "w2")
        self.assertEqual(ex.attempt_index, 2)
        self.assertEqual(ex.prior_lines, ("w1",))
        self.assertEqual(ex.published_refutations, (("tests", "v1", "tests_pass", 0, "w1"),))
        self.assertEqual(custody.exposure(h.a, "w1").attempt_index, 1)


class TrustBaseC9(unittest.TestCase):
    def test_derived_tier_agrees_with_the_kernel_for_a_and_b(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        a = h.tier_a_escape()
        self.assertEqual(custody.derived_tier(h.cal, a), a.tier)
        self.assertTrue(custody.run_base(h.cal, a) <= custody.trust_base(h.a, h.a.sealed["w"]))
        h.a.declare(Refuter("hawk", "v1", "hawk-author", "ledger"))
        b = h.cal.file_escape("w", "tests_pass", "hawk", "v1", "n1", b"w-body-0", "any", "hk", "aud")
        self.assertEqual(b.tier, "B")
        self.assertEqual(custody.derived_tier(h.cal, b), "B")
        self.assertIn(custody.ADJUDICATION, custody.run_base(h.cal, b))
        self.assertIn("B5", custody.trust_base(h.a, h.a.sealed["w"]))


class AnchoredAndExposedSurface(unittest.TestCase):
    """§5 (T10 as corrected): a witness is deletable iff no later event
    recomputes content from it. A later same-class stamp recomputes
    corpus_size/charged_cells from the escapes before it and anchors them."""

    def test_escape_after_the_last_stamp_is_exposed_and_before_a_later_stamp_is_anchored(self):
        h = CalHarness(); h.declare_tests(); h.seal_line("w")
        h.tier_a_escape("w", nonce="e1")
        self.assertTrue(all(e.exposed for e in custody.deletion_surface(h.cal, "w")))
        h.seal_line("x")                                        # same class: its stamp anchors the escape
        surface = custody.deletion_surface(h.cal, "w")
        self.assertTrue(surface and all(not e.exposed for e in surface))
        self.assertEqual(custody.exposed(h.cal, "w"), ())
        stamp_x = next(i for i, e in enumerate(h.cal.events)
                       if e.get("type") == "cal_stamp" and e.get("line_id") == "x")
        self.assertIn(("cal", stamp_x), surface[0].anchored_by)
        pruned = [e for e in h.cal.events
                  if not (e.get("type") in ("cal_run", "cal_replay") and e.get("run_index") == 0)]
        with self.assertRaises(ValueError) as ctx:
            CalibrationAuthority.from_events(pruned, h.a, h.cal.policy)
        self.assertIn("stamp does not recompute", str(ctx.exception))

    def test_a_tail_refusal_group_is_exposed_and_its_deletion_replays_clean(self):
        h = CalHarness(); h.declare_tests(); h.seal_line("w")
        h.fcd_open("z"); h.a.open("z", "gen", "temp=0.7")
        h.fcd_write("z"); h.sample("z", b"z0"); h.trial("z")
        h.a.replay("z", 0, "refuted", "w-same")                 # diverges: refuses `tests`, taints w
        self.assertTrue(h.a.tainted("w"))
        surface = custody.deletion_surface(h.cal, "w")
        self.assertEqual({e.type for e in surface}, {"rga_replay", "rga_refuse", "rga_close"})   # the cascaded V4 too
        self.assertTrue(all(e.exposed for e in surface))
        drop = {e.index for e in surface}
        pruned = [e for i, e in enumerate(h.a.events) if i not in drop]
        rebuilt = Admission.from_events(pruned, h.e, h.a.policy)
        self.assertFalse(rebuilt.tainted("w"))                   # un-tainted by a deletion replay accepts
        self.assertTrue(rebuilt.admissible("w"))

    def test_an_e5_close_anchors_the_escape_that_demoted_its_refuter(self):
        h = CalHarness(e_max=0, gate="seal"); h.declare_tests(); h.seal_line("w")
        h.tier_a_escape("w")                                    # one charge > e_max: demoted
        h.fcd_open("x")
        h.a.open("x", "gen", "temp=0.7")                         # around CalOpen, which would refuse the pin
        for i in range(h.k):
            h.fcd_write("x"); h.sample("x", f"x-{i}".encode()); h.trial("x", i)
        h.replay_all("x"); h.fcd_check("x")
        with self.assertRaises(ValueError):
            h.cal.seal("x")                                      # E5: published close, recomputed on rebuild
        surface = custody.deletion_surface(h.cal, "w")
        self.assertTrue(surface and all(not e.exposed for e in surface))
        e5 = next(i for i, e in enumerate(h.cal.events) if e.get("type") == "cal_close" and e.get("fault") == "E5")
        self.assertIn(("cal", e5), surface[0].anchored_by)
        pruned = [e for e in h.cal.events if not (e.get("type") in ("cal_run", "cal_replay") and e.get("run_index") == 0)]
        with self.assertRaises(ValueError) as ctx:
            CalibrationAuthority.from_events(pruned, h.a, h.cal.policy)
        self.assertIn("E5 close without a demotion", str(ctx.exception))


class SupportDetermination(unittest.TestCase):
    """The value of admissible(w) depends on the record only through its
    signed support: a later, unrelated line can be removed entirely."""

    def _prune(self, h, line_id):
        keep = lambda e: e.get("work_item_id") != line_id and e.get("line_id") != line_id
        fcd2 = Enforcer.from_events([e for e in h.e.events if keep(e)], fcd_policy())
        adm2 = Admission.from_events([e for e in h.a.events if keep(e)], fcd2, admission_policy())
        return CalibrationAuthority.from_events([e for e in h.cal.events if keep(e)], adm2, h.cal.policy)

    def test_removing_a_later_unrelated_line_leaves_the_value_unchanged(self):
        for impeach in (False, True):
            h = CalHarness(); h.declare_tests(); h.seal_line("w")
            if impeach:
                h.tier_a_escape("w")
            h.seal_line("x")
            sup = custody.support(h.cal, "w")
            self.assertFalse(any(t == "x" for _, _, t in sup.positive))
            before = h.cal.admissible("w")
            self.assertEqual(before, not impeach)
            rebuilt = self._prune(h, "x")
            self.assertEqual(rebuilt.admissible("w"), before)
            self.assertNotIn("x", rebuilt.adm.sealed)


class SupportIncludesValidityDegraders(unittest.TestCase):
    """T17(i): the events that void a witness against w are positive atoms of
    admissible(w); deleting them revives the witness and lowers standing."""

    def test_deleting_the_discredit_pair_revives_the_escape(self):
        h = CalHarness(); h.declare_tests(); h.seal_line("w")
        h.tier_a_escape("w", nonce="e1")
        second = h.tier_a_escape("w", nonce="e2", replay=False)
        h.cal.replay_run(second.index, "refuted", "other")       # discredits `tests`: w un-impeached
        self.assertTrue(h.cal.admissible("w"))
        sup = custody.support(h.cal, "w")
        self.assertEqual(sup.negative, ())                        # no valid witness stands
        self.assertIn("cal_discredit", {t for _, _, t in sup.positive})
        drop = {i for j, i, t in sup.positive if j == "cal" and t in ("cal_discredit", "cal_replay")
                and h.cal.events[i].get("run_index", second.index) == second.index}
        pruned = [e for i, e in enumerate(h.cal.events) if i not in drop]
        rebuilt = CalibrationAuthority.from_events(pruned, h.a, h.cal.policy)
        self.assertFalse(rebuilt.admissible("w"))                  # the first escape stands again


class FindingF1DiscreditIsFailOpen(unittest.TestCase):
    """Kernel finding F1. One party holding the sealed bytes (B12) files a second
    tier-A escape with any witness and replays it divergently; the pinned
    refuter is discredited and `_check_valid` voids every run of that checker,
    including the first escape that was established by identical replay. The
    line is un-impeached, the refuter un-demoted, nothing is tainted and
    Admission.refused stays empty. The transition table (paper/RGA/INVARIANTS.md
    §8.2, ReplayEscape) says 'every UNESTABLISHED escape of a discredited
    checker is void'; the code voids established ones too, in the standing-
    raising direction. This test documents today's behaviour."""

    def test_single_party_un_impeaches_by_self_discredit(self):
        h = CalHarness(e_max=0); h.declare_tests(); h.seal_line()
        first = h.tier_a_escape(nonce="e1")
        self.assertTrue(first.established)
        self.assertTrue(h.cal.impeached("w") and h.cal.demoted("tests", "v1", "impl"))
        second = h.tier_a_escape(nonce="e2", replay=False)
        h.cal.replay_run(second.index, "refuted", "other-witness")     # one divergent report
        self.assertIn(TESTS, h.cal.discredited)
        self.assertTrue(first.established)                              # its identical replay still stands
        self.assertFalse(h.cal.impeached("w"))
        self.assertTrue(h.cal.admissible("w"))
        self.assertFalse(h.cal.demoted("tests", "v1", "impl"))
        self.assertFalse(h.a.tainted("w"))
        self.assertEqual(h.a.refused, set())
        self.assertEqual(custody.polarity_of("cal_discredit"), "+")


class FindingF14RefusedCheckerAcceptedOnRebuild(unittest.TestCase):
    """F14: from_events' cal_run branch does not re-check Admission.refused; a
    filing by an already-refused checker, refused live, is accepted on rebuild
    (standing-neutral: _check_valid voids it), a fail-open replay seam."""

    def test_filing_by_a_refused_checker_is_refused_live_and_accepted_on_rebuild(self):
        from rga.core import derive_seed
        h = CalHarness(); h.declare_tests(); h.seal_line("w")
        h.fcd_open("z"); h.a.open("z", "gen", "temp=0.7")
        h.fcd_write("z"); h.sample("z", b"z0"); h.trial("z")
        h.a.replay("z", 0, "refuted", "w-same")                  # `tests` refused
        seal = h.a.sealed["w"]
        seed = derive_seed("n", seal.artifact_hash, "tests", "v1", "tests_pass")
        with self.assertRaises(ValueError):
            h.cal.file_escape("w", "tests_pass", "tests", "v1", "n", b"w-body-0", seed, "k", "f")   # live: refused
        forged = list(h.cal.events) + [{"type": "cal_run", "run_index": len(h.cal.runs), "line_id": "w",
                                        "class": "impl", "claim_id": "tests_pass", "checker_id": "tests",
                                        "checker_version": "v1", "tier": "A", "nonce": "n",
                                        "artifact_hash": seal.artifact_hash, "seed": seed,
                                        "verdict": "refuted", "witness_hash": "k", "finder": "f", "ts": 0.0}]
        rebuilt = CalibrationAuthority.from_events(forged, h.a, h.cal.policy)   # accepted on rebuild
        self.assertEqual(len(rebuilt.runs), 1)
        self.assertFalse(rebuilt._check_valid(rebuilt.runs[0]))
        self.assertFalse(rebuilt.impeached("w"))


class FindingF1RefusalPath(unittest.TestCase):
    """F1, second path (T5): a divergent Admission.replay report refuses a
    checker everywhere; _check_valid then voids its escapes at every
    position. A tier-B checker's accepted escape against w is voided by its
    refusal on another line, un-impeaching w with no taint (w never pinned it)."""

    def test_refusal_of_a_tier_b_checker_un_impeaches_without_taint(self):
        from rga.core import AdmissionPolicy, ClassAdmission
        h = CalHarness(e_max=0); h.declare_tests(); h.seal_line()
        h.a.declare(Refuter("hawk", "v1", "hawk-author", "ledger"))
        run = h.cal.file_escape("w", "tests_pass", "hawk", "v1", "n1", b"w-body-0", "any-seed", "hk", "aud")
        h.cal.replay_run(run.index, "refuted", "hk")
        h.cal.adjudicate(run.index, "owner", "accept", "reproduced by hand")
        self.assertTrue(h.cal.impeached("w"))
        h.a.measure("hawk", "v1", DefectModel("d-hawk", "mutator"), [LedgerEntry("m0", "killed")])
        pol = AdmissionPolicy({"impl": ClassAdmission(
            claims=(ClaimSpec("tests_pass", "spec-hash-1", frozenset({TESTS, ("hawk", "v1")}), D1),),
            k=K, theta=1.0, p_min=0.5, excluded=frozenset({"refuter_source", "refuter_results"}),
            residual=(("correct fix", "check_stage"),))}, version="r2")
        h.a.install(pol)                                          # around the ratchet: the probe's boundary
        h.fcd_open("z"); h.a.open("z", "gen", "temp=0.7")
        h.fcd_write("z"); h.sample("z", b"z0"); h.trial("z", 0, refuter=("hawk", "v1"))
        h.a.replay("z", 0, "refuted", "w-same")                  # one divergent report
        self.assertIn(("hawk", "v1"), h.a.refused)
        self.assertFalse(h.cal.impeached("w"))
        self.assertFalse(h.a.tainted("w"))
        self.assertTrue(h.cal.admissible("w"))


class FindingF2ReplaySeam(unittest.TestCase):
    """Kernel finding F2. CalibrationAuthority.from_events re-checks
    _guard_audit_checker against escapes(cls) at the FINAL registry (as_of=None),
    so an honest journal in which an audit was filed by a checker refused
    LATER in Admission is refused on rebuild: the live machine accepted what
    replay refuses (an oplax seam, in the record branch's vocabulary)."""

    HAWK = ("hawk", "v1")
    CLAIMS = (ClaimSpec("tests_pass", "spec-hash-1", frozenset({TESTS}), D1),
              ClaimSpec("lint_ok", "spec-hash-2", frozenset({HAWK}), D1))

    def _seal(self, h, iid):
        h.fcd_open(iid); h.cal.open(iid, "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write(iid); h.sample(iid, f"{iid}-body-{i}".encode())
            h.trial(iid, i, refuter=TESTS, claim="tests_pass")
            h.trial(iid, i, refuter=self.HAWK, claim="lint_ok", witness="h-same")
        h.replay_all(iid); h.fcd_check(iid)
        return h.cal.seal(iid)

    def test_honest_journal_with_an_audit_by_a_later_refused_checker_is_refused_on_rebuild(self):
        from rga.core import derive_seed
        h = CalHarness(claims=self.CLAIMS); h.declare_tests()
        h.a.declare(Refuter("hawk", "v1", "hawk-author", "ledger"))
        h.a.measure("hawk", "v1", DefectModel(D1, "mutator"), ledger(8, 10))
        self._seal(h, "w")
        run = h.cal.file_escape("w", "tests_pass", "hawk", "v1", "nB", b"w-body-0", "any", "hk", "aud")
        h.cal.replay_run(run.index, "refuted", "hk")
        h.cal.adjudicate(run.index, "owner", "accept", "reproduced by hand")   # hawk: a valid escape's checker
        sx = self._seal(h, "x")
        seed = derive_seed("nA", sx.artifact_hash, "hawk", "v1", "tests_pass")
        h.cal.file_audit("x", "tests_pass", "hawk", "v1", "nA", b"x-body-0", seed, "surv", "aud")  # accepted live
        h.fcd_open("z"); h.cal.open("z", "gen", "temp=0.7")
        h.fcd_write("z"); h.sample("z", b"z0")
        h.trial("z", 0, refuter=self.HAWK, claim="lint_ok", witness="h-same")
        h.a.replay("z", 0, "refuted", "h-same")                        # hawk refused, after the audit
        self.assertIn(self.HAWK, h.a.refused)
        with self.assertRaises(ValueError):
            rebuild(h, claims=self.CLAIMS)


class FindingF3RollbackWritesTheLowerMachine(unittest.TestCase):
    """Kernel finding F3. A calibration attempt that drives Admission.seal
    (committed: rga_seal emitted) and then fails in its own half retracts the
    committed Admission transition — restoring adm.lines/adm.sealed and
    truncating adm._events — so C7's proof sentence that the file assigns only
    the authority's own fields is false on the rollback path, which no kernel
    test drives. Non-interference holds at attempt granularity, not per step."""

    def test_failed_calibration_attempt_retracts_a_committed_admission_seal(self):
        h = Harness(); h.declare_tests(); h.run_to_seal_ready()

        def clock():
            raise RuntimeError("clock unavailable")     # _emit maps it to JournalValueError

        cal = CalibrationAuthority(h.a, CalibrationPolicy({"impl": CalibrationClass(e_max=1, demotion_gate="seal")}),
                                   clock=clock)
        before = len(h.a.events)
        with self.assertRaises(JournalValueError):
            cal.seal("w")
        self.assertEqual(len(h.a.events), before)          # the committed rga_seal is gone
        self.assertNotIn("w", h.a.sealed)
        self.assertEqual(h.a.lines["w"].pc, "Open")
        self.assertEqual(cal.events, ())


class FindingF4UnregisteredPairCut(unittest.TestCase):
    """Kernel finding F4 (T14b): a violation refused by exactly two guards is
    invisible to single-deletion mutation. A sealed line with k+1 samples is
    reached only when _guard_seal_complete and _guard_sample_count are both
    deleted; the registry's JOINT table does not carry the pair."""

    def test_k_plus_one_samples_seal_only_with_both_guards_deleted(self):
        from test_rga_mutation import attempt, deleted

        def body():
            h = Harness(writes=K + 1); h.declare_tests(); h.fcd_open(); h.rga_open()
            for i in range(K):
                h.fcd_write(); h.sample(body=f"b{i}".encode()); h.trial(i=i)
            h.fcd_write(); h.sample(body=b"extra")
            h.replay_all(); h.fcd_check(); h.a.seal("w")
            return "w" in h.a.sealed and len(h.a.lines["w"].samples) > K

        self.assertFalse(attempt(body))
        for g in ("_guard_seal_complete", "_guard_sample_count"):
            with deleted([g]):
                self.assertFalse(attempt(body))
        with deleted(["_guard_seal_complete", "_guard_sample_count"]):
            self.assertTrue(attempt(body))

    def test_a_refuter_refused_before_open_seals_admissibly_only_with_both_guards_deleted(self):
        from test_rga_mutation import attempt, deleted

        def body():
            h = Harness(); h.declare_tests()
            h.fcd_open("x"); h.rga_open("x")
            h.fcd_write("x"); h.sample("x", b"x0"); h.trial("x")
            h.a.replay("x", 0, "refuted", "w-same")              # refuses `tests` before w opens
            h.fcd_open("w"); h.rga_open("w")
            for i in range(K):
                h.fcd_write("w"); h.sample("w", f"w{i}".encode()); h.trial("w", i)
            h.replay_all("w"); h.fcd_check("w"); h.a.seal("w")
            return "w" in h.a.sealed and TESTS in h.a.refused and h.a.admissible("w")

        self.assertFalse(attempt(body))
        for g in ("_guard_pinned_before_open", "_guard_not_refused"):
            with deleted([g]):
                self.assertFalse(attempt(body))
        with deleted(["_guard_pinned_before_open", "_guard_not_refused"]):
            self.assertTrue(attempt(body))                        # tainted needs refused_at >= sealed_at

    def test_one_registered_scenario_reddens_under_an_unrelated_deletion(self):
        from test_rga_mutation import GUARDS, deleted
        scenario = GUARDS["_guard_not_refused"][2]
        self.assertFalse(scenario())
        with deleted(["_check_replay"]):
            self.assertTrue(scenario())                           # non-specific predicate (N25)


class FindingF5InstallCoverageNotRecomputed(unittest.TestCase):
    """F5: cal_install carries coverage primaries that rebuild never recomputes;
    an escape before a later install deletes clean (the ratchet only eases)."""

    def test_escape_before_a_later_install_deletes_clean(self):
        from rga.core import AdmissionPolicy, ClassAdmission
        h = CalHarness(); h.declare_tests(); h.seal_line("w")
        run = h.tier_a_escape("w")
        h.a.declare(Refuter("tests", "v2", "tester", "ledger"))
        ids = [LedgerEntry(f"m{i}", "killed") for i in range(10)] + [LedgerEntry(h.cal.derived_defect_id(run), "killed")]
        h.a.measure("tests", "v2", DefectModel("d-succ", "mutator"), ids)
        succ = AdmissionPolicy({"impl": ClassAdmission(
            claims=(ClaimSpec("tests_pass", "spec-hash-1", frozenset({("tests", "v2")}), "d-succ"),),
            k=K, theta=1.0, p_min=0.5, excluded=frozenset({"refuter_source", "refuter_results"}),
            residual=(("correct fix", "check_stage"),))}, version="r2")
        h.cal.install(succ)                                        # ratchet: the corpus is covered
        self.assertEqual(h.cal.events[-1].get("coverage", {}).get("impl", {}).get("corpus_size"), 1)
        pruned = [e for e in h.cal.events if not (e.get("type") in ("cal_run", "cal_replay") and e.get("run_index") == 0)]
        fcd2 = Enforcer.from_events(list(h.e.events), fcd_policy())
        adm2 = Admission.from_events(list(h.a.events), fcd2, admission_policy(), succ)
        rebuilt = CalibrationAuthority.from_events(pruned, adm2, h.cal.policy)
        self.assertFalse(rebuilt.impeached("w"))                   # replays clean: install is not an anchor


class FindingF7CalOpenLeavesNoTrace(unittest.TestCase):
    """F7 (carry gate): CalOpen emits no event, so a line opened around the
    authority with a demoted pinned refuter is mediated, admissible, and
    replays clean. With gate=seal, CalSeal refuses it with E5 instead."""

    def test_bypassed_open_with_a_demoted_pin_is_admissible_under_carry(self):
        h = CalHarness(e_max=0, gate="carry"); h.declare_tests(); h.seal_line("w")
        h.tier_a_escape("w")
        self.assertTrue(h.cal.demoted("tests", "v1", "impl"))
        h.fcd_open("x")
        with self.assertRaises(ValueError):
            h.cal.open("x", "gen", "temp=0.7")                     # CalOpen refuses live
        h.a.open("x", "gen", "temp=0.7")                           # around the authority
        for i in range(h.k):
            h.fcd_write("x"); h.sample("x", f"x-{i}".encode()); h.trial("x", i)
        h.replay_all("x"); h.fcd_check("x"); h.cal.seal("x")
        self.assertTrue(h.cal.mediated("x") and h.cal.admissible("x"))
        self.assertTrue(rebuild(h).admissible("x"))


class FindingF11UnmediatedSealIsUnanchored(unittest.TestCase):
    """F11: only cal_stamp.sealed_at anchors the scrutiny journal's length; a
    refusal group before an unmediated (IR) seal deletes clean."""

    def test_refusal_group_before_an_ir_seal_deletes_clean(self):
        h = CalHarness(); h.declare_tests(); h.seal_line("w")
        h.fcd_open("z"); h.a.open("z", "gen", "temp=0.7")
        h.fcd_write("z"); h.sample("z", b"z0"); h.trial("z")
        h.a.replay("z", 0, "refuted", "w-same")                  # refusal group: taints w; closes z
        h.a.declare(Refuter("pbt", "v1", "prop-author", "ledger"))
        h.a.measure("pbt", "v1", DefectModel(D1, "mutator"), ledger(9, 10))   # later scrutiny events, no stamp
        surface = custody.deletion_surface(h.cal, "w")
        self.assertTrue(surface and all(e.exposed for e in surface))
        drop = {e.index for e in surface}
        pruned = [e for i, e in enumerate(h.a.events) if i not in drop]
        self.assertTrue(Admission.from_events(pruned, h.e, h.a.policy).admissible("w"))
        cert_w = custody.standing_certificate(h.cal, "w")
        self.assertEqual(custody.verify_certificate(h.cal, cert_w), [])


class FindingF6SortlessFloor(unittest.TestCase):
    """Kernel finding F6. bound() accepts (epsilon=1, N=1), so a declared figure of
    1.0 enters the cross-sort max and satisfies any p_min on a claim whose
    kernel-counted power is 0/|D|. The floor compares a projection that has
    forgotten its sort (the quantitative branch's T2')."""

    def test_a_declared_bounded_figure_satisfies_the_floor_over_a_zero_kill_ledger(self):
        BND = ("bnd", "v1")
        h = CalHarness(refuters=frozenset({TESTS, BND}), p_min=0.9)
        h.declare_tests(kills=0, size=10)
        h.a.declare(Refuter("bnd", "v1", "bnd-author", "bounded"))
        h.a.bound("bnd", "v1", 1.0, 1)
        h.fcd_open("w"); h.cal.open("w", "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write("w"); h.sample("w", f"w-{i}".encode())
            h.trial("w", i); h.trial("w", i, refuter=BND, witness="b-same")
        h.replay_all("w"); h.fcd_check("w")
        seal = h.cal.seal("w")
        c = seal.claims[0]
        self.assertEqual((c.composition, c.composite), ("max", 1.0))
        self.assertEqual(next(r.power for r in c.refuters if r.mode == "ledger"), 0.0)
        self.assertAlmostEqual(seal.power_min, 1.0)


class FindingF8EscapeAtThePublishedTrialPoint(unittest.TestCase):
    """Kernel finding F8. Sample nonces are journaled, and _guard_run_seed only
    requires the seed to be the kernel's derivation from the filed nonce, so a
    tier-A escape can be filed at exactly the seed of a trial that survived.
    It is accepted and established; the contradiction with the trial is not
    treated as a replay divergence of the refuter (R5 fires only through
    Admission.replay)."""

    def test_escape_at_a_surviving_trials_own_seed_is_accepted_and_established(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        s0 = h.a.lines["w"].samples[0]; t0 = h.a.lines["w"].trials[0]
        run = h.cal.file_escape("w", "tests_pass", "tests", "v1", s0.nonce, b"w-body-0", t0.seed, "kill", "finder")
        self.assertEqual(run.seed, t0.seed)
        h.cal.replay_run(run.index, "refuted", "kill")
        self.assertTrue(h.cal.impeached("w"))
        self.assertEqual(h.a.refused, set())


class PositionWitnessT12(unittest.TestCase):
    """T12(c): a recorded journal position is a root on replay, range-checked
    only, so the offline holder of a journal chooses it freely within the
    accepting range — the before-generation guard is position-witnessed."""

    def test_recorded_fcd_position_is_a_free_root_within_the_accepting_range(self):
        from rga.core import Admission
        h = CalHarness(); h.declare_tests(); h.seal_line()
        events = [dict(e) for e in h.a.events]
        opened = next(e for e in events if e["type"] == "rga_open")
        stage_positions = [i for i, e in enumerate(h.e.events)
                           if e.get("type") == "stage" and e.get("stage_id", "").startswith("w.")]
        self.assertLessEqual(opened["fcd_position"], min(stage_positions))   # honest: recorded before the stages
        opened["fcd_position"] = 0                                  # rewritten downward: accepted
        rebuilt = Admission.from_events(events, h.e, h.a.policy)
        self.assertIn("w", rebuilt.sealed)
        opened["fcd_position"] = max(stage_positions) + 1           # rewritten past the stages: refused
        with self.assertRaises(ValueError):
            Admission.from_events(events, h.e, h.a.policy)
        # The preimage-witnessed guard has no such freedom: a rewritten seed is refused.
        events = [dict(e) for e in h.a.events]
        trial = next(e for e in events if e["type"] == "rga_trial")
        trial["seed"] = "0" * 64
        with self.assertRaises(ValueError):
            Admission.from_events(events, h.e, h.a.policy)


if __name__ == "__main__":
    unittest.main()
