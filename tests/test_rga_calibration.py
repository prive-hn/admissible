"""Executable checks of C1–C7 and E1–E9 on the calibration machine
(paper/RGA/INVARIANTS.md §8), plus per-guard deletion proofs in the
test_rga_mutation.py discipline: every guard and check method of
CalibrationAuthority (and its stamp effect) has a scenario that is
unreachable with the method intact and reached with it deleted.
"""
from __future__ import annotations

import copy
import os
import sys
import unittest
from contextlib import ExitStack
from unittest.mock import patch

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

from rga.calibration import CalibrationAuthority, CalibrationClass, CalibrationPolicy, Run  # noqa: E402
from rga.core import AdmissionPolicy, ClaimSpec, ClassAdmission, DefectModel, LedgerEntry, Refuter, derive_seed, sha256  # noqa: E402
from test_rga_invariants import D1, K, TESTS, Harness, admission_policy, ledger  # noqa: E402


class CalHarness(Harness):
    """RGA harness plus a calibration authority wrapping open/seal."""

    def __init__(self, *, e_max=2, gate="seal", **kw):
        super().__init__(**kw)
        self.cal = CalibrationAuthority(
            self.a, CalibrationPolicy({"impl": CalibrationClass(e_max=e_max, demotion_gate=gate)}))

    def seal_line(self, iid="w", bodies=None):
        bodies = bodies or [f"{iid}-body-{i}".encode() for i in range(self.k)]
        self.fcd_open(iid)
        self.cal.open(iid, "gen", "temp=0.7")
        for i in range(self.k):
            self.fcd_write(iid)
            self.sample(iid, bodies[i])
            self.trial(iid, i)
        self.replay_all(iid)
        self.fcd_check(iid)
        return self.cal.seal(iid)

    def tier_a_escape(self, iid="w", nonce="esc-1", witness="kill-w", replay=True):
        seal = self.a.sealed[iid]
        seed = derive_seed(nonce, seal.artifact_hash, "tests", "v1", "tests_pass")
        run = self.cal.file_escape(iid, "tests_pass", "tests", "v1", nonce,
                                   f"{iid}-body-0".encode(), seed, witness, finder="auditor")
        if replay:
            self.cal.replay_run(run.index, "refuted", witness)
        return run


class C1EstablishedNeverAsserted(unittest.TestCase):
    def test_tier_a_escape_impeaches_only_after_identical_replay(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        run = h.tier_a_escape(replay=False)
        self.assertEqual(run.tier, "A")
        self.assertFalse(h.cal.impeached("w"))           # filed is not established
        h.cal.replay_run(run.index, "refuted", "kill-w")
        self.assertTrue(h.cal.impeached("w"))
        self.assertFalse(h.cal.admissible("w"))
        self.assertIn("w", h.a.sealed)                   # the seal is never rewritten
        with self.assertRaises(ValueError):
            h.cal.check_dependencies(["w"], floor=0.0)

    def test_filing_is_single_holder(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        seal = h.a.sealed["w"]
        seed = derive_seed("n", seal.artifact_hash, "tests", "v1", "tests_pass")
        with self.assertRaises(ValueError) as ctx:
            h.cal.file_escape("w", "tests_pass", "tests", "v1", "n", b"other-bytes", seed, "x", "aud")
        self.assertIn("hash", str(ctx.exception))

    def test_tier_a_seed_is_the_kernels_derivation(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        with self.assertRaises(ValueError):
            h.cal.file_escape("w", "tests_pass", "tests", "v1", "n", b"w-body-0", "bogus-seed", "x", "aud")

    def test_filing_requires_seal_claim_and_declared_checker(self):
        h = CalHarness(); h.declare_tests()
        with self.assertRaises(ValueError):
            h.cal.file_escape("w", "tests_pass", "tests", "v1", "n", b"b", "s", "x", "aud")
        h.seal_line()
        with self.assertRaises(ValueError):
            h.cal.file_escape("w", "no_such_claim", "tests", "v1", "n", b"w-body-0", "s", "x", "aud")
        with self.assertRaises(ValueError):
            h.cal.file_escape("w", "tests_pass", "ghost", "v9", "n", b"w-body-0", "s", "x", "aud")

    def test_divergent_replay_discredits_monotonically(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        first = h.tier_a_escape(nonce="e1")             # established, impeaches
        second = h.tier_a_escape(nonce="e2", replay=False)
        h.cal.replay_run(second.index, "refuted", "other-witness")   # diverges
        self.assertIn(TESTS, h.cal.discredited)
        self.assertFalse(h.cal.impeached("w"))          # first escape's validity degrades too
        self.assertFalse(first.established and h.cal._check_valid(first))
        with self.assertRaises(ValueError):
            h.tier_a_escape(nonce="e3")                 # discredited checker cannot file

    def test_admission_refusal_degrades_escape_validity(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.tier_a_escape()
        self.assertTrue(h.cal.impeached("w"))
        # a trial replay divergence in the Admission registry refuses the refuter
        h.fcd_open("z"); h.a.open("z", "gen", "temp=0.7")
        h.fcd_write("z"); h.sample("z", b"z0"); h.trial("z")
        h.a.replay("z", 0, "refuted", "w-same")
        self.assertIn(TESTS, h.a.refused)
        self.assertFalse(h.cal.impeached("w"))          # its kills are no longer evidence
        self.assertTrue(h.a.tainted("w"))               # but the seal is tainted instead


class C2ChargeTotalityAndUnit(unittest.TestCase):
    def test_one_charge_per_cell_however_many_witnesses(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.tier_a_escape(nonce="e1", witness="k1")
        h.tier_a_escape(nonce="e2", witness="k2")
        self.assertEqual(h.cal.charges("tests", "v1", "impl"), 1)
        h.seal_line("x")
        h.tier_a_escape("x", nonce="e3")
        self.assertEqual(h.cal.charges("tests", "v1", "impl"), 2)

    def test_charges_are_read_not_declared(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        self.assertEqual(h.cal.charge_cells("impl"), frozenset())
        h.tier_a_escape()
        self.assertEqual(h.cal.charge_cells("impl"),
                         frozenset({("w", "tests_pass", "tests", "v1")}))


class TierBAdjudication(unittest.TestCase):
    def _hawk_escape(self, h, iid="w", replay=True):
        h.a.declare(Refuter("hawk", "v1", "hawk-author", "ledger"))
        seal = h.a.sealed[iid]
        run = h.cal.file_escape(iid, "tests_pass", "hawk", "v1", "n1",
                                f"{iid}-body-0".encode(), "any-seed", "hk", "aud")
        self.assertEqual(run.tier, "B")
        if replay:
            h.cal.replay_run(run.index, "refuted", "hk")
        return run

    def test_tier_b_has_no_effect_until_adjudicated(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        run = self._hawk_escape(h)
        self.assertFalse(h.cal.impeached("w"))
        h.cal.adjudicate(run.index, "owner", "accept", "reproduced by hand")
        self.assertTrue(h.cal.impeached("w"))

    def test_adjudication_guards(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        a_run = h.tier_a_escape()
        with self.assertRaises(ValueError):
            h.cal.adjudicate(a_run.index, "owner", "accept", "r")     # tier A needs none
        b_run = self._hawk_escape(h, replay=False)
        with self.assertRaises(ValueError):
            h.cal.adjudicate(b_run.index, "owner", "accept", "r")     # not established
        h.cal.replay_run(b_run.index, "refuted", "hk")
        with self.assertRaises(ValueError):
            h.cal.adjudicate(b_run.index, "", "accept", "r")          # unnamed actor
        h.cal.adjudicate(b_run.index, "owner", "reject", "not the claim")
        self.assertFalse(h.cal._check_valid(b_run))                    # rejected: no effect
        with self.assertRaises(ValueError):
            h.cal.adjudicate(b_run.index, "owner", "accept", "r")     # decided once


class C4Ratchet(unittest.TestCase):
    def _successor(self, refuters, d_hash, version="r2", claims=None):
        claims = claims or (ClaimSpec("tests_pass", "spec-hash-1", frozenset(refuters), d_hash),)
        return AdmissionPolicy({"impl": ClassAdmission(
            claims=claims, k=K, theta=1.0, p_min=0.5,
            excluded=frozenset({"refuter_source", "refuter_results"}),
            residual=(("correct fix", "check_stage"),))}, version=version)

    def test_install_refuses_a_model_that_forgets_a_valid_escape(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        run = h.tier_a_escape()
        with self.assertRaises(ValueError) as ctx:
            h.cal.install(self._successor({TESTS}, D1))
        self.assertIn(h.cal.derived_defect_id(run), str(ctx.exception))

    def test_install_passes_when_the_successor_covers_the_corpus(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        run = h.tier_a_escape()
        h.a.declare(Refuter("tests", "v2", "tester", "ledger"))
        entries = ledger(9, 10) + [LedgerEntry(h.cal.derived_defect_id(run), "killed")]
        h.a.measure("tests", "v2", DefectModel("d2-hash", "mutator"), entries)
        h.cal.install(self._successor({("tests", "v2")}, "d2-hash"))
        ev = [e for e in h.cal.events if e["type"] == "cal_install"][-1]
        self.assertEqual(ev["coverage"]["impl"],
                         {"corpus_size": 1, "excluded": 0, "models": {"tests_pass": "d2-hash"}})
        self.assertEqual(ev["dropped_classes"], [])

    def test_exclusion_is_the_named_exit(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        run = h.tier_a_escape()
        with self.assertRaises(ValueError):
            h.cal.exclude("impl", [run.index], "", "no actor")
        with self.assertRaises(ValueError):
            h.cal.exclude("impl", [999], "owner", "unknown escape")
        h.cal.exclude("impl", [run.index], "owner", "class retired; defect unexpressible")
        h.cal.install(self._successor({TESTS}, D1))     # coverage obligation released
        ev = [e for e in h.cal.events if e["type"] == "cal_exclude"][-1]
        self.assertEqual((ev["corpus_size"], ev["excluded_total"]), (1, 1))

    def test_install_requires_measured_models_and_no_bounded_only_claims(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.tier_a_escape()
        h.a.declare(Refuter("tests", "v3", "tester", "ledger"))
        with self.assertRaises(ValueError) as ctx:
            h.cal.install(self._successor({("tests", "v3")}, "never-measured"))
        self.assertIn("no Measure record", str(ctx.exception))
        h.a.declare(Refuter("pbt", "v1", "tester", "bounded"))
        h.a.bound("pbt", "v1", 0.1, 20)
        with self.assertRaises(ValueError) as ctx:
            h.cal.install(self._successor({("pbt", "v1")}, D1, version="r3"))
        self.assertIn("bounded-only", str(ctx.exception))


class C5TrackRecordCarried(unittest.TestCase):
    def test_stamp_in_the_same_step_as_the_seal(self):
        h = CalHarness(); h.declare_tests()
        h.seal_line()
        stamp = h.cal.sealed_stamp("w")
        self.assertIsNotNone(stamp)
        rec = stamp["track_records"]["tests@v1"]
        self.assertEqual(rec["charged_cells"], 0)
        self.assertEqual(rec["seals_participated"], 1)

    def test_primaries_after_an_escape(self):
        h = CalHarness(e_max=5, gate="carry"); h.declare_tests(); h.seal_line()
        h.tier_a_escape()
        h.seal_line("x")
        rec = h.cal.sealed_stamp("x")["track_records"]["tests@v1"]
        self.assertEqual((rec["charged_cells"], rec["seals_participated"], rec["corpus_size"]),
                         (1, 2, 1))


class C6Demotion(unittest.TestCase):
    def test_demotion_blocks_new_pins_at_open(self):
        h = CalHarness(e_max=0); h.declare_tests(); h.seal_line()
        h.tier_a_escape()                                # 1 charge > e_max=0
        self.assertTrue(h.cal.demoted("tests", "v1", "impl"))
        h.fcd_open("y")
        with self.assertRaises(ValueError) as ctx:
            h.cal.open("y", "gen", "temp=0.7")
        self.assertIn("demoted", str(ctx.exception))

    def test_seal_gate_closes_published_with_primaries(self):
        h = CalHarness(e_max=0, gate="seal"); h.declare_tests(); h.seal_line()
        # open a second line before the demotion crossing
        h.fcd_open("x"); h.cal.open("x", "gen", "temp=0.7")
        for i in range(K):
            h.fcd_write("x"); h.sample("x", f"x-body-{i}".encode()); h.trial("x", i)
        h.replay_all("x"); h.fcd_check("x")
        h.tier_a_escape()                                # crossing: charges=1 > 0
        with self.assertRaises(ValueError):
            h.cal.seal("x")
        self.assertEqual(h.a.lines["x"].pc, "Closed")    # closed at its own Seal attempt
        self.assertNotIn("x", h.a.sealed)
        close = [e for e in h.cal.events if e["type"] == "cal_close"][-1]
        self.assertEqual((close["fault"], close["refuter_id"]), ("E5", "tests"))
        self.assertEqual(close["primaries"]["charged_cells"], 1)

    def test_carry_class_seals_an_in_flight_line_with_the_charge_on_the_stamp(self):
        h = CalHarness(e_max=0, gate="carry"); h.declare_tests(); h.seal_line()
        # a line already open at the crossing: the pin predates demotion
        h.fcd_open("x"); h.cal.open("x", "gen", "temp=0.7")
        for i in range(K):
            h.fcd_write("x"); h.sample("x", f"x-body-{i}".encode()); h.trial("x", i)
        h.replay_all("x"); h.fcd_check("x")
        h.tier_a_escape()                                # crossing while x is open
        h.cal.seal("x")                                  # carry: seals, record carried
        self.assertIn("x", h.a.sealed)
        self.assertEqual(h.cal.sealed_stamp("x")["track_records"]["tests@v1"]["charged_cells"], 1)
        # new pins stay blocked regardless of the gate bit
        h.fcd_open("y")
        with self.assertRaises(ValueError):
            h.cal.open("y", "gen", "temp=0.7")

    def test_demotion_never_touches_existing_seals(self):
        h = CalHarness(e_max=0); h.declare_tests(); h.seal_line()
        h.tier_a_escape()
        self.assertIn("w", h.a.sealed)
        self.assertEqual(h.a.lines["w"].pc, "Sealed")


class AuditsAndSuspect(unittest.TestCase):
    def test_null_audit_is_journalable_and_junk_checkers_are_refused(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        seal = h.a.sealed["w"]
        seed = derive_seed("a1", seal.artifact_hash, "tests", "v1", "tests_pass")
        run = h.cal.file_audit("w", "tests_pass", "tests", "v1", "a1",
                               b"w-body-0", seed, "ok-w", "auditor")
        h.cal.replay_run(run.index, "survived", "ok-w")
        self.assertEqual(len(h.cal.audit_exposure("w")), 1)
        h.a.declare(Refuter("junk", "v1", "someone", "ledger"))
        with self.assertRaises(ValueError) as ctx:
            h.cal.file_audit("w", "tests_pass", "junk", "v1", "a2", b"w-body-0", "s", "j", "x")
        self.assertIn("neither pinned", str(ctx.exception))

    def test_suspect_folds_over_direct_dependencies(self):
        h = CalHarness(e_max=5); h.declare_tests(); h.seal_line()
        h.fcd_open("b")                                  # would fail: w accepted, use depends_on
        # rebuild: open b depending on w (w is in fcd store)
        h.e.open("b2", "impl", "b2-body", depends_on=("w",))
        self.assertFalse(h.cal.suspect("b2"))
        h.tier_a_escape()
        self.assertTrue(h.cal.suspect("b2"))


class C7NonInterference(unittest.TestCase):
    def test_ledger_transitions_write_no_admission_or_fcd_field(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()

        def snap():
            return (copy.deepcopy(h.e.items), set(h.e.store), list(h.e.events),
                    dict(h.a.sealed), set(h.a.refused), dict(h.a.power),
                    len(h.a.events), copy.deepcopy(h.a.lines))

        before = snap()
        run = h.tier_a_escape(replay=False)
        h.cal.replay_run(run.index, "refuted", "kill-w")
        h.a.declare(Refuter("hawk", "v1", "hawk-author", "ledger"))
        mid = snap()
        b = h.cal.file_escape("w", "tests_pass", "hawk", "v1", "n", b"w-body-0", "s", "hk", "aud")
        h.cal.replay_run(b.index, "refuted", "hk")
        h.cal.adjudicate(b.index, "owner", "reject", "not the claim")
        h.cal.exclude("impl", [run.index], "owner", "retired")
        _ = h.cal.impeached("w"), h.cal.charges("tests", "v1", "impl"), h.cal.suspect("w")
        self.assertEqual(snap()[0:6], mid[0:6])
        self.assertEqual(snap()[6], mid[6])              # not even an Admission event
        self.assertEqual(before[0], mid[0])              # FCD untouched throughout


class ReplayTests(unittest.TestCase):
    def _rebuild(self, h: CalHarness):
        from fcd.core import Enforcer
        from rga.core import Admission
        from test_rga_invariants import fcd_policy
        fcd2 = Enforcer.from_events(list(h.e.events), fcd_policy())
        adm2 = Admission.from_events(list(h.a.events), fcd2, admission_policy())
        return CalibrationAuthority.from_events(list(h.cal.events), adm2, h.cal.policy)

    def test_from_events_rebuilds_the_ledger(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        run = h.tier_a_escape()
        h.cal.exclude("impl", [run.index], "owner", "retired")
        rebuilt = self._rebuild(h)
        self.assertEqual(len(rebuilt.runs), 1)
        self.assertTrue(rebuilt.runs[0].established)
        self.assertEqual(rebuilt.exclusions["impl"], {0})
        self.assertEqual(rebuilt.events, h.cal.events)
        self.assertTrue(rebuilt.impeached("w"))          # excluded from coverage, still impeaching

    def test_from_events_refuses_a_tampered_run_hash(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.tier_a_escape()
        journal = [dict(e) for e in h.cal.events]
        for ev in journal:
            if ev["type"] == "cal_run":
                ev["artifact_hash"] = sha256(b"other")
        from fcd.core import Enforcer
        from rga.core import Admission
        from test_rga_invariants import fcd_policy
        fcd2 = Enforcer.from_events(list(h.e.events), fcd_policy())
        adm2 = Admission.from_events(list(h.a.events), fcd2, admission_policy())
        with self.assertRaises(ValueError):
            CalibrationAuthority.from_events(journal, adm2, h.cal.policy)

    def test_policy_validation(self):
        with self.assertRaises(ValueError):
            CalibrationPolicy({"impl": CalibrationClass(e_max=-1, demotion_gate="seal")})
        with self.assertRaises(ValueError):
            CalibrationPolicy({"impl": CalibrationClass(e_max=1, demotion_gate="maybe")})


# -- delete the guard; prove it goes red ------------------------------------------


def noop(*args, **kwargs):
    return None


def always_true(*args, **kwargs):
    return True


def never_diverges(*args, **kwargs):
    return False


def attempt(fn):
    try:
        return bool(fn())
    except (ValueError, AssertionError, AttributeError, TypeError, KeyError):
        return False


def s_guard_run_verdict():
    def body():
        h = CalHarness(); h.declare_tests(); h.seal_line()
        seal = h.a.sealed["w"]
        seed = derive_seed("n", seal.artifact_hash, "tests", "v1", "tests_pass")
        h.cal.file_escape("w", "tests_pass", "tests", "v1", "n", b"w-body-0", seed, "x", "a",
                          verdict="survived")
        return h.cal.runs[0].verdict == "survived"       # an escape that never refuted
    return attempt(body)


def s_guard_run_checker():
    def body():
        h = CalHarness(); h.declare_tests(); h.seal_line()
        seal = h.a.sealed["w"]
        seed = derive_seed("n", seal.artifact_hash, "ghost", "v9", "tests_pass")
        h.cal.file_escape("w", "tests_pass", "ghost", "v9", "n", b"w-body-0", seed, "x", "a")
        return h.cal.runs[0].checker == ("ghost", "v9")
    return attempt(body)


def s_guard_run_bytes():
    def body():
        h = CalHarness(); h.declare_tests(); h.seal_line()
        seal = h.a.sealed["w"]
        # seed derived correctly over the SEAL's hash, so only the bytes guard stands
        seed = derive_seed("n", seal.artifact_hash, "tests", "v1", "tests_pass")
        h.cal.file_escape("w", "tests_pass", "tests", "v1", "n", b"other", seed, "x", "a")
        return h.cal.runs[0].artifact_hash != seal.artifact_hash
    return attempt(body)


def s_guard_run_seed():
    def body():
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.cal.file_escape("w", "tests_pass", "tests", "v1", "n", b"w-body-0", "bogus", "x", "a")
        return h.cal.runs[0].seed == "bogus"
    return attempt(body)


def s_guard_replay_verdict():
    def body():
        from rga.calibration import RUN_VERDICTS
        h = CalHarness(); h.declare_tests(); h.seal_line("w")
        r = h.tier_a_escape(replay=False)
        h.cal.replay_run(r.index, "maybe", "kill-w")   # out-of-enum verdict
        return any(e["type"] == "cal_replay" and e["verdict"] not in RUN_VERDICTS
                   for e in h.cal.events)
    return attempt(body)


def s_guard_class_configured():
    def body():
        h = CalHarness(); h.declare_tests()
        h.fcd_open("w")
        h.cal.policy = CalibrationPolicy({})     # the class loses its budget
        h.cal.open("w", "gen", "temp=0.7")       # must refuse; without the guard it opens
        return "w" in h.a.lines
    return attempt(body)


def s_guard_audit_checker():
    def body():
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.a.declare(Refuter("junk", "v1", "someone", "ledger"))
        r = h.cal.file_audit("w", "tests_pass", "junk", "v1", "n", b"w-body-0", "s", "j", "x")
        h.cal.replay_run(r.index, "survived", "j")
        return len(h.cal.audit_exposure("w")) == 1       # junk exposure counted
    return attempt(body)


def s_check_run_replay():
    def body():
        h = CalHarness(); h.declare_tests(); h.seal_line()
        r = h.tier_a_escape(replay=False)
        h.cal.replay_run(r.index, "refuted", "different-witness")   # diverges
        return r.established and h.cal.impeached("w")
    return attempt(body)


def s_check_valid():
    def body():
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.tier_a_escape(replay=False)                    # never established
        return h.cal.impeached("w")
    return attempt(body)


def s_guard_adjudication():
    def body():
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.a.declare(Refuter("hawk", "v1", "hawk-author", "ledger"))
        r = h.cal.file_escape("w", "tests_pass", "hawk", "v1", "n", b"w-body-0", "s", "hk", "a")
        h.cal.replay_run(r.index, "refuted", "hk")
        h.cal.adjudicate(r.index, "", "accept", "")      # unnamed, unreasoned
        return r.adjudication == "accept"
    return attempt(body)


def s_guard_exclusion():
    def body():
        h = CalHarness(); h.declare_tests(); h.seal_line()
        r = h.tier_a_escape()
        h.cal.exclude("impl", [r.index], "", "")         # unnamed, unreasoned
        return r.index in h.cal.exclusions.get("impl", set())
    return attempt(body)


def s_guard_install_measured():
    def body():
        h = CalHarness(); h.declare_tests(); h.seal_line()   # empty corpus: covers no-ops
        h.a.declare(Refuter("tests", "v3", "tester", "ledger"))
        pol = AdmissionPolicy({"impl": ClassAdmission(
            claims=(ClaimSpec("tests_pass", "s", frozenset({("tests", "v3")}), "never-measured"),),
            k=K, theta=1.0, p_min=0.5)}, version="r9")
        h.cal.install(pol)
        return "r9" in h.a._policies
    return attempt(body)


def s_guard_install_covers():
    def body():
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.tier_a_escape()
        h.a.declare(Refuter("tests", "v2", "tester", "ledger"))
        h.a.measure("tests", "v2", DefectModel("d2-hash", "mutator"), ledger(9, 10))  # no corpus id
        pol = AdmissionPolicy({"impl": ClassAdmission(
            claims=(ClaimSpec("tests_pass", "s", frozenset({("tests", "v2")}), "d2-hash"),),
            k=K, theta=1.0, p_min=0.5)}, version="r9")
        h.cal.install(pol)
        return "r9" in h.a._policies
    return attempt(body)


def s_guard_install_bounded():
    def body():
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.tier_a_escape()
        h.a.declare(Refuter("pbt", "v1", "tester", "bounded"))
        h.a.bound("pbt", "v1", 0.1, 20)
        pol = AdmissionPolicy({"impl": ClassAdmission(
            claims=(ClaimSpec("tests_pass", "s", frozenset({("pbt", "v1")}), D1),),
            k=K, theta=1.0, p_min=0.5)}, version="r9")
        h.cal.install(pol)
        return "r9" in h.a._policies
    return attempt(body)


def s_guard_open_demoted():
    def body():
        h = CalHarness(e_max=0); h.declare_tests(); h.seal_line()
        h.tier_a_escape()
        h.fcd_open("y")
        h.cal.open("y", "gen", "temp=0.7")
        return "y" in h.a.lines
    return attempt(body)


def s_check_seal_demotion():
    def body():
        h = CalHarness(e_max=0, gate="seal"); h.declare_tests(); h.seal_line()
        h.fcd_open("x"); h.cal.open("x", "gen", "temp=0.7")
        for i in range(K):
            h.fcd_write("x"); h.sample("x", f"x-body-{i}".encode()); h.trial("x", i)
        h.replay_all("x"); h.fcd_check("x")
        h.tier_a_escape()
        h.cal.seal("x")
        return "x" in h.a.sealed and h.cal.demoted("tests", "v1", "impl")
    return attempt(body)


def s_stamp():
    def body():
        h = CalHarness(); h.declare_tests()
        h.seal_line()
        return "w" in h.a.sealed and h.cal.sealed_stamp("w") is None
    return attempt(body)


GUARDS: dict[str, tuple[str, object, object]] = {
    "_guard_run_verdict":     ("E6", noop, s_guard_run_verdict),
    "_guard_run_checker":     ("E1", noop, s_guard_run_checker),
    "_guard_run_bytes":       ("E6", noop, s_guard_run_bytes),
    "_guard_run_seed":        ("E6", noop, s_guard_run_seed),
    "_guard_audit_checker":   ("E1", noop, s_guard_audit_checker),
    "_guard_class_configured": ("E9", noop, s_guard_class_configured),
    "_guard_replay_verdict":  ("E1", noop, s_guard_replay_verdict),
    "_check_run_replay":      ("E1", never_diverges, s_check_run_replay),
    "_check_valid":           ("E1", always_true, s_check_valid),
    "_guard_adjudication":    ("E7", noop, s_guard_adjudication),
    "_guard_exclusion":       ("E7", noop, s_guard_exclusion),
    "_guard_install_measured": ("E4", noop, s_guard_install_measured),
    "_guard_install_covers":  ("E4", noop, s_guard_install_covers),
    "_guard_install_bounded": ("E4", noop, s_guard_install_bounded),
    "_guard_open_demoted":    ("C6", noop, s_guard_open_demoted),
    "_check_seal_demotion":   ("E5", noop, s_check_seal_demotion),
    "_stamp":                 ("C5", noop, s_stamp),
}


def deleted(names):
    stack = ExitStack()
    for name in names:
        stack.enter_context(patch.object(CalibrationAuthority, name, GUARDS[name][1]))
    return stack


class GuardDeletionTests(unittest.TestCase):
    def _one(self, name: str) -> None:
        fault, _, scenario = GUARDS[name]
        self.assertFalse(scenario(), f"{fault}/{name}: forbidden state reachable with the guard intact")
        with deleted([name]):
            self.assertTrue(scenario(), f"{fault}/{name}: deleting the guard did not go red")


for _name in GUARDS:
    setattr(GuardDeletionTests, f"test_{GUARDS[_name][0].lower()}_{_name.strip('_')}",
            (lambda n: lambda self: self._one(n))(_name))


class EveryGuardIsLoadBearing(unittest.TestCase):
    def test_every_guard_method_has_a_scenario(self):
        methods = {n for n in dir(CalibrationAuthority)
                   if n.startswith("_guard_") or n.startswith("_check_")}
        self.assertEqual(methods - set(GUARDS), set(), "guards no scenario turns red")
        self.assertEqual(set(GUARDS) - methods - {"_stamp"}, set(), "scenarios naming no guard")

    def test_every_fault_family_has_a_scenario(self):
        covered = {fault for fault, _, _ in GUARDS.values()}
        self.assertTrue({"E1", "E4", "E5", "E6", "E7", "E9", "C5", "C6"} <= covered)




class ExactHeadReviewRepairs(unittest.TestCase):
    """The PR review's two P1 findings, each reproduced before it was fixed.

    Both were real: a seal that never passed through the calibration
    authority answered admissible() with True, so a consumer could not tell
    an IRC seal from an RGA-only one; and a class with no calibration policy
    behaved as an unlimited one — charges accrued, nothing ever demoted."""

    # -- P1: CalSeal mediation (C5 totality) ---------------------------------

    def _rga_only_seal(self, h, iid="w"):
        """Drive a line to a seal WITHOUT the calibration authority."""
        h.fcd_open(iid)
        h.cal.open(iid, "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write(iid)
            h.sample(iid, f"{iid}-body-{i}".encode())
            h.trial(iid, i)
        h.replay_all(iid)
        h.fcd_check(iid)
        return h.a.seal(iid)                      # bypasses CalibrationAuthority.seal

    def test_a_seal_that_bypassed_calibration_is_not_admissible(self):
        h = CalHarness(); h.declare_tests()
        self._rga_only_seal(h)
        self.assertTrue(h.a.is_sealed("w"))       # layer R sealed it
        self.assertIsNone(h.cal.sealed_stamp("w"))
        self.assertFalse(h.cal.mediated("w"))     # layer C never saw it
        self.assertFalse(h.cal.admissible("w"))   # so it is IR, not IRC

    def test_an_unmediated_dependency_is_refused(self):
        h = CalHarness(); h.declare_tests()
        self._rga_only_seal(h)
        with self.assertRaises(ValueError) as caught:
            h.cal.check_dependencies(["w"], 0.0)
        self.assertIn("not mediated", str(caught.exception))

    def test_a_deleted_stamp_lowers_standing_and_never_raises_it(self):
        """Deletion cannot be detected — an unstamped seal is indistinguishable
        from a line the authority never mediated — but it must fail closed:
        the line degrades to IR, it does not keep its standing."""
        h = CalHarness(); h.declare_tests(); h.seal_line("w")
        self.assertTrue(h.cal.admissible("w"))
        kept = [e for e in h.cal.events if e["type"] != "cal_stamp"]
        rebuilt = CalibrationAuthority.from_events(kept, h.a, h.cal.policy)
        self.assertFalse(rebuilt.mediated("w"))
        self.assertFalse(rebuilt.admissible("w"))

    def test_a_duplicate_stamp_is_refused_at_replay(self):
        h = CalHarness(); h.declare_tests(); h.seal_line("w")
        stamp = next(e for e in h.cal.events if e["type"] == "cal_stamp")
        with self.assertRaises(ValueError):
            CalibrationAuthority.from_events(list(h.cal.events) + [dict(stamp)], h.a, h.cal.policy)

    def test_a_stamp_bound_to_no_seal_is_refused_at_replay(self):
        h = CalHarness(); h.declare_tests(); h.seal_line("w")
        forged = [dict(e, sealed_at=e["sealed_at"] + 99) if e["type"] == "cal_stamp" else e
                  for e in h.cal.events]
        with self.assertRaises(ValueError):
            CalibrationAuthority.from_events(forged, h.a, h.cal.policy)

    def test_an_honest_journal_with_two_seals_replays(self):
        """Found while pinning the tamper boundary: every stamp recomputed
        its 'seals participated' against the FINAL rebuilt Admission, so any
        honest journal with more than one seal was refused on rebuild — the
        one thing replay must never do."""
        h = CalHarness(); h.declare_tests()
        h.seal_line("w"); h.seal_line("x")
        rebuilt = CalibrationAuthority.from_events(list(h.cal.events), h.a, h.cal.policy)
        self.assertTrue(rebuilt.mediated("w"))
        self.assertTrue(rebuilt.mediated("x"))
        self.assertEqual(len(rebuilt.events), len(h.cal.events))

    def test_replay_refuses_alteration_but_truncation_is_not_detectable(self):
        """The exact boundary of replay's tamper-evidence, executable.

        Altering, forging, duplicating or removing an event that a later
        event recomputes against is refused. Removing the TAIL is not: a
        shorter history is self-consistent, and truncation is the one tamper
        that RAISES standing — a dropped escape un-impeaches its line. No
        journal-internal check can catch it; that needs an anchor outside
        the journal (append-only storage or a signed head), which this
        kernel does not implement and the papers therefore do not claim."""
        h = CalHarness(); h.declare_tests(); h.seal_line("w"); h.seal_line("x")
        h.tier_a_escape("w", nonce="n1", witness="kill-w")
        h.tier_a_escape("x", nonce="n2", witness="kill-x")
        self.assertTrue(h.cal.impeached("w"))

        # middle deletion: later events no longer recompute -> refused
        middle = [e for e in h.cal.events
                  if not (e["type"] == "cal_run" and e.get("line_id") == "w")]
        with self.assertRaises(ValueError):
            CalibrationAuthority.from_events(middle, h.a, h.cal.policy)

        # tail truncation: accepted, and the impeachment is gone
        head = list(h.cal.events)
        while head and head[-1]["type"] in ("cal_run", "cal_replay"):
            head.pop()
        rebuilt = CalibrationAuthority.from_events(head, h.a, h.cal.policy)
        self.assertFalse(rebuilt.impeached("x"))
        self.assertTrue(rebuilt.admissible("x"))
        self.assertTrue(h.cal.impeached("w"))          # the earlier one still stands

    # -- P1: explicit calibration class, no implicit unlimited policy --------

    def test_a_class_with_no_calibration_policy_cannot_open(self):
        h = Harness()
        cal = CalibrationAuthority(h.a, CalibrationPolicy(
            {"impl": CalibrationClass(e_max=1, demotion_gate="seal")}))
        h.declare_tests()
        h.fcd_open("w")
        cal.policy = CalibrationPolicy({})        # the class loses its config
        with self.assertRaises(ValueError) as caught:
            cal.open("w", "gen", "temp=0.7")
        self.assertIn("no calibration policy", str(caught.exception))

    def test_a_class_with_no_calibration_policy_cannot_seal(self):
        h = CalHarness(); h.declare_tests()
        h.fcd_open("w"); h.cal.open("w", "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write("w"); h.sample("w", f"w-body-{i}".encode()); h.trial("w", i)
        h.replay_all("w"); h.fcd_check("w")
        h.cal.policy = CalibrationPolicy({})
        with self.assertRaises(ValueError):
            h.cal.seal("w")
        self.assertFalse(h.a.is_sealed("w"))      # nothing sealed behind the refusal

    def test_demoted_refuses_to_answer_for_an_unconfigured_class(self):
        """A budget nobody declared is not a budget of infinity."""
        h = CalHarness(); h.declare_tests()
        with self.assertRaises(ValueError):
            h.cal.demoted("tests", "v1", "no-such-class")

    def test_construction_requires_a_class_for_every_admission_class(self):
        h = Harness(); h.declare_tests()
        with self.assertRaises(ValueError) as caught:
            CalibrationAuthority(h.a, CalibrationPolicy({}))
        self.assertIn("no calibration policy", str(caught.exception))

    def test_install_refuses_a_successor_class_with_no_calibration_config(self):
        h = CalHarness(); h.declare_tests()
        successor = admission_policy(version="r2")
        successor.classes["new_lane"] = successor.classes["impl"]
        with self.assertRaises(ValueError) as caught:
            h.cal.install(successor)
        self.assertIn("no calibration policy", str(caught.exception))
        self.assertEqual(h.a.policy.version, "r1")     # neither policy moved

    def test_install_evolves_both_policies_atomically(self):
        h = CalHarness(); h.declare_tests()
        successor = admission_policy(version="r2")
        successor.classes["new_lane"] = successor.classes["impl"]
        h.cal.install(successor, cal_policy=CalibrationPolicy(
            {"impl": CalibrationClass(e_max=2, demotion_gate="seal"),
             "new_lane": CalibrationClass(e_max=0, demotion_gate="carry")}, version="c2"))
        self.assertEqual(h.a.policy.version, "r2")
        self.assertEqual(sorted(h.cal.policy.classes), ["impl", "new_lane"])


class RoundTwoReviewRepairs(unittest.TestCase):
    """The second adversarial round. Every one of these was a journal the
    live machine produced that replay refused, or a standing a forger could
    manufacture — both directions of the property replay exists to provide."""

    def test_a_refusal_after_a_stamp_does_not_break_that_stamp(self):
        """`_check_valid` read the FINAL refused set, so a refuter refused
        after a stamp was written made the stamp un-recomputable and the
        honest journal unreplayable."""
        h = CalHarness(e_max=5, gate="carry"); h.declare_tests()
        h.seal_line("w"); h.tier_a_escape("w")
        h.seal_line("x")
        h.fcd_open("z"); h.a.open("z", "gen", "temp=0.7")
        h.fcd_write("z"); h.sample("z", b"z0"); h.trial("z")
        h.a.replay("z", 0, "refuted", "diverges")        # refuses the checker, after both stamps
        rebuilt = CalibrationAuthority.from_events(list(h.cal.events), h.a, h.cal.policy)
        self.assertTrue(rebuilt.mediated("w"))
        self.assertTrue(rebuilt.mediated("x"))

    def test_an_e5_close_replays_after_a_later_refusal(self):
        h = CalHarness(e_max=0, gate="seal"); h.declare_tests(); h.seal_line("w")
        # opened before the crossing: CalOpen blocks a demoted pin (C6), so
        # the E5 gate is reached only by a line already in flight
        h.fcd_open("y"); h.cal.open("y", "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write("y"); h.sample("y", f"y-body-{i}".encode()); h.trial("y", i)
        h.replay_all("y"); h.fcd_check("y")
        h.tier_a_escape("w")                              # crosses the budget
        with self.assertRaises(ValueError):
            h.cal.seal("y")                               # E5 close, journaled
        close = [e for e in h.cal.events if e["type"] == "cal_close"][-1]
        self.assertIn("as_of", close)                     # the position it read the demotion at
        rebuilt = CalibrationAuthority.from_events(list(h.cal.events), h.a, h.cal.policy)
        self.assertEqual(len(rebuilt.events), len(h.cal.events))

    def test_an_exclusion_replays_after_a_later_refusal(self):
        """Every event whose replay guard reads Admission state now carries
        the position it was written at. Without it, an ordinary post-seal
        audit divergence made an already-journaled exclusion unreplayable."""
        h = CalHarness(e_max=5, gate="carry"); h.declare_tests(); h.seal_line("w")
        r = h.tier_a_escape("w")
        h.cal.exclude("impl", [r.index], "owner", "retired")
        h.fcd_open("z"); h.a.open("z", "gen", "temp=0.7")
        h.fcd_write("z"); h.sample("z", b"z0"); h.trial("z")
        h.a.replay("z", 0, "refuted", "diverges")
        rebuilt = CalibrationAuthority.from_events(list(h.cal.events), h.a, h.cal.policy)
        self.assertEqual(len(rebuilt.events), len(h.cal.events))

    def test_a_stamp_forged_for_an_earlier_seal_is_refused(self):
        """Appending a stamp is how an unmediated seal would buy IRC. One
        forged for any but the most recent seal breaks stamp order."""
        h = CalHarness(); h.declare_tests(); h.seal_line("w"); h.seal_line("x")
        h.fcd_open("z"); h.cal.open("z", "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write("z"); h.sample("z", f"z-body-{i}".encode()); h.trial("z", i)
        h.replay_all("z"); h.fcd_check("z")
        h.a.seal("z")                                     # bypass: no stamp
        seal_w = h.a.sealed["w"]
        forged = list(h.cal.events) + [dict(
            type="cal_stamp", line_id="w", sealed_at=seal_w.sealed_at,
            track_records={}, corpus_provenance={}, ts=0.0)]
        with self.assertRaises(ValueError) as caught:
            CalibrationAuthority.from_events(forged, h.a, h.cal.policy)
        self.assertIn("stamp", str(caught.exception))

    def test_the_budgets_are_in_the_journal_and_replay_checks_them(self):
        """demoted() gates CalOpen and CalSeal, so a budget the record does
        not carry is a gate nobody can audit — and a replay handed a
        different budget would silently answer differently."""
        h = CalHarness(e_max=0, gate="seal"); h.declare_tests()
        h.cal.install(admission_policy(version="r2"))
        ev = [e for e in h.cal.events if e["type"] == "cal_install"][-1]
        self.assertEqual(ev["budgets"], {"impl": {"e_max": 0, "demotion_gate": "seal"}})
        self.assertEqual(ev["calibration_policy_version"], h.cal.policy.version)
        # Replay ADOPTS the journaled budget, so a caller who supplies a
        # different one cannot make the rebuild answer a different question:
        # before this, the rebuilt authority silently ran under whatever
        # policy it was handed.
        wrong = CalibrationPolicy({"impl": CalibrationClass(e_max=99, demotion_gate="carry")})
        rebuilt = CalibrationAuthority.from_events(list(h.cal.events), h.a, wrong)
        self.assertEqual(rebuilt.policy.classes["impl"].e_max, 0)
        self.assertEqual(rebuilt.policy.classes["impl"].demotion_gate, "seal")
        self.assertEqual(rebuilt.policy.version, h.cal.policy.version)

    def test_rebuild_ends_on_the_policy_live_execution_ended_on(self):
        """Re-opening each line under its pinned version left the rebuilt
        machine on the LAST line's pin, so the class-coverage check measured
        against the wrong policy and refused honest journals."""
        h = CalHarness(); h.declare_tests(); h.seal_line("w")
        h.cal.install(admission_policy(version="r2"))
        h.fcd_open("x"); h.cal.open("x", "gen", "temp=0.7")
        from rga.core import Admission
        rebuilt = Admission.from_events(list(h.a.events), h.e,
                                        admission_policy(version="r1"),
                                        admission_policy(version="r2"))
        self.assertEqual(rebuilt.policy.version, "r2")


class CalibrationRound1Repairs(unittest.TestCase):
    """The review's confirmed defects, each as a red-first trace."""

    def _rebuild_journal(self, h: CalHarness, journal):
        from fcd.core import Enforcer
        from rga.core import Admission
        from test_rga_invariants import fcd_policy
        fcd2 = Enforcer.from_events(list(h.e.events), fcd_policy())
        adm2 = Admission.from_events(list(h.a.events), fcd2, admission_policy())
        return CalibrationAuthority.from_events(journal, adm2, h.cal.policy)

    def test_replay_refuses_a_tampered_tier(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.a.declare(Refuter("hawk", "v1", "hawk-author", "ledger"))
        r = h.cal.file_escape("w", "tests_pass", "hawk", "v1", "n", b"w-body-0", "s", "hk", "aud")
        h.cal.replay_run(r.index, "refuted", "hk")       # established tier B, unadjudicated
        self.assertFalse(h.cal.impeached("w"))
        journal = [dict(e) for e in h.cal.events]
        for ev in journal:
            if ev["type"] == "cal_run":
                ev["tier"] = "A"                          # forge automatic effect
        with self.assertRaises(ValueError) as ctx:
            self._rebuild_journal(h, journal)
        self.assertIn("tier", str(ctx.exception))

    def test_replay_refuses_a_deleted_discredit(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        r = h.tier_a_escape(replay=False)
        h.cal.replay_run(r.index, "refuted", "other-w")  # diverges -> discredit event
        journal = [dict(e) for e in h.cal.events if e["type"] != "cal_discredit"]
        with self.assertRaises(ValueError) as ctx:
            self._rebuild_journal(h, journal)
        self.assertIn("discredit", str(ctx.exception))

    def test_replay_refuses_a_forged_actorless_exclusion(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        r = h.tier_a_escape()
        journal = [dict(e) for e in h.cal.events]
        journal.append({"type": "cal_exclude", "class": "impl", "run_indices": [r.index],
                        "actor": "", "reason": "", "corpus_size": 1, "excluded_total": 1, "ts": 0.0})
        with self.assertRaises(ValueError) as ctx:
            self._rebuild_journal(h, journal)
        self.assertIn("actor", str(ctx.exception))

    def test_replay_refuses_a_tampered_seed(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.tier_a_escape()
        journal = [dict(e) for e in h.cal.events]
        for ev in journal:
            if ev["type"] == "cal_run":
                ev["seed"] = "forged"
        with self.assertRaises(ValueError):
            self._rebuild_journal(h, journal)

    def test_install_refuses_dropping_a_class_that_owes_coverage(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        r = h.tier_a_escape()
        other = AdmissionPolicy({"other_cls": ClassAdmission(
            claims=(ClaimSpec("c", "s", frozenset({TESTS}), D1),), k=1, theta=1.0, p_min=0.0)},
            version="r5")
        # The successor names its own class budget (E9); what is under test
        # here is the ratchet, not the coverage guard.
        other_cal = CalibrationPolicy(
            {"other_cls": CalibrationClass(e_max=2, demotion_gate="seal")}, version="c2")
        with self.assertRaises(ValueError) as ctx:
            h.cal.install(other, cal_policy=other_cal)    # 'impl' vanishes with a live corpus
        self.assertIn("cannot be dropped", str(ctx.exception))
        h.cal.exclude("impl", [r.index], "owner", "class retired")
        h.cal.install(other, cal_policy=other_cal)        # named exit releases it
        ev = [e for e in h.cal.events if e["type"] == "cal_install"][-1]
        self.assertEqual(ev["dropped_classes"], ["impl"])

    def test_seal_of_a_sealed_line_raises_without_a_spurious_close(self):
        h = CalHarness(e_max=0, gate="seal"); h.declare_tests(); h.seal_line()
        h.tier_a_escape()                                 # demotion crossing after sealing
        before = [e for e in h.cal.events if e["type"] == "cal_close"]
        with self.assertRaises(ValueError):
            h.cal.seal("w")                               # already Sealed
        after = [e for e in h.cal.events if e["type"] == "cal_close"]
        self.assertEqual(before, after)                   # no journaled step that never happened
        self.assertEqual(h.a.lines["w"].pc, "Sealed")

    def test_stamp_carries_the_corpus_provenance_split(self):
        h = CalHarness(e_max=5, gate="carry"); h.declare_tests(); h.seal_line()
        seal = h.a.sealed["w"]
        seed = derive_seed("g1", seal.artifact_hash, "tests", "v1", "tests_pass")
        r = h.cal.file_escape("w", "tests_pass", "tests", "v1", "g1", b"w-body-0", seed,
                              "kg", finder="gen")         # found by the generator itself
        h.cal.replay_run(r.index, "refuted", "kg")
        h.seal_line("x")
        prov = h.cal.sealed_stamp("x")["corpus_provenance"]
        self.assertEqual(prov, {"finder_is_generator": 1, "independent": 0})


if __name__ == "__main__":
    unittest.main()
