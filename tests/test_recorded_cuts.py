"""The leftover reviewer findings: recorded cuts, integer N, cal_open roots,
and a declared floor not called measured.
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
from rga.calibration import CalibrationAuthority  # noqa: E402
from rga.core import (  # noqa: E402
    AdmissionPolicy, ClaimSpec, ClassAdmission, DefectModel, LedgerEntry, Refuter,
)
from rga.recorded_cut import RecordedCut  # noqa: E402
from server.seal_sentence import FloorSentence  # noqa: E402
from test_rga_calibration import CalHarness  # noqa: E402
from test_rga_invariants import D1, K, LINT, TESTS, Harness, ledger  # noqa: E402


def _forgetful_successor(h):
    if ("tests", "v2") not in h.a.refuters:
        h.a.declare(Refuter("tests", "v2", "tester", "ledger"))
        h.a.measure("tests", "v2", DefectModel("d-succ", "mutator"),
                    [LedgerEntry(f"m{i}", "killed") for i in range(10)])
    return AdmissionPolicy({"impl": ClassAdmission(
        claims=(ClaimSpec("tests_pass", "spec-hash-1", frozenset({("tests", "v2")}), "d-succ"),),
        k=K, theta=1.0, p_min=0.5,
        excluded=frozenset({"refuter_source", "refuter_results"}),
        residual=(("correct fix", "check_stage"),))}, version="r2")


def _backdate(events, typ):
    forged = [dict(e) for e in events]
    at = next(i for i, e in enumerate(forged) if e["type"] == typ)
    prior = [e["as_of"] for e in forged[:at] if e.get("type") in RecordedCut.TYPES]
    forged[at]["as_of"] = (min(prior) if prior else 1) - 1
    return forged


class BoundNIsAnInteger(unittest.TestCase):
    def test_bound_refuses_a_fractional_n(self):
        h = Harness()
        h.a.declare(Refuter("bnd", "v1", "bnd-author", "bounded"))
        with self.assertRaises(ValueError) as caught:
            h.a.bound("bnd", "v1", 0.2, 2.5)
        self.assertIn("integer", str(caught.exception))

    def test_bound_refuses_bool_n(self):
        h = Harness()
        h.a.declare(Refuter("bnd", "v1", "bnd-author", "bounded"))
        with self.assertRaises(ValueError) as caught:
            h.a.bound("bnd", "v1", 0.2, True)
        self.assertIn("integer", str(caught.exception))


class RecordedCutsSpanEventTypes(unittest.TestCase):
    def test_an_honest_exclude_and_install_replay(self):
        h = CalHarness(e_max=5, gate="carry")
        h.declare_tests()
        h.seal_line("w")
        run = h.tier_a_escape("w")
        h.cal.exclude("impl", [run.index], "owner", "class retired")
        h.cal.install(_forgetful_successor(h))
        rebuilt = CalibrationAuthority.from_events(list(h.cal.events), h.a, h.cal.policy)
        self.assertEqual(len(rebuilt.exclusions.get("impl", set())), 1)
        self.assertEqual(rebuilt.adm.policy.version, "r2")

    def test_a_backdated_exclude_is_refused(self):
        h = CalHarness(e_max=5, gate="carry")
        h.declare_tests()
        h.seal_line("w")
        run = h.tier_a_escape("w")
        h.cal.exclude("impl", [run.index], "owner", "class retired")
        with self.assertRaises(ValueError) as caught:
            CalibrationAuthority.from_events(_backdate(h.cal.events, "cal_exclude"),
                                             h.a, h.cal.policy)
        self.assertIn("backwards", str(caught.exception))

    def test_a_backdated_install_is_refused(self):
        h = CalHarness(e_max=5, gate="carry")
        h.declare_tests()
        h.seal_line("w")
        run = h.tier_a_escape("w")
        h.cal.exclude("impl", [run.index], "owner", "class retired")
        h.cal.install(_forgetful_successor(h))
        with self.assertRaises(ValueError) as caught:
            CalibrationAuthority.from_events(_backdate(h.cal.events, "cal_install"),
                                             h.a, h.cal.policy)
        self.assertIn("backwards", str(caught.exception))

    def test_a_backdated_close_is_refused(self):
        h = CalHarness(e_max=0, gate="seal")
        h.declare_tests()
        h.seal_line("w")
        h.fcd_open("x")
        h.cal.open("x", "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write("x")
            h.sample("x", f"x-{i}".encode())
            h.trial("x", i)
        h.replay_all("x")
        h.fcd_check("x")
        h.tier_a_escape("w")
        with self.assertRaises(ValueError):
            h.cal.seal("x")
        self.assertTrue(any(e["type"] == "cal_close" for e in h.cal.events))
        with self.assertRaises(ValueError) as caught:
            CalibrationAuthority.from_events(_backdate(h.cal.events, "cal_close"),
                                             h.a, h.cal.policy)
        self.assertIn("backwards", str(caught.exception))

    def test_a_non_integer_exclude_cut_is_refused(self):
        h = CalHarness(e_max=5, gate="carry")
        h.declare_tests()
        h.seal_line("w")
        run = h.tier_a_escape("w")
        h.cal.exclude("impl", [run.index], "owner", "class retired")
        forged = [dict(e) for e in h.cal.events]
        at = next(i for i, e in enumerate(forged) if e["type"] == "cal_exclude")
        forged[at]["as_of"] = 2.5
        with self.assertRaises(ValueError) as caught:
            CalibrationAuthority.from_events(forged, h.a, h.cal.policy)
        self.assertIn("integer", str(caught.exception))


class CalOpenIsANecessityRoot(unittest.TestCase):
    def test_the_open_is_among_the_necessity_roots(self):
        h = CalHarness()
        h.declare_tests()
        h.seal_line()
        types = [r[2]["type"] for r in custody._necessity_events(h.cal, "w")]
        self.assertIn("cal_open", types)
        self.assertIn("cal_stamp", types)

    def test_refitting_away_the_open_moves_the_roots_hash(self):
        h = CalHarness()
        h.declare_tests()
        h.seal_line()
        cert = custody.standing_certificate(h.cal, "w")
        pruned = [dict(e) for e in h.cal.events if e["type"] != "cal_open"]
        for idx, ev in enumerate(pruned):
            if ev["type"] != "cal_stamp":
                continue
            prefix = CalibrationAuthority.from_events(pruned[:idx], h.a, h.cal.policy)
            seal = h.a.sealed[ev["line_id"]]
            ev["track_records"] = {
                f"{r.id}@{r.version}": prefix.track_record(
                    r.id, r.version, seal.cls, as_of_seal=seal.sealed_at)
                for c in seal.claims for r in c.refuters}
            ev["corpus_provenance"] = prefix._corpus_provenance(seal.cls, seal.generator)
        rebuilt = CalibrationAuthority.from_events(pruned, h.a, h.cal.policy)
        self.assertFalse(rebuilt.mediated("w"))
        self.assertNotEqual(
            custody.standing_certificate(rebuilt, "w").roots_hash, cert.roots_hash)

    def test_a_tail_appended_open_after_a_stamp_is_refused(self):
        h = CalHarness()
        h.declare_tests()
        h.seal_line("w")
        h.fcd_open("x")
        h.a.open("x", "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write("x")
            h.sample("x", f"x-{i}".encode())
            h.trial("x", i)
        h.replay_all("x")
        h.fcd_check("x")
        h.cal.seal("x")
        self.assertFalse(h.cal.mediated("x"))
        forged = list(h.cal.events) + [dict(type="cal_open", line_id="x",
                                            **{"class": "impl"}, generator="gen", ts=0.0)]
        with self.assertRaises(ValueError) as caught:
            CalibrationAuthority.from_events(forged, h.a, h.cal.policy)
        self.assertIn("stamp", str(caught.exception))

    def test_an_open_inserted_before_a_later_demotion_is_refused(self):
        h = CalHarness(e_max=0, gate="carry")
        h.declare_tests()
        h.seal_line("w")
        h.tier_a_escape("w")
        h.fcd_open("x")
        h.a.open("x", "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write("x")
            h.sample("x", f"x-{i}".encode())
            h.trial("x", i)
        h.replay_all("x")
        h.fcd_check("x")
        h.cal.seal("x")
        self.assertFalse(h.cal.mediated("x"))
        forged = [dict(e) for e in h.cal.events]
        at = next(i for i, e in enumerate(forged) if e["type"] == "cal_run")
        forged.insert(at, dict(type="cal_open", line_id="x", **{"class": "impl"},
                               generator="gen", ts=0.0))
        for ev in forged[at + 1:]:
            if ev["type"] != "cal_stamp":
                continue
            ev["track_records"] = {
                k: {**dict(rec), "as_of": rec["as_of"] + 1}
                for k, rec in ev["track_records"].items()
            }
        with self.assertRaises(ValueError) as caught:
            CalibrationAuthority.from_events(forged, h.a, h.cal.policy)
        self.assertIn("demoted", str(caught.exception))


class FloorSentenceReadsTheWitness(unittest.TestCase):
    def test_a_ledger_floor_is_called_measured(self):
        h = Harness()
        h.declare_tests()
        h.run_to_seal_ready()
        text = FloorSentence().render(h.a.seal("w"))
        self.assertIn("at measured power", text)

    def test_a_bounded_only_floor_is_called_declared(self):
        bnd = ("bnd", "v1")
        claims = (ClaimSpec("tests_pass", "spec-1", frozenset({bnd}), D1),)
        h = Harness(claims=claims, refuters=frozenset({bnd}), p_min=0.5)
        h.a.declare(Refuter("bnd", "v1", "bnd-author", "bounded"))
        h.a.bound("bnd", "v1", 0.2, 10)
        h.fcd_open()
        h.rga_open()
        for i in range(h.k):
            h.fcd_write()
            h.sample(body=f"b{i}".encode())
            h.trial(i=i, refuter=bnd, witness="b-same")
        h.replay_all()
        h.fcd_check()
        text = FloorSentence().render(h.a.seal("w"))
        self.assertIn("at declared power", text)
        self.assertNotIn("at measured power", text)

    def test_the_sentence_names_the_claim_that_realized_power_min(self):
        claims = (ClaimSpec("tests_pass", "spec-1", frozenset({TESTS}), D1),
                  ClaimSpec("lint_clean", "spec-2", frozenset({LINT}), "d2-hash"))
        h = Harness(claims=claims)
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        h.a.declare(Refuter("lint", "v1", "linter", "ledger"))
        h.a.measure("tests", "v1", DefectModel(D1, "mutator"), ledger(9, 10))
        h.a.measure("lint", "v1", DefectModel("d2-hash", "mutator"), ledger(6, 10))
        h.fcd_open()
        h.rga_open()
        for i in range(h.k):
            h.fcd_write()
            h.sample(body=f"b{i}".encode())
            h.trial(i=i, refuter=TESTS, claim="tests_pass")
            h.trial(i=i, refuter=LINT, claim="lint_clean", witness="lint-w")
        h.replay_all()
        h.fcd_check()
        seal = h.a.seal("w")
        text = FloorSentence().render(seal)
        self.assertIn("0.6", text)
        self.assertIn("lint@v1:6/10", text)
        self.assertNotIn("tests@v1:9/10", text)

    def test_seal_joint_reads_floor_basis_not_the_cross_sort_max(self):
        bnd = ("bnd", "v1")
        claims = (ClaimSpec("tests_pass", "spec-1", frozenset({TESTS, bnd}), D1),)
        h = Harness(claims=claims, refuters=frozenset({TESTS, bnd}), p_min=0.5)
        h.declare_tests(kills=6, size=10)
        h.a.declare(Refuter("bnd", "v1", "bnd-author", "bounded"))
        h.a.bound("bnd", "v1", 0.2, 10)
        h.fcd_open()
        h.rga_open()
        for i in range(h.k):
            h.fcd_write()
            h.sample(body=f"b{i}".encode())
            h.trial(i=i, refuter=TESTS)
            h.trial(i=i, refuter=bnd, witness="b-same")
        h.replay_all()
        h.fcd_check()
        seal = h.a.seal("w")
        self.assertLessEqual(custody.seal_joint(seal), seal.power_min + 1e-12)
