"""Contract: the package-separation guards are load-bearing, proved by sabotage.

``tests/architecture/test_distribution_separation``, ``tests/ready``,
``tests/trust`` and ``tests/compatibility`` assert that Ready and Trust are two
distributions that cannot reach each other.  Every one of those assertions is
written against a tree in which the separation already holds, and an assertion
that has never seen the property fail is an assertion nobody has shown to be
load-bearing.  A suite can pass because the guard works, or because the check
was looking somewhere else the whole time, and from a green run the two are
indistinguishable.

So this suite breaks the separation on purpose, one bounded way at a time, and
requires a *named* test to notice.  Twelve invariants, ``SEP1``--``SEP12``, are
registered in :mod:`tests.architecture.separation_guards` with the concrete
guard site each one lives at; every mutant names the single test that must go
red when it is applied, and a mutant no named test kills is reported as a
survivor rather than quietly counted.

Three properties make the result mean something:

*The live worktree is never mutated.*  Each mutant is applied to a complete
disposable copy of this checkout in a temporary directory, and the test process
runs there.  A harness that edits the tree it is being run from has to be right
about restoration on every path including a signal; a harness that edits a copy
has nothing to restore.  The last class in this file re-digests the tracked
tree anyway, because "never mutated" is a claim and not an assumption.

*A mutation that changed nothing is an error.*  The failure mode that makes a
mutation harness useless is a needle that no longer matches: the edit silently
does nothing, the suite passes for the reason it always did, and the run
reports a kill.  Every edit is verified to have moved bytes, and a needle that
occurs zero or twice is an error rather than a mutation.

*A kill has to be the guard's own assertion.*  Every mutant registers the
exception and the message fragments of the failure it is aimed at, and a run
that goes red some other way -- an import that broke, a fixture that raised, an
unrelated assertion -- is an error rather than a kill.  The rules that make
that distinction, and the probes that exercise each way of getting it wrong,
are in :mod:`tests.architecture.test_separation_harness`; this suite depends on
them and does not restate them.

*The control runs first.*  Before any sabotage, every named killing test is run
against a pristine clone and must pass.  Without that, a test that was already
red -- or that errors on any tree at all -- would read as a guard that works.
"""
from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

from . import separation_guards as guards

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The tracked tree as this module was imported, so the final class can prove
#: that running every mutant above left the checkout byte-for-byte unchanged.
_TREE_BEFORE = guards.worktree_digest(REPO_ROOT)


class SabotageCase(unittest.TestCase):
    """Shared machinery: run a registered invariant's mutants and report."""

    def assert_invariant_is_load_bearing(self, sep: str) -> None:
        """Every mutant registered for ``sep`` is killed by its named test."""

        mutants = guards.mutants_for(sep)
        self.assertTrue(mutants, f"{sep} has no registered mutant")
        for mutant in mutants:
            with self.subTest(mutant=mutant.mutant_id):
                receipt = guards.evaluate(mutant, root=REPO_ROOT)
                self.assertEqual(guards.KILLED, receipt.verdict, receipt.detail)


class TheGuardRegistryIsCompleteAndStable(unittest.TestCase):
    """The registry is a manifest, not a list that grew: it is checked."""

    def test_the_twelve_invariants_are_registered_under_stable_ids(self):
        self.assertEqual(
            tuple(f"SEP{number}" for number in range(1, 13)),
            guards.SEP_IDS)
        self.assertEqual(set(guards.SEP_IDS), set(guards.INVARIANTS))

    def test_every_invariant_states_one_property_in_words(self):
        for sep in guards.SEP_IDS:
            with self.subTest(sep=sep):
                statement = guards.INVARIANTS[sep]
                self.assertIsInstance(statement, str)
                self.assertGreater(len(statement.strip()), 30, statement)

    def test_mutant_identifiers_are_unique(self):
        identifiers = [mutant.mutant_id for mutant in guards.MUTANTS]
        self.assertEqual(sorted(set(identifiers)), sorted(identifiers),
                         "a duplicate mutant id makes one receipt overwrite "
                         "another, and a survivor can hide behind a kill")

    def test_every_mutant_names_a_registered_invariant(self):
        for mutant in guards.MUTANTS:
            with self.subTest(mutant=mutant.mutant_id):
                self.assertIn(mutant.sep, guards.INVARIANTS)
                self.assertTrue(mutant.mutant_id.startswith(f"{mutant.sep}-"),
                                "a mutant id must carry its own invariant")

    def test_every_invariant_has_at_least_one_mutant(self):
        for sep in guards.SEP_IDS:
            with self.subTest(sep=sep):
                self.assertTrue(guards.mutants_for(sep),
                                f"{sep} is asserted by nothing that can fail")

    def test_every_required_sabotage_shape_has_a_mutant(self):
        covered = {mutant.shape for mutant in guards.MUTANTS}
        self.assertEqual([], sorted(set(guards.REQUIRED_SHAPES) - covered))

    def test_every_mutant_shape_is_one_of_the_declared_shapes(self):
        for mutant in guards.MUTANTS:
            with self.subTest(mutant=mutant.mutant_id):
                self.assertIn(mutant.shape, guards.DECLARED_SHAPES)

    def test_every_mutant_names_a_test_method_that_exists(self):
        for mutant in guards.MUTANTS:
            with self.subTest(mutant=mutant.mutant_id):
                self.assertTrue(
                    guards.test_exists(REPO_ROOT, mutant.kills),
                    f"{mutant.kills} is not a test method in this tree")

    def test_every_declared_control_names_a_test_method_that_exists(self):
        for mutant in guards.MUTANTS:
            if mutant.control is None:
                continue
            with self.subTest(mutant=mutant.mutant_id):
                self.assertTrue(
                    guards.test_exists(REPO_ROOT, mutant.control),
                    f"{mutant.control} is not a test method in this tree")

    def test_every_mutant_registers_the_failure_it_expects(self):
        """A row with no signature is a row that would accept any red run."""
        for mutant in guards.MUTANTS:
            with self.subTest(mutant=mutant.mutant_id):
                self.assertIsInstance(mutant.expects, guards.GuardFailure)
                self.assertTrue(mutant.expects.contains)

    def test_every_registered_signature_is_specific_and_unique(self):
        self.assertEqual([], list(guards.signature_problems()))

    def test_no_mutant_kills_itself_with_its_own_control(self):
        for mutant in guards.MUTANTS:
            with self.subTest(mutant=mutant.mutant_id):
                self.assertNotEqual(mutant.kills, mutant.control)

    def test_every_mutant_edit_addresses_exactly_one_site(self):
        """A needle that matches zero or twice is an error, not a mutation."""
        for mutant in guards.MUTANTS:
            with self.subTest(mutant=mutant.mutant_id):
                guards.check_edits(REPO_ROOT, mutant.edits)

    def test_no_edit_escapes_the_repository(self):
        for mutant in guards.MUTANTS:
            for edit in mutant.edits:
                with self.subTest(mutant=mutant.mutant_id, path=edit.path):
                    self.assertFalse(Path(edit.path).is_absolute())
                    self.assertNotIn("..", Path(edit.path).parts)


class TheHarnessCannotLieAboutAKill(unittest.TestCase):
    """The reporting paths that would otherwise turn a defect into a pass."""

    def test_a_needle_that_is_absent_is_an_error(self):
        with self.assertRaises(guards.MutationError):
            guards.check_edits(REPO_ROOT, (guards.Substitution(
                "README.md", "a needle that is not in this file", "x"),))

    def test_a_needle_that_occurs_more_than_once_is_an_error(self):
        with self.assertRaises(guards.MutationError):
            guards.check_edits(REPO_ROOT, (guards.Substitution(
                "README.md", "the", "x"),))

    def test_a_substitution_that_changes_no_byte_is_an_error(self):
        with self.assertRaises(guards.MutationError):
            guards.check_edits(REPO_ROOT, (guards.Substitution(
                "scripts/sabotage_admissible.py", "RESIDUE_MARKERS = (",
                "RESIDUE_MARKERS = ("),))

    def test_a_creation_over_a_file_that_exists_is_an_error(self):
        with self.assertRaises(guards.MutationError):
            guards.check_edits(REPO_ROOT, (guards.Creation(
                "README.md", "not this one"),))

    def test_a_mutant_no_test_notices_is_reported_as_a_survivor(self):
        """The property that makes every kill below mean something."""
        receipt = guards.evaluate(guards.HARMLESS_MUTANT, root=REPO_ROOT)
        self.assertEqual(guards.SURVIVED, receipt.verdict, receipt.detail)

    def test_the_child_environment_carries_no_dangerous_variable(self):
        environment = guards.scrubbed_environment()
        for name in guards.SCRUBBED_EXAMPLES:
            with self.subTest(variable=name):
                self.assertNotIn(name, environment)
        self.assertEqual("1", environment.get("PIP_NO_INDEX"))
        self.assertEqual("0", environment.get("GIT_TERMINAL_PROMPT"))

    def test_the_child_environment_is_built_rather_than_inherited(self):
        """The stronger claim the list above only samples."""
        environment = guards.scrubbed_environment()
        self.assertEqual(
            [],
            sorted(set(environment) - set(guards.FORCED_ENVIRONMENT_NAMES)
                   - set(guards.INHERITED_NAMES)))
        self.assertNotEqual(os.environ.get("HOME"), environment["HOME"])
        self.assertEqual("1", environment["GIT_CONFIG_NOSYSTEM"])

    def test_a_mutant_is_only_ever_run_behind_a_verified_boundary(self):
        """No boundary, no run: an unenforced isolation is never claimed."""
        self.assertEqual("", guards.network_denial_problem(),
                         "this platform cannot deny a mutant the network, so "
                         "the harness must refuse rather than pretend")


class TheCloneIsCompleteAndDisposable(unittest.TestCase):
    """A mutant runs against a copy of this checkout, never against it."""

    def test_a_clone_carries_every_source_file_this_checkout_has(self):
        with guards.disposable_clone(REPO_ROOT) as clone:
            self.assertEqual(guards.worktree_digest(REPO_ROOT),
                             guards.worktree_digest(clone))

    def test_the_source_list_is_exactly_what_git_reports(self):
        """The walk and Git must agree, or "complete copy" means nothing."""
        listed = subprocess.run(
            ("git", "ls-files", "-z", "--cached", "--others",
             "--exclude-standard"),
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
            check=True).stdout
        self.assertEqual(sorted(path for path in listed.split("\0") if path),
                         sorted(guards.source_files(REPO_ROOT)))

    def test_a_clone_carries_no_link_back_to_the_live_repository(self):
        """The clone gets a repository of its own, not a pointer to this one."""
        with guards.disposable_clone(REPO_ROOT) as clone:
            git_dir = clone / ".git"
            self.assertTrue(git_dir.is_dir())
            self.assertFalse(git_dir.is_symlink())
            for command, expected in ((("remote",), ""),
                                      (("rev-list", "--all", "--count"), "0")):
                with self.subTest(command=command):
                    answer = subprocess.run(
                        ("git", "-C", str(clone), *command),
                        capture_output=True, text=True, timeout=120,
                        env=guards.scrubbed_environment(), check=True)
                    self.assertEqual(expected, answer.stdout.strip())
            self.assertEqual([], [
                path for path in guards.source_files(clone)
                if path.split("/")[0] == ".git"])

    def test_a_mutated_clone_leaves_the_live_worktree_untouched(self):
        before = guards.worktree_digest(REPO_ROOT)
        with guards.disposable_clone(REPO_ROOT) as clone:
            guards.apply_edits(clone, guards.HARMLESS_MUTANT.edits)
            self.assertNotEqual(before, guards.worktree_digest(clone))
        self.assertEqual(before, guards.worktree_digest(REPO_ROOT))


class TheUnmutatedCandidatePasses(unittest.TestCase):
    """The control: every named killing test is green before any sabotage.

    Without this, a test that is red on any tree -- or that errors before it
    reaches its assertion -- would be indistinguishable from a guard that
    caught the sabotage, and every kill below would be worthless.
    """

    def test_every_named_killing_test_passes_before_any_mutation(self):
        receipt = guards.control_receipt(REPO_ROOT)
        self.assertEqual(guards.PASSED, receipt.verdict, receipt.detail)


class EveryRegisteredSabotageIsKilled(SabotageCase):
    """One test per invariant, so a survivor names the boundary that moved."""

    def test_sep1_the_ready_wheel_carries_no_trust_surface(self):
        self.assert_invariant_is_load_bearing("SEP1")

    def test_sep2_the_trust_wheel_carries_no_execution_surface(self):
        self.assert_invariant_is_load_bearing("SEP2")

    def test_sep3_ready_reaches_core_and_never_trust(self):
        self.assert_invariant_is_load_bearing("SEP3")

    def test_sep4_trust_reaches_core_and_never_ready(self):
        self.assert_invariant_is_load_bearing("SEP4")

    def test_sep5_every_ready_entry_refuses_beside_a_credential(self):
        self.assert_invariant_is_load_bearing("SEP5")

    def test_sep6_trust_has_no_reachable_candidate_executor(self):
        self.assert_invariant_is_load_bearing("SEP6")

    def test_sep7_passing_ready_checks_cannot_emit_an_admission(self):
        self.assert_invariant_is_load_bearing("SEP7")

    def test_sep8_authenticated_ready_needs_a_verified_current_receipt(self):
        self.assert_invariant_is_load_bearing("SEP8")

    def test_sep9_the_umbrella_is_not_a_trusted_deployment_artifact(self):
        self.assert_invariant_is_load_bearing("SEP9")

    def test_sep10_every_shared_schema_has_one_core_owner(self):
        self.assert_invariant_is_load_bearing("SEP10")

    def test_sep11_legacy_dispatch_never_crosses_or_guesses_a_domain(self):
        self.assert_invariant_is_load_bearing("SEP11")

    def test_sep12_removing_a_guard_kills_one_named_test_and_no_control(self):
        self.assert_invariant_is_load_bearing("SEP12")


class TheLiveWorktreeSurvivedThisSuite(unittest.TestCase):
    """Byte identity, checked rather than assumed, after every mutant above."""

    def test_the_tracked_tree_is_byte_identical_to_the_pre_run_capture(self):
        self.assertEqual(_TREE_BEFORE, guards.worktree_digest(REPO_ROOT))

    def test_no_clone_workspace_is_left_behind(self):
        self.assertEqual([], guards.orphaned_workspaces())


if __name__ == "__main__":  # pragma: no cover - convenience only
    unittest.main()
