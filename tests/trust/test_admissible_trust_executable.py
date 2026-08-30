"""Contract: the ``git`` Trust runs is the system's, never the candidate's.

The boundary suite proves that Trust starts exactly one kind of process and
that its argument vector is fixed.  That is only half of what "one fixed
command" means.  An argument vector beginning with the bare word ``git`` names
a *program to look for*, and the looking is done with ``PATH`` -- a string the
ambient environment supplies and, in the one workflow this distribution exists
for, a string the candidate's own tooling has usually just edited.  A repository
that ships ``./bin/git`` and prepends its own directory would have Trust
execute it, inside the process holding the admission key, with that key in the
child's environment.  Nothing else in the product would have noticed: the argv
would still be six fixed queries, the environment would still be stripped of
every ``GIT_*`` variable, and the receipt would still be issued -- by a program
the candidate wrote.

So the adapter resolves an absolute executable from a closed system search
path before it starts anything, validates it as a real regular executable that
only root or this user can write, and passes that absolute path as ``argv[0]``.
Four claims are asserted here:

* **resolution** -- the executable comes from
  :data:`admissible_trust.git_reader.TRUSTED_SEARCH_DIRECTORIES` and from
  nowhere else.  ``PATH`` is not consulted, and there is no constructor
  argument, CLI option or configuration field that could supply one;
* **the fake is never reached** -- a program named ``git`` is planted at the
  front of ``PATH`` and inside the candidate repository itself, with every
  Admissible credential exported beside it.  It records its environment and
  claims the keys when it runs.  Every ``GitReader`` query and a whole
  finalization are then driven, and the recording never happens; the argv
  receipts show one validated absolute executable and no other;
* **an untrustworthy executable is refused before any spawn** -- a symlink, a
  world-writable file, a group-writable file, a non-executable file and a
  group-writable parent directory are each planted as the only candidate, and
  each is refused with ``subprocess`` armed to fail the test if it is touched;
* **the control** -- the same fixtures, unmutated, resolve and answer all six
  of the kernel's questions against a real repository, so none of the refusals
  above is a test that would pass by refusing everything.

The poison is proved to be poison: one test executes the bare word ``git``
under the fixture environment and requires the fake to run, so that every
assertion that it did *not* run is a statement about the adapter rather than
about a fixture that never worked.
"""
from __future__ import annotations

import ast
import inspect as inspect_module
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from admissible_core.identity import GIT_QUERIES, IdentityError

from admissible_trust import cli as trust_cli
from admissible_trust import git_reader

from . import TRUST_SRC
from .test_admissible_trust_finalization import FinalizationCase

TRUST_PACKAGE = TRUST_SRC / "admissible_trust"

#: Credentials exported beside the fake so a successful theft would be visible.
PLANTED_CREDENTIALS = {
    "ADMISSIBLE_HMAC_KEY": "planted-admission-secret-not-real",
    "ADMISSIBLE_HMAC_KEY_ID": "planted-admission",
    "ADMISSIBLE_REVIEW_KEY": "planted-review-secret-not-real",
    "ADMISSIBLE_REVIEW_KEY_ID": "planted-reviewer",
    "ADMISSIBLE_EVALUATION_KEY": "planted-observer-secret-not-real",
    "ADMISSIBLE_EVALUATION_KEY_ID": "planted-observer",
}

#: A program that answers plausibly and keeps everything it was handed.
#:
#: It prints a well-formed SHA so that a caller which *did* run it would get a
#: long way before noticing, which is the point: the failure this suite guards
#: against is silent, not loud.
FAKE_GIT = """#!/bin/sh
env > "%(receipt)s"
printf '%%s\\n' "$@" >> "%(receipt)s"
echo stolen > "%(loot)s"
echo 1111111111111111111111111111111111111111
"""


def plant_fake_git(directory: Path, receipt: Path, loot: Path) -> Path:
    """Write an executable named ``git`` that records instead of answering."""

    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "git"
    path.write_text(FAKE_GIT % {"receipt": receipt, "loot": loot},
                    encoding="utf-8")
    path.chmod(0o755)
    return path


def real_git() -> str:
    """The executable this machine's tests were themselves set up with."""

    found = shutil.which("git")
    if found is None:  # pragma: no cover - the suite cannot run without one
        raise unittest.SkipTest("no git on this machine")
    return found


def copy_real_git(directory: Path) -> Path:
    """A private, mutable copy of a real ``git``, owned by this test.

    ``copyfile`` rather than ``copy2``: the system executable carries platform
    flags this process is not allowed to reproduce, and none of them is what
    any test here is about.
    """

    path = directory / "git"
    shutil.copyfile(real_git(), path)
    path.chmod(0o755)
    return path


class ExecutableFixtureCase(unittest.TestCase):
    """A scratch directory, a restored environment, and a planted fake."""

    def setUp(self) -> None:
        raw = tempfile.mkdtemp(prefix="trust-executable-")
        self.addCleanup(shutil.rmtree, raw, True)
        # Resolved: on macOS the temporary root is reached through a symlink,
        # and a fixture whose own path is a redirection would fail the very
        # check it is here to exercise for reasons that have nothing to do
        # with the mutation under test.
        self.tmp = Path(raw).resolve()
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(),
                                 os.environ.update(saved)))

    def fixture_directory(self, name: str, *, mode: int = 0o755) -> Path:
        path = self.tmp / name
        path.mkdir()
        path.chmod(mode)
        self.addCleanup(path.chmod, 0o755)
        return path

    def only_candidate(self, directory: Path) -> None:
        """Make ``directory`` the whole of the trusted search path."""

        patch = mock.patch.object(git_reader, "TRUSTED_SEARCH_DIRECTORIES",
                                  (str(directory),))
        patch.start()
        self.addCleanup(patch.stop)


class TheExecutableIsResolvedFromTheSystem(ExecutableFixtureCase):
    """Resolution reads a closed list of directories and no variable."""

    def test_the_resolved_executable_is_absolute_real_and_a_regular_file(self):
        found = git_reader.trusted_git_executable()
        self.assertTrue(os.path.isabs(found), found)
        self.assertEqual(os.path.realpath(found), found)
        info = os.lstat(found)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertFalse(stat.S_IMODE(info.st_mode) & 0o022)

    def test_it_is_found_in_one_of_the_declared_system_directories(self):
        found = git_reader.trusted_git_executable()
        self.assertIn(os.path.dirname(found),
                      git_reader.TRUSTED_SEARCH_DIRECTORIES)

    def test_every_declared_search_directory_is_absolute(self):
        for directory in git_reader.TRUSTED_SEARCH_DIRECTORIES:
            with self.subTest(directory=directory):
                self.assertTrue(os.path.isabs(directory))
        self.assertTrue(git_reader.TRUSTED_SEARCH_DIRECTORIES)

    def test_a_poisoned_path_does_not_move_the_resolution(self):
        """The ambient ``PATH`` is not an input to this decision."""

        before = git_reader.trusted_git_executable()
        directory = self.fixture_directory("poison")
        plant_fake_git(directory, self.tmp / "receipt", self.tmp / "loot")
        os.environ["PATH"] = f"{directory}{os.pathsep}{os.environ.get('PATH', '')}"
        self.assertEqual(before, git_reader.trusted_git_executable())
        self.assertEqual(before, git_reader.GitReader().argv(self.tmp)[0])

    def test_an_empty_ambient_path_does_not_break_the_resolution(self):
        os.environ["PATH"] = ""
        self.assertTrue(git_reader.trusted_git_executable())

    def test_argv_begins_with_the_validated_absolute_executable(self):
        reader = git_reader.GitReader()
        expected = git_reader.trusted_git_executable()
        for query in GIT_QUERIES:
            with self.subTest(query=query):
                argv = reader.argv(self.tmp, query)
                self.assertEqual(expected, argv[0])
                self.assertTrue(os.path.isabs(argv[0]))

    def test_a_caller_supplied_path_is_overwritten_not_inherited(self):
        """``PATH`` is an output of this adapter, never an input."""

        reader = git_reader.GitReader(
            environment={"PATH": "/candidate/bin", "HOME": "/tmp"})
        self.assertEqual(git_reader.TRUSTED_PATH,
                         reader.environment()["PATH"])

    def test_the_adapter_never_reads_path_out_of_the_ambient_environment(self):
        """A source scan: the runtime one cannot see a lookup never taken."""

        source = (TRUST_PACKAGE / "git_reader.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or node.value != "PATH":
                continue
            with self.subTest(line=node.lineno):
                text = source.splitlines()[node.lineno - 1]
                # ``PATH`` may be written into the child's environment; it may
                # never be looked up in the caller's.
                self.assertNotIn("_source", text)
                self.assertNotIn("os.environ", text)


class ThereIsNoDoorForAnExecutablePath(ExecutableFixtureCase):
    """Nothing a candidate, an operator or a config file writes gets in."""

    def test_the_reader_takes_no_executable_argument(self):
        signature = inspect_module.signature(git_reader.GitReader.__init__)
        self.assertEqual(["self", "timeout_seconds", "environment"],
                         list(signature.parameters))

    def test_the_resolver_takes_no_arguments_at_all(self):
        signature = inspect_module.signature(git_reader.trusted_git_executable)
        self.assertEqual([], list(signature.parameters))

    def test_no_command_line_option_names_a_program(self):
        parser = trust_cli._build_parser()
        options = set()
        for action in parser._subparsers._group_actions[0].choices.values():
            for item in action._actions:
                options.update(item.option_strings)
                nested = getattr(item, "choices", None)
                if isinstance(nested, dict):
                    for sub in nested.values():
                        for entry in sub._actions:
                            options.update(entry.option_strings)
        offending = sorted(
            option for option in options
            if re.search(r"git|exec|binary|program|command", option))
        self.assertEqual([], offending)

    def test_the_environment_is_never_consulted_for_an_executable(self):
        """A variable would be an ordinary-environment door by another name."""

        source = (TRUST_PACKAGE / "git_reader.py").read_text(encoding="utf-8")
        for name in ("ADMISSIBLE_GIT", "GIT_EXEC_PATH", "GIT_BINARY",
                     "ADMISSIBLE_GIT_EXECUTABLE"):
            with self.subTest(variable=name):
                self.assertNotIn(name, source)


class AFakeGitOnThePathIsNeverExecuted(ExecutableFixtureCase):
    """The whole point, driven against every query the adapter answers."""

    def setUp(self) -> None:
        super().setUp()
        self.receipt = self.tmp / "fake-git-ran"
        self.loot = self.tmp / "fake-git-loot"
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        for args in (("init", "--quiet", "-b", "main"),
                     ("config", "user.email", "git@example.invalid"),
                     ("config", "user.name", "Git")):
            subprocess.run((real_git(), "-C", str(self.repo), *args),
                           check=True, timeout=120,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        (self.repo / "file.txt").write_text("content\n", encoding="utf-8")

        # One fake in a directory of its own, one *committed into* the
        # candidate repository. The second is the shape a repository can
        # actually ship, and committing it is what makes it that shape: an
        # untracked program would be refused by the dirty-tree rule long
        # before anything looked at ``PATH``, which is not the failure this
        # suite is about.
        self.planted = self.fixture_directory("candidate-bin")
        plant_fake_git(self.planted, self.receipt, self.loot)
        plant_fake_git(self.repo, self.receipt, self.loot)

        subprocess.run((real_git(), "-C", str(self.repo), "add", "-A"),
                       check=True, timeout=120, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        subprocess.run((real_git(), "-C", str(self.repo), "commit", "--quiet",
                        "-m", "one"), check=True, timeout=120,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.environ["PATH"] = os.pathsep.join(
            [str(self.planted), str(self.repo), os.environ.get("PATH", "")])
        os.environ.update(PLANTED_CREDENTIALS)

    def recorded_runs(self):
        """Record every argv while still really running it."""

        recorded: list[tuple[str, ...]] = []
        genuine = subprocess.run

        def record(argv, **kwargs):
            recorded.append(tuple(argv))
            return genuine(argv, **kwargs)

        return recorded, mock.patch("subprocess.run", record)

    def test_the_fake_is_genuinely_first_on_the_path(self):
        """Otherwise every assertion below would be about a broken fixture."""

        proof = self.tmp / "proof"
        loot = self.tmp / "proof-loot"
        plant_fake_git(self.planted, proof, loot)
        completed = subprocess.run(("git", "--version"), env=dict(os.environ),
                                   capture_output=True, timeout=120)
        self.assertEqual(0, completed.returncode)
        self.assertTrue(proof.is_file(), "the planted git did not run")
        self.assertIn("ADMISSIBLE_HMAC_KEY",
                      proof.read_text(encoding="utf-8", errors="replace"))
        # Put the real fake back for the tests that follow.
        plant_fake_git(self.planted, self.receipt, self.loot)

    def test_every_query_runs_the_system_git_and_not_the_planted_one(self):
        recorded, patch = self.recorded_runs()
        expected = git_reader.trusted_git_executable()
        with patch:
            reader = git_reader.GitReader()
            self.assertEqual(40, len(reader.head_commit(self.repo)))
            self.assertTrue(reader.top_level(self.repo))
            self.assertEqual("", reader.origin_url(self.repo))
            reader.status(self.repo)
            head = reader.head_commit(self.repo)
            self.assertEqual(40, len(reader.tree_of(self.repo, head)))
            self.assertTrue(reader.root_commits(self.repo, head))
        self.assertFalse(self.receipt.exists(), "the planted git ran")
        self.assertFalse(self.loot.exists(), "the planted git took the keys")
        self.assertTrue(recorded)
        self.assertEqual({expected}, {argv[0] for argv in recorded})

    def test_the_identity_read_answers_from_the_real_repository(self):
        found = git_reader.repository_identity(self.repo)
        self.assertEqual(40, len(found.commit_sha))
        self.assertEqual(40, len(found.tree_sha))
        self.assertFalse(found.dirty)
        self.assertFalse(self.receipt.exists())

    def test_the_child_environment_carries_the_fixed_path_only(self):
        environment = git_reader.GitReader().environment()
        self.assertEqual(git_reader.TRUSTED_PATH, environment["PATH"])
        self.assertNotIn(str(self.planted), environment["PATH"])
        self.assertNotIn(str(self.repo), environment["PATH"])
        for entry in environment["PATH"].split(os.pathsep):
            with self.subTest(entry=entry):
                self.assertTrue(os.path.isabs(entry))

    def test_the_child_environment_carries_no_credential_and_no_git_variable(self):
        os.environ["GIT_DIR"] = str(self.repo / ".git")
        environment = git_reader.GitReader().environment()
        for name in PLANTED_CREDENTIALS:
            with self.subTest(variable=name):
                self.assertNotIn(name, environment)
        for name in git_reader.STRIPPED_CREDENTIAL_NAMES:
            with self.subTest(variable=name):
                self.assertNotIn(name, environment)
        self.assertNotIn("GIT_DIR", environment)

    def test_the_child_environment_is_an_allowlist_not_a_filtered_copy(self):
        os.environ["A_VARIABLE_NOBODY_DECLARED"] = "value"
        environment = git_reader.GitReader().environment()
        self.assertNotIn("A_VARIABLE_NOBODY_DECLARED", environment)
        self.assertEqual(
            [], sorted(set(environment)
                       - set(git_reader.PRESERVED_ENVIRONMENT_NAMES)
                       - {"PATH", "GIT_CONFIG_NOSYSTEM", "GIT_OPTIONAL_LOCKS",
                          "GIT_TERMINAL_PROMPT"}))

    def test_a_preserved_platform_variable_survives_when_it_is_plausible(self):
        os.environ["HOME"] = str(self.tmp)
        self.assertEqual(str(self.tmp),
                         git_reader.GitReader().environment().get("HOME"))

    def test_an_implausible_platform_variable_is_dropped_rather_than_passed(self):
        os.environ["HOME"] = "x" * 100000
        self.assertNotIn("HOME", git_reader.GitReader().environment())


class AFullFinalizationNeverReachesTheFake(FinalizationCase):
    """The end-to-end claim: a receipt is issued and the fake never runs.

    ``FinalizationCase`` builds a real repository, a retained preview and an
    observer attestation with the ambient ``PATH`` intact, because the fixture
    itself has to be able to run ``git``.  The poison is planted afterwards,
    which is also the real sequence: the candidate's tooling edits ``PATH``
    long before a trusted process is asked to sign anything.

    The second fake goes inside the checkout's own ``.git``.  The working tree
    has to stay byte-identical to the artefact the preview describes -- that is
    the rule finalization refuses on first -- and ``.git`` is both outside what
    ``status`` reports and writable by anyone who can write the checkout, which
    makes it the repository-resident case that a clean tree still permits.
    """

    def setUp(self) -> None:
        super().setUp()
        raw = tempfile.mkdtemp(prefix="trust-finalize-poison-")
        self.addCleanup(shutil.rmtree, raw, True)
        self.poison = Path(raw).resolve()
        self.receipt_file = self.poison / "fake-git-ran"
        self.loot = self.poison / "fake-git-loot"
        plant_fake_git(self.poison, self.receipt_file, self.loot)
        inside = self.repo / ".git" / "candidate-bin"
        plant_fake_git(inside, self.receipt_file, self.loot)
        os.environ["PATH"] = os.pathsep.join(
            [str(self.poison), str(inside), os.environ.get("PATH", "")])
        os.environ.update(PLANTED_CREDENTIALS)

    def test_a_whole_finalization_runs_one_validated_absolute_git(self):
        recorded: list[tuple[str, ...]] = []
        genuine = subprocess.run

        def record(argv, **kwargs):
            recorded.append(tuple(argv))
            return genuine(argv, **kwargs)

        expected = git_reader.trusted_git_executable()
        with mock.patch("subprocess.run", record):
            store, receipt = self.admitted()
        self.assertEqual("ADMITTED", receipt.state)
        self.assertEqual(self.sha, receipt.commit_sha)
        self.assertFalse(self.receipt_file.exists(), "the planted git ran")
        self.assertFalse(self.loot.exists(), "the planted git took the keys")
        self.assertTrue(recorded, "finalization read the tree through git")
        self.assertEqual({expected}, {argv[0] for argv in recorded})
        for argv in recorded:
            with self.subTest(argv=argv):
                self.assertTrue(os.path.isabs(argv[0]))

    def test_the_authenticated_projection_also_avoids_the_fake(self):
        from admissible_trust import ready_status

        store, _receipt = self.admitted()
        store.close()
        document = ready_status.inspect_authenticated(
            str(self.repo), verifier=self.signer(), home=self.home)
        self.assertEqual("ready", document["status"])
        self.assertFalse(self.receipt_file.exists())

    def test_the_planted_credentials_are_still_in_this_process(self):
        """The theft was possible; it did not happen because of the adapter."""

        for name, value in PLANTED_CREDENTIALS.items():
            with self.subTest(variable=name):
                self.assertEqual(value, os.environ[name])


class AnUntrustworthyExecutableIsRefusedBeforeAnySpawn(ExecutableFixtureCase):
    """Mutate the fixture the validator accepts, and require a refusal."""

    def armed(self):
        """Fail the test if anything is started while the trap is set."""

        def refuse(*args, **kwargs):
            raise AssertionError(f"Trust started a process: {args!r}")

        return mock.patch("subprocess.run", refuse)

    def refusal(self, directory: Path) -> str:
        self.only_candidate(directory)
        with self.armed():
            with self.assertRaises(git_reader.TrustedExecutableError) as caught:
                git_reader.GitReader()
        return str(caught.exception)

    # -- the control the mutations are measured against ---------------------
    def test_an_unmutated_fixture_is_accepted_and_really_answers(self):
        directory = self.fixture_directory("good")
        copy_real_git(directory)
        (directory / "git").chmod(0o755)
        self.only_candidate(directory)
        reader = git_reader.GitReader()
        self.assertEqual(str(directory / "git"), reader.argv(self.tmp)[0])

    # -- and the mutations --------------------------------------------------
    def test_a_symlinked_executable_is_refused(self):
        directory = self.fixture_directory("symlinked")
        os.symlink(real_git(), directory / "git")
        message = self.refusal(directory)
        self.assertIn(str(directory / "git"), message)
        self.assertIn("link", message)

    def test_a_world_writable_executable_is_refused(self):
        directory = self.fixture_directory("world-writable")
        copy_real_git(directory)
        (directory / "git").chmod(0o777)
        message = self.refusal(directory)
        self.assertIn("writable by group or others", message)

    def test_a_group_writable_executable_is_refused(self):
        directory = self.fixture_directory("group-writable")
        copy_real_git(directory)
        (directory / "git").chmod(0o775)
        self.assertIn("writable by group or others", self.refusal(directory))

    def test_a_non_executable_file_is_refused(self):
        directory = self.fixture_directory("not-executable")
        (directory / "git").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (directory / "git").chmod(0o644)
        self.assertIn("not executable", self.refusal(directory))

    def test_a_directory_named_git_is_refused(self):
        directory = self.fixture_directory("a-directory")
        (directory / "git").mkdir()
        self.assertIn("not a regular file", self.refusal(directory))

    def test_a_world_writable_parent_directory_is_refused(self):
        directory = self.fixture_directory("open-parent", mode=0o777)
        copy_real_git(directory)
        (directory / "git").chmod(0o755)
        message = self.refusal(directory)
        self.assertIn(str(directory), message)
        self.assertIn("writable by group or others", message)

    def test_a_group_writable_parent_directory_is_refused(self):
        directory = self.fixture_directory("group-parent", mode=0o775)
        copy_real_git(directory)
        (directory / "git").chmod(0o755)
        self.assertIn("writable by group or others", self.refusal(directory))

    def test_an_absent_executable_is_a_refusal_and_not_a_fallback(self):
        directory = self.fixture_directory("empty")
        message = self.refusal(directory)
        self.assertIn("no git", message.lower())

    def test_the_refusal_is_an_identity_failure_every_caller_already_handles(self):
        self.assertTrue(issubclass(git_reader.TrustedExecutableError,
                                   IdentityError))

    def test_the_refusal_explains_where_trust_will_and_will_not_look(self):
        directory = self.fixture_directory("empty")
        message = self.refusal(directory)
        self.assertIn("PATH", message)
        self.assertIn(str(directory), message)

    def test_repository_identity_refuses_rather_than_falling_back(self):
        directory = self.fixture_directory("empty")
        self.only_candidate(directory)
        with self.armed():
            with self.assertRaises(IdentityError):
                git_reader.repository_identity(self.tmp)


class TheRealSystemGitStillAnswersEverything(ExecutableFixtureCase):
    """A control: the hardening did not turn the adapter into a refusal."""

    def setUp(self) -> None:
        super().setUp()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        for args in (("init", "--quiet", "-b", "main"),
                     ("config", "user.email", "git@example.invalid"),
                     ("config", "user.name", "Git")):
            subprocess.run((real_git(), "-C", str(self.repo), *args),
                           check=True, timeout=120,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        (self.repo / "file.txt").write_text("content\n", encoding="utf-8")
        subprocess.run((real_git(), "-C", str(self.repo), "add", "-A"),
                       check=True, timeout=120, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        subprocess.run((real_git(), "-C", str(self.repo), "commit", "--quiet",
                        "-m", "one"), check=True, timeout=120,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run((real_git(), "-C", str(self.repo), "remote", "add",
                        "origin", "https://github.com/acme/widget.git"),
                       check=True, timeout=120, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)

    def test_all_six_questions_answer_against_a_real_repository(self):
        reader = git_reader.GitReader()
        head = reader.head_commit(self.repo)
        self.assertEqual(40, len(head))
        self.assertEqual(str(self.repo), reader.top_level(self.repo))
        self.assertEqual(40, len(reader.tree_of(self.repo, head)))
        self.assertEqual("", reader.status(self.repo))
        self.assertEqual("https://github.com/acme/widget.git",
                         reader.origin_url(self.repo))
        self.assertEqual(head, reader.root_commits(self.repo, head))

    def test_a_dirty_tree_is_still_seen_as_dirty(self):
        (self.repo / "extra.txt").write_text("x\n", encoding="utf-8")
        self.assertIn("extra.txt", git_reader.GitReader().status(self.repo))

    def test_the_fixed_configuration_is_still_forced_on_every_call(self):
        reader = git_reader.GitReader()
        for query in GIT_QUERIES:
            with self.subTest(query=query):
                argv = reader.argv(self.repo, query)
                self.assertIn("core.hooksPath=/dev/null", argv)
                self.assertIn("core.fsmonitor=false", argv)

    def test_a_hook_the_repository_planted_is_not_run(self):
        hooks = self.repo / ".git" / "hooks"
        hooks.mkdir(parents=True, exist_ok=True)
        marker = self.tmp / "hook-ran"
        for name in ("post-index-change", "pre-commit", "reference-transaction"):
            hook = hooks / name
            hook.write_text(f"#!/bin/sh\necho ran > {marker}\n",
                            encoding="utf-8")
            hook.chmod(0o755)
        reader = git_reader.GitReader()
        reader.status(self.repo)
        reader.head_commit(self.repo)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
