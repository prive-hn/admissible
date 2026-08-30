"""Contract: the two places Ready touches the outside are narrow on purpose.

Ready starts exactly two kinds of process.  One is the candidate's own check,
which is the capability this distribution exists to have; the other is ``git``,
which is how a working tree is identified at all.  They are separated because
the second must not become the first: a policy chooses the argv of a check, and
nothing chooses the argv of an identity read.

So :mod:`admissible_ready.git_reader` is asserted to be *fixed*.  Its six
questions map to six literal argument lists, the only interpolated values are a
path the caller supplied and a commit SHA the kernel has already required to be
40 hex characters, and the environment it hands the child is stripped of every
``GIT_*`` variable and every signing credential.  A repository-controlled string
has no route into any of it.

The second half is the GitHub boundary.  :mod:`admissible_ready.github` carries
the evaluate side and nothing else, and that is asserted as an absence: no
finalisation, no receipt, no attestation verification, no policy trust.  The
preview it writes is unsigned by construction and refuses to describe one
evaluation two ways.
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from admissible import github as legacy_github

from admissible_core.identity import GIT_QUERIES, IdentityError

from admissible_ready import git_reader
from admissible_ready import github
from admissible_ready import runner as runner_module


class TheGitAdapterIsFixed(unittest.TestCase):
    """Six questions, six literal argument lists, and no way to add a seventh."""

    def setUp(self) -> None:
        raw = tempfile.mkdtemp(prefix="ready-git-")
        self.addCleanup(shutil.rmtree, raw, True)
        self.repo = Path(raw)
        for args in (("init", "--quiet"),
                     ("config", "user.email", "git@example.com"),
                     ("config", "user.name", "Git")):
            subprocess.run(("git", "-C", str(self.repo), *args), check=True,
                           timeout=60, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        (self.repo / "file.txt").write_text("content\n", encoding="utf-8")
        subprocess.run(("git", "-C", str(self.repo), "add", "-A"), check=True,
                       timeout=60)
        subprocess.run(("git", "-C", str(self.repo), "commit", "--quiet",
                        "-m", "one"), check=True, timeout=60,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_it_answers_exactly_the_kernel_s_six_questions(self):
        reader = git_reader.GitReader()
        for query in GIT_QUERIES:
            with self.subTest(query=query):
                self.assertTrue(callable(getattr(reader, query, None)))

    def test_every_argv_it_would_run_is_a_literal_plus_bounded_values(self):
        """Recorded, then compared as a set of exact argument lists."""

        recorded: list[tuple[str, ...]] = []

        def record(argv, **kwargs):
            recorded.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with mock.patch("subprocess.run", record):
            reader = git_reader.GitReader()
            reader.top_level(self.repo)
            reader.head_commit(self.repo)
            reader.tree_of(self.repo, "a" * 40)
            reader.status(self.repo)
            reader.origin_url(self.repo)
            reader.root_commits(self.repo, "a" * 40)
        prefix = ("git", "-c", "core.fsmonitor=false", "-c",
                  "core.hooksPath=/dev/null", "-C", str(self.repo))
        self.assertEqual([
            (*prefix, "rev-parse", "--show-toplevel"),
            (*prefix, "rev-parse", "HEAD"),
            (*prefix, "rev-parse", "a" * 40 + "^{tree}"),
            (*prefix, "status", "--porcelain", "--untracked-files=all"),
            (*prefix, "remote", "get-url", "origin"),
            (*prefix, "rev-list", "--max-parents=0", "a" * 40),
        ], recorded)

    def test_hooks_and_the_filesystem_monitor_are_disabled_on_every_call(self):
        """Both are repository-controlled, and both can name a program."""
        reader = git_reader.GitReader()
        for query in GIT_QUERIES:
            with self.subTest(query=query):
                argv = reader.argv(self.repo, query)
                self.assertIn("core.hooksPath=/dev/null", argv)
                self.assertIn("core.fsmonitor=false", argv)

    def test_no_git_variable_survives_into_the_child(self):
        source = {"GIT_DIR": "/elsewhere/.git", "GIT_INDEX_FILE": "/tmp/index",
                  "GIT_AUTHOR_NAME": "someone", "PATH": "/usr/bin"}
        environment = git_reader.GitReader(environment=source).environment()
        self.assertEqual(
            [], sorted(name for name in environment
                       if name.startswith("GIT_")
                       and name not in ("GIT_CONFIG_NOSYSTEM",
                                        "GIT_OPTIONAL_LOCKS",
                                        "GIT_TERMINAL_PROMPT")))
        self.assertEqual("/usr/bin", environment["PATH"])

    def test_no_signing_credential_survives_into_the_child(self):
        source = {name: "material"
                  for name in runner_module.SIGNING_CREDENTIAL_NAMES}
        source["PATH"] = "/usr/bin"
        environment = git_reader.GitReader(environment=source).environment()
        for name in runner_module.SIGNING_CREDENTIAL_NAMES:
            with self.subTest(variable=name):
                self.assertNotIn(name, environment)

    def test_system_configuration_and_prompting_are_off(self):
        environment = git_reader.GitReader(environment={}).environment()
        self.assertEqual("1", environment["GIT_CONFIG_NOSYSTEM"])
        self.assertEqual("0", environment["GIT_OPTIONAL_LOCKS"])
        self.assertEqual("0", environment["GIT_TERMINAL_PROMPT"])

    def test_no_argv_is_built_from_a_non_literal_string(self):
        """Static: every ``_run`` call in the module passes literal arguments.

        The runtime assertion above proves what today's code does. This one
        proves that a future edit cannot introduce a formatted subcommand
        without failing here.
        """

        source = Path(git_reader.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", getattr(node.func, "id", ""))
            if name != "_run":
                continue
            # args[0] is the repository root the caller supplied; every
            # argument after it names the git subcommand and its options.
            # `commit` is the only non-literal permitted, and the kernel has
            # already required it to be 40 lowercase hex characters before any
            # of these are called.
            for argument in node.args[1:]:
                if isinstance(argument, ast.Constant):
                    continue
                if isinstance(argument, ast.Name) and argument.id == "commit":
                    continue
                if (isinstance(argument, ast.JoinedStr)
                        and _only_names(argument, {"commit"})):
                    continue
                offenders.append(ast.dump(argument)[:80])
        self.assertEqual([], offenders,
                         "a git subcommand must be a literal")

    def test_a_missing_git_is_reported_as_an_identity_refusal(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaises(IdentityError):
                git_reader.GitReader().head_commit(self.repo)

    def test_a_timeout_is_reported_as_an_identity_refusal(self):
        with mock.patch("subprocess.run",
                        side_effect=subprocess.TimeoutExpired("git", 60)):
            with self.assertRaises(IdentityError):
                git_reader.GitReader().head_commit(self.repo)

    def test_an_absent_origin_is_a_fact_rather_than_a_failure(self):
        self.assertEqual("", git_reader.GitReader().origin_url(self.repo))

    def test_the_identity_it_produces_is_the_monolith_s(self):
        """Field for field, because the two dataclasses are different types.

        They have to be: one is ``admissible.identity.Identity`` and the other
        is the kernel's, and a dataclass compares unequal across classes. What
        must agree is every field, which is what an artefact is bound by.
        """

        import dataclasses

        from admissible import identity as legacy_identity

        found = git_reader.repository_identity(self.repo)
        expected = legacy_identity.repository_identity(self.repo)
        self.assertEqual(dataclasses.asdict(expected),
                         dataclasses.asdict(found))
        self.assertEqual(expected.to_dict(), found.to_dict())


def _only_names(node: ast.JoinedStr, allowed: set[str]) -> bool:
    """Whether an f-string interpolates only names from ``allowed``."""

    for value in node.values:
        if isinstance(value, ast.Constant):
            continue
        if (isinstance(value, ast.FormattedValue)
                and isinstance(value.value, ast.Name)
                and value.value.id in allowed):
            continue
        return False
    return True


class TheGitHubBoundaryIsEvaluateOnly(unittest.TestCase):
    """The evaluate half, and the absence of the other one."""

    def context(self, **overrides) -> dict:
        environment = {"GITHUB_EVENT_NAME": "push",
                       "GITHUB_REPOSITORY": "acme/widget",
                       "GITHUB_SHA": "a" * 40,
                       "GITHUB_REF": "refs/heads/main"}
        environment.update(overrides)
        return environment

    def test_the_evaluation_context_agrees_with_the_monolith(self):
        environment = self.context()
        self.assertEqual(
            legacy_github.context_to_dict(
                legacy_github.evaluation_context(environment)),
            github.context_to_dict(github.evaluation_context(environment)))

    def test_pull_request_target_is_refused(self):
        with self.assertRaises(github.GitHubError):
            github.evaluation_context(
                self.context(GITHUB_EVENT_NAME="pull_request_target"))

    def test_a_pull_request_binds_the_head_commit_not_the_merge_commit(self):
        raw = tempfile.mkdtemp(prefix="ready-event-")
        self.addCleanup(shutil.rmtree, raw, True)
        payload = Path(raw) / "event.json"
        payload.write_text(json.dumps({
            "pull_request": {
                "head": {"sha": "b" * 40,
                         "repo": {"full_name": "fork/widget"}},
                "base": {"repo": {"full_name": "acme/widget"}},
            }}), encoding="utf-8")
        found = github.evaluation_context(self.context(
            GITHUB_EVENT_NAME="pull_request",
            GITHUB_EVENT_PATH=str(payload)))
        self.assertEqual("b" * 40, found.commit_sha)
        self.assertTrue(found.is_fork)
        self.assertFalse(found.can_sign)
        self.assertTrue(found.preview_only)

    def test_a_fork_is_marked_on_the_preview_it_produces(self):
        raw = tempfile.mkdtemp(prefix="ready-event-")
        self.addCleanup(shutil.rmtree, raw, True)
        payload = Path(raw) / "event.json"
        payload.write_text(json.dumps({
            "pull_request": {
                "head": {"sha": "b" * 40,
                         "repo": {"full_name": "fork/widget"}},
                "base": {"repo": {"full_name": "acme/widget"}},
            }}), encoding="utf-8")
        environment = self.context(GITHUB_EVENT_NAME="pull_request",
                                   GITHUB_EVENT_PATH=str(payload))
        with mock.patch.dict(os.environ, environment, clear=True):
            self.assertTrue(github.fork_from_environment())

    def test_an_unidentifiable_ci_context_is_treated_as_a_fork(self):
        """Untrusted is the safe default; trusted is not."""
        with mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": "pull_request"},
                             clear=True):
            self.assertTrue(github.fork_from_environment())

    def test_no_ci_context_at_all_is_not_a_fork(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(github.fork_from_environment())

    def test_the_policy_anchor_is_unanchored_without_a_store(self):
        self.assertEqual(
            github.POLICY_ANCHOR_UNANCHORED,
            github.policy_anchor(None, repository="example.com/one",
                                 class_id="default", policy_digest="c" * 64,
                                 enforcement_digest="e" * 64))

    def test_the_policy_anchor_constants_are_the_monolith_s(self):
        for name in ("POLICY_ANCHOR_TRUSTED", "POLICY_ANCHOR_CHANGED",
                     "POLICY_ANCHOR_UNANCHORED"):
            with self.subTest(constant=name):
                self.assertEqual(getattr(legacy_github, name),
                                 getattr(github, name))

    def test_the_preview_schema_and_ceilings_are_the_monolith_s(self):
        self.assertEqual(legacy_github.PREVIEW_SCHEMA, github.PREVIEW_SCHEMA)
        self.assertEqual(legacy_github.MAX_PREVIEW_HANDOVER_BYTES,
                         github.MAX_PREVIEW_HANDOVER_BYTES)
        self.assertEqual(legacy_github.GITHUB_JOB_OUTPUT_LIMIT_BYTES,
                         github.GITHUB_JOB_OUTPUT_LIMIT_BYTES)

    def test_no_finalisation_surface_is_present(self):
        """Named individually, so a failure says which one came back."""
        for name in ("finalize", "require_trusted_policy", "assert_trusted_tool",
                     "approving_reviews",
                     "expected_finalization_receipt_body_digest"):
            with self.subTest(callable=name):
                self.assertFalse(hasattr(github, name))
                self.assertTrue(hasattr(legacy_github, name),
                                f"{name} must exist in the monolith, or this "
                                "assertion is checking a typo")

    def test_a_preview_that_declares_no_isolation_is_still_written(self):
        """``none`` is the truth about a bare process group, not an error.

        It is the finalizer that refuses it, in the other distribution. Ready
        records what confined the commands and does not decide what that is
        worth.
        """

        document = self.preview(isolation="none")
        self.assertEqual("none", document["isolation"])

    def test_an_unknown_isolation_mode_is_refused(self):
        with self.assertRaises(github.GitHubError):
            self.preview(isolation="a-vibe")

    def test_a_preview_whose_decision_disagrees_with_it_is_refused(self):
        with self.assertRaises(github.GitHubError):
            self.preview(commit_sha="f" * 40)

    def test_a_preview_can_never_carry_the_admitted_state(self):
        with self.assertRaises(github.GitHubError):
            self.preview(state="ADMITTED")

    def test_the_preview_matches_the_monolith_s_field_for_field(self):
        self.assertEqual(self.legacy_preview(), self.preview())

    # -- fixtures ------------------------------------------------------------
    def arguments(self, **overrides) -> dict:
        decision = {
            "scope": "developer-workflow-admission",
            "state": "CHECKS_PASSED",
            "readiness": "READY_FOR_ATTESTATION",
            "repository": "github.com/acme/widget",
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
            "policy_digest": "c" * 64,
            "class_id": "default",
            "evaluated_at": 100,
        }
        arguments = {
            "repository": "github.com/acme/widget",
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
            "policy_digest": "c" * 64,
            "class_id": "default",
            "state": "CHECKS_PASSED",
            "readiness": "READY_FOR_ATTESTATION",
            "decision": decision,
            "evidence": {"commands": [], "reviews": []},
            "dependencies": (),
            "issued_at": 100,
            "fork": False,
            "isolation": "none",
        }
        arguments.update(overrides)
        if "state" in overrides:
            arguments["decision"] = dict(decision, state=overrides["state"])
        return arguments

    def preview(self, **overrides) -> dict:
        return github.preview_document(**self.arguments(**overrides))

    def legacy_preview(self, **overrides) -> dict:
        return legacy_github.preview_document(**self.arguments(**overrides))
