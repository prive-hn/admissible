"""Contract: the split Ready behaves as the monolith's Ready behaved.

Every assertion below runs *both* implementations against the same throwaway
repository, in the same process, and compares what came back.  A test that only
exercised the new code would prove it works; the claim that has to survive this
refactor is narrower and harder -- that it works *the same way*.

Where the two deliberately differ, the difference is asserted rather than
tolerated, and each one is named in :class:`DeliberateDifferences` with the
reason it exists.  A silent divergence and an intended one look identical in a
diff, so the intended ones are written down.

Both implementations share the durable home for these tests, and that is the
point of several of them: an attempt the monolith recorded must be readable by
the split store, and vice versa, because a v0.7 home does not get rewritten by
this release.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from admissible import cli as legacy_cli
from admissible import ready as legacy_ready
from admissible import store as legacy_store

from admissible_ready import cli as ready_cli
from admissible_ready import git_reader
from admissible_ready import ready as ready_state
from admissible_ready import store as ready_store

def policy_document(argv: list[str]) -> dict:
    """A shipped profile with its checks replaced by one known command.

    Built from ``profile_document`` rather than written out here: a policy
    literal in a test drifts from the schema the moment a required key is
    added, and the failure then reads as a Ready bug rather than as a stale
    fixture. Only the check list is fixture-specific.
    """

    from admissible_core import profiles

    document = profiles.profile_document("python-library")
    document["classes"][0]["checks"] = [{
        "id": "one",
        "version": "1",
        "argv": list(argv),
        "timeout_seconds": 30,
        "cost_units": 1,
        "required": True,
        "description": "A command that is on every machine this runs on.",
        "cacheable": True,
        "cache_max_age_seconds": 86400,
    }]
    return document


class ReadyRepositoryCase(unittest.TestCase):
    """A throwaway git repository, a throwaway home, and both implementations."""

    def setUp(self) -> None:
        self.home = Path(self.scratch("admissible-shared-home-"))
        self.legacy_home = Path(self.scratch("admissible-legacy-home-"))
        self.ready_home = Path(self.scratch("admissible-ready-home-"))
        self.repo = Path(self.scratch("admissible-ready-repo-"))
        self.git("init", "--quiet")
        self.git("config", "user.email", "ready@example.com")
        self.git("config", "user.name", "Ready")
        self.git("remote", "add", "origin",
                 "https://github.com/acme/widget.git")
        self.write_policy(policy_document(["/usr/bin/true"]))
        self.commit("policy")
        patch = mock.patch.dict(
            os.environ, {"ADMISSIBLE_HOME": str(self.home)}, clear=False)
        patch.start()
        self.addCleanup(patch.stop)
        # A credential left over from another test would make every command
        # below refuse, and the refusal would look like a parity failure.
        for name in ready_cli.runner_module.SIGNING_CREDENTIAL_NAMES:
            os.environ.pop(name, None)

    def scratch(self, prefix: str) -> str:
        raw = tempfile.mkdtemp(prefix=prefix)
        self.addCleanup(shutil.rmtree, raw, True)
        return raw

    def git(self, *args: str) -> None:
        subprocess.run(("git", "-C", str(self.repo), *args), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=60)

    def write_policy(self, document: dict) -> None:
        (self.repo / ".admissible.json").write_text(
            json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def commit(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "--quiet", "-m", message)

    # -- running both CLIs ---------------------------------------------------
    #
    # Each implementation gets its own home by default. Sharing one would make
    # the second run reuse the first run's cached evidence, so a comparison of
    # two cold runs would silently become a comparison of one cold run against
    # one reuse -- which differs in `provenance` and proves nothing about
    # either. The cross-read tests below pass `home=self.home` deliberately,
    # because sharing is exactly what they are about.
    def run_legacy(self, argv: list[str],
                   home: Path | None = None) -> tuple[int, str, str]:
        return _capture(legacy_cli.main, argv, home or self.legacy_home)

    def run_ready(self, argv: list[str],
                  home: Path | None = None) -> tuple[int, str, str]:
        return _capture(ready_cli.main, argv, home or self.ready_home)


def _capture(main, argv: list[str], home: Path) -> tuple[int, str, str]:
    import io

    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, {"ADMISSIBLE_HOME": str(home)},
                         clear=False):
        code = main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _without_volatile(document: dict) -> dict:
    """The Ready document minus the fields two separate runs cannot share.

    An attempt id is a random digest and the check timings are wall clock, so
    comparing them would compare the clock. Everything that describes *what was
    decided* stays -- including ``provenance``, because whether a result was
    executed or reused is part of what the document claims.
    """

    stripped = json.loads(json.dumps(document))
    stripped["identity"]["attempt_id"] = None
    for check in stripped.get("checks", []):
        for field in ("duration_ms", "started_at", "finished_at",
                      "attempt_id", "log_name", "reused_from_attempt"):
            check.pop(field, None)
    return stripped


class CheckOutputParity(ReadyRepositoryCase):
    """``check`` produces the same Ready document and the same exit code."""

    def test_a_passing_check_agrees_field_for_field(self):
        legacy_code, legacy_out, _ = self.run_legacy(
            ["check", "--repo", str(self.repo), "--json"])
        ready_code, ready_out, _ = self.run_ready(
            ["check", "--repo", str(self.repo), "--json"])
        self.assertEqual(legacy_code, ready_code)
        self.assertEqual(0, ready_code, ready_out)
        self.assertEqual(_without_volatile(json.loads(legacy_out)),
                         _without_volatile(json.loads(ready_out)))

    def test_a_passing_check_is_checks_complete_and_never_ready(self):
        _, ready_out, _ = self.run_ready(
            ["check", "--repo", str(self.repo), "--json"])
        document = json.loads(ready_out)
        self.assertEqual("checks_complete", document["status"])
        self.assertEqual("CHECKS_PASSED", document["canonical"]["state"])
        self.assertIn(document["status"], ready_state.UNSIGNED_STATUSES)

    def test_a_failing_check_agrees_field_for_field(self):
        self.write_policy(policy_document(["/usr/bin/false"]))
        self.commit("failing policy")
        legacy_code, legacy_out, _ = self.run_legacy(
            ["check", "--repo", str(self.repo), "--json"])
        ready_code, ready_out, _ = self.run_ready(
            ["check", "--repo", str(self.repo), "--json"])
        self.assertEqual(legacy_code, ready_code)
        # A refused evaluation is exit 1, not 2: it is a decision, and only an
        # operationally blocked invocation is 2.
        self.assertEqual(1, ready_code)
        self.assertEqual("needs_attention", json.loads(ready_out)["status"])
        self.assertEqual(_without_volatile(json.loads(legacy_out)),
                         _without_volatile(json.loads(ready_out)))

    def test_the_plain_rendering_is_byte_identical(self):
        _, legacy_out, _ = self.run_legacy(["check", "--repo", str(self.repo)])
        _, ready_out, _ = self.run_ready(["check", "--repo", str(self.repo)])
        self.assertEqual(legacy_out, ready_out)

    def test_a_dirty_worktree_blocks_identically(self):
        (self.repo / "stray.txt").write_text("x\n", encoding="utf-8")
        legacy_code, legacy_out, _ = self.run_legacy(
            ["check", "--repo", str(self.repo), "--json"])
        ready_code, ready_out, _ = self.run_ready(
            ["check", "--repo", str(self.repo), "--json"])
        self.assertEqual(legacy_code, ready_code)
        self.assertEqual(2, ready_code)
        self.assertEqual(_without_volatile(json.loads(legacy_out)),
                         _without_volatile(json.loads(ready_out)))


class RunPreviewParity(ReadyRepositoryCase):
    """``run --preview`` produces the same decision and the same preview."""

    def test_the_decision_document_agrees(self):
        legacy_code, legacy_out, _ = self.run_legacy(
            ["run", "--preview", "--repo", str(self.repo), "--json"])
        ready_code, ready_out, _ = self.run_ready(
            ["run", "--preview", "--repo", str(self.repo), "--json"])
        self.assertEqual(legacy_code, ready_code)
        legacy_document = json.loads(legacy_out)
        ready_document = json.loads(ready_out)
        for document in (legacy_document, ready_document):
            # An evidence digest binds the attempt it was recorded in, and an
            # attempt id is a fresh random digest per run. Two separate runs
            # therefore cannot share one, and comparing them would compare
            # `secrets.token_hex`.
            for volatile in ("attempt_id", "evaluated_at", "log_directory",
                             "evidence", "evidence_digests"):
                document.pop(volatile, None)
            for check in document.get("checks", []):
                for field in ("duration_ms", "started_at", "finished_at",
                              "attempt_id", "log_name", "reused_from_attempt"):
                    check.pop(field, None)
        self.assertEqual(legacy_document, ready_document)

    def test_a_long_ready_run_uses_completion_time_for_its_decision(self):
        original_run_check = ready_cli.runner_module.run_check
        original_time = ready_cli.time.time
        moments = iter((1000, 1402))

        def delayed_result(check_object, **_kwargs):
            return ready_cli.runner_module.CommandResult(
                check_id=check_object.id,
                check_version=check_object.version,
                argv_digest=check_object.argv_digest,
                exit_code=0,
                timed_out=False,
                launch_failed=False,
                duration_ms=402000,
                stdout_sha256="0" * 64,
                stderr_sha256="0" * 64,
                stdout_bytes=0,
                stderr_bytes=0,
                output_truncated=False,
                started_at=1401,
                finished_at=1402,
            )

        ready_cli.runner_module.run_check = delayed_result
        ready_cli.time.time = lambda: next(moments)
        self.addCleanup(lambda: setattr(ready_cli.runner_module, "run_check",
                                        original_run_check))
        self.addCleanup(lambda: setattr(ready_cli.time, "time", original_time))

        code, out, err = self.run_ready(
            ["run", "--preview", "--repo", str(self.repo), "--no-cache", "--json"])
        self.assertEqual(code, 0, out + err)
        self.assertEqual(json.loads(out)["state"], "CHECKS_PASSED")

    def test_the_preview_artefact_agrees_apart_from_its_evidence_digests(self):
        legacy_path = Path(self.scratch("preview-legacy-")) / "preview.json"
        ready_path = Path(self.scratch("preview-ready-")) / "preview.json"
        self.run_legacy(["run", "--preview", "--repo", str(self.repo),
                         "--json", "--preview-out", str(legacy_path)])
        self.run_ready(["run", "--preview", "--repo", str(self.repo),
                        "--json", "--preview-out", str(ready_path)])
        legacy_document = json.loads(legacy_path.read_text(encoding="utf-8"))
        ready_document = json.loads(ready_path.read_text(encoding="utf-8"))
        for key in ("schema", "repository", "commit_sha", "tree_sha",
                    "policy_digest", "class_id", "state", "readiness",
                    "isolation", "policy_anchor", "config_path", "fork",
                    "dependencies"):
            with self.subTest(key=key):
                self.assertEqual(legacy_document[key], ready_document[key])

    def test_the_preview_is_owner_only(self):
        path = Path(self.scratch("preview-mode-")) / "preview.json"
        self.run_ready(["run", "--preview", "--repo", str(self.repo),
                        "--json", "--preview-out", str(path)])
        self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_run_without_preview_refuses_and_names_the_trust_command(self):
        code, out, _ = self.run_ready(
            ["run", "--repo", str(self.repo), "--json"])
        self.assertEqual(2, code)
        document = json.loads(out)
        self.assertEqual("BLOCKED", document["state"])
        self.assertIn("--preview", document["message"])
        self.assertIn("admissible-trust finalize", document["message"])
        self.assertTrue(any("admissible-trust finalize" in step
                            for step in document["remediation"]))

    def test_the_legacy_run_also_refuses_without_preview(self):
        """The refusal is inherited, not invented: parity on the exit code."""
        legacy_code, _, _ = self.run_legacy(
            ["run", "--repo", str(self.repo), "--json"])
        ready_code, _, _ = self.run_ready(
            ["run", "--repo", str(self.repo), "--json"])
        self.assertEqual(legacy_code, ready_code)


class EvidenceAndAttemptParity(ReadyRepositoryCase):
    """What each implementation records in the shared home is the same shape."""

    def identity(self):
        return git_reader.repository_identity(self.repo, allow_dirty=True)

    def test_an_attempt_written_by_one_is_read_by_the_other(self):
        self.run_ready(["run", "--preview", "--repo", str(self.repo), "--json"],
                       home=self.home)
        found = self.identity()
        legacy_opened = legacy_store.open_store(self.home)
        try:
            legacy_attempt = legacy_opened.latest_attempt(
                found.repository, found.commit_sha)
        finally:
            legacy_opened.close()
        ready_opened = ready_store.open_store(self.home)
        try:
            ready_attempt = ready_opened.latest_attempt(
                found.repository, found.commit_sha)
        finally:
            ready_opened.close()
        self.assertIsNotNone(ready_attempt)
        self.assertEqual(legacy_attempt, ready_attempt)

    def test_evidence_written_by_one_is_read_by_the_other(self):
        self.run_ready(["run", "--preview", "--repo", str(self.repo), "--json"],
                       home=self.home)
        found = self.identity()
        legacy_opened = legacy_store.open_store(self.home)
        try:
            legacy_rows = legacy_opened.evidence_for(
                found.repository, found.commit_sha)
        finally:
            legacy_opened.close()
        ready_opened = ready_store.open_store(self.home)
        try:
            ready_rows = ready_opened.evidence_for(
                found.repository, found.commit_sha)
        finally:
            ready_opened.close()
        self.assertTrue(ready_rows)
        self.assertEqual(legacy_rows, ready_rows)

    def test_the_private_check_log_is_written_owner_only(self):
        self.run_ready(["run", "--preview", "--repo", str(self.repo), "--json"])
        logs = sorted((self.ready_home / "logs").rglob("*.log"))
        self.assertTrue(logs, "the runner writes one private log per check")
        for path in logs:
            with self.subTest(log=path.name):
                self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_the_evidence_cache_is_reused_by_the_second_run(self):
        self.run_ready(["run", "--preview", "--repo", str(self.repo), "--json"])
        _, out, _ = self.run_ready(
            ["run", "--preview", "--repo", str(self.repo), "--json"])
        document = json.loads(out)
        provenance = {check["check_id"]: check.get("provenance")
                      for check in document["checks"]}
        self.assertEqual({"one": "reused"}, provenance)

    def test_a_cache_entry_from_the_monolith_is_reused_by_the_split(self):
        """The cache key is the same arithmetic on both sides, or reuse lies."""
        self.run_legacy(["run", "--preview", "--repo", str(self.repo), "--json"],
                        home=self.home)
        _, out, _ = self.run_ready(
            ["run", "--preview", "--repo", str(self.repo), "--json"],
            home=self.home)
        document = json.loads(out)
        self.assertEqual(
            {"one": "reused"},
            {check["check_id"]: check.get("provenance")
             for check in document["checks"]})


class InspectionParity(ReadyRepositoryCase):
    """The unsigned inspection answers what the monolith answered unsigned.

    Both inspections read ``ADMISSIBLE_HOME``, which ``setUp`` points at the
    shared home, so the run below writes there too: the claim is that the two
    read one home the same way, not that each reads its own.
    """

    def record_an_attempt(self) -> None:
        self.run_ready(["run", "--preview", "--repo", str(self.repo), "--json"],
                       home=self.home)

    def test_before_any_check_both_say_not_checked(self):
        legacy = legacy_ready.inspect(str(self.repo))
        ready = ready_state.inspect_unsigned(str(self.repo))
        self.assertEqual(legacy, ready)
        self.assertEqual("needs_attention", ready["status"])
        self.assertEqual(["not_checked"],
                         [reason["code"] for reason in ready["reasons"]])

    def test_after_a_check_both_describe_the_same_attempt(self):
        self.record_an_attempt()
        legacy = legacy_ready.inspect(str(self.repo))
        ready = ready_state.inspect_unsigned(str(self.repo))
        self.assertEqual(legacy, ready)
        self.assertEqual("checks_complete", ready["status"])

    def test_a_dirty_worktree_is_reported_identically(self):
        (self.repo / "stray.txt").write_text("x\n", encoding="utf-8")
        self.assertEqual(legacy_ready.inspect(str(self.repo)),
                         ready_state.inspect_unsigned(str(self.repo)))

    def test_the_work_package_agrees_apart_from_its_nonce(self):
        self.record_an_attempt()
        legacy = legacy_ready.work_package(
            str(self.repo), "fix the thing", issue_nonce="fixed")
        ready = ready_state.work_package(
            str(self.repo), "fix the thing", issue_nonce="fixed")
        self.assertEqual(legacy["package_id"], ready["package_id"])
        self.assertEqual(legacy["identity"], ready["identity"])
        self.assertEqual(legacy["capabilities"], ready["capabilities"])
        self.assertEqual(legacy["completion"], ready["completion"])
        self.assertEqual(legacy["readiness"], ready["readiness"])

    def test_the_work_package_forbids_every_trust_verb(self):
        self.record_an_attempt()
        package = ready_state.work_package(str(self.repo), "fix the thing")
        self.assertEqual(
            ["sign", "finalize", "trust_policy", "revoke_policy",
             "attest_review", "attest_evaluation", "impeach", "merge",
             "deploy"],
            package["capabilities"]["forbidden"])


class DeliberateDifferences(ReadyRepositoryCase):
    """Where the split behaves differently on purpose, and why.

    Each of these would be a parity failure if it were an accident.  They are
    asserted so that a future change which removes one has to say so.
    """

    def test_the_connector_names_the_command_this_wheel_installs(self):
        """The monolith told a client to run ``admissible``; this wheel has none.

        A Ready-only environment installs ``admissible-ready`` and nothing
        else, so a connector snippet naming ``admissible`` would configure an
        MCP client to run a program that is not there.
        """
        from admissible import agent_connection as legacy_connection

        from admissible_ready import agent_connection as ready_connection

        legacy = legacy_connection.instructions(
            str(self.repo), name="a", purpose="b", runtime="local")
        ready = ready_connection.instructions(
            str(self.repo), name="a", purpose="b", runtime="local")
        self.assertEqual("admissible", legacy["command"][0])
        self.assertEqual("admissible-ready", ready["command"][0])
        self.assertEqual(legacy["command"][1:], ready["command"][1:])

    def test_the_init_json_keeps_the_trusted_key_and_it_is_always_empty(self):
        """``init --trust-policy`` is gone; the JSON shape it fed is not.

        Making a policy enforceable is an operator's act in a trusted context,
        and this distribution has no ``trust_policy`` to call. The key stays so
        a consumer of the v0.7 shape still parses, and it is always empty
        because nothing here can fill it.
        """
        repo = Path(self.scratch("init-"))
        subprocess.run(("git", "init", "--quiet", str(repo)), check=True,
                       timeout=60)
        _, out, _ = self.run_ready(
            ["init", "--repo", str(repo), "--profile", "python-library",
             "--json"])
        document = json.loads(out)
        self.assertEqual([], document["trusted"])
        self.assertEqual(
            sorted(["path", "profile", "written", "ignored", "trusted",
                    "tool_sha", "ci"]),
            sorted(document))

    def test_init_rejects_the_trust_policy_flag_outright(self):
        repo = Path(self.scratch("init-trust-"))
        subprocess.run(("git", "init", "--quiet", str(repo)), check=True,
                       timeout=60)
        code, out, err = self.run_ready(
            ["init", "--repo", str(repo), "--profile", "python-library",
             "--trust-policy", "--json"])
        self.assertEqual(2, code)
        self.assertNotIn("trust", (out + err).split("unrecognized")[0].lower()
                         .replace("admissible-trust", ""))

    def test_render_plain_refuses_an_authenticated_status(self):
        """The monolith rendered ``ready``; this module refuses to.

        It can never produce the status, so rendering one it was handed would
        be presenting somebody else's authenticated answer under this
        distribution's name.
        """
        document = ready_state.from_problem("x")
        document["status"] = "ready"
        with self.assertRaises(ready_state.ReadyError):
            ready_state.render_plain(document)
        # The monolith renders it, which is what makes this a difference.
        self.assertIn("Ready", legacy_ready.render_plain(document))

    def test_the_help_names_only_the_ready_commands(self):
        code, out, _ = self.run_ready(["--help"])
        self.assertEqual(0, code)
        for command in ("profiles", "init", "run --preview", "check", "mcp",
                        "connect", "ui"):
            with self.subTest(command=command):
                self.assertIn(command, out)
        for absent in ("ready-status", "attest-review", "attest-evaluation",
                       "finalize", "impeach"):
            with self.subTest(absent=absent):
                # Named only as something `admissible-trust` owns, never as a
                # command this program accepts.
                self.assertNotIn(f"\n  {absent} ", out)

    def test_every_trust_command_is_unknown_here(self):
        for command in ("ready-status", "attest-review", "attest-evaluation",
                        "policy", "finalize", "verify", "explain", "export",
                        "import", "impeach", "status"):
            with self.subTest(command=command):
                code, _, _ = self.run_ready([command, "--json"])
                self.assertEqual(2, code)
