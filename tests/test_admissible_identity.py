"""Contract: exact repository identity, argv-only execution, path containment."""
from __future__ import annotations

import os
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import TempCase, git, make_repo, require_module  # noqa: E402

identity = require_module("admissible.identity")
runner = require_module("admissible.runner")
config = require_module("admissible.config")
fsutil = require_module("admissible.fsutil")


class RepositoryIdentityTest(TempCase):
    def setUp(self):
        super().setUp()
        self.root = self.tmp / "repo"
        self.sha = make_repo(self.root)

    def test_identity_reports_full_sha_tree_and_namespace(self):
        found = identity.repository_identity(self.root)
        self.assertEqual(found.commit_sha, self.sha)
        self.assertEqual(len(found.commit_sha), 40)
        self.assertEqual(len(found.tree_sha), 40)
        self.assertEqual(found.repository, "github.com/acme/widget")
        self.assertFalse(found.dirty)

    def test_ssh_remote_normalizes_to_the_same_namespace(self):
        other = self.tmp / "ssh"
        make_repo(other, remote="git@github.com:acme/widget.git")
        self.assertEqual(identity.repository_identity(other).repository,
                         "github.com/acme/widget")

    def test_credentials_in_a_remote_url_never_reach_the_namespace(self):
        other = self.tmp / "tokenised"
        make_repo(other,
                  remote="https://someone:ghp_notarealtokenvalue@github.com/acme/widget.git")
        found = identity.repository_identity(other)
        self.assertEqual(found.repository, "github.com/acme/widget")
        self.assertNotIn("ghp_", found.repository)
        self.assertNotIn("someone", found.repository)

    def test_missing_remote_still_yields_a_deterministic_namespace(self):
        other = self.tmp / "solo"
        make_repo(other, remote=None)
        found = identity.repository_identity(other)
        self.assertTrue(found.repository)
        self.assertEqual(found.repository,
                         identity.repository_identity(other).repository)

    def test_dirty_worktree_is_refused(self):
        (self.root / "README.md").write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(identity.IdentityError):
            identity.repository_identity(self.root)

    def test_untracked_file_makes_the_worktree_dirty(self):
        (self.root / "scratch.txt").write_text("x\n", encoding="utf-8")
        with self.assertRaises(identity.IdentityError):
            identity.repository_identity(self.root)

    def test_dirty_worktree_is_reported_when_explicitly_allowed(self):
        (self.root / "README.md").write_text("dirty\n", encoding="utf-8")
        found = identity.repository_identity(self.root, allow_dirty=True)
        self.assertTrue(found.dirty)

    def test_partial_sha_is_refused_as_a_format_problem(self):
        with self.assertRaises(identity.IdentityError) as caught:
            identity.repository_identity(self.root, expected_sha=self.sha[:12])
        # It must say the SHA is not full, not merely that it is not HEAD:
        # an abbreviated SHA of the *current* commit is still refused.
        message = str(caught.exception).lower()
        self.assertIn("full", message)
        self.assertIn("lowercase", message)

    def test_uppercase_sha_is_refused_as_a_format_problem(self):
        with self.assertRaises(identity.IdentityError) as caught:
            identity.repository_identity(self.root, expected_sha=self.sha.upper())
        self.assertIn("lowercase", str(caught.exception).lower())

    def test_non_string_sha_is_refused(self):
        for bad in (1, b"a" * 40, ["a" * 40], object()):
            with self.assertRaises(identity.IdentityError):
                identity.repository_identity(self.root, expected_sha=bad)

    def test_stale_sha_is_refused_with_the_observed_head(self):
        (self.root / "README.md").write_text("second\n", encoding="utf-8")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "second")
        head = git(self.root, "rev-parse", "HEAD")
        self.assertNotEqual(head, self.sha)
        with self.assertRaises(identity.IdentityError) as caught:
            identity.repository_identity(self.root, expected_sha=self.sha)
        self.assertIn(head, str(caught.exception))

    def test_non_repository_is_refused(self):
        plain = self.tmp / "plain"
        plain.mkdir()
        with self.assertRaises(identity.IdentityError):
            identity.repository_identity(plain)

    def test_identity_uses_captured_commit_tree_and_rejects_head_movement(self):
        first = "a" * 40
        moved = "c" * 40
        tree = "b" * 40
        calls = []

        def fake_git(root, *args, required=True):
            calls.append(args)
            if args == ("rev-parse", "--show-toplevel"):
                return str(self.root)
            if args == ("rev-parse", "HEAD"):
                return first if calls.count(args) == 1 else moved
            if args == ("rev-parse", f"{first}^{{tree}}"):
                return tree
            if args == ("status", "--porcelain", "--untracked-files=all"):
                return ""
            if args == ("remote", "get-url", "origin"):
                return "https://github.com/acme/widget.git"
            self.fail(f"unexpected git call: {args}")

        with mock.patch.object(identity, "_git", side_effect=fake_git):
            with self.assertRaises(identity.IdentityError) as caught:
                identity.repository_identity(self.root)
        self.assertIn("changed", str(caught.exception).lower())
        self.assertIn(("rev-parse", f"{first}^{{tree}}"), calls)
        self.assertNotIn(("rev-parse", "HEAD^{tree}"), calls)


class PathContainmentTest(TempCase):
    def test_relative_path_inside_the_root_resolves(self):
        base = self.tmp / "root"
        (base / "logs").mkdir(parents=True)
        (base / "logs" / "a.txt").write_text("x", encoding="utf-8")
        resolved = fsutil.resolve_within(base, "logs/a.txt")
        self.assertEqual(resolved, (base / "logs" / "a.txt").resolve())

    def test_absolute_path_is_refused(self):
        base = self.tmp / "root"
        base.mkdir()
        with self.assertRaises(fsutil.PathError):
            fsutil.resolve_within(base, str(self.tmp / "outside.txt"))

    def test_parent_traversal_is_refused(self):
        base = self.tmp / "root"
        base.mkdir()
        with self.assertRaises(fsutil.PathError):
            fsutil.resolve_within(base, "../outside.txt")

    def test_symlink_escape_is_refused(self):
        base = self.tmp / "root"
        base.mkdir()
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("s", encoding="utf-8")
        os.symlink(str(outside), str(base / "link"))
        with self.assertRaises(fsutil.PathError):
            fsutil.resolve_within(base, "link/secret.txt")

    def test_empty_and_non_string_paths_are_refused(self):
        base = self.tmp / "root"
        base.mkdir()
        for bad in ("", ".", None, 3, b"x"):
            with self.assertRaises(fsutil.PathError):
                fsutil.resolve_within(base, bad)


class RunnerTest(TempCase):
    def make_check(self, argv, *, timeout=30, check_id="unit"):
        document = {
            "version": 1,
            "profile": "python-library",
            "classes": [{
                "id": "default",
                "checks": [{
                    "id": check_id, "argv": list(argv),
                    "timeout_seconds": timeout, "cost_units": 1,
                    "required": True, "version": "1",
                }],
                "required_independent_reviews": 0,
                "review_max_age_seconds": 86400,
                "max_cost_units": 10, "max_wall_seconds": 600,
            }],
        }
        return config.parse_config(document).select_class("default").checks[0]

    def test_successful_command_hashes_its_exact_bytes(self):
        import hashlib
        check = self.make_check([sys.executable, "-c", "print('hello')"])
        result = runner.run_check(check, cwd=self.tmp)
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(result.timed_out)
        self.assertEqual(result.stdout_sha256,
                         hashlib.sha256(b"hello\n").hexdigest())
        self.assertEqual(result.stdout_bytes, 6)

    def test_failing_command_reports_its_exit_code(self):
        check = self.make_check([sys.executable, "-c", "raise SystemExit(3)"])
        self.assertEqual(runner.run_check(check, cwd=self.tmp).exit_code, 3)

    def test_no_shell_interpolation(self):
        marker = self.tmp / "pwned.txt"
        check = self.make_check(
            [sys.executable, "-c", "print('safe')", f"; touch {marker}"])
        runner.run_check(check, cwd=self.tmp)
        self.assertFalse(marker.exists())

    def test_environment_variables_are_not_expanded_in_argv(self):
        check = self.make_check([sys.executable, "-c",
                                 "import sys;print(sys.argv[1])", "$HOME"])
        result = runner.run_check(check, cwd=self.tmp, log_dir=self.tmp / "logs")
        text = (self.tmp / "logs" / result.log_name).read_text(encoding="utf-8")
        self.assertIn("$HOME", text)

    def test_timeout_is_reported_and_the_process_group_is_killed(self):
        check = self.make_check(
            [sys.executable, "-c", "import time;time.sleep(30)"], timeout=1)
        result = runner.run_check(check, cwd=self.tmp)
        self.assertTrue(result.timed_out)
        self.assertNotEqual(result.exit_code, 0)
        self.assertLess(result.duration_ms, 20000)

    def test_result_never_carries_raw_output(self):
        check = self.make_check(
            [sys.executable, "-c", "print('SUPER_SECRET_TOKEN')"])
        result = runner.run_check(check, cwd=self.tmp)
        import dataclasses
        blob = repr(dataclasses.asdict(result)) + repr(result)
        self.assertNotIn("SUPER_SECRET_TOKEN", blob)

    def test_private_log_is_written_with_owner_only_permissions(self):
        check = self.make_check([sys.executable, "-c", "print('logged')"])
        logs = self.tmp / "logs"
        result = runner.run_check(check, cwd=self.tmp, log_dir=logs)
        path = logs / result.log_name
        self.assertIn("logged", path.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)

    def test_log_bytes_are_the_hashed_bytes(self):
        import hashlib
        check = self.make_check(
            [sys.executable, "-c", "import sys;sys.stdout.write('abc')"])
        logs = self.tmp / "logs"
        result = runner.run_check(check, cwd=self.tmp, log_dir=logs)
        recorded = runner.read_stdout_bytes(logs / result.log_name)
        self.assertEqual(hashlib.sha256(recorded).hexdigest(),
                         result.stdout_sha256)

    def test_oversized_output_is_bounded_and_flagged(self):
        check = self.make_check(
            [sys.executable, "-c",
             "import sys;sys.stdout.write('x'*200000)"])
        result = runner.run_check(check, cwd=self.tmp, max_output_bytes=1024)
        self.assertTrue(result.output_truncated)
        self.assertEqual(result.stdout_bytes, 1024)

    def test_missing_executable_is_a_runner_error_not_a_crash(self):
        check = self.make_check(["definitely-not-a-real-binary-xyz"])
        result = runner.run_check(check, cwd=self.tmp)
        self.assertTrue(result.launch_failed)
        self.assertNotEqual(result.exit_code, 0)

    def test_a_hostile_check_id_cannot_escape_the_log_directory(self):
        """Config validation blocks this id; the runner must refuse it too."""
        import dataclasses
        check = dataclasses.replace(
            self.make_check([sys.executable, "-c", "print('x')"]),
            id="../../escaped")
        with self.assertRaises(runner.RunnerError):
            runner.run_check(check, cwd=self.tmp, log_dir=self.tmp / "logs")
        self.assertFalse((self.tmp / "escaped").exists())
        self.assertFalse((self.tmp.parent / "escaped").exists())

    def test_secrets_are_stripped_from_the_child_environment(self):
        os.environ["ADMISSIBLE_HMAC_KEY"] = "super-secret-value-not-for-children"
        check = self.make_check(
            [sys.executable, "-c",
             "import os;print(os.environ.get('ADMISSIBLE_HMAC_KEY','ABSENT'))"])
        logs = self.tmp / "logs"
        result = runner.run_check(check, cwd=self.tmp, log_dir=logs)
        text = (logs / result.log_name).read_text(encoding="utf-8")
        self.assertIn("ABSENT", text)
        self.assertNotIn("super-secret-value", text)


if __name__ == "__main__":
    unittest.main()
