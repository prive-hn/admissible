"""Contract: end-to-end CLI behaviour in real temporary git repositories."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import (OBSERVER_KEY_ID,  # noqa: E402
                                OBSERVER_SECRET, TempCase, admit,
                                evaluating_domain, git, make_repo,
                                require_module, source_receipt_document)

attestation_module = require_module("admissible.attestation")
cli = require_module("admissible.cli")

SECRET = "unit-test-secret-not-a-real-key"
ROOT = Path(__file__).resolve().parent.parent


def config_document(argv, *, reviews=0, check_id="unit", extra_checks=(),
                    reviewer_key_ids=()):
    checks = [{"id": check_id, "argv": list(argv), "timeout_seconds": 60,
               "cost_units": 1, "required": True, "version": "1"}]
    checks.extend(extra_checks)
    artifact_class = {
        "id": "default",
        "checks": checks,
        "required_independent_reviews": reviews,
        "review_max_age_seconds": 86400,
        "max_cost_units": 10,
        "max_wall_seconds": 600,
    }
    if reviewer_key_ids:
        artifact_class["reviewer_key_ids"] = list(reviewer_key_ids)
    if reviews:
        # Naming the reviewer keys is half of "independent"; naming the author
        # keys is the other half, and a class that requires review needs both.
        artifact_class.setdefault("author_key_ids", ["author-key"])
    return {"version": 1, "profile": "python-library",
            "classes": [artifact_class]}


class CLICase(TempCase):
    def setUp(self):
        super().setUp()
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET
        self.repo = self.tmp / "repo"

    def make(self, document=None, *, argv=None, files=None):
        payload = files or {"README.md": "widget\n"}
        sha = make_repo(self.repo, files=payload)
        document = document or config_document(
            argv or [sys.executable, "-c", "print('ok')"])
        (self.repo / ".admissible.json").write_text(
            json.dumps(document), encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "config")
        return git(self.repo, "rev-parse", "HEAD")

    def admitted(self, document=None, **overrides):
        """A commit taken all the way to an anchored receipt.

        Four steps in three trust domains -- evaluate, observe, trust the
        policy once, finalize -- because ``run`` no longer signs anything and
        there is no shorter honest path.
        """

        sha = self.make(document)
        return sha, admit(self, self.repo, sha, **overrides)

    def invoke(self, *argv):
        """Invoke the CLI, previewing every ``run``.

        ``run`` evaluates and never signs, so ``--preview`` is not optional any
        more. Adding it here keeps each call site about the thing it is
        testing; :meth:`invoke_exact` is for the tests that are about the flag.
        """

        argv = tuple(argv)
        if argv[:1] == ("run",) and "--preview" not in argv:
            argv = ("run", "--preview") + argv[1:]
        return self.invoke_exact(*argv)

    def invoke_exact(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        if argv[:1] == ("run",):
            # An evaluate job holds no signing credential; these fixtures share
            # one process with the finalizer, so the domain is separated here.
            with evaluating_domain():
                code = cli.main(list(argv), stdout=out, stderr=err)
        else:
            code = cli.main(list(argv), stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()


class ProfilesAndInitTest(CLICase):
    def test_profiles_lists_the_eight_built_in_profiles(self):
        code, out, _ = self.invoke("profiles", "--json")
        self.assertEqual(code, 0)
        document = json.loads(out)
        names = [item["name"] for item in document["profiles"]]
        self.assertEqual(len(names), 8)
        self.assertIn("payment-change", names)
        self.assertIn("documentation-only", names)

    def test_profiles_plain_output_names_review_requirements(self):
        code, out, _ = self.invoke("profiles")
        self.assertEqual(code, 0)
        self.assertIn("documentation-only", out)
        self.assertIn("payment-change", out)

    def test_init_writes_config_and_refuses_a_second_time(self):
        self.repo.mkdir(parents=True)
        code, out, _ = self.invoke("init", "--profile", "python-library",
                                "--repo", str(self.repo))
        self.assertEqual(code, 0)
        self.assertTrue((self.repo / ".admissible.json").is_file())
        code, _, err = self.invoke("init", "--profile", "rest-api",
                                "--repo", str(self.repo))
        self.assertEqual(code, 2)
        self.assertIn("--force", err + out)

    def test_unknown_profile_exits_two_with_the_catalog(self):
        self.repo.mkdir(parents=True)
        code, out, err = self.invoke("init", "--profile", "node-service",
                                  "--repo", str(self.repo))
        self.assertEqual(code, 2)
        self.assertIn("python-library", out + err)


class RunTest(CLICase):
    def test_clean_repository_with_passing_checks_passes_its_checks(self):
        sha = self.make()
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha,
                                "--json")
        self.assertEqual(code, 0)
        document = json.loads(out)
        # Not ADMITTED, and deliberately so: `run` signs nothing and anchors
        # nothing, so the strongest thing it can truthfully say is that the
        # checks passed and an observer could now attest it.
        self.assertEqual(document["state"], "CHECKS_PASSED")
        self.assertEqual(document["readiness"], "READY_FOR_ATTESTATION")
        self.assertEqual(document["commit_sha"], sha)
        self.assertEqual(document["scope"], "developer-workflow-admission")
        self.assertIsNone(document["receipt"])
        self.assertTrue(document["preview"])

    def test_the_whole_path_produces_a_receipt(self):
        sha, issued = self.admitted()
        self.assertEqual(len(issued.receipt_hash), 64)
        self.assertEqual(issued.commit_sha, sha)
        self.assertEqual(issued.state, "ADMITTED")

    def test_run_without_preview_is_refused_and_starts_nothing(self):
        """`run` starts candidate-owned commands, so it never holds a key."""

        sha = self.make()
        code, out, err = self.invoke_exact(
            "run", "--repo", str(self.repo), "--sha", sha, "--json")
        self.assertEqual(code, 2)
        document = json.loads(out)
        self.assertEqual(document["state"], "BLOCKED")
        self.assertIn("--preview", document["message"])

    def test_plain_run_output_has_the_three_developer_sections(self):
        sha = self.make()
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha)
        lowered = out.lower()
        self.assertEqual(code, 0)
        self.assertIn("what happened", lowered)
        self.assertIn("what is known", lowered)
        self.assertIn("what to do next", lowered)

    def test_failing_required_check_refuses_with_exit_one(self):
        sha = self.make(config_document(
            [sys.executable, "-c", "raise SystemExit(1)"], check_id="unit"))
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha)
        self.assertEqual(code, 1)
        self.assertIn("unit", out)

    def test_stale_sha_is_blocked_with_the_observed_head(self):
        sha = self.make()
        (self.repo / "README.md").write_text("next\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "next")
        code, out, err = self.invoke("run", "--repo", str(self.repo), "--sha", sha)
        self.assertEqual(code, 2)
        self.assertIn(git(self.repo, "rev-parse", "HEAD"), out + err)

    def test_short_sha_is_refused(self):
        sha = self.make()
        code, out, err = self.invoke("run", "--repo", str(self.repo),
                                  "--sha", sha[:12])
        self.assertEqual(code, 2)
        self.assertIn("full", (out + err).lower())

    def test_dirty_worktree_is_blocked_with_remediation(self):
        sha = self.make()
        (self.repo / "README.md").write_text("dirty\n", encoding="utf-8")
        code, out, err = self.invoke("run", "--repo", str(self.repo), "--sha", sha)
        self.assertEqual(code, 2)
        self.assertIn("commit", (out + err).lower())

    def test_a_preview_needs_no_key_and_anchors_nothing(self):
        """It records what it observed, and it makes nothing current.

        Recording and anchoring are different acts. An evaluation writes down
        the attempt and its evidence so `explain` can answer about it later;
        only a signed receipt makes a commit current, and there is none here.
        """

        sha = self.make()
        del os.environ["ADMISSIBLE_HMAC_KEY"]
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha,
                                "--json")
        self.assertEqual(code, 0)
        document = json.loads(out)
        self.assertIsNone(document["receipt"])
        self.assertTrue(document["preview"])
        self.assertTrue(document["recorded"])
        code, _, _ = self.invoke("verify", sha, "--repo", str(self.repo))
        self.assertEqual(code, 1)

    def test_no_store_records_nothing_and_says_so(self):
        sha = self.make()
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha,
                                   "--no-store", "--json")
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out)["recorded"])
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha,
                                   "--no-store")
        self.assertIn("--no-store", out)

    def test_no_cache_still_records_the_attempt(self):
        """Not reusing evidence was never a reason not to write it down."""

        sha = self.make()
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha,
                                   "--no-cache", "--json")
        self.assertEqual(code, 0)
        document = json.loads(out)
        self.assertTrue(document["recorded"])
        code, text, err = self.invoke("explain", sha, "--repo", str(self.repo),
                                      "--json")
        self.assertEqual(json.loads(text)["decision_attempt_id"],
                         document["attempt_id"], err)

    def test_a_run_reads_no_signing_key_even_when_one_is_present(self):
        """The key in the environment must make no difference to a run.

        It used to make all the difference: without it a run refused, with it a
        run signed. Both readings are wrong for a process that executes
        candidate-owned commands, so `run` no longer looks.
        """

        sha = self.make()
        with_key, out_with, _ = self.invoke(
            "run", "--repo", str(self.repo), "--sha", sha, "--json")
        del os.environ["ADMISSIBLE_HMAC_KEY"]
        without_key, out_without, err = self.invoke(
            "run", "--repo", str(self.repo), "--sha", sha, "--json")
        self.assertEqual(with_key, 0)
        self.assertEqual(without_key, 0, out_without + err)
        for text in (out_with, out_without):
            self.assertIsNone(json.loads(text)["receipt"])

    def test_missing_config_is_an_operational_error_naming_init(self):
        make_repo(self.repo)
        sha = git(self.repo, "rev-parse", "HEAD")
        code, out, err = self.invoke("run", "--repo", str(self.repo), "--sha", sha)
        self.assertEqual(code, 2)
        self.assertIn("admissible init", out + err)

    def test_output_never_contains_the_signing_secret(self):
        sha = self.make()
        code, out, err = self.invoke("run", "--repo", str(self.repo), "--sha", sha,
                                  "--json")
        self.assertEqual(code, 0)
        self.assertNotIn(SECRET, out + err)

    def test_run_records_evidence_and_a_private_bounded_log(self):
        sha = self.make(config_document(
            [sys.executable, "-c", "print('SECRET_LOOKING_OUTPUT')"]))
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha,
                                "--json")
        self.assertEqual(code, 0)
        self.assertNotIn("SECRET_LOOKING_OUTPUT", out)
        logs = list((self.home / "logs").rglob("*.log"))
        self.assertTrue(logs)
        self.assertIn("SECRET_LOOKING_OUTPUT",
                      logs[0].read_text(encoding="utf-8"))
        import stat
        self.assertEqual(stat.S_IMODE(logs[0].stat().st_mode) & 0o077, 0)

    def review_record(self, sha, klass, **overrides):
        import hashlib

        document = {
            "kind": "review", "review_id": "r1",
            "reviewer_id": "reviewer-one", "reviewer_version": "1",
            "author_id": "author-one", "verdict": "approve",
            "repository": "github.com/acme/widget",
            "commit_sha": sha,
            "tree_sha": git(self.repo, "rev-parse", "HEAD^{tree}"),
            "policy_digest": klass.policy_digest,
            "findings_digest": hashlib.sha256(b"").hexdigest(),
            "issued_at": int(time.time()),
            "attempt_id": "",
        }
        document.update(overrides)
        return document

    def keyring(self, **entries):
        path = self.tmp / "reviewer-keyring.json"
        path.write_text(json.dumps(entries), encoding="utf-8")
        os.chmod(path, 0o600)
        os.environ["ADMISSIBLE_REVIEW_KEYRING"] = str(path)
        return path

    def selected_class(self):
        from admissible import config as config_module

        document = json.loads(
            (self.repo / ".admissible.json").read_text(encoding="utf-8"))
        return config_module.parse_config(document).select_class("default")

    def test_a_signed_review_satisfies_an_independent_review(self):
        from admissible import review as review_module

        sha = self.make(config_document(
            [sys.executable, "-c", "print('ok')"], reviews=1,
            reviewer_key_ids=["reviewer-key-a"]))
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha)
        self.assertEqual(code, 1)
        self.assertIn("review", out.lower())
        klass = self.selected_class()
        attestation = review_module.attest(
            self.review_record(sha, klass), key_id="reviewer-key-a",
            secret=b"reviewer-secret")
        # Who wrote this commit, signed by the key the policy pins as an
        # author. Without it the class admits nothing: "nobody reviews their
        # own change" is a rule about keys, and an unclaimed authorship leaves
        # nothing to exclude.
        authorship = review_module.attest_authorship({
            "kind": "authorship", "author_id": "author-one",
            "repository": "github.com/acme/widget", "commit_sha": sha,
            "tree_sha": git(self.repo, "rev-parse", "HEAD^{tree}"),
            "policy_digest": klass.policy_digest, "issued_at": int(time.time()),
        }, key_id="author-key", secret=b"author-secret")
        bundle = {
            "schema": "admissible/v0.6/workflow-evidence",
            "commands": [], "reviews": [], "defects": [],
            "attestations": [attestation],
            "author_attestations": [authorship],
        }
        path = self.tmp / "reviews.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        # A keyring in the environment changes nothing here: `run` never reads
        # one. The evaluation carries the signature on and waits.
        self.keyring(**{"reviewer-key-a": "reviewer-secret"})
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha,
                                   "--evidence", str(path))
        self.assertEqual(code, 1, out)
        self.assertIn("review", out.lower())
        # The finalizer holds the keyring, and it is what admits.
        issued = admit(self, self.repo, sha, evidence=path,
                       reviewer_keyring={"reviewer-key-a": b"reviewer-secret",
                                         "author-key": b"author-secret"})
        self.assertEqual(issued.state, "ADMITTED")
        self.assertEqual([key for _digest, key in issued.authenticated_reviews],
                         ["reviewer-key-a"])

    def test_an_unsigned_review_never_satisfies_an_independent_review(self):
        sha = self.make(config_document(
            [sys.executable, "-c", "print('ok')"], reviews=1,
            reviewer_key_ids=["reviewer-key-a"]))
        klass = self.selected_class()
        bundle = {
            "schema": "admissible/v0.6/workflow-evidence",
            "commands": [], "reviews": [self.review_record(sha, klass)],
            "defects": [], "attestations": [],
        }
        path = self.tmp / "reviews.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha,
                                   "--evidence", str(path))
        self.assertEqual(code, 1, out)
        self.assertIn("review", out.lower())

    def test_a_future_dated_signed_review_is_refused(self):
        from admissible import review as review_module

        sha = self.make(config_document(
            [sys.executable, "-c", "print('ok')"], reviews=1,
            reviewer_key_ids=["reviewer-key-a"]))
        klass = self.selected_class()
        attestation = review_module.attest(
            self.review_record(sha, klass, issued_at=4102444800),
            key_id="reviewer-key-a", secret=b"reviewer-secret")
        bundle = {
            "schema": "admissible/v0.6/workflow-evidence",
            "commands": [], "reviews": [], "defects": [],
            "attestations": [attestation],
        }
        path = self.tmp / "reviews.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        self.keyring(**{"reviewer-key-a": "reviewer-secret"})
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha,
                                   "--evidence", str(path))
        self.assertEqual(code, 1, out)
        self.assertIn("future", out.lower())


class VerifyExplainStatusTest(CLICase):
    def admit(self):
        return self.admitted()[0]

    def test_verify_reports_a_current_authenticated_receipt(self):
        sha = self.admit()
        code, out, _ = self.invoke("verify", sha, "--repo", str(self.repo), "--json")
        self.assertEqual(code, 0)
        document = json.loads(out)
        self.assertEqual(document["state"], "CURRENT")
        self.assertTrue(document["signature_valid"])
        self.assertEqual(document["scope"], "developer-workflow-admission")

    def test_verify_survives_a_restart(self):
        sha = self.admit()
        env = dict(os.environ)
        result = subprocess.run(
            [sys.executable, "-m", "admissible", "verify", sha,
             "--repo", str(self.repo), "--json"],
            cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(json.loads(result.stdout.decode("utf-8"))["state"],
                         "CURRENT")

    def test_verify_with_a_wrong_key_fails_closed(self):
        sha = self.admit()
        os.environ["ADMISSIBLE_HMAC_KEY"] = "a-different-secret"
        code, out, err = self.invoke("verify", sha, "--repo", str(self.repo))
        self.assertEqual(code, 1)
        self.assertIn("signature", (out + err).lower())

    def test_verify_unknown_sha_exits_one(self):
        self.make()
        code, out, _ = self.invoke("verify", "9" * 40, "--repo", str(self.repo))
        self.assertEqual(code, 1)
        self.assertIn("what to do next", out.lower())

    def test_explain_describes_the_stored_decision(self):
        sha = self.admit()
        code, out, _ = self.invoke("explain", sha, "--repo", str(self.repo))
        self.assertEqual(code, 0)
        lowered = out.lower()
        self.assertIn("what happened", lowered)
        self.assertIn("unit", lowered)

    def test_status_reports_the_repository_and_counts(self):
        sha = self.admit()
        code, out, _ = self.invoke("status", "--repo", str(self.repo), "--json")
        self.assertEqual(code, 0)
        document = json.loads(out)
        self.assertEqual(document["repository"], "github.com/acme/widget")
        self.assertEqual(document["receipts"], 1)
        self.assertEqual(document["head"]["event_count"], 1)
        self.assertEqual(document["current_sha"], sha)


class ImpeachTest(CLICase):
    def test_impeachment_flips_standing_and_keeps_the_receipt_authentic(self):
        sha, _issued = self.admitted()
        defect = self.tmp / "defect.json"
        defect.write_text(json.dumps({
            "kind": "defect", "defect_id": "d1",
            "repository": "github.com/acme/widget", "commit_sha": sha,
            "severity": "high", "summary": "rounding error in totals",
            "missed_check_ids": ["unit"], "regression_test_id": "unit",
            "discovered_at": 5000}), encoding="utf-8")
        code, out, err = self.invoke("impeach", sha, "--repo", str(self.repo),
                                  "--evidence", str(defect), "--test", "unit")
        self.assertEqual(code, 0, err)
        self.assertIn("unit", out)
        code, out, _ = self.invoke("verify", sha, "--repo", str(self.repo), "--json")
        self.assertEqual(code, 1)
        document = json.loads(out)
        self.assertEqual(document["state"], "IMPEACHED")
        self.assertTrue(document["signature_valid"])
        code, out, _ = self.invoke("status", "--repo", str(self.repo), "--json")
        self.assertEqual(json.loads(out)["defects"], 1)

    def test_impeach_requires_a_defect_evidence_file(self):
        sha = self.make()
        code, out, err = self.invoke("impeach", sha, "--repo", str(self.repo),
                                  "--evidence", str(self.tmp / "nope.json"))
        self.assertEqual(code, 2)
        self.assertIn("evidence", (out + err).lower())


class CLIContractTest(CLICase):
    def test_unknown_command_exits_two(self):
        code, _, err = self.invoke("teleport")
        self.assertEqual(code, 2)

    def test_no_command_prints_usage_and_exits_two(self):
        code, out, err = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn("admissible", (out + err).lower())

    def test_module_entry_point_is_installed(self):
        result = subprocess.run(
            [sys.executable, "-m", "admissible", "profiles", "--json"],
            cwd=str(ROOT), env=dict(os.environ), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(
            len(json.loads(result.stdout.decode("utf-8"))["profiles"]), 8)


if __name__ == "__main__":
    unittest.main()


class PreviewAndFinalizeTest(CLICase):
    """The CI two-boundary flow, driven exactly as the action drives it."""

    def preview(self, sha):
        path = self.tmp / "preview.json"
        code, out, err = self.invoke(
            "run", "--repo", str(self.repo), "--sha", sha,
            "--preview-out", str(path), "--json")
        self.assertEqual(code, 0, err + out)
        return path

    def observed(self, path):
        """The external observer's signed statement about that preview."""

        out = self.tmp / "evaluation.json"
        preview = json.loads(path.read_text(encoding="utf-8"))
        out.write_text(json.dumps(attestation_module.attest_preview(
            preview, key_id=OBSERVER_KEY_ID, secret=OBSERVER_SECRET,
            isolation="pid-namespace",
            source_receipt=source_receipt_document(preview["commit_sha"]),
            observed_at=max(int(time.time()), preview["issued_at"]))),
            encoding="utf-8")
        keyring = self.tmp / "observers.json"
        keyring.write_text(json.dumps(
            {OBSERVER_KEY_ID: OBSERVER_SECRET.decode()}), encoding="utf-8")
        os.chmod(keyring, 0o600)
        os.environ["ADMISSIBLE_EVALUATION_KEYRING"] = str(keyring)
        return out

    def trusted(self):
        """The operator's one deliberate act: this policy may enforce here."""

        from admissible import config as config_module
        from admissible import store as store_module

        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        parsed = config_module.load_config(self.repo)
        for artifact_class in parsed.classes:
            opened.trust_policy(
                repository="github.com/acme/widget",
                class_id=artifact_class.id,
                policy_digest=artifact_class.policy_digest,
                enforcement_digest=config_module.enforcement_digest(
                    artifact_class),
                trusted_at=int(time.time()))

    def finalize(self, path, sha, *extra):
        self.trusted()
        return self.invoke(
            "finalize", "--preview", str(path), "--sha", sha,
            "--repo", str(self.repo), "--policy-root", str(self.repo),
            "--evaluation-attestation", str(self.observed(path)), *extra)

    def test_preview_out_writes_an_unsigned_finalizable_artifact(self):
        sha = self.make()
        del os.environ["ADMISSIBLE_HMAC_KEY"]
        path = self.preview(sha)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], "admissible/v0.6/workflow-preview")
        self.assertEqual(document["commit_sha"], sha)
        self.assertEqual(document["state"], "CHECKS_PASSED")
        self.assertIs(document["fork"], False)
        self.assertNotIn("signature", json.dumps(document))

    def test_finalize_signs_a_preview_and_makes_it_current(self):
        sha = self.make()
        path = self.preview(sha)
        code, out, err = self.finalize(path, sha, "--json")
        self.assertEqual(code, 0, err + out)
        self.assertEqual(len(json.loads(out)["receipt_hash"]), 64)
        code, out, _ = self.invoke("verify", sha, "--repo", str(self.repo),
                                   "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["state"], "CURRENT")

    def test_finalize_rechecks_the_policy_in_this_checkout(self):
        sha = self.make()
        path = self.preview(sha)
        code, out, err = self.finalize(path, sha, "--json")
        self.assertEqual(code, 0, err + out)

    def test_finalize_refuses_a_different_sha(self):
        sha = self.make()
        path = self.preview(sha)
        code, out, err = self.finalize(path, "9" * 40)
        self.assertEqual(code, 2)
        self.assertIn("9" * 40, out + err)

    def test_finalize_without_a_key_is_blocked(self):
        sha = self.make()
        path = self.preview(sha)
        del os.environ["ADMISSIBLE_HMAC_KEY"]
        code, out, err = self.finalize(path, sha)
        self.assertEqual(code, 2)
        self.assertIn("ADMISSIBLE_HMAC_KEY", out + err)

    def test_finalize_without_a_trusted_checkout_is_blocked(self):
        sha = self.make()
        path = self.preview(sha)
        code, out, err = self.invoke(
            "finalize", "--preview", str(path), "--sha", sha,
            "--repo", str(self.repo), "--evaluation-attestation",
            str(self.observed(path)))
        self.assertEqual(code, 2)
        self.assertIn("policy-root", out + err)

    def test_finalize_without_an_evaluation_attestation_is_blocked(self):
        sha = self.make()
        path = self.preview(sha)
        code, out, err = self.invoke(
            "finalize", "--preview", str(path), "--sha", sha,
            "--repo", str(self.repo), "--policy-root", str(self.repo))
        self.assertEqual(code, 2)
        self.assertIn("evaluation-attestation", out + err)

    def test_finalize_without_a_trusted_policy_baseline_is_blocked(self):
        """A candidate may propose a policy; only an operator anchors one."""

        sha = self.make()
        path = self.preview(sha)
        code, out, err = self.invoke(
            "finalize", "--preview", str(path), "--sha", sha,
            "--repo", str(self.repo), "--policy-root", str(self.repo),
            "--evaluation-attestation", str(self.observed(path)))
        self.assertEqual(code, 2)
        self.assertIn("policy trust", out + err)

    def test_a_written_receipt_names_the_admission_it_anchored(self):
        sha = self.make()
        path = self.preview(sha)
        out_path = self.tmp / "receipt.json"
        code, out, err = self.finalize(path, sha, "--out", str(out_path),
                                       "--json")
        self.assertEqual(code, 0, err + out)
        written = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(written["receipt_hash"],
                         json.loads(out)["receipt_hash"])

    def test_a_failed_receipt_write_never_hides_an_anchored_admission(self):
        """The one lie an automated caller cannot recover from."""

        sha = self.make()
        path = self.preview(sha)
        unwritable = self.tmp / "no-such-directory" / "receipt.json"
        code, out, err = self.finalize(path, sha, "--out", str(unwritable))
        self.assertEqual(code, 2)
        text = out + err
        self.assertIn("IS anchored", text)
        # And it is: standing agrees, whatever this invocation returned.
        code, out, _ = self.invoke("verify", sha, "--repo", str(self.repo),
                                   "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["state"], "CURRENT")


class DependencyTest(CLICase):
    """A consumer records what it depends on; impeachment can then reach it."""

    def test_depends_on_is_recorded_and_reported_by_explain(self):
        upstream = "github.com/acme/upstream@" + ("7" * 40)
        _sha, issued = self.admitted(run_args=("--depends-on", upstream))
        self.assertEqual(issued.dependencies,
                         (("github.com/acme/upstream", "7" * 40),))

    def test_malformed_depends_on_is_blocked(self):
        sha = self.make()
        code, out, err = self.invoke("run", "--repo", str(self.repo),
                                     "--sha", sha, "--depends-on", "not-a-ref")
        self.assertEqual(code, 2)
        self.assertIn("REPOSITORY@FULL_SHA", out + err)


class EdgeCaseTest(CLICase):
    def test_unknown_class_is_blocked_and_lists_the_real_ones(self):
        sha = self.make()
        code, out, err = self.invoke("run", "--repo", str(self.repo),
                                     "--sha", sha, "--class", "nope")
        self.assertEqual(code, 2)
        self.assertIn("default", out + err)

    def test_explain_on_an_unknown_commit_still_answers_the_three_questions(self):
        self.make()
        code, out, _ = self.invoke("explain", "9" * 40, "--repo", str(self.repo))
        self.assertEqual(code, 1)
        lowered = out.lower()
        self.assertIn("what happened", lowered)
        self.assertIn("what is known", lowered)
        self.assertIn("what to do next", lowered)

    def test_run_json_reports_a_blocked_error_as_json(self):
        sha = self.make()
        (self.repo / "README.md").write_text("dirty\n", encoding="utf-8")
        code, out, _ = self.invoke("run", "--repo", str(self.repo), "--sha", sha,
                                   "--json")
        self.assertEqual(code, 2)
        document = json.loads(out)
        self.assertEqual(document["state"], "BLOCKED")
        self.assertTrue(document["remediation"])

    def test_verify_accepts_a_receipt_hash_as_the_target(self):
        sha, issued = self.admitted()
        code, out, _ = self.invoke("verify", issued.receipt_hash, "--repo",
                                   str(self.repo), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["commit_sha"], sha)


class ExplainScenarioTest(CLICase):
    """`explain` must answer every refusal shape from what is on record."""

    def admit(self, document=None):
        return self.admitted(document)[0]

    def explain(self, target, *extra):
        code, out, err = self.invoke("explain", target, "--repo",
                                     str(self.repo), *extra)
        return code, out + err

    def test_missing_check_is_explained_without_running_anything(self):
        sha = self.admit()
        # Add a second required check to the policy after the fact: the stored
        # evidence no longer satisfies the current policy.
        document = json.loads(
            (self.repo / ".admissible.json").read_text(encoding="utf-8"))
        document["classes"][0]["checks"].append({
            "id": "lint", "argv": [sys.executable, "-c", "pass"],
            "timeout_seconds": 60, "cost_units": 1, "required": True,
            "version": "1"})
        (self.repo / ".admissible.json").write_text(json.dumps(document),
                                                    encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "tighten")
        code, text = self.explain(sha)
        self.assertIn("missing_check", text)
        self.assertIn("lint", text)

    def test_failed_check_is_explained(self):
        sha = self.make(config_document(
            [sys.executable, "-c", "raise SystemExit(2)"]))
        self.assertEqual(self.invoke("run", "--repo", str(self.repo),
                                     "--sha", sha)[0], 1)
        code, text = self.explain(sha)
        self.assertEqual(code, 1)
        self.assertIn("failed_check", text)

    def test_timeout_is_explained(self):
        sha = self.make({
            "version": 1, "profile": "python-library",
            "classes": [{
                "id": "default",
                "checks": [{"id": "slow",
                            "argv": [sys.executable, "-c",
                                     "import time;time.sleep(30)"],
                            "timeout_seconds": 1, "cost_units": 1,
                            "required": True, "version": "1"}],
                "required_independent_reviews": 0,
                "review_max_age_seconds": 86400,
                "max_cost_units": 10, "max_wall_seconds": 600}]})
        self.assertEqual(self.invoke("run", "--repo", str(self.repo),
                                     "--sha", sha)[0], 1)
        code, text = self.explain(sha)
        self.assertIn("check_timeout", text)

    def test_missing_independent_review_is_explained(self):
        sha = self.make(config_document(
            [sys.executable, "-c", "print('ok')"], reviews=1,
            reviewer_key_ids=["reviewer-key-a"]))
        self.assertEqual(self.invoke("run", "--repo", str(self.repo),
                                     "--sha", sha)[0], 1)
        code, text = self.explain(sha)
        self.assertIn("missing_independent_review", text)

    def test_an_unevaluated_commit_is_explained_as_having_no_attempt(self):
        """A commit nobody evaluated is not "missing checks"; it is unobserved.

        Re-judging its stored records as though they were one observation would
        invent an attempt that never happened and report the invention as a
        finding. What is actually known is that nothing here observed this
        commit, and that is what it says.
        """

        self.admit()
        (self.repo / "README.md").write_text("moved on\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "next")
        head = git(self.repo, "rev-parse", "HEAD")
        code, text = self.explain(head)
        self.assertEqual(code, 1)
        self.assertIn("no attempt is recorded", text)
        self.assertIn(head, text)

    def test_budget_ceiling_is_explained(self):
        sha = self.admit()
        document = json.loads(
            (self.repo / ".admissible.json").read_text(encoding="utf-8"))
        document["classes"][0]["max_cost_units"] = 0
        (self.repo / ".admissible.json").write_text(json.dumps(document),
                                                    encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "tiny budget")
        code, text = self.explain(sha)
        self.assertIn("cost_ceiling", text)

    def test_invalid_signature_is_explained(self):
        sha = self.admit()
        os.environ["ADMISSIBLE_HMAC_KEY"] = "a-different-secret"
        code, text = self.explain(sha)
        self.assertEqual(code, 1)
        self.assertIn("signature", text.lower())

    def test_a_head_that_is_no_longer_current_is_explained(self):
        first = self.admit()
        (self.repo / "README.md").write_text("second\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "second")
        second = git(self.repo, "rev-parse", "HEAD")
        # A second anchored admission moves the journal head past the first.
        admit(self, self.repo, second)
        code, text = self.explain(first)
        self.assertEqual(code, 0)
        self.assertIn("no longer the current head", text)

    def test_impeachment_is_explained(self):
        sha = self.admit()
        defect = self.tmp / "defect.json"
        defect.write_text(json.dumps({
            "kind": "defect", "defect_id": "d1",
            "repository": "github.com/acme/widget", "commit_sha": sha,
            "severity": "high", "summary": "wrong totals",
            "missed_check_ids": ["unit"], "regression_test_id": "unit",
            "discovered_at": 5000}), encoding="utf-8")
        self.assertEqual(self.invoke("impeach", sha, "--repo", str(self.repo),
                                     "--evidence", str(defect))[0], 0)
        code, text = self.explain(sha)
        self.assertEqual(code, 1)
        self.assertIn("IMPEACHED", text)
        self.assertIn("wrong totals", text)


class ExportImportTest(CLICase):
    def test_export_and_import_move_a_journal_between_stores(self):
        sha, _issued = self.admitted()
        bundle = self.tmp / "journal.json"
        code, out, err = self.invoke("export", "--out", str(bundle), "--repo",
                                     str(self.repo))
        self.assertEqual(code, 0, err + out)
        self.assertTrue(bundle.is_file())

        other = self.tmp / "other-home"
        os.environ["ADMISSIBLE_HOME"] = str(other)
        code, out, err = self.invoke("verify", sha, "--repo", str(self.repo))
        self.assertEqual(code, 1)
        code, out, err = self.invoke("import", "--in", str(bundle), "--repo",
                                     str(self.repo))
        self.assertEqual(code, 0, err + out)
        code, out, _ = self.invoke("verify", sha, "--repo", str(self.repo),
                                   "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["state"], "CURRENT")

    def test_importing_a_rollback_is_refused(self):
        sha, _issued = self.admitted()
        bundle = self.tmp / "journal.json"
        self.assertEqual(self.invoke("export", "--out", str(bundle), "--repo",
                                     str(self.repo))[0], 0)
        defect = self.tmp / "defect.json"
        defect.write_text(json.dumps({
            "kind": "defect", "defect_id": "d1",
            "repository": "github.com/acme/widget", "commit_sha": sha,
            "severity": "low", "summary": "later news",
            "missed_check_ids": [], "regression_test_id": "unit",
            "discovered_at": 5000}), encoding="utf-8")
        self.assertEqual(self.invoke("impeach", sha, "--repo", str(self.repo),
                                     "--evidence", str(defect))[0], 0)
        code, out, err = self.invoke("import", "--in", str(bundle), "--repo",
                                     str(self.repo))
        self.assertEqual(code, 2)
        self.assertIn("roll", (out + err).lower())


class EvidenceBundleTest(CLICase):
    def test_run_refuses_a_bundle_that_carries_defect_records(self):
        sha = self.make()
        bundle = self.tmp / "bundle.json"
        bundle.write_text(json.dumps({
            "schema": "admissible/v0.6/workflow-evidence",
            "commands": [], "reviews": [],
            "defects": [{
                "kind": "defect", "defect_id": "d1",
                "repository": "github.com/acme/widget", "commit_sha": sha,
                "severity": "high", "summary": "smuggled in through --evidence",
                "missed_check_ids": [], "regression_test_id": "unit",
                "discovered_at": 1}],
            "attestations": []}), encoding="utf-8")
        code, out, err = self.invoke("run", "--repo", str(self.repo),
                                     "--sha", sha, "--evidence", str(bundle))
        self.assertEqual(code, 2)
        self.assertIn("impeach", (out + err).lower())
        code, out, _ = self.invoke("status", "--repo", str(self.repo), "--json")
        self.assertEqual(json.loads(out)["defects"], 0)
