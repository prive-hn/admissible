"""Contract: finalization consumes retained files, re-derives, and refuses.

This is the end-to-end claim the whole distribution exists to make.  A preview
produced somewhere else -- here, by the monolith standing in for the candidate
domain -- is handed to Trust with an observer's attestation beside it.  Trust
opens files, re-derives repository, commit, tree, configuration and policy
through Core and its fixed Git reader, recomputes the decision from the
retained evidence and the trusted baseline, and only then issues and anchors
one receipt.

Two things are asserted about the *result*: it is byte-identical to what the
monolith produces from the same inputs, and it is what an authenticated read
back through this distribution reports as ``CURRENT`` and ``ready``.

Everything else here is a refusal.  The failure matrix is the substance of the
contract, because a finalizer is defined by what it will not sign: a stale
head, a different tree, an untrusted or changed policy, a dirty checkout, a
fork preview, an observer who asserted no isolation boundary, a review bound to
another artefact, an attestation from a key nobody pinned, a missing admission
key, a reviewer keyring that shares a secret with the admission key, a home
with a live sidecar, a home a newer build wrote, and a stored row somebody
edited afterwards.

Two of those refusals are about the *reading* itself rather than about what
was read: the preview is consumed under a byte ceiling that metadata cannot
talk it out of, and a dependency edge is typed before anything sorts, signs or
records it.  Both are stated over a credentialed process, which is why they are
stated here and not left to the shape of a traceback.

Nothing here starts a candidate process, and the trap in
``test_admissible_trust_boundary`` proves it for the same code path.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from admissible import cli as legacy_cli
from admissible import github as legacy_github
from admissible import receipt as legacy_receipt
from admissible import runner as legacy_runner
from admissible import store as legacy_store

from admissible_core import config as config_module
from admissible_core import store_base

from admissible_trust import attestation as attestation_module
from admissible_trust import cli as trust_cli
from admissible_trust import defects as defects_module
from admissible_trust import github as trust_github
from admissible_trust import ready_status
from admissible_trust import receipt as trust_receipt
from admissible_trust import standing as standing_module
from admissible_trust import store as trust_store

OBSERVER_KEY_ID = "observer-1"
OBSERVER_SECRET = b"test-external-observer-secret-not-real"
ADMISSION_SECRET = "test-admission-secret-not-real"

GIT_ENV = {
    "GIT_AUTHOR_NAME": "Admissible Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Admissible Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}

POLICY = {
    "version": 1,
    "profile": "python-library",
    "title": "Widget",
    "summary": "A finalization fixture, not a real policy.",
    "classes": [{
        "id": "default",
        "description": "one required check, no independent review",
        "checks": [{
            "id": "unit", "argv": ["/usr/bin/true"], "timeout_seconds": 60,
            "cost_units": 1, "required": True, "version": "1",
            "description": "A command every machine has.",
            "cacheable": False,
        }],
        "required_independent_reviews": 0,
        "review_max_age_seconds": 86400,
        "max_cost_units": 10,
        "max_wall_seconds": 600,
    }],
}


def git(root: Path, *args: str) -> str:
    environment = dict(os.environ)
    environment.update(GIT_ENV)
    completed = subprocess.run(
        ("git", *args), cwd=str(root), env=environment, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    return completed.stdout.decode("utf-8").strip()


class FinalizationCase(unittest.TestCase):
    """One real repository, one retained preview, one observer attestation."""

    def setUp(self) -> None:
        raw = tempfile.mkdtemp(prefix="trust-final-")
        self.addCleanup(shutil.rmtree, raw, True)
        self.tmp = Path(raw)
        self.home = self.tmp / "home"
        self.home.mkdir()
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(),
                                 os.environ.update(saved)))
        for name in list(os.environ):
            if name.startswith("ADMISSIBLE_") or name.startswith("GITHUB_"):
                del os.environ[name]
        os.environ.update(GIT_ENV)
        os.environ["ADMISSIBLE_HOME"] = str(self.home)
        os.environ["ADMISSIBLE_ISOLATION"] = "pid-namespace"

        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        (self.repo / "README.md").write_text("widget\n", encoding="utf-8")
        (self.repo / ".admissible.json").write_text(
            json.dumps(POLICY, indent=2) + "\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "initial")
        git(self.repo, "remote", "add", "origin",
            "https://github.com/acme/widget.git")
        self.sha = git(self.repo, "rev-parse", "HEAD")
        self.moment = int(time.time())
        self.preview_path = self.tmp / "preview.json"
        self.attestation_path = self.tmp / "evaluation.json"
        self.evaluate()

    # -- fixtures ----------------------------------------------------------
    def evaluate(self) -> None:
        """Produce the retained preview in the domain that runs commands.

        The monolith stands in for the candidate distribution here: this suite
        deliberately cannot import ``admissible_ready``, and what matters for
        finalization is the artefact, not who wrote it. The cross-process
        handoff suite drives the real Ready wheel.
        """

        argv = ["run", "--preview", "--repo", str(self.repo), "--sha",
                self.sha, "--preview-out", str(self.preview_path), "--json"]
        out, err = io.StringIO(), io.StringIO()
        lifted = {name: os.environ.pop(name)
                  for name in legacy_runner.SIGNING_CREDENTIAL_NAMES
                  if name in os.environ}
        try:
            code = legacy_cli.main(argv, stdout=out, stderr=err)
        finally:
            os.environ.update(lifted)
        self.assertEqual(0, code, out.getvalue() + err.getvalue())
        self.preview = json.loads(
            self.preview_path.read_text(encoding="utf-8"))
        self.attest_evaluation()

    def source_receipt(self, **overrides) -> dict:
        document = {
            "schema": "admissible/v0.6/external-source-receipt",
            "provider": "github-actions",
            "run_id": "17825349901",
            "commit_sha": self.sha,
            "conclusion": "success",
            "receipt_digest": "a1" * 32,
        }
        document.update(overrides)
        return document

    def attest_evaluation(self, *, isolation="pid-namespace",
                          secret=OBSERVER_SECRET, key_id=OBSERVER_KEY_ID,
                          preview=None, **receipt_overrides) -> Path:
        document = attestation_module.attest_preview(
            self.preview if preview is None else preview,
            key_id=key_id, secret=secret, isolation=isolation,
            source_receipt=self.source_receipt(**receipt_overrides),
            observed_at=max(self.moment, self.preview["issued_at"]))
        self.attestation_path.write_text(json.dumps(document),
                                         encoding="utf-8")
        return self.attestation_path

    def signer(self):
        return trust_receipt.signer_from_secret(
            "local", ADMISSION_SECRET.encode("utf-8"))

    def opened(self, home: Path | None = None):
        store = trust_store.open_store(self.home if home is None else home)
        self.addCleanup(store.close)
        return store

    def trust_the_policy(self, store, *, policy=None) -> None:
        parsed = config_module.load_config(
            self.repo if policy is None else policy)
        for artifact_class in parsed.classes:
            store.trust_policy(
                repository=self.preview["repository"],
                class_id=artifact_class.id,
                policy_digest=artifact_class.policy_digest,
                enforcement_digest=config_module.enforcement_digest(
                    artifact_class),
                trusted_at=self.moment)

    def finalize(self, store=None, **overrides):
        store = self.opened() if store is None else store
        arguments = {
            "preview_path": self.preview_path,
            "signer": self.signer(),
            "expected_sha": self.sha,
            "now": max(self.moment, self.preview["issued_at"]),
            "policy_root": self.repo,
            "evaluation_attestation": self.attestation_path,
            "evaluation_keyring": {OBSERVER_KEY_ID: OBSERVER_SECRET},
            "keyring": {},
            "environment": {},
        }
        arguments.update(overrides)
        preview_path = arguments.pop("preview_path")
        return trust_github.finalize(store, preview_path, **arguments)

    def admitted(self):
        store = self.opened()
        self.trust_the_policy(store)
        return store, self.finalize(store)


class ARetainedPreviewBecomesAReceipt(FinalizationCase):
    def test_finalization_issues_an_authenticated_current_receipt(self):
        store, receipt = self.admitted()
        self.assertEqual(self.sha, receipt.commit_sha)
        self.assertEqual("ADMITTED", receipt.state)
        self.assertTrue(
            trust_receipt.verify_current(store, receipt, self.signer()))

    def test_standing_is_current_under_the_same_key(self):
        store, receipt = self.admitted()
        state = standing_module.current_standing(
            store, receipt.repository, receipt.commit_sha,
            verifier=self.signer())
        self.assertEqual(standing_module.CURRENT, state.state)
        self.assertEqual(0, state.exit_code)

    def test_standing_without_a_verifier_is_unknown(self):
        store, receipt = self.admitted()
        state = standing_module.current_standing(
            store, receipt.repository, receipt.commit_sha, verifier=None)
        self.assertEqual(standing_module.UNKNOWN, state.state)

    def test_standing_under_a_different_key_is_unknown(self):
        store, receipt = self.admitted()
        other = trust_receipt.signer_from_secret("local", b"not-the-key")
        state = standing_module.current_standing(
            store, receipt.repository, receipt.commit_sha, verifier=other)
        self.assertEqual(standing_module.UNKNOWN, state.state)
        self.assertTrue(state.unauthenticated or state.integrity_problem)

    def test_the_authenticated_ready_projection_says_ready(self):
        store, receipt = self.admitted()
        store.close()
        document = ready_status.inspect_authenticated(
            str(self.repo), verifier=self.signer(), home=self.home)
        self.assertEqual("ready", document["status"])
        self.assertEqual("ADMITTED", document["canonical"]["state"])
        self.assertEqual("CURRENT", document["canonical"]["standing"])
        self.assertEqual(receipt.receipt_hash,
                         document["advanced"]["receipt_hash"])

    def test_an_authenticated_projection_needs_a_verifier(self):
        with self.assertRaises(ready_status.ReadyError):
            ready_status.inspect_authenticated(
                str(self.repo), verifier=None, home=self.home)

    def test_a_wrong_key_never_promotes_to_ready(self):
        store, _receipt = self.admitted()
        store.close()
        other = trust_receipt.signer_from_secret("local", b"not-the-key")
        document = ready_status.inspect_authenticated(
            str(self.repo), verifier=other, home=self.home)
        self.assertNotEqual("ready", document["status"])

    def test_issuance_is_idempotent(self):
        store, first = self.admitted()
        second = self.finalize(store)
        self.assertEqual(first.receipt_hash, second.receipt_hash)
        self.assertEqual(1, store.receipt_count(first.repository))

    def test_the_expected_body_digest_matches_what_issuance_wrote(self):
        store = self.opened()
        self.trust_the_policy(store)
        expected = trust_github.expected_finalization_receipt_body_digest(
            store, self.preview_path, expected_sha=self.sha,
            now=max(self.moment, self.preview["issued_at"]),
            policy_root=self.repo,
            evaluation_attestation=self.attestation_path,
            evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
            keyring={}, environment={})
        receipt = self.finalize(store)
        self.assertEqual(expected, receipt.body_digest)

    def test_a_guarded_body_digest_that_disagrees_refuses(self):
        store = self.opened()
        self.trust_the_policy(store)
        with self.assertRaises(trust_github.GitHubError):
            self.finalize(store, expected_body_digest="b" * 64)
        self.assertEqual(0, store.receipt_count(self.preview["repository"]))


class FinalizationStartsNothingButAnIdentityRead(FinalizationCase):
    """The runtime half of the boundary claim, on the path that signs.

    ``test_admissible_trust_boundary`` proves that no Trust module *names* a
    process starter except the git adapter. That is a fact about source text.
    This is the fact about behaviour: a whole finalization runs with every
    executor trapped, and the only argument vectors that reach the trap are
    ``git`` queries from the adapter's fixed vocabulary, run against the
    trusted checkout.
    """

    def armed(self):
        """Record every child this process starts, and refuse the other doors.

        The recorder sits on ``Popen`` rather than on ``run``, because ``run``
        is implemented in terms of ``Popen``: trapping the outer one would miss
        a direct ``Popen`` call, and trapping both would make the outer call
        trip the inner refusal. Everything that starts a process without going
        through ``Popen`` at all -- ``os.system``, ``exec*``, ``posix_spawn``
        -- refuses outright.
        """

        from unittest import mock

        seen: list[tuple[str, ...]] = []
        real_popen = subprocess.Popen

        class Recording(real_popen):
            def __init__(self, argv, *args, **kwargs):
                seen.append((argv,) if isinstance(argv, str) else tuple(argv))
                super().__init__(argv, *args, **kwargs)

        def refuse(*args, **kwargs):
            raise AssertionError(f"finalization started a process: {args!r}")

        patches = [
            mock.patch("subprocess.Popen", Recording),
            mock.patch.object(os, "system", refuse),
            mock.patch.object(os, "execv", refuse),
            mock.patch.object(os, "posix_spawn", refuse),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return seen

    def test_only_fixed_git_identity_queries_run_during_finalization(self):
        store = self.opened()
        self.trust_the_policy(store)
        seen = self.armed()
        receipt = self.finalize(store)
        self.assertTrue(receipt.receipt_hash)
        self.assertTrue(seen, "the trap must actually be reachable")
        from admissible_trust import git_reader

        # ``argv[0]`` is the absolute system executable the adapter resolved
        # and validated, never the bare word: a name would be looked up in the
        # ``PATH`` a candidate's tooling wrote.
        executable = git_reader.trusted_git_executable()
        for argv in seen:
            with self.subTest(argv=argv):
                self.assertEqual(
                    (executable, "-c", "core.fsmonitor=false", "-c",
                     "core.hooksPath=/dev/null", "-C"), argv[:6])
                self.assertIn(argv[7],
                              ("rev-parse", "status", "remote", "rev-list"))

    def test_the_only_working_tree_it_reads_is_the_trusted_checkout(self):
        """The first query names what the caller passed; the rest name what
        ``git rev-parse --show-toplevel`` answered, which on this platform may
        be the resolved path. Both are the trusted checkout and nothing else.
        """

        store = self.opened()
        self.trust_the_policy(store)
        seen = self.armed()
        self.finalize(store)
        roots = {argv[argv.index("-C") + 1] for argv in seen}
        self.assertEqual(
            set(), roots - {str(self.repo), str(self.repo.resolve())})

    def test_identity_is_captured_once_and_re_read_only_as_the_contract_says(self):
        """One capture, and the closing ``HEAD`` read the kernel requires.

        ``admissible_core.identity.repository_identity`` brackets its own read:
        it asks for ``HEAD`` at the start and again at the end, and refuses if
        the two disagree, so the result is a snapshot rather than a summary of
        a moving tree. That second read is the only re-read finalization makes,
        and it is why ``rev-parse HEAD`` appears exactly twice.
        """

        store = self.opened()
        self.trust_the_policy(store)
        seen = self.armed()
        self.finalize(store)
        tail = [argv[7:] for argv in seen]
        self.assertEqual(2, tail.count(("rev-parse", "HEAD")))
        self.assertEqual(1, tail.count(("rev-parse", "--show-toplevel")))
        self.assertEqual(
            1, tail.count(("status", "--porcelain", "--untracked-files=all")))

    def test_no_argument_vector_mentions_the_policy_s_own_command(self):
        """The candidate's ``argv`` exists in the policy and reaches nothing."""

        store = self.opened()
        self.trust_the_policy(store)
        seen = self.armed()
        self.finalize(store)
        for argv in seen:
            with self.subTest(argv=argv):
                self.assertNotIn("/usr/bin/true", argv)


class TheMonolithAndTheSplitAgreeExactly(FinalizationCase):
    """Same preview, same key, same moment: the same receipt document."""

    def test_the_issued_receipt_documents_are_byte_identical(self):
        from fcd.journal import canonical_json

        trust_home = self.tmp / "trust-home"
        legacy_home = self.tmp / "legacy-home"
        store = self.opened(trust_home)
        self.trust_the_policy(store)
        mine = self.finalize(store)

        legacy = legacy_store.open_store(legacy_home)
        self.addCleanup(legacy.close)
        parsed = config_module.load_config(self.repo)
        for artifact_class in parsed.classes:
            legacy.trust_policy(
                repository=self.preview["repository"],
                class_id=artifact_class.id,
                policy_digest=artifact_class.policy_digest,
                enforcement_digest=config_module.enforcement_digest(
                    artifact_class),
                trusted_at=self.moment)
        theirs = legacy_github.finalize(
            legacy, self.preview_path,
            signer=legacy_receipt.signer_from_secret(
                "local", ADMISSION_SECRET.encode("utf-8")),
            expected_sha=self.sha,
            now=max(self.moment, self.preview["issued_at"]),
            policy_root=self.repo,
            evaluation_attestation=self.attestation_path,
            evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
            keyring={}, environment={})

        self.assertEqual(theirs.body_digest, mine.body_digest)
        self.assertEqual(theirs.receipt_hash, mine.receipt_hash)
        self.assertEqual(
            canonical_json(legacy_receipt.receipt_to_dict(theirs)),
            canonical_json(trust_receipt.receipt_to_dict(mine)))

    def test_the_expected_body_digests_agree_before_anything_is_written(self):
        trust_home = self.tmp / "trust-home"
        legacy_home = self.tmp / "legacy-home"
        store = self.opened(trust_home)
        self.trust_the_policy(store)
        legacy = legacy_store.open_store(legacy_home)
        self.addCleanup(legacy.close)
        parsed = config_module.load_config(self.repo)
        for artifact_class in parsed.classes:
            legacy.trust_policy(
                repository=self.preview["repository"],
                class_id=artifact_class.id,
                policy_digest=artifact_class.policy_digest,
                enforcement_digest=config_module.enforcement_digest(
                    artifact_class),
                trusted_at=self.moment)
        arguments = dict(
            expected_sha=self.sha,
            now=max(self.moment, self.preview["issued_at"]),
            policy_root=self.repo,
            evaluation_attestation=self.attestation_path,
            evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
            keyring={}, environment={})
        self.assertEqual(
            legacy_github.expected_finalization_receipt_body_digest(
                legacy, self.preview_path, **arguments),
            trust_github.expected_finalization_receipt_body_digest(
                store, self.preview_path, **arguments))


class TheFailureMatrix(FinalizationCase):
    """What a finalizer will not sign, one refusal per reason."""

    def prepared(self):
        store = self.opened()
        self.trust_the_policy(store)
        return store

    def assert_nothing_anchored(self, store):
        self.assertEqual(0, store.receipt_count(self.preview["repository"]))
        self.assertIsNone(store.current_head(
            trust_receipt.journal_id_for(self.preview["repository"])))

    def edited_preview(self, **changes) -> Path:
        document = dict(self.preview)
        document.update(changes)
        path = self.tmp / "edited-preview.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_an_untrusted_policy_refuses(self):
        store = self.opened()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store)
        self.assertIn("trusted policy baseline", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_changed_policy_refuses(self):
        store = self.opened()
        store.trust_policy(
            repository=self.preview["repository"], class_id="default",
            policy_digest="c" * 64, enforcement_digest="d" * 64,
            trusted_at=self.moment)
        with self.assertRaises(trust_github.GitHubError):
            self.finalize(store)
        self.assert_nothing_anchored(store)

    def test_a_revoked_policy_refuses(self):
        store = self.prepared()
        parsed = config_module.load_config(self.repo)
        store.revoke_policy(
            repository=self.preview["repository"], class_id="default",
            policy_digest=parsed.classes[0].policy_digest,
            revoked_at=self.moment)
        with self.assertRaises(trust_github.GitHubError):
            self.finalize(store)
        self.assert_nothing_anchored(store)

    def test_a_stale_sha_refuses(self):
        store = self.prepared()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, expected_sha="0" * 40)
        self.assertIn("nothing was signed", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_different_tree_refuses(self):
        store = self.prepared()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, preview_path=self.edited_preview(
                tree_sha="b" * 40))
        self.assertIn("tree", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_fork_preview_can_never_be_finalized(self):
        store = self.prepared()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, preview_path=self.edited_preview(fork=True))
        self.assertIn("fork", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_dirty_trusted_checkout_refuses(self):
        store = self.prepared()
        (self.repo / "scratch.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store)
        self.assertIn("uncommitted", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_trusted_checkout_at_another_commit_refuses(self):
        store = self.prepared()
        (self.repo / "later.txt").write_text("later\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "later")
        with self.assertRaises(trust_github.GitHubError):
            self.finalize(store)
        self.assert_nothing_anchored(store)

    def test_an_observer_asserting_no_isolation_refuses(self):
        store = self.prepared()
        self.attest_evaluation(isolation="none")
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store)
        self.assertIn("isolation", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_an_attestation_from_an_unpinned_key_refuses(self):
        store = self.prepared()
        self.attest_evaluation(key_id="observer-nobody-named")
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store)
        self.assertIn("observer", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_an_attestation_signed_with_the_wrong_secret_refuses(self):
        store = self.prepared()
        self.attest_evaluation(secret=b"not-the-observer-secret")
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store)
        self.assertIn("not usable", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_no_attestation_at_all_refuses(self):
        store = self.prepared()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, evaluation_attestation=None)
        self.assertIn("external observer", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_an_empty_observer_keyring_refuses(self):
        store = self.prepared()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, evaluation_keyring={})
        self.assertIn("keyring", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_source_receipt_for_another_commit_refuses(self):
        """Signed deliberately around the observer helper's own refusal.

        ``attest_preview`` already refuses to sign a receipt for a different
        commit, which is the observer declining to lie. This case is the other
        half: an observer that signed anyway, and a finalizer that must not
        accept the result. The body is therefore built and signed directly.
        """

        store = self.prepared()
        body = attestation_module.parse_evaluation(json.loads(
            self.attestation_path.read_text(encoding="utf-8")))["evaluation"]
        body = dict(body)
        body["source_receipt"] = self.source_receipt(commit_sha="0" * 40)
        self.attestation_path.write_text(json.dumps(
            attestation_module.attest(body, key_id=OBSERVER_KEY_ID,
                                      secret=OBSERVER_SECRET)),
            encoding="utf-8")
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store)
        self.assertIn("source receipt", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_cancelled_provider_conclusion_refuses(self):
        store = self.prepared()
        self.attest_evaluation(conclusion="cancelled")
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store)
        self.assertIn("conclusion", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_an_edited_preview_the_observer_did_not_sign_refuses(self):
        store = self.prepared()
        with self.assertRaises(trust_github.GitHubError):
            self.finalize(store, preview_path=self.edited_preview(
                issued_at=self.preview["issued_at"] + 5))
        self.assert_nothing_anchored(store)

    def test_a_missing_admission_signer_refuses(self):
        store = self.prepared()
        with self.assertRaises(trust_receipt.SigningError):
            self.finalize(store, signer=None)
        self.assert_nothing_anchored(store)

    def test_an_admission_key_that_is_also_a_reviewer_key_refuses(self):
        store = self.prepared()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, keyring={
                "reviewer-a": ADMISSION_SECRET.encode("utf-8")})
        self.assertIn("admission key", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_reviewer_keyring_that_maps_one_secret_twice_refuses(self):
        store = self.prepared()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, keyring={"reviewer-a": b"shared",
                                          "reviewer-b": b"shared"})
        self.assertIn("same secret", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_reviewer_and_observer_sharing_a_secret_refuses(self):
        store = self.prepared()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, keyring={"reviewer-a": OBSERVER_SECRET})
        self.assertIn("independent trust roles", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_the_tool_may_not_come_out_of_the_candidate_checkout(self):
        store = self.prepared()
        shadow = self.repo / "admissible_trust"
        shadow.mkdir()
        (shadow / "__init__.py").write_text("", encoding="utf-8")
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store)
        self.assertIn("refusing to finalize", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_every_shadowed_namespace_is_refused(self):
        for namespace in ("admissible", "admissible_core", "admissible_trust"):
            with self.subTest(namespace=namespace):
                root = self.tmp / f"shadow-{namespace}"
                (root / namespace).mkdir(parents=True)
                (root / namespace / "__init__.py").write_text(
                    "", encoding="utf-8")
                with self.assertRaises(trust_github.GitHubError):
                    trust_github.assert_trusted_tool(root)

    def signed_review_bundle(self, **overrides) -> Path:
        """One out-of-band signed review, bound to whatever ``overrides`` say.

        The default is the exact artefact under evaluation; a test overrides
        one element of the candidate tuple to make the review name a different
        one.
        """

        from admissible_trust import review as review_module

        record = {
            "kind": "review", "review_id": "review-1",
            "reviewer_id": "reviewer-a", "reviewer_version": "1",
            "author_id": "author-a", "verdict": "approve",
            "repository": self.preview["repository"],
            "commit_sha": self.sha,
            "tree_sha": self.preview["tree_sha"],
            "policy_digest": self.preview["policy_digest"],
            "findings_digest": "0" * 64,
            "issued_at": self.preview["issued_at"],
            "attempt_id": self.preview["decision"]["attempt_id"],
        }
        record.update(overrides)
        attestation = review_module.attest(
            record, key_id="reviewer-a", secret=b"a-reviewer-secret")
        path = self.tmp / "reviews.json"
        path.write_text(json.dumps({
            "schema": "admissible/v0.6/workflow-evidence",
            "commands": [], "reviews": [], "defects": [],
            "attestations": [attestation], "author_attestations": [],
        }), encoding="utf-8")
        return path

    def test_a_signed_review_bound_to_another_tree_refuses(self):
        """The candidate tuple is what a review approves, and it is exact."""

        store = self.prepared()
        bundle = self.signed_review_bundle(tree_sha="b" * 40)
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, reviews=bundle,
                          keyring={"reviewer-a": b"a-reviewer-secret"})
        self.assertIn("not bound to this exact", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_signed_review_bound_to_another_commit_refuses(self):
        store = self.prepared()
        bundle = self.signed_review_bundle(commit_sha="0" * 40)
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, reviews=bundle,
                          keyring={"reviewer-a": b"a-reviewer-secret"})
        self.assertIn("not bound to this exact", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_signed_review_under_another_policy_refuses(self):
        store = self.prepared()
        bundle = self.signed_review_bundle(policy_digest="9" * 64)
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, reviews=bundle,
                          keyring={"reviewer-a": b"a-reviewer-secret"})
        self.assertIn("not bound to this exact", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_review_bundle_carrying_a_command_record_refuses(self):
        """That transport carries signed human authority and nothing else."""

        store = self.prepared()
        path = self.tmp / "smuggled.json"
        path.write_text(json.dumps({
            "schema": "admissible/v0.6/workflow-evidence",
            "commands": self.preview["evidence"]["commands"],
            "reviews": [], "defects": [],
            "attestations": [], "author_attestations": [],
        }), encoding="utf-8")
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, reviews=path)
        self.assertIn("command record", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_a_review_signed_by_a_key_the_finalizer_does_not_pin_refuses(self):
        store = self.prepared()
        bundle = self.signed_review_bundle()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, reviews=bundle,
                          keyring={"reviewer-b": b"a-different-secret"})
        self.assertIn("not usable", str(caught.exception))
        self.assert_nothing_anchored(store)

    def test_no_policy_root_at_all_refuses(self):
        store = self.prepared()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, policy_root=None)
        self.assertIn("--policy-root", str(caught.exception))
        self.assert_nothing_anchored(store)


class DurableStateRefusals(FinalizationCase):
    """The home itself can make finalization refuse, and it must."""

    def test_a_home_with_a_live_sidecar_cannot_be_opened(self):
        store = self.opened()
        store.close()
        path = store_base.database_path(self.home)
        Path(str(path) + "-wal").write_bytes(b"\x00" * 32)
        with self.assertRaises(trust_store.StoreError):
            trust_store.open_store(self.home)

    def test_a_home_a_newer_build_wrote_cannot_be_opened(self):
        import sqlite3

        self.opened().close()
        connection = sqlite3.connect(str(store_base.database_path(self.home)))
        connection.execute("UPDATE schema_meta SET value=? WHERE key=?",
                           (str(trust_store.SCHEMA_VERSION + 1),
                            store_base.SCHEMA_VERSION_KEY))
        connection.commit()
        connection.close()
        with self.assertRaises(trust_store.StoreError):
            trust_store.open_store(self.home)

    def test_a_forged_receipt_row_makes_standing_unknown_not_current(self):
        import sqlite3

        store, receipt = self.admitted()
        store.close()
        connection = sqlite3.connect(str(store_base.database_path(self.home)))
        try:
            connection.execute("DROP TRIGGER workflow_receipts_no_update")
            document = json.loads(connection.execute(
                "SELECT receipt_json FROM workflow_receipts WHERE "
                "receipt_hash=?", (receipt.receipt_hash,)).fetchone()[0])
            document["class_id"] = "tampered"
            connection.execute(
                "UPDATE workflow_receipts SET receipt_json=? WHERE "
                "receipt_hash=?",
                (json.dumps(document, sort_keys=True), receipt.receipt_hash))
            connection.commit()
        finally:
            connection.close()
        reopened = self.opened()
        state = standing_module.current_standing(
            reopened, receipt.repository, receipt.commit_sha,
            verifier=self.signer())
        self.assertEqual(standing_module.UNKNOWN, state.state)

    def test_a_deleted_evidence_row_makes_standing_unknown_not_current(self):
        import sqlite3

        store, receipt = self.admitted()
        store.close()
        connection = sqlite3.connect(str(store_base.database_path(self.home)))
        try:
            connection.execute("DROP TRIGGER evidence_no_delete")
            connection.execute("DELETE FROM evidence WHERE digest=?",
                               (receipt.evidence_digests[0],))
            connection.commit()
        finally:
            connection.close()
        reopened = self.opened()
        state = standing_module.current_standing(
            reopened, receipt.repository, receipt.commit_sha,
            verifier=self.signer())
        self.assertEqual(standing_module.UNKNOWN, state.state)
        self.assertTrue(state.historical_receipts)
        self.assertTrue(state.integrity_problem)

    def test_an_unsigned_extra_dependency_row_blocks_a_second_issuance(self):
        import sqlite3

        store, receipt = self.admitted()
        store.close()
        connection = sqlite3.connect(str(store_base.database_path(self.home)))
        try:
            connection.execute(
                "INSERT INTO dependencies(consumer_repository, "
                "consumer_commit_sha, dependency_repository, "
                "dependency_commit_sha, recorded_at) VALUES(?,?,?,?,?)",
                (receipt.repository, receipt.commit_sha, "other/repo",
                 "c" * 40, 1))
            connection.commit()
        finally:
            connection.close()
        reopened = self.opened()
        state = standing_module.current_standing(
            reopened, receipt.repository, receipt.commit_sha,
            verifier=self.signer())
        self.assertEqual(standing_module.UNKNOWN, state.state)


class ImpeachmentChangesStandingAndNeverAReceipt(FinalizationCase):
    def defect_document(self) -> dict:
        return {
            "kind": "defect",
            "defect_id": "DEF-1",
            "repository": self.preview["repository"],
            "commit_sha": self.sha,
            "severity": "high",
            "summary": "The widget melts.",
            "missed_check_ids": ["unit"],
            "discovered_at": self.moment + 10,
            "regression_test_id": "unit",
        }

    def test_a_filed_defect_impeaches_without_touching_the_receipt(self):
        store, receipt = self.admitted()
        defects_module.file_defect(store, self.defect_document(),
                                   signer=self.signer(), now=self.moment + 20)
        state = standing_module.current_standing(
            store, receipt.repository, receipt.commit_sha,
            verifier=self.signer())
        self.assertEqual(standing_module.IMPEACHED, state.state)
        self.assertEqual(1, state.exit_code)
        stored = store.workflow_receipt(receipt.receipt_hash)
        self.assertEqual(receipt, stored)

    def test_filing_the_same_defect_twice_is_one_filing(self):
        store, receipt = self.admitted()
        for _ in range(2):
            defects_module.file_defect(
                store, self.defect_document(), signer=self.signer(),
                now=self.moment + 20)
        self.assertEqual(1, store.defect_count(receipt.repository))

    def test_an_impeached_commit_is_not_ready(self):
        store, receipt = self.admitted()
        defects_module.file_defect(store, self.defect_document(),
                                   signer=self.signer(), now=self.moment + 20)
        store.close()
        document = ready_status.inspect_authenticated(
            str(self.repo), verifier=self.signer(), home=self.home)
        self.assertEqual("needs_attention", document["status"])
        self.assertEqual("IMPEACHED", document["canonical"]["standing"])

    def test_the_impact_report_names_the_defect_and_next_steps(self):
        store, receipt = self.admitted()
        defects_module.file_defect(store, self.defect_document(),
                                   signer=self.signer(), now=self.moment + 20)
        report = standing_module.impact_report(
            store, receipt.repository, receipt.commit_sha,
            verifier=self.signer())
        self.assertEqual(standing_module.IMPEACHED, report.state)
        self.assertTrue(report.remediation)
        rendered = standing_module.render_plain(report)
        self.assertIn("DEF-1", rendered)


class TheJournalTravels(FinalizationCase):
    def test_an_export_imports_into_a_clean_home_and_stays_current(self):
        store, receipt = self.admitted()
        bundle = store.export_journal(receipt.journal_id)
        other = self.opened(self.tmp / "other-home")
        head = other.import_journal(bundle, self.signer())
        self.assertEqual(receipt.head.receipt_hash, head.receipt_hash)
        state = standing_module.current_standing(
            other, receipt.repository, receipt.commit_sha,
            verifier=self.signer())
        self.assertEqual(standing_module.CURRENT, state.state)

    def test_an_export_missing_its_evidence_is_refused_on_import(self):
        store, receipt = self.admitted()
        bundle = store.export_journal(receipt.journal_id)
        bundle["evidence"] = []
        other = self.opened(self.tmp / "other-home")
        with self.assertRaises(trust_store.StoreError) as caught:
            other.import_journal(bundle, self.signer())
        self.assertIn("did not travel", str(caught.exception))

    def test_the_exported_bundle_matches_the_monolith_s(self):
        from fcd.journal import canonical_json

        store, receipt = self.admitted()
        mine = store.export_journal(receipt.journal_id)
        store.close()
        legacy = legacy_store.open_store(self.home)
        try:
            theirs = legacy.export_journal(receipt.journal_id)
        finally:
            legacy.close()
        self.assertEqual(canonical_json(theirs), canonical_json(mine))


class TheCommandLineDrivesTheSameThing(FinalizationCase):
    """The verbs a user types, over the same fixture, in this process."""

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = trust_cli.main(list(argv), stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def with_admission_key(self):
        os.environ["ADMISSIBLE_HMAC_KEY"] = ADMISSION_SECRET
        os.environ["ADMISSIBLE_HMAC_KEY_ID"] = "local"

    def test_policy_trust_then_finalize_then_verify(self):
        self.with_admission_key()
        code, out, err = self.run_cli(
            "policy", "trust", "--repo", str(self.repo), "--json")
        self.assertEqual(0, code, err)
        self.assertTrue(json.loads(out)["trusted"])

        os.environ["ADMISSIBLE_EVALUATION_KEYRING"] = str(self.keyring_file())
        code, out, err = self.run_cli(
            "finalize", "--preview", str(self.preview_path), "--sha", self.sha,
            "--policy-root", str(self.repo), "--evaluation-attestation",
            str(self.attestation_path), "--repo", str(self.repo), "--json")
        self.assertEqual(0, code, out + err)
        issued = json.loads(out)
        self.assertEqual(self.sha, issued["commit_sha"])

        code, out, err = self.run_cli(
            "verify", self.sha, "--repo", str(self.repo), "--json")
        self.assertEqual(0, code, out + err)
        self.assertEqual("CURRENT", json.loads(out)["state"])

        code, out, err = self.run_cli(
            "status", "--repo", str(self.repo), "--json")
        self.assertEqual(0, code, out + err)
        self.assertEqual("CURRENT", json.loads(out)["state"])

        code, out, err = self.run_cli(
            "ready-status", "--repo", str(self.repo), "--json")
        self.assertEqual(0, code, out + err)
        self.assertEqual("ready", json.loads(out)["status"])

        code, out, err = self.run_cli(
            "explain", self.sha, "--repo", str(self.repo), "--json")
        self.assertEqual(0, code, out + err)
        self.assertEqual("CURRENT", json.loads(out)["state"])

        bundle_path = self.tmp / "journal.json"
        code, out, err = self.run_cli(
            "export", "--out", str(bundle_path), "--repo", str(self.repo),
            "--json")
        self.assertEqual(0, code, out + err)
        self.assertTrue(bundle_path.is_file())

        other_home = self.tmp / "imported-home"
        os.environ["ADMISSIBLE_HOME"] = str(other_home)
        code, out, err = self.run_cli(
            "import", "--in", str(bundle_path), "--repo", str(self.repo),
            "--json")
        self.assertEqual(0, code, out + err)
        os.environ["ADMISSIBLE_HOME"] = str(self.home)

        defect = self.tmp / "defect.json"
        defect.write_text(json.dumps({
            "kind": "defect", "defect_id": "DEF-9",
            "repository": self.preview["repository"], "commit_sha": self.sha,
            "severity": "high", "summary": "It melts.",
            "missed_check_ids": ["unit"],
            "discovered_at": self.moment + 10,
            "regression_test_id": "unit",
        }), encoding="utf-8")
        code, out, err = self.run_cli(
            "impeach", self.sha, "--evidence", str(defect), "--repo",
            str(self.repo), "--json")
        self.assertEqual(0, code, out + err)
        self.assertEqual("IMPEACHED", json.loads(out)["state"])

        code, out, err = self.run_cli(
            "verify", self.sha, "--repo", str(self.repo), "--json")
        self.assertEqual(1, code)
        self.assertEqual("IMPEACHED", json.loads(out)["state"])

    def keyring_file(self) -> Path:
        path = self.tmp / "observers.json"
        path.write_text(json.dumps(
            {OBSERVER_KEY_ID: OBSERVER_SECRET.decode("utf-8")}),
            encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def test_the_transitional_run_verb_is_an_alias_for_finalize(self):
        self.with_admission_key()
        os.environ["ADMISSIBLE_EVALUATION_KEYRING"] = str(self.keyring_file())
        self.run_cli("policy", "trust", "--repo", str(self.repo), "--json")
        code, out, err = self.run_cli(
            "run", "--preview", str(self.preview_path), "--sha", self.sha,
            "--policy-root", str(self.repo), "--evaluation-attestation",
            str(self.attestation_path), "--repo", str(self.repo), "--json")
        self.assertEqual(0, code, out + err)
        self.assertEqual(self.sha, json.loads(out)["commit_sha"])
        self.assertIn("transitional alias", err)
        self.assertNotIn("transitional alias", out)

    def test_the_transitional_run_verb_refuses_without_a_preview(self):
        code, out, err = self.run_cli("run", "--json")
        self.assertEqual(2, code)
        document = json.loads(out)
        self.assertIn("finalize", document["message"])
        self.assertIn("admissible-ready run --preview",
                      " ".join(document["remediation"]))


class ThePreviewIsReadUnderACeilingMetadataCannotRaise(FinalizationCase):
    """The ceiling is over bytes read, from the object that was opened.

    ``finalize`` runs on the machine that holds the admission key and reads a
    file somebody else wrote.  Asking the *path* how big it is and then reading
    the *path* again asks two questions of two filesystem objects that need not
    be the same one, and never rules out that the second one is unbounded.
    Whoever can write the containing directory answers the first question with
    a small file and the second with a large one, and a credentialed process
    reads whatever arrives into its memory.

    So the claim is stated over bytes: one open, the file type and the content
    both taken from that one descriptor, and never more than
    ``MAX_PREVIEW_BYTES + 1`` bytes consumed from it.  Each test arms one way of
    making metadata lie -- an understated size, a replacement, growth after the
    check, a symbolic link, and a pipe that has no size at all -- and requires
    the same answer.

    The pipe needs no hook, which is why it is here: a FIFO's ``st_size`` is
    honestly zero however many bytes are on their way through it, and the count
    a blocked writer reaches measures exactly what the reader was willing to
    swallow.
    """

    def oversized(self, **changes) -> bytes:
        """A syntactically valid preview exactly one byte over the ceiling."""

        document = dict(self.preview)
        document.update(changes)
        document["config_path"] = ""
        padding = (trust_github.MAX_PREVIEW_BYTES + 1
                   - len(json.dumps(document).encode("utf-8")))
        self.assertGreater(padding, 0)
        document["config_path"] = "x" * padding
        raw = json.dumps(document).encode("utf-8")
        self.assertEqual(trust_github.MAX_PREVIEW_BYTES + 1, len(raw))
        return raw

    @contextlib.contextmanager
    def understated_size(self, path: Path):
        """Make ``path.stat()`` report a plausible size, whatever is on disk.

        A filesystem that reports a stale size, a file whose size is not the
        number of bytes a read returns, and an outright race all present the
        same way to the reader: metadata that is smaller than the content.
        """

        real = Path.stat

        def understating(self_path, *args, **kwargs):
            info = real(self_path, *args, **kwargs)
            if str(self_path) != str(path):
                return info
            fields = list(info)
            fields[6] = 64
            return os.stat_result(fields)

        with mock.patch.object(Path, "stat", understating):
            yield

    @contextlib.contextmanager
    def armed(self, path: Path, *, replacement: bytes | None = None,
              growth: bytes | None = None):
        """Change ``path`` once, the first time anything looks at it.

        Whoever races a credentialed reader acts after that reader's first
        question and before its second, whichever two those are.  So the hook
        fires as soon as any ``stat`` or ``open`` has answered *for this path*
        -- the moment that exposes a check-the-path-then-read-the-path reader
        and leaves an open-once reader untouched, because the descriptor it
        already holds names the object that was checked.
        """

        state = {"fired": False}

        def fire():
            if state["fired"]:
                return
            state["fired"] = True
            if growth is not None:
                with open(path, "ab") as handle:
                    handle.write(growth)
            else:
                scratch = path.with_name(path.name + ".swap")
                scratch.write_bytes(replacement or b"")
                os.replace(scratch, path)

        def wrap(original):
            def wrapper(subject, *args, **kwargs):
                answer = original(subject, *args, **kwargs)
                if str(subject) == str(path):
                    fire()
                return answer
            return wrapper

        with contextlib.ExitStack() as stack:
            for owner, name in ((Path, "stat"), (Path, "open"),
                                (os, "stat"), (os, "open")):
                stack.enter_context(mock.patch.object(
                    owner, name, wrap(getattr(owner, name))))
            yield

    def test_an_understated_size_does_not_raise_the_ceiling(self):
        oversized = self.tmp / "oversized-preview.json"
        oversized.write_bytes(self.oversized())
        store = self.opened()
        with self.understated_size(oversized):
            with self.assertRaises(trust_github.GitHubError) as caught:
                self.finalize(store, preview_path=oversized)
        self.assertIn("too large", str(caught.exception))
        self.assertEqual(0, store.receipt_count(self.preview["repository"]))

    def test_the_document_parsed_is_the_file_that_was_opened(self):
        # The loader is called directly because the claim is about which bytes
        # it returns, and every public caller only ever reports what it did
        # with them afterwards.
        with self.armed(self.preview_path,
                        replacement=self.oversized(commit_sha="f" * 40)):
            document = trust_github._load_preview(self.preview_path)
        self.assertEqual(self.sha, document["commit_sha"])
        self.assertEqual(self.preview["config_path"], document["config_path"])

    def test_a_file_that_grows_after_it_is_looked_at_is_refused(self):
        store = self.opened()
        with self.armed(self.preview_path,
                        growth=b"x" * (2 * trust_github.MAX_PREVIEW_BYTES)):
            with self.assertRaises(trust_github.GitHubError) as caught:
                self.finalize(store)
        self.assertIn("too large", str(caught.exception))
        self.assertEqual(0, store.receipt_count(self.preview["repository"]))

    def test_a_symlinked_preview_is_refused_rather_than_followed(self):
        link = self.tmp / "preview-link.json"
        link.symlink_to(self.preview_path)
        store = self.opened()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, preview_path=link)
        self.assertIn("symbolic link", str(caught.exception))
        self.assertEqual(0, store.receipt_count(self.preview["repository"]))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs POSIX FIFOs")
    def test_a_preview_that_is_not_a_regular_file_is_never_drained(self):
        fifo = self.tmp / "preview.fifo"
        os.mkfifo(fifo)
        volume = 2 * trust_github.MAX_PREVIEW_BYTES
        written: list[int] = []

        def feed():
            block = b"x" * 65536
            total = 0
            try:
                descriptor = os.open(str(fifo), os.O_WRONLY)
            except OSError:  # pragma: no cover - the reader never opened
                written.append(total)
                return
            try:
                while total < volume:
                    total += os.write(descriptor, block)
            except OSError:
                pass
            finally:
                os.close(descriptor)
                written.append(total)

        writer = threading.Thread(target=feed, daemon=True)
        writer.start()
        store = self.opened()
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, preview_path=fifo)
        writer.join(timeout=60)
        self.assertIn("regular file", str(caught.exception))
        self.assertTrue(written, "the writer never stopped")
        self.assertLessEqual(written[0], trust_github.MAX_PREVIEW_BYTES)
        self.assertEqual(0, store.receipt_count(self.preview["repository"]))


class AMalformedDependencyEdgeIsARefusalNotACrash(FinalizationCase):
    """Dependency edges are typed before anything sorts, signs or records them.

    The edges are candidate-written and end up in the signed body of a receipt,
    so ``repository`` is read twice: once as a sort key next to every other
    edge's, and once as a field a receipt records forever.  A repository that
    is not a string fails the first use with ``TypeError`` -- comparing ``int``
    to ``str`` is not an ordering -- and the second use silently, by recording
    whatever arrived.

    ``TypeError`` is the part that matters.  ``_command_finalize`` catches the
    domain errors this module raises and answers with one structured document;
    anything else leaves through ``main`` as a traceback, which is a crash
    report where a caller expected ``BLOCKED`` and a remediation list.  So the
    refusal is asserted at the edge reader, through ``finalize``, and on the
    machine stream a ``--json`` caller reads.
    """

    def edge(self, repository) -> dict:
        return {"repository": repository, "commit_sha": "d" * 40}

    def edited_preview(self, **changes) -> Path:
        document = dict(self.preview)
        document.update(changes)
        path = self.tmp / "edited-preview.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_a_repository_that_is_not_a_non_empty_string_is_refused(self):
        for label, repository in (("null", None), ("an integer", 7),
                                  ("a list", ["github.com/acme/widget"]),
                                  ("the empty string", "")):
            with self.subTest(repository=label):
                with self.assertRaises(trust_github.GitHubError) as caught:
                    trust_github._dependency_edges([self.edge(repository)])
                self.assertIn("repository", str(caught.exception))

    def test_repositories_of_mixed_types_never_reach_the_sort(self):
        with self.assertRaises(trust_github.GitHubError) as caught:
            trust_github._dependency_edges(
                [self.edge("github.com/acme/widget"), self.edge(7)])
        self.assertIn("repository", str(caught.exception))

    def test_well_formed_edges_are_still_read_and_sorted(self):
        edges = trust_github._dependency_edges([
            {"repository": "github.com/acme/b", "commit_sha": "b" * 40},
            {"repository": "github.com/acme/a", "commit_sha": "a" * 40}])
        self.assertEqual(["github.com/acme/a", "github.com/acme/b"],
                         [edge["repository"] for edge in edges])

    def test_finalization_refuses_a_preview_whose_edges_cannot_be_sorted(self):
        store = self.opened()
        self.trust_the_policy(store)
        with self.assertRaises(trust_github.GitHubError) as caught:
            self.finalize(store, preview_path=self.edited_preview(
                dependencies=[self.edge("github.com/acme/widget"),
                              self.edge(7)]))
        self.assertIn("repository", str(caught.exception))
        self.assertEqual(0, store.receipt_count(self.preview["repository"]))

    def test_the_command_line_answers_a_malformed_edge_with_one_document(self):
        os.environ["ADMISSIBLE_HMAC_KEY"] = ADMISSION_SECRET
        os.environ["ADMISSIBLE_HMAC_KEY_ID"] = "local"
        keyring = self.tmp / "observers.json"
        keyring.write_text(
            json.dumps({OBSERVER_KEY_ID: OBSERVER_SECRET.decode("utf-8")}),
            encoding="utf-8")
        os.chmod(keyring, 0o600)
        os.environ["ADMISSIBLE_EVALUATION_KEYRING"] = str(keyring)
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(0, trust_cli.main(
            ["policy", "trust", "--repo", str(self.repo), "--json"],
            stdout=out, stderr=err), err.getvalue())

        preview = self.edited_preview(dependencies=[
            self.edge("github.com/acme/widget"), self.edge(None)])
        out, err = io.StringIO(), io.StringIO()
        code = trust_cli.main(
            ["finalize", "--preview", str(preview), "--sha", self.sha,
             "--policy-root", str(self.repo), "--evaluation-attestation",
             str(self.attestation_path), "--repo", str(self.repo), "--json"],
            stdout=out, stderr=err)
        self.assertEqual(2, code, out.getvalue() + err.getvalue())
        document = json.loads(out.getvalue())
        self.assertEqual("BLOCKED", document["state"])
        self.assertIn("repository", document["message"])
        self.assertTrue(document["remediation"])
        self.assertEqual("", err.getvalue())


if __name__ == "__main__":
    unittest.main()
