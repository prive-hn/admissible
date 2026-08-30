"""Contract tests for the findings the first closure pass left open.

The first pass (``test_admissible_final_closure``) closed the boundaries the
workflow and formal reviews named. These cover the rest of the exact-head
findings: the ones the recovered repair implemented without a test that would
notice it being undone, and the ones it had not reached at all.

Every class names one finding. They are written to fail against ``c932b1d``
and to keep failing if the repair is reverted.
"""
from __future__ import annotations

import io
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import (  # noqa: E402
    OBSERVER_KEY_ID, OBSERVER_SECRET, TempCase, evaluating_domain, make_repo,
    source_receipt_document)
from test_admissible_final_closure import (  # noqa: E402
    AUTHOR_KEY, KEY_A, KEY_B, SECRET, ClosureCase)

from admissible import attestation as attestation_module  # noqa: E402
from admissible import cli as cli_module
from admissible import config as config_module
from admissible import decision as decision_module
from admissible import evidence as evidence_module
from admissible import github as github_module
from admissible import receipt as receipt_module
from admissible import runner as runner_module
from admissible import standing as standing_module
from admissible import store as store_module

ROOT = Path(__file__).resolve().parent.parent


def quiet_policy(*, argv=None, reviews=0):
    """One class under no high-risk floor, so a test can shape its checks."""

    return {
        "version": 1, "profile": "python-library",
        "classes": [{
            "id": "default",
            "checks": [{
                "id": "unit",
                "argv": list(argv or [sys.executable, "-c", "pass"]),
                "timeout_seconds": 60, "cost_units": 1, "required": True,
                "version": "1", "cacheable": False}],
            "required_independent_reviews": reviews,
            "review_max_age_seconds": 86400,
            "max_cost_units": 10, "max_wall_seconds": 600}]}


# ----------------------------------------------------------------------
# W1: the boundary has to reach the shipped hosted path, not only the CLI.
# ----------------------------------------------------------------------
class ShippedIsolationWiringTest(unittest.TestCase):
    """W1: the hosted caller cannot manufacture the observer's boundary.

    The generic workflow is candidate-adjacent and therefore always reports
    evaluator isolation as ``none``.  An external observer later supplies the
    independent signed assertion.  The composite action remains an
    evaluator-owned diagnostic surface and may carry its local operator's
    claim, but that preview field is not finalization authority.
    """

    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_the_reusable_workflow_forces_isolation_none(self):
        body = self.read(".github/workflows/admissible-gate.yml")
        inputs = body[body.index("    inputs:"):body.index("    outputs:")]
        self.assertNotIn("      isolation:", inputs)
        self.assertNotIn("inputs.isolation", body)
        self.assertIn("ADMISSIBLE_ISOLATION: none", body)

    def test_the_composite_action_accepts_and_passes_an_isolation_input(self):
        body = self.read(".github/actions/admissible/action.yml")
        self.assertIn("  isolation:", body)
        self.assertIn("ADMISSIBLE_ISOLATION: ${{ inputs.isolation }}", body)

    def test_the_shipped_templates_carry_the_same_wiring(self):
        for shipped, canonical in (
                ("admissible/templates/reusable-workflow.yml",
                 ".github/workflows/admissible-gate.yml"),
                ("admissible/templates/action.yml",
                 ".github/actions/admissible/action.yml")):
            self.assertEqual(self.read(shipped), self.read(canonical), shipped)

    def test_every_declared_mode_is_documented_where_a_caller_looks(self):
        body = self.read("docs/GITHUB_ACTIONS.md")
        for mode in runner_module.ISOLATION_MODES:
            if mode != runner_module.ISOLATION_NONE:
                self.assertIn(mode, body)


class AmbientCredentialClosureTest(ClosureCase):
    """W1: every signing credential refuses the run, not only the three keys.

    The first pass covered the three inline key variables. The file-shaped and
    keyring-shaped ones are the same hazard and the more likely one: a check
    runs as this user and can open whatever path they name.
    """

    def test_every_named_signing_credential_refuses_the_run(self):
        self.assertTrue(runner_module.SIGNING_CREDENTIAL_NAMES)
        for name in runner_module.SIGNING_CREDENTIAL_NAMES:
            with self.subTest(variable=name):
                os.environ[name] = "not-a-real-credential"
                try:
                    code, document, err = self.evaluate()
                finally:
                    os.environ.pop(name, None)
                self.assertEqual(code, 2, document or err)
                self.assertEqual(document["state"], decision_module.BLOCKED)
                self.assertIn(name, document["message"])
                self.assertFalse(
                    self.preview.exists(),
                    "a run refused for holding a credential handed over a "
                    "preview anyway")

    def test_the_refusal_names_the_variable_to_unset(self):
        os.environ["ADMISSIBLE_HMAC_KEY_FILE"] = "/nowhere/key"
        self.addCleanup(os.environ.pop, "ADMISSIBLE_HMAC_KEY_FILE", None)
        _, document, _ = self.evaluate()
        self.assertTrue(any("unset ADMISSIBLE_HMAC_KEY_FILE" in line
                            for line in document["remediation"]),
                        document["remediation"])


# ----------------------------------------------------------------------
# W3: the three key domains, kept physically apart.
# ----------------------------------------------------------------------
class ObserverKeySeparationTest(ClosureCase):
    """W3: the admission key may not also be an observer key.

    The first pass refused an admission key that was also a reviewer key. The
    observer is the third domain and the same argument applies with more
    force: a finalizer that can attest the evaluation it admits has removed
    the only party in this product that is outside the evaluating job.
    """

    def evaluated(self):
        path = self.bundle_file(
            attestations=self.two_attestations(),
            author_attestations=[self.authorship_document()])
        with evaluating_domain():
            self.evaluate(evidence_path=path)
        return self.attest()

    def test_the_admission_key_may_not_also_be_an_observer_key(self):
        evaluation = self.evaluated()
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        opened.trust_policy(
            repository="github.com/acme/widget", class_id=self.klass.id,
            policy_digest=self.klass.policy_digest,
            enforcement_digest=config_module.enforcement_digest(self.klass),
            trusted_at=self.now)
        shared = receipt_module.signer_from_secret("finalizer-1",
                                                   OBSERVER_SECRET)
        with self.assertRaises(github_module.GitHubError) as caught:
            github_module.finalize(
                opened, self.preview, signer=shared, expected_sha=self.sha,
                now=self.now, policy_root=self.root,
                evaluation_attestation=evaluation,
                evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
                keyring=self.keyring,
                environment={"ADMISSIBLE_HMAC_KEY":
                             OBSERVER_SECRET.decode("utf-8")})
        self.assertIn("evaluation keyring", str(caught.exception))

    def test_separate_material_still_admits(self):
        evaluation = self.evaluated()
        issued = self.finalize(evaluation=evaluation)
        self.assertEqual(issued.state, decision_module.ADMITTED)


# ----------------------------------------------------------------------
# W5/U1: a review-required class must be completable on the hosted path.
# ----------------------------------------------------------------------
class RedGateSourceReceiptTest(ClosureCase):
    """W5: the gate is red for AWAITING_REVIEW, so its receipt says failure.

    Two shipped rules used to contradict each other. ``AWAITING_REVIEW`` is
    red on every event, deliberately; a provider records a red run as
    ``failure``; and finalization accepted only ``success``. Together they
    meant no review-required class could ever be admitted through the shipped
    path -- the gate's honesty made its own output unusable.
    """

    def pending_preview(self):
        """An evaluation whose only outstanding blocker is a review."""

        path = self.bundle_file(
            attestations=self.two_attestations(),
            author_attestations=[self.authorship_document()])
        with evaluating_domain():
            code, document, err = self.evaluate(evidence_path=path)
        self.assertEqual(code, 1, document or err)
        parsed = json.loads(self.preview.read_text(encoding="utf-8"))
        self.assertEqual(parsed["readiness"],
                         decision_module.READINESS_AWAITING_REVIEW)
        return parsed

    def attested(self, parsed, conclusion):
        receipt = source_receipt_document(parsed["commit_sha"])
        receipt["conclusion"] = conclusion
        document = attestation_module.attest_preview(
            parsed, key_id=OBSERVER_KEY_ID, secret=OBSERVER_SECRET,
            isolation="pid-namespace",
            source_receipt=receipt,
            observed_at=max(self.now, parsed["issued_at"]))
        path = self.tmp / f"evaluation-{conclusion}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_a_failed_provider_run_still_admits_an_awaiting_review_preview(self):
        parsed = self.pending_preview()
        issued = self.finalize(evaluation=self.attested(parsed, "failure"))
        self.assertEqual(issued.state, decision_module.ADMITTED)
        self.assertEqual(
            sorted(key_id for _digest, key_id in issued.authenticated_reviews),
            ["reviewer-a", "reviewer-b"])

    def test_a_cancelled_provider_run_is_refused_even_there(self):
        """An unfinished run establishes nothing to be waiting on."""

        parsed = self.pending_preview()
        with self.assertRaises(github_module.GitHubError) as caught:
            self.finalize(evaluation=self.attested(parsed, "cancelled"))
        self.assertIn("cancelled", str(caught.exception))

    def test_a_failed_run_is_still_refused_for_a_ready_preview(self):
        """Outside AWAITING_REVIEW, only success completes an admission."""

        document = quiet_policy()
        root = self.tmp / "quiet"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(document, indent=2) + "\n"})
        preview = self.tmp / "quiet-preview.json"
        out, err = io.StringIO(), io.StringIO()
        with evaluating_domain():
            code = cli_module.main(
                ["run", "--repo", str(root), "--sha", sha, "--preview",
                 "--preview-out", str(preview), "--json"],
                stdout=out, stderr=err)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        parsed = json.loads(preview.read_text(encoding="utf-8"))
        self.assertEqual(parsed["readiness"],
                         decision_module.READINESS_READY_FOR_ATTESTATION)
        receipt = source_receipt_document(sha)
        receipt["conclusion"] = "failure"
        attested = self.tmp / "quiet-evaluation.json"
        attested.write_text(json.dumps(attestation_module.attest_preview(
            parsed, key_id=OBSERVER_KEY_ID, secret=OBSERVER_SECRET,
            isolation="pid-namespace",
            source_receipt=receipt,
            observed_at=max(self.now, parsed["issued_at"]))),
            encoding="utf-8")
        klass = config_module.parse_config(document).select_class("default")
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        opened.trust_policy(
            repository="github.com/acme/widget", class_id=klass.id,
            policy_digest=klass.policy_digest,
            enforcement_digest=config_module.enforcement_digest(klass),
            trusted_at=self.now)
        with self.assertRaises(github_module.GitHubError) as caught:
            github_module.finalize(
                opened, preview, signer=self.signer, expected_sha=sha,
                now=self.now, policy_root=root,
                evaluation_attestation=attested,
                evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
                keyring=self.keyring, environment={})
        self.assertIn("READY_FOR_ATTESTATION", str(caught.exception))

    def test_the_conclusion_set_is_a_function_of_readiness(self):
        self.assertEqual(
            attestation_module.admissible_source_conclusions(
                decision_module.READINESS_READY_FOR_ATTESTATION),
            frozenset({"success"}))
        self.assertEqual(
            attestation_module.admissible_source_conclusions(
                decision_module.READINESS_AWAITING_REVIEW),
            frozenset({"success", "failure"}))


class ReviewTransportDocumentationTest(unittest.TestCase):
    """U1: the developer guide recommended an impossible transport."""

    def guide(self):
        return (ROOT / "docs" / "DEVELOPER_WORKFLOW.md").read_text(
            encoding="utf-8")

    def test_committing_a_review_bundle_is_no_longer_called_supported(self):
        body = self.guide()
        self.assertNotIn(
            "committing a\nbundle of them into the candidate tree is a "
            "supported transport", body)
        self.assertNotIn("into the candidate tree is a supported transport",
                         body)

    def test_the_guide_names_the_transport_that_exists(self):
        self.assertIn("--reviews", self.guide())


# ----------------------------------------------------------------------
# F2/F7: a journal that can be exported can be imported.
# ----------------------------------------------------------------------
class AuthorshipRoundTripTest(ClosureCase):
    """F2: authorship evidence must survive export and import.

    Authorship is required evidence for every review-gated class, is bound by
    the receipt, and is listed in that receipt's evidence digests. An importer
    that accepted only ``command`` and ``review`` therefore rejected the whole
    journal on the digest bijection: the export was unreadable by design.
    """

    def admitted(self):
        path = self.bundle_file(
            attestations=self.two_attestations(),
            author_attestations=[self.authorship_document()])
        with evaluating_domain():
            self.evaluate(evidence_path=path)
        return self.finalize()

    def test_a_receipt_with_authorship_survives_export_and_import(self):
        issued = self.admitted()
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        bundle = opened.export_journal(issued.journal_id)
        kinds = {row["kind"] for row in bundle["evidence"]}
        self.assertIn("authorship", kinds,
                      "the export carries no authorship to import")

        far_side = self.tmp / "far-home"
        other = store_module.open_store(far_side)
        self.addCleanup(other.close)
        other.import_journal(bundle, self.signer)
        landed = other.receipts_for("github.com/acme/widget", self.sha)
        self.assertEqual([item.receipt_hash for item in landed],
                         [issued.receipt_hash])

    def test_the_import_kind_list_matches_what_export_can_emit(self):
        source = (ROOT / "admissible" / "store.py").read_text(encoding="utf-8")
        importer = source[source.index("has unknown kind") - 4000:
                          source.index("has unknown kind")]
        self.assertIn('"authorship"', importer)


class JournalCeilingTest(TempCase):
    """F7: export must not write a file import will refuse.

    Bounding a journal by the evidence-bundle ceiling made a long-lived home
    exportable and un-importable, with no supported way to split the transfer.
    One number, used on both sides, is the whole fix -- and a test that both
    sides read the same constant is what keeps it one number.
    """

    def test_both_sides_use_the_same_ceiling(self):
        source = (ROOT / "admissible" / "cli.py").read_text(encoding="utf-8")
        export = source[source.index("def _command_export"):
                        source.index("def _command_import")]
        importer = source[source.index("def _command_import"):
                          source.index("def _command_import") + 3000]
        self.assertIn("MAX_JOURNAL_BYTES", export)
        self.assertIn("MAX_JOURNAL_BYTES", importer)
        self.assertNotIn("MAX_EVIDENCE_BYTES", importer)

    def test_the_journal_ceiling_is_above_the_evidence_bundle_ceiling(self):
        self.assertGreater(store_module.MAX_JOURNAL_BYTES,
                           evidence_module.MAX_EVIDENCE_BYTES)

    def test_an_export_above_the_ceiling_writes_nothing(self):
        root = self.tmp / "candidate"
        make_repo(root)
        out_path = self.tmp / "journal.json"
        original = store_module.MAX_JOURNAL_BYTES
        store_module.MAX_JOURNAL_BYTES = 8
        self.addCleanup(setattr, store_module, "MAX_JOURNAL_BYTES", original)

        opened = store_module.open_store(self.home)
        opened.close()
        os.environ["ADMISSIBLE_HMAC_KEY"] = "export-test-secret"
        out, err = io.StringIO(), io.StringIO()
        code = cli_module.main(
            ["export", "--out", str(out_path), "--repo", str(root), "--json"],
            stdout=out, stderr=err)
        self.assertEqual(code, 2, out.getvalue() + err.getvalue())
        self.assertFalse(out_path.exists(),
                         "an export above the ceiling wrote a file anyway")


# ----------------------------------------------------------------------
# F3/U5: cache facts are ordered by one transaction, not by two commits.
# ----------------------------------------------------------------------
class CacheTransactionTest(TempCase):
    """F3/U5: allocating a sequence and writing its row is one event.

    In autocommit mode these were two commits, so a failure could take
    sequence 1, a pass commit as sequence 2, and the failure land afterwards.
    Lookup compares 1 < 2 and reuses the pass -- a check that failed, serving
    a green answer, because of the order two commits happened to interleave.
    """

    def record(self, *, passed, digest_seed):
        return evidence_module.command_evidence_from_dict({
            "kind": "command", "check_id": "unit", "check_version": "1",
            "repository": "github.com/acme/widget", "commit_sha": "a1" * 20,
            "tree_sha": "b2" * 20, "policy_digest": "c" * 64,
            "argv_digest": "d" * 64, "exit_code": 0 if passed else 1,
            "duration_ms": 5, "timed_out": False, "output_truncated": False,
            "stdout_bytes": len(digest_seed), "stderr_bytes": 0,
            "stdout_sha256": "e" * 64, "stderr_sha256": "f" * 64,
            "started_at": 1000, "finished_at": 1005, "attempt_id": "att-1",
            "launch_failed": False,
        })

    def opened(self):
        store = store_module.open_store(self.home)
        self.addCleanup(store.close)
        return store

    def test_the_sequence_is_allocated_inside_the_writing_transaction(self):
        store = self.opened()
        seen = []
        original = store_module.Store.next_cache_sequence

        def watched(self):
            seen.append(self._connection.in_transaction)
            return original(self)

        # Patched on the class: Store defines __slots__, so there is nowhere on
        # an instance to hang a replacement.
        store_module.Store.next_cache_sequence = watched
        self.addCleanup(setattr, store_module.Store, "next_cache_sequence",
                        original)
        store.cache_command_evidence(self.record(passed=True, digest_seed="a"),
                                     recorded_at=1000, cacheable=True)
        store.cache_command_evidence(self.record(passed=False, digest_seed="b"),
                                     recorded_at=1001)
        self.assertEqual(seen, [True, True],
                         "a cache sequence was allocated in its own commit")

    def test_a_failure_after_a_pass_stops_the_pass_being_reused(self):
        store = self.opened()
        identity = {
            "repository": "github.com/acme/widget", "commit_sha": "a1" * 20,
            "tree_sha": "b2" * 20, "policy_digest": "c" * 64,
            "check_id": "unit", "check_version": "1", "argv_digest": "d" * 64,
        }
        store.cache_command_evidence(self.record(passed=True, digest_seed="a"),
                                     recorded_at=1000, cacheable=True)
        self.assertIsNotNone(store.cached_command_evidence(**identity))
        store.cache_command_evidence(self.record(passed=False, digest_seed="a"),
                                     recorded_at=1001)
        self.assertIsNone(store.cached_command_evidence(**identity),
                          "a contradicted pass was reused")

    def test_the_lookup_reads_the_row_and_its_invalidation_together(self):
        source = (ROOT / "admissible" / "store.py").read_text(encoding="utf-8")
        body = source[source.index("def cached_command_evidence"):]
        body = body[:body.index("# -- trusted policy baseline")]
        self.assertIn("evidence_cache_invalidations", body)
        self.assertNotIn("self.cache_invalidated_sequence(key)", body)


# ----------------------------------------------------------------------
# F4/F5: what an interrupted or partly-failed finalize is allowed to say.
# ----------------------------------------------------------------------
class _Options:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class InterruptedFinalizeTest(ClosureCase):
    """F4: recovery is about this exact receipt body, not this commit.

    Even attempt/class/policy is too coarse: a different recomputed decision
    can share all three.  Only the body digest prepared before the uncertain
    commit boundary identifies what this invocation could have written.
    """

    def admitted(self):
        path = self.bundle_file(
            attestations=self.two_attestations(),
            author_attestations=[self.authorship_document()])
        with evaluating_domain():
            self.evaluate(evidence_path=path)
        return self.finalize()

    def report(self, expected_body_digest):
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET.decode("utf-8")
        os.environ["ADMISSIBLE_HMAC_KEY_ID"] = "finalizer-1"
        options = _Options(preview=str(self.preview), sha=self.sha,
                           policy_root=str(self.root), json=True)
        opened = store_module.open_store(self.home)
        out, err = io.StringIO(), io.StringIO()
        code = cli_module._report_interrupted_finalize(options, out, out,
                                                       opened,
                                                       expected_body_digest)
        return code, json.loads(out.getvalue()), err.getvalue()

    def test_the_real_attempt_is_recognised(self):
        issued = self.admitted()
        code, document, _ = self.report(issued.body_digest)
        self.assertEqual(code, 0, document)
        self.assertEqual(document["receipt_hash"], issued.receipt_hash)

    def test_another_attempts_receipt_is_not_this_invocations_success(self):
        self.admitted()
        code, document, _ = self.report("f" * 64)
        self.assertEqual(code, 2, document)
        self.assertEqual(document["state"], "UNKNOWN_COMMIT_OUTCOME")

    def test_a_preview_naming_another_policy_is_not_this_ones_success(self):
        self.admitted()
        code, document, _ = self.report("e" * 64)
        self.assertEqual(code, 2, document)
        self.assertEqual(document["state"], "UNKNOWN_COMMIT_OUTCOME")

    def test_same_attempt_but_another_decision_is_not_reported_as_success(self):
        self.admitted()
        code, document, _ = self.report("d" * 64)
        self.assertEqual(code, 2, document)
        self.assertEqual(document["state"], "UNKNOWN_COMMIT_OUTCOME")

    def test_an_impeached_admission_is_not_reported_as_a_plain_success(self):
        issued = self.admitted()
        defect = self.tmp / "defect.json"
        defect.write_text(json.dumps({
            "kind": "defect", "defect_id": "WID-1",
            "repository": "github.com/acme/widget", "commit_sha": self.sha,
            "severity": "high", "summary": "it lost cents",
            "missed_check_ids": ["unit"], "regression_test_id": "unit",
            "discovered_at": self.now}), encoding="utf-8")
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET.decode("utf-8")
        os.environ["ADMISSIBLE_HMAC_KEY_ID"] = "finalizer-1"
        out, err = io.StringIO(), io.StringIO()
        filed = cli_module.main(
            ["impeach", self.sha, "--evidence", str(defect), "--test", "unit",
             "--repo", str(self.root)], stdout=out, stderr=err)
        self.assertEqual(filed, 0, out.getvalue() + err.getvalue())
        code, document, _ = self.report(issued.body_digest)
        self.assertEqual(code, 2, document)
        self.assertNotEqual(document.get("receipt_hash"), issued.receipt_hash)


class FinalizeOutputFailureTest(ClosureCase):
    """F5: a failed --out copy must not be reported as no admission.

    The admission is durable before the copy is attempted. Routing the copy
    failure through the generic failure envelope produced BLOCKED/NOT_READY,
    exit 2, no receipt locator, and -- in prose -- "nothing was recorded for
    this invocation", over an admission that is on record. A caller that
    believes that re-runs, or reports a failure that did not happen.
    """

    def setUp(self):
        super().setUp()
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET.decode("utf-8")
        os.environ["ADMISSIBLE_HMAC_KEY_ID"] = "finalizer-1"
        os.environ["ADMISSIBLE_DURABLE_HOME"] = "1"

    def prepared(self):
        path = self.bundle_file(
            attestations=self.two_attestations(),
            author_attestations=[self.authorship_document()])
        with evaluating_domain():
            self.evaluate(evidence_path=path)
        evaluation = self.attest()
        opened = store_module.open_store(self.home)
        opened.trust_policy(
            repository="github.com/acme/widget", class_id=self.klass.id,
            policy_digest=self.klass.policy_digest,
            enforcement_digest=config_module.enforcement_digest(self.klass),
            trusted_at=self.now)
        opened.close()
        keyring = self.tmp / "keyring.json"
        keyring.write_text(json.dumps({
            "reviewer-a": KEY_A.decode(), "reviewer-b": KEY_B.decode(),
            "author-key": AUTHOR_KEY.decode()}), encoding="utf-8")
        os.chmod(keyring, 0o600)
        os.environ["ADMISSIBLE_REVIEW_KEYRING"] = str(keyring)
        observers = self.tmp / "observers.json"
        observers.write_text(json.dumps(
            {OBSERVER_KEY_ID: OBSERVER_SECRET.decode()}), encoding="utf-8")
        os.chmod(observers, 0o600)
        os.environ["ADMISSIBLE_EVALUATION_KEYRING"] = str(observers)
        return evaluation

    def finalize_cli(self, out_path, *, json_mode=True):
        evaluation = self.prepared()
        argv = ["finalize", "--preview", str(self.preview), "--sha", self.sha,
                "--policy-root", str(self.root),
                "--evaluation-attestation", str(evaluation),
                "--out", str(out_path)]
        if json_mode:
            argv.append("--json")
        stdout, stderr = io.StringIO(), io.StringIO()
        code = cli_module.main(argv, stdout=stdout, stderr=stderr)
        return code, stdout.getvalue(), stderr.getvalue()

    def unwritable(self) -> Path:
        # A directory where a file must go: no permission bit repairs it, and
        # it fails after the admission is anchored rather than before.
        blocked = self.tmp / "receipt-out"
        blocked.mkdir()
        return blocked

    def test_json_reports_the_anchored_receipt_and_not_a_lost_admission(self):
        code, out, err = self.finalize_cli(self.unwritable())
        self.assertEqual(code, 2, out + err)
        document = json.loads(out)
        self.assertEqual(document["state"], decision_module.ADMITTED)
        self.assertTrue(document["receipt_hash"])
        self.assertIn("IS anchored", document["message"])
        self.assertTrue(any("do not re-run" in line
                            for line in document["remediation"]),
                        document["remediation"])

    def test_prose_never_says_nothing_was_recorded(self):
        code, out, err = self.finalize_cli(self.unwritable(), json_mode=False)
        self.assertEqual(code, 2, out + err)
        text = out + err
        self.assertNotIn("nothing was recorded", text)
        self.assertIn("IS anchored", text)

    def test_the_receipt_really_is_readable_afterwards(self):
        self.finalize_cli(self.unwritable())
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        found = opened.receipts_for("github.com/acme/widget", self.sha)
        self.assertEqual([item.state for item in found],
                         [decision_module.ADMITTED])


# ----------------------------------------------------------------------
# F6/U3/U6: what explain and status may say, and what they must not.
# ----------------------------------------------------------------------
class ExplainAndStatusTest(ClosureCase):
    """F6/U3/U6: read-only commands answer from signatures, not from rows."""

    def setUp(self):
        super().setUp()
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET.decode("utf-8")
        os.environ["ADMISSIBLE_HMAC_KEY_ID"] = "finalizer-1"

    def admitted(self):
        path = self.bundle_file(
            attestations=self.two_attestations(),
            author_attestations=[self.authorship_document()])
        with evaluating_domain():
            self.evaluate(evidence_path=path)
        return self.finalize()

    def invoke(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = cli_module.main(list(argv), stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    # -- F6 ---------------------------------------------------------------
    def test_explain_re_evaluates_with_the_authorship_it_recorded(self):
        self.admitted()
        code, out, err = self.invoke("explain", self.sha, "--repo",
                                     str(self.root), "--json")
        document = json.loads(out)
        self.assertEqual(code, 0, out + err)
        kinds = {row["kind"] for row in document["evidence"]}
        self.assertIn("authorship", kinds)
        reasons = [reason["code"] for reason in document.get("reasons", [])]
        self.assertNotIn("missing_author_attestation", reasons,
                         "explain reported missing authorship it had stored")

    def test_plain_explain_renders_authorship_without_raising(self):
        self.admitted()
        code, out, err = self.invoke("explain", self.sha, "--repo",
                                     str(self.root))
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("Traceback", out + err)
        self.assertIn("authorship claimed by mallory", out)

    def test_stored_evidence_rebuilds_all_three_kinds(self):
        self.admitted()
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        rows = opened.evidence_for("github.com/acme/widget", self.sha)
        commands, reviews, authorships = cli_module._stored_evidence(rows)
        self.assertTrue(commands)
        self.assertTrue(reviews)
        self.assertTrue(authorships,
                        "authorship was dropped rebuilding stored evidence")

    # -- U3 ---------------------------------------------------------------
    def test_status_will_not_call_an_unverifiable_row_current(self):
        self.admitted()
        code, out, err = self.invoke("status", "--repo", str(self.root),
                                     "--json")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(json.loads(out)["state"], standing_module.CURRENT)

        os.environ["ADMISSIBLE_HMAC_KEY"] = "a-different-domains-key"
        code, out, err = self.invoke("status", "--repo", str(self.root),
                                     "--json")
        document = json.loads(out)
        self.assertEqual(code, 1, out + err)
        self.assertNotEqual(document["state"], standing_module.CURRENT)
        self.assertTrue(document["unauthenticated_receipts"])

    def test_status_without_any_key_is_not_current_either(self):
        self.admitted()
        os.environ.pop("ADMISSIBLE_HMAC_KEY", None)
        code, out, err = self.invoke("status", "--repo", str(self.root),
                                     "--json")
        document = json.loads(out)
        self.assertEqual(code, 1, out + err)
        self.assertEqual(document["state"], "UNVERIFIED")
        self.assertTrue(document["signature_problem"])

    def test_explain_never_says_current_while_a_signature_fails(self):
        self.admitted()
        os.environ["ADMISSIBLE_HMAC_KEY"] = "a-different-domains-key"
        code, out, err = self.invoke("explain", self.sha, "--repo",
                                     str(self.root), "--json")
        document = json.loads(out)
        self.assertEqual(code, 1, out + err)
        self.assertNotEqual(document["state"], standing_module.CURRENT)
        self.assertEqual(document["exit_code"], 1)
        self.assertTrue(document["unauthenticated_receipts"])
        self.assertNotIn("nothing: this artefact is current",
                         " ".join(document["remediation"]))

    # -- U6 ---------------------------------------------------------------
    def test_the_unknown_target_remediation_names_a_command_that_exists(self):
        root = self.tmp / "empty"
        make_repo(root)
        unknown = "9" * 40
        code, out, err = self.invoke("verify", unknown, "--repo", str(root))
        self.assertEqual(code, 1, out + err)
        self.assertNotIn("admissible run --sha", out + err)
        self.assertIn("--preview", out + err)

    def test_the_standing_report_recommends_the_four_step_path(self):
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        report = standing_module.impact_report(
            opened, "github.com/acme/widget", "9" * 40)
        joined = " ".join(report.remediation)
        self.assertNotIn("admissible run --sha", joined)
        self.assertIn("--preview", joined)
        self.assertIn("finalize", joined)

    def test_plain_explain_prints_the_decisions_remediation(self):
        """A refusal with no next step is the one thing this output avoids."""

        broken = quiet_policy(
            argv=[sys.executable, "-c", "raise SystemExit(1)"])
        root = self.tmp / "broken"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(broken, indent=2) + "\n"})
        out, err = io.StringIO(), io.StringIO()
        with evaluating_domain():
            cli_module.main(["run", "--repo", str(root), "--sha", sha,
                             "--preview", "--json"], stdout=out, stderr=err)
        code, out, err = self.invoke("explain", sha, "--repo", str(root))
        self.assertEqual(code, 1, out + err)
        self.assertIn("What to do next about that decision:", out)


# ----------------------------------------------------------------------
# C2/U2: the evaluation contract never says ADMITTED.
# ----------------------------------------------------------------------
class EvaluationOutputContractTest(unittest.TestCase):
    """C2/U2: an integration must not be able to wait for an impossible value."""

    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_the_action_advertises_no_admitted_output(self):
        for relative in (".github/actions/admissible/action.yml",
                         "admissible/templates/action.yml"):
            body = self.read(relative)
            outputs = body[body.index("outputs:"):body.index("runs:")]
            self.assertNotIn("state=ADMITTED", outputs)
            self.assertNotIn("readiness: ADMITTED", outputs)
            self.assertIn("CHECKS_PASSED", outputs)
            self.assertIn("READY_FOR_ATTESTATION", outputs)

    def test_the_readme_readiness_table_states_the_real_values(self):
        body = self.read("README.md")
        table = body[body.index("| `readiness` | meaning |"):]
        table = table[:table.index("`AWAITING_REVIEW` is never called")]
        self.assertIn("| `READY_FOR_ATTESTATION` |", table)
        self.assertNotIn("| `ADMITTED` |", table)

    def test_every_advertised_state_is_one_the_program_can_emit(self):
        emitted = {decision_module.CHECKS_PASSED, decision_module.REFUSED,
                   decision_module.BLOCKED}
        self.assertNotIn(decision_module.ADMITTED, emitted)
        body = self.read(".github/workflows/admissible-gate.yml")
        outputs = body[body.index("    outputs:"):body.index("permissions:")]
        self.assertNotIn("ADMITTED,", outputs)


# ----------------------------------------------------------------------
# Blocking P2: init, the bundled schema, the documented envelope, the demo.
# ----------------------------------------------------------------------
class InitAtomicityTest(TempCase):
    """P2-1: `init` is all-or-nothing for every failure, not only two."""

    def plan(self, root):
        return config_module.plan_init(root, "python-library", ci="github",
                                       force=True, allow_placeholder=True)

    def repo(self):
        root = self.tmp / "candidate"
        make_repo(root)
        return root

    def test_an_interrupt_between_writes_puts_the_tree_back(self):
        root = self.repo()
        writes = self.plan(root)
        self.assertGreater(len(writes), 1)
        before = {item.path: (item.path.read_bytes()
                              if item.path.exists() else None)
                  for item in writes}
        original = config_module._atomic_write
        calls = []

        def failing(path, body):
            calls.append(path)
            if len(calls) > 1:
                raise KeyboardInterrupt("operator pressed Ctrl-C")
            original(path, body)

        config_module._atomic_write = failing
        self.addCleanup(setattr, config_module, "_atomic_write", original)
        with self.assertRaises(KeyboardInterrupt):
            config_module.apply_init(writes)
        for path, body in before.items():
            if body is None:
                self.assertFalse(path.exists(),
                                 f"{path} survived an interrupted init")
            else:
                self.assertEqual(path.read_bytes(), body)

    def test_a_rollback_that_cannot_finish_is_never_called_clean(self):
        root = self.repo()
        writes = self.plan(root)
        # Prior content on every target, so the undo has to write and not
        # merely unlink: a rollback that only deletes cannot fail the way a
        # rollback that restores can.
        for item in writes:
            item.path.parent.mkdir(parents=True, exist_ok=True)
            item.path.write_bytes(b"what was here before\n")
        original = config_module._atomic_write
        calls = []

        def failing(path, body):
            calls.append(path)
            if len(calls) == 1:
                original(path, body)
                return
            if len(calls) == 2:
                raise OSError(28, "No space left on device")
            # The undo pass. It cannot finish either.
            raise OSError(30, "Read-only file system")

        config_module._atomic_write = failing
        self.addCleanup(setattr, config_module, "_atomic_write", original)
        with self.assertRaises(config_module.ConfigError) as caught:
            config_module.apply_init(writes)
        message = str(caught.exception)
        self.assertNotIn("Nothing was written", message)
        self.assertIn("NOT as this command found them", message)

    def test_a_clean_rollback_still_says_nothing_was_written(self):
        root = self.repo()
        writes = self.plan(root)
        original = config_module._atomic_write
        calls = []

        def failing(path, body):
            calls.append(path)
            if len(calls) == 1:
                original(path, body)
                return
            raise OSError(28, "No space left on device")

        config_module._atomic_write = failing
        self.addCleanup(setattr, config_module, "_atomic_write", original)
        with self.assertRaises(config_module.ConfigError) as caught:
            config_module.apply_init(writes)
        self.assertIn("Nothing was written", str(caught.exception))
        for item in writes:
            self.assertFalse(item.path.exists(), item.path)


class BundledSchemaTest(unittest.TestCase):
    """P2-2: the bundled schema must not accept what the parser refuses."""

    def test_missed_check_ids_entries_are_non_empty_in_both_schemas(self):
        embedded = json.loads(
            (ROOT / "protocol" / "workflow-evidence.schema.json").read_text(
                encoding="utf-8"))
        standalone = json.loads(
            (ROOT / "protocol" / "defect-record.schema.json").read_text(
                encoding="utf-8"))
        defect = embedded["$defs"]["defect"]["properties"]["missed_check_ids"]
        self.assertEqual(defect["items"].get("minLength"), 1)
        self.assertEqual(
            standalone["properties"]["missed_check_ids"]["items"].get(
                "minLength"), 1)

    def test_the_runtime_parser_still_refuses_an_empty_id(self):
        with self.assertRaises(evidence_module.EvidenceError):
            evidence_module.defect_from_dict({
                "kind": "defect", "defect_id": "WID-1",
                "repository": "github.com/acme/widget",
                "commit_sha": "a1" * 20, "severity": "high",
                "summary": "it lost cents", "missed_check_ids": [""],
                "regression_test_id": "unit", "filed_at": 1000})


class DocumentedEnvelopeTest(ClosureCase):
    """P2-3: the documented nonzero JSON envelope must be the real one."""

    def guide(self):
        return (ROOT / "docs" / "DEVELOPER_WORKFLOW.md").read_text(
            encoding="utf-8")

    def test_the_one_rule_no_longer_promises_a_message_on_decisions(self):
        body = self.guide()
        rule = body[body.index("A consumer that wants one rule"):]
        rule = rule[:rule.index(
            "## What `admissible-ready run --preview` actually does")]
        self.assertIn("`message` is **not** in that universal rule", rule)
        # Named with its distribution: `run` is two commands since the split,
        # and only Ready's explains itself through `reasons` alone.
        self.assertIn("an\n`admissible-ready run --preview` decision explains "
                      "itself through `reasons`", rule)
        self.assertNotIn("`run` or `explain`", rule)

    def test_a_refused_run_carries_the_documented_fields(self):
        broken = quiet_policy(
            argv=[sys.executable, "-c", "raise SystemExit(1)"])
        root = self.tmp / "refusing"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(broken, indent=2) + "\n"})
        out, err = io.StringIO(), io.StringIO()
        with evaluating_domain():
            code = cli_module.main(
                ["run", "--repo", str(root), "--sha", sha, "--preview",
                 "--json"], stdout=out, stderr=err)
        self.assertEqual(code, 1, out.getvalue() + err.getvalue())
        document = json.loads(out.getvalue())
        for field in ("state", "readiness", "exit_code", "remediation"):
            self.assertIn(field, document)
        self.assertTrue(document["reasons"])

    def test_a_nonzero_status_carries_the_documented_fields(self):
        root = self.tmp / "unknown"
        make_repo(root)
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET.decode("utf-8")
        out, err = io.StringIO(), io.StringIO()
        code = cli_module.main(["status", "--repo", str(root), "--json"],
                               stdout=out, stderr=err)
        self.assertEqual(code, 1, out.getvalue() + err.getvalue())
        document = json.loads(out.getvalue())
        for field in ("state", "readiness", "exit_code", "message",
                      "remediation"):
            self.assertIn(field, document)
        self.assertTrue(document["remediation"])


class DemoHonestyTest(unittest.TestCase):
    """P2-4: the demo's high-risk step must be the high-risk profile."""

    def demo(self):
        return (ROOT / "examples" / "developer-workflow" / "demo.sh").read_text(
            encoding="utf-8")

    def test_the_money_step_initialises_the_payment_profile(self):
        body = self.demo()
        money = body[body.index('step "10.'):body.index('step "11.')]
        self.assertIn("--profile payment-change", money)

    def test_the_demo_no_longer_edits_the_library_policy_into_a_payment_one(self):
        self.assertNotIn("require-two-reviews", self.demo())

    def test_the_helper_keeps_the_profiles_own_floors(self):
        helper = (ROOT / "examples" / "developer-workflow" / "show.py"
                  ).read_text(encoding="utf-8")
        body = helper[helper.index("def adopt_payment_profile"):]
        body = body[:body.index("\ndef ", 10)]
        for field in ("required_independent_reviews", "review_max_age_seconds",
                      "max_cost_units", "max_wall_seconds"):
            self.assertNotIn(f'artifact_class["{field}"] =', body,
                             f"the demo overrides the profile's {field}")

    def test_the_demo_separates_preview_and_observer_isolation(self):
        body = self.demo()
        self.assertIn("export ADMISSIBLE_ISOLATION=none", body)
        self.assertIn('observer_isolation=pid-namespace', body)
        self.assertIn('--isolation "$observer_isolation"', body)
        self.assertIn("asserts", body)
        self.assertIn("does not have one", body)

    def test_the_demo_store_is_explicitly_temporary(self):
        body = self.demo()
        self.assertIn("temporary demonstration store", body)
        self.assertIn("deleted at script exit", body)


if __name__ == "__main__":
    unittest.main()
