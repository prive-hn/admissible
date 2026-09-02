"""Contract: the last bounded repair — what an attestation has to close.

Five ideas carry this file, and each one is a place the product still let
something speak with an authority it had not earned:

* an **evaluation attestation** closes over every field finalization uses, and
  it is not proof by re-signing the preview: it states that an operator or an
  adapter observed a **closed external source receipt** from a provider outside
  this run. No source receipt, no attestation, no receipt;
* an **unsigned evaluation is never ``ADMITTED``**. It reaches
  ``CHECKS_PASSED`` and readiness ``READY_FOR_ATTESTATION``; only a signed
  durable workflow receipt says ``ADMITTED``/``CURRENT``;
* **identity is what decides**: the enforcement digest carries every
  decision-changing policy field, and the cache fingerprint carries the actual
  child environment, the resolved executables and the repository's lockfiles;
* **order is observation order**. A cache invalidation is ordered by a monotone
  database sequence, never by the wall clock an attempt happened to start at;
* **one act, one record**. Concurrent identical defect filings collapse inside
  the compare-and-set transaction, and finalize retried after a crash produces
  the same body and one journal event.
"""
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
from admissible_support import (OBSERVER_KEY_ID, OBSERVER_SECRET,  # noqa: E402
                                TempCase, admit, evaluating_domain, make_repo,
                                require_module, source_receipt_document)

attestation_module = require_module("admissible.attestation")
cli = require_module("admissible.cli")
config_module = require_module("admissible.config")
decision = require_module("admissible.decision")
evidence = require_module("admissible.evidence")
ghmod = require_module("admissible.github")
receipt = require_module("admissible.receipt")
review_module = require_module("admissible.review")
runner_module = require_module("admissible.runner")
standing_module = require_module("admissible.standing")
store_module = require_module("admissible.store")

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / ".github" / "workflows" / "admissible-gate.yml"
TEMPLATE = ROOT / "admissible" / "templates" / "reusable-workflow.yml"

SECRET = b"bounded-repair-signing-secret"


def policy(argv=("python3", "-c", "pass"), **overrides):
    """A one-check, no-review policy this file can tamper with field by field."""

    artifact_class = {
        "id": "default",
        "checks": [{"id": "unit", "argv": list(argv), "timeout_seconds": 60,
                    "cost_units": 1, "required": True, "version": "1"}],
        "required_independent_reviews": 0,
        "review_max_age_seconds": 86400,
        "max_cost_units": 10,
        "max_wall_seconds": 600,
    }
    artifact_class.update(overrides)
    return {"version": 1, "profile": "python-library",
            "classes": [artifact_class]}


class BoundedCase(TempCase):
    """One real repository, one real preview, one real durable store."""

    def setUp(self):
        super().setUp()
        os.environ["ADMISSIBLE_HMAC_KEY_ID"] = "k1"
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET.decode("utf-8")
        self.signer = receipt.signer_from_secret("k1", SECRET)
        self.store = store_module.open_store(self.home)
        self.addCleanup(self.store.close)
        self.root = self.tmp / "candidate"
        self.sha = make_repo(self.root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(policy()),
        })
        self.repository = "github.com/acme/widget"
        self.preview = self.tmp / "preview.json"
        self.run_gate()
        artifact_class = config_module.load_config(
            self.root).select_class("default")
        self.store.trust_policy(
            repository=self.repository, class_id="default",
            policy_digest=artifact_class.policy_digest,
            enforcement_digest=config_module.enforcement_digest(artifact_class),
            trusted_at=int(time.time()))

    def run_gate(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        # An evaluate job holds no signing credential and `run` refuses to
        # start while one is present; this fixture shares a process with the
        # finalizer, so the two domains are separated here instead.
        with evaluating_domain():
            code = cli.main(["run", "--repo", str(self.root), "--sha", self.sha,
                             "--preview", "--preview-out", str(self.preview),
                             "--json", *extra], stdout=out, stderr=err)
        self.output = out.getvalue()
        return code, out.getvalue(), err.getvalue()

    def preview_document(self):
        return json.loads(self.preview.read_text(encoding="utf-8"))

    def source_receipt(self, *, commit_sha=None, **overrides):
        return source_receipt_document(
            self.sha if commit_sha is None else commit_sha, **overrides)

    def attestation(self, *, document=None, source=None, observed_at=None,
                    **overrides):
        document = self.preview_document() if document is None else document
        overrides.setdefault("isolation", "pid-namespace")
        signed = attestation_module.attest_preview(
            document, key_id=OBSERVER_KEY_ID, secret=OBSERVER_SECRET,
            source_receipt=self.source_receipt() if source is None else source,
            observed_at=int(time.time()) if observed_at is None else observed_at,
            **overrides)
        path = self.tmp / "evaluation-attestation.json"
        path.write_text(json.dumps(signed), encoding="utf-8")
        return path

    def finalize(self, *, attestation_path=None, now=None, preview=None):
        return ghmod.finalize(
            self.store, self.preview if preview is None else preview,
            signer=self.signer, expected_sha=self.sha,
            now=int(time.time()) if now is None else now,
            policy_root=self.root,
            evaluation_attestation=(self.attestation()
                                    if attestation_path is None
                                    else attestation_path),
            evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
            environment={})

    def rewrite_preview(self, **changes):
        document = self.preview_document()
        document.update(changes)
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        return document


# --------------------------------------------------------------------------
# 1. The evaluation attestation closes over every finalization-critical field.
# --------------------------------------------------------------------------
class AttestationClosureTest(BoundedCase):
    """E1: everything finalization reads is inside the signed statement."""

    def test_the_signed_body_names_every_finalisation_critical_field(self):
        statement = json.loads(
            self.attestation().read_text(encoding="utf-8"))["evaluation"]
        for key in ("preview_schema", "issued_at", "repository",
                    "commit_sha", "tree_sha", "policy_digest",
                    "class_id", "attempt_id", "state", "readiness",
                    "config_path", "fork", "isolation", "dependencies",
                    "command_digests", "review_digests", "decision_digest",
                    "source_receipt", "observed_at"):
            self.assertIn(key, statement, key)

    def test_a_well_formed_preview_and_attestation_still_finalise(self):
        issued = self.finalize()
        self.assertEqual(issued.state, decision.ADMITTED)
        self.assertEqual(issued.commit_sha, self.sha)

    def _tampered(self, **changes):
        """Sign the honest preview, then change it and finalize."""

        attestation_path = self.attestation()
        self.rewrite_preview(**changes)
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=attestation_path)
        return str(caught.exception)

    def test_clearing_the_fork_flag_after_signing_is_refused(self):
        # The observer signed `fork: false`. Any later value -- true, null, 0,
        # or the key removed -- is a different statement, and the signature
        # covers the one that was signed.
        for value in (True, None, 0, "false"):
            with self.subTest(value=value):
                self.setUp()
                message = self._tampered(fork=value)
                self.assertIn("fork", message.lower())

    def test_a_removed_fork_key_is_refused_rather_than_defaulted(self):
        attestation_path = self.attestation()
        document = self.preview_document()
        document.pop("fork")
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError):
            self.finalize(attestation_path=attestation_path)

    def test_a_signed_statement_for_another_config_path_is_refused(self):
        """Re-signed, so only the config-path comparison can tell."""

        path = self.attestation(config_path="elsewhere/.admissible.json")
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=path)
        message = str(caught.exception)
        self.assertIn("names config path", message)
        self.assertIn("elsewhere/.admissible.json", message)
        self.assertIn(".admissible.json", message)
        self.assertEqual(self.store.receipt_count(self.repository), 0)

    def test_changing_readiness_after_signing_is_refused(self):
        message = self._tampered(readiness=decision.READINESS_AWAITING_REVIEW)
        self.assertIn("readiness", message.lower())

    def test_changing_the_state_after_signing_is_refused(self):
        message = self._tampered(state=decision.REFUSED)
        self.assertIn("state", message.lower())

    def test_changing_the_config_path_after_signing_is_refused(self):
        message = self._tampered(config_path="other.json")
        self.assertIn("config", message.lower())

    def test_adding_a_dependency_edge_after_signing_is_refused(self):
        message = self._tampered(dependencies=[
            {"repository": "github.com/acme/other", "commit_sha": "a" * 40}])
        self.assertIn("dependenc", message.lower())

    def test_signed_review_authority_does_not_depend_on_observer_resigning(self):
        # Review signatures belong to their own keyring. The observer witnesses
        # command evidence and must not become a second signer for review or
        # authorship authority.
        record = {
            "kind": "review", "review_id": "r-1", "reviewer_id": "rev",
            "reviewer_version": "1", "author_id": "dev", "verdict": "approve",
            "repository": self.repository, "commit_sha": self.sha,
            "tree_sha": self.preview_document()["tree_sha"],
            "policy_digest": self.preview_document()["policy_digest"],
            "findings_digest": "0" * 64, "issued_at": int(time.time()),
            "attempt_id": "",
        }
        signed = review_module.attest(record, key_id="rev-1",
                                      secret=b"reviewer-secret")
        document = self.preview_document()
        document["evidence"]["attestations"] = [signed]
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        attestation_path = self.attestation()
        document["evidence"]["attestations"] = []
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        issued = self.finalize(attestation_path=attestation_path)
        self.assertEqual(issued.state, decision.ADMITTED)


# --------------------------------------------------------------------------
# 2. attest-evaluation is not proof by re-signing the preview.
# --------------------------------------------------------------------------
class ExternalSourceReceiptTest(BoundedCase):
    """E2: an observer states it saw a receipt from outside this run."""

    def test_attesting_without_a_source_receipt_is_refused(self):
        with self.assertRaises(attestation_module.EvaluationError) as caught:
            attestation_module.attest_preview(
                self.preview_document(), key_id=OBSERVER_KEY_ID,
                secret=OBSERVER_SECRET, isolation="pid-namespace",
                source_receipt=None, observed_at=1)
        # It has to refuse *as* the missing-receipt refusal. Falling through to
        # the receipt parser also raises, and also says "source receipt", so an
        # assertion that stops at those two words passes just as happily with
        # this requirement deleted -- and the message an observer would then
        # read ("must be a JSON object") does not tell them what to supply.
        message = str(caught.exception)
        self.assertIn("no external source receipt", message)
        self.assertIn("Nothing was signed", message)

    def test_the_source_receipt_is_closed_and_exactly_typed(self):
        for missing in ("provider", "run_id", "commit_sha", "conclusion",
                        "receipt_digest"):
            with self.subTest(missing=missing):
                document = self.source_receipt()
                document.pop(missing)
                with self.assertRaises(attestation_module.EvaluationError):
                    attestation_module.source_receipt(document)

    def test_a_source_receipt_for_another_commit_cannot_be_attested(self):
        with self.assertRaises(attestation_module.EvaluationError) as caught:
            attestation_module.attest_preview(
                self.preview_document(), key_id=OBSERVER_KEY_ID,
                secret=OBSERVER_SECRET,
                isolation="pid-namespace",
                source_receipt=self.source_receipt(commit_sha="b" * 40),
                observed_at=1)
        self.assertIn("commit", str(caught.exception).lower())

    def test_a_canonical_source_document_supplies_the_digest(self):
        payload = {"id": 42, "status": "completed", "conclusion": "success"}
        document = self.source_receipt()
        document.pop("receipt_digest")
        document["source_document"] = payload
        parsed = attestation_module.source_receipt(document)
        self.assertEqual(
            parsed["receipt_digest"],
            attestation_module.source_document_digest(payload))

    def test_finalize_refuses_a_source_receipt_for_a_different_commit(self):
        # The signature is authentic; the statement is about another artefact.
        honest = self.attestation()
        signed = json.loads(honest.read_text(encoding="utf-8"))
        # Re-signed, so the signature is authentic and only the statement is
        # about another run.
        signed = attestation_module.attest(
            {**signed["evaluation"],
             "source_receipt": self.source_receipt(commit_sha="c" * 40)},
            key_id=OBSERVER_KEY_ID, secret=OBSERVER_SECRET)
        path = self.tmp / "other-run.json"
        path.write_text(json.dumps(signed), encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=path)
        self.assertIn("source receipt", str(caught.exception).lower())

    def test_finalize_refuses_a_source_receipt_that_did_not_succeed(self):
        path = self.attestation(source=self.source_receipt(
            conclusion="failure"))
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=path)
        self.assertIn("conclusion", str(caught.exception).lower())

    def test_the_cli_requires_a_source_receipt_file(self):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["attest-evaluation", "--preview", str(self.preview),
                         "--out", str(self.tmp / "evaluation.json"),
                         "--isolation", "pid-namespace",
                         "--json"], stdout=out, stderr=err)
        self.assertEqual(code, 2, out.getvalue())
        self.assertFalse((self.tmp / "evaluation.json").exists())

    def test_the_cli_signs_when_the_observer_supplies_one(self):
        os.environ["ADMISSIBLE_EVALUATION_KEY_ID"] = OBSERVER_KEY_ID
        os.environ["ADMISSIBLE_EVALUATION_KEY"] = OBSERVER_SECRET.decode("utf-8")
        source = self.tmp / "source-receipt.json"
        source.write_text(json.dumps(self.source_receipt()), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["attest-evaluation", "--preview", str(self.preview),
                         "--source-receipt", str(source),
                         "--out", str(self.tmp / "evaluation.json"),
                         "--isolation", "pid-namespace",
                         "--json"], stdout=out, stderr=err)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        document = json.loads(out.getvalue())
        self.assertEqual(document["source_receipt"]["provider"],
                         "github-actions")

    def test_the_module_no_longer_claims_evidence_becomes_proof(self):
        text = (ROOT / "admissible" / "attestation.py").read_text(
            encoding="utf-8")
        lowered = text.lower()
        self.assertNotIn("turns evidence into proof", lowered)
        self.assertNotIn("cannot lie", lowered)
        self.assertIn("adapter", lowered)

    def test_the_documentation_keeps_the_adapter_honesty_assumption(self):
        text = (ROOT / "docs" / "DEVELOPER_WORKFLOW.md").read_text(
            encoding="utf-8").lower()
        self.assertIn("adapter", text)
        self.assertIn("source receipt", text)


# --------------------------------------------------------------------------
# 3. An unsigned evaluation is never ADMITTED.
# --------------------------------------------------------------------------
class UnsignedEvaluationTest(BoundedCase):
    """E3: only a signed durable receipt says ADMITTED."""

    def test_a_passing_evaluation_reports_checks_passed(self):
        code, out, _ = self.run_gate()
        document = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(document["state"], decision.CHECKS_PASSED)
        self.assertEqual(document["readiness"],
                         decision.READINESS_READY_FOR_ATTESTATION)
        self.assertNotEqual(document["state"], decision.ADMITTED)

    def test_the_preview_never_carries_the_admitted_state(self):
        document = self.preview_document()
        self.assertNotEqual(document["state"], decision.ADMITTED)
        self.assertEqual(document["state"], decision.CHECKS_PASSED)

    def test_only_a_receipt_says_admitted(self):
        issued = self.finalize()
        self.assertEqual(issued.state, decision.ADMITTED)

    def test_admitted_is_not_a_readiness_value(self):
        self.assertNotIn(decision.ADMITTED, decision.READINESS)

    def test_the_hosted_gate_exits_zero_only_for_ready_for_attestation(self):
        for path in (GATE, TEMPLATE):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertIn("READY_FOR_ATTESTATION", text)
                self.assertNotIn('READINESS" = "ADMITTED"', text)
                self.assertNotIn('"$READINESS" = "ADMITTED"', text)


# --------------------------------------------------------------------------
# 4. The enforcement digest carries every decision-changing field.
# --------------------------------------------------------------------------
class EnforcementIdentityTest(TempCase):
    """E4: only editorial prose is outside the enforcement digest."""

    def digest(self, **overrides):
        document = policy(**overrides)
        parsed = config_module.parse_config(document)
        return config_module.enforcement_digest(parsed.select_class("default"))

    def check_digest(self, **check_overrides):
        document = policy()
        document["classes"][0]["checks"][0].update(check_overrides)
        parsed = config_module.parse_config(document)
        return config_module.enforcement_digest(parsed.select_class("default"))

    def test_every_decision_changing_class_field_moves_the_digest(self):
        baseline = self.digest()
        for field, value in (("max_cost_units", 999),
                             ("max_wall_seconds", 999),
                             ("review_max_age_seconds", 999),
                             ("collect_all_checks", True)):
            with self.subTest(field=field):
                self.assertNotEqual(baseline, self.digest(**{field: value}))

    def test_every_decision_changing_check_field_moves_the_digest(self):
        baseline = self.digest()
        for field, value in (("timeout_seconds", 61), ("cost_units", 7),
                             ("required", False), ("version", "2")):
            with self.subTest(field=field):
                self.assertNotEqual(baseline, self.check_digest(**{field: value}))

    def test_turning_caching_on_moves_the_digest(self):
        """A policy says nothing about reuse until it says it, and saying it
        is a change to the gate: a reused pass is a check that did not run."""

        baseline = self.digest()
        cached = self.check_digest(cacheable=True, cache_max_age_seconds=3600)
        self.assertNotEqual(baseline, cached)
        self.assertNotEqual(
            cached,
            self.check_digest(cacheable=True, cache_max_age_seconds=7200))

    def test_a_cacheable_check_with_no_bound_is_not_a_policy(self):
        with self.assertRaises(config_module.ConfigError) as caught:
            self.check_digest(cacheable=True)
        self.assertIn("cache_max_age_seconds", str(caught.exception))

    def test_a_check_that_says_nothing_about_reuse_is_not_cacheable(self):
        document = policy()
        parsed = config_module.parse_config(document)
        self.assertFalse(parsed.select_class("default").checks[0].cacheable)

    def test_changing_the_argv_moves_the_digest(self):
        self.assertNotEqual(self.digest(),
                            self.check_digest(argv=["python3", "-c", "raise"]))

    def test_editorial_prose_stays_outside_the_digest(self):
        baseline = self.digest()
        self.assertEqual(baseline, self.digest(
            description="what this class is for",
            residual_risks=["nothing about runtime behaviour"],
            tightening=["add a fuzz check"],
            review_requirement="two humans"))
        self.assertEqual(baseline,
                         self.check_digest(description="the unit suite"))

    def test_the_profile_floor_is_inside_the_digest(self):
        document = policy()
        first = config_module.parse_config(document)
        document = policy()
        document["profile"] = "documentation-only"
        second = config_module.parse_config(document)
        self.assertNotEqual(
            config_module.enforcement_digest(first.select_class("default")),
            config_module.enforcement_digest(second.select_class("default")))


# --------------------------------------------------------------------------
# 5. The cache fingerprint binds the environment a command actually saw.
# --------------------------------------------------------------------------
class CacheFingerprintTest(TempCase):
    """E5: reuse is exact or it is not reuse."""

    def setUp(self):
        super().setUp()
        self.root = self.tmp / "repo"
        self.root.mkdir()

    def fingerprint(self, environment=None, *, executables=(), root=None):
        return runner_module.environment_fingerprint(
            {"PATH": os.environ.get("PATH", "")} if environment is None
            else environment,
            executables=executables, root=self.root if root is None else root)

    def test_a_changed_environment_value_changes_the_fingerprint(self):
        first = self.fingerprint({"PATH": "/usr/bin", "LANG": "C"})
        second = self.fingerprint({"PATH": "/usr/bin", "LANG": "en_US.UTF-8"})
        self.assertNotEqual(first, second)

    def test_an_added_environment_name_changes_the_fingerprint(self):
        first = self.fingerprint({"PATH": "/usr/bin"})
        second = self.fingerprint({"PATH": "/usr/bin", "CFLAGS": "-O2"})
        self.assertNotEqual(first, second)

    def test_a_filtered_control_variable_does_not_change_it(self):
        # The child never sees these, so they cannot change what it observes.
        first = self.fingerprint({"PATH": "/usr/bin"})
        second = self.fingerprint({"PATH": "/usr/bin",
                                   "GITHUB_TOKEN": "shhh",
                                   "ADMISSIBLE_HOME": "/tmp/home"})
        self.assertEqual(first, second)

    def test_a_different_executable_changes_the_fingerprint(self):
        bin_a = self.tmp / "bin-a"
        bin_b = self.tmp / "bin-b"
        for directory, body in ((bin_a, "#!/bin/sh\nexit 0\n"),
                                (bin_b, "#!/bin/sh\nexit 1\n")):
            directory.mkdir()
            tool = directory / "mytool"
            tool.write_text(body, encoding="utf-8")
            tool.chmod(0o755)
        first = self.fingerprint({"PATH": str(bin_a)}, executables=("mytool",))
        second = self.fingerprint({"PATH": str(bin_b)}, executables=("mytool",))
        self.assertNotEqual(first, second)

    def test_an_unresolvable_executable_is_recorded_as_unresolved(self):
        first = self.fingerprint({"PATH": "/nonexistent"},
                                 executables=("mytool",))
        second = self.fingerprint({"PATH": "/nonexistent"}, executables=())
        self.assertNotEqual(first, second)

    def test_a_changed_lockfile_changes_the_fingerprint(self):
        lock = self.root / "poetry.lock"
        lock.write_text("one\n", encoding="utf-8")
        first = self.fingerprint()
        lock.write_text("two\n", encoding="utf-8")
        self.assertNotEqual(first, self.fingerprint())

    def test_every_known_lockfile_is_read(self):
        for name in ("poetry.lock", "uv.lock", "Pipfile.lock",
                     "requirements.txt", "package-lock.json", "yarn.lock",
                     "pnpm-lock.yaml", "Cargo.lock", "go.sum",
                     "Gemfile.lock", "composer.lock"):
            with self.subTest(name=name):
                self.assertIn(name, runner_module.LOCKFILE_NAMES)

    def test_the_hosted_documentation_says_a_temporary_home_caches_nothing(self):
        text = (ROOT / "docs" / "GITHUB_ACTIONS.md").read_text(encoding="utf-8")
        lowered = text.lower()
        self.assertIn("cache", lowered)
        self.assertIn("no cross-run cache", lowered)


# --------------------------------------------------------------------------
# 6. Cache invalidation is ordered by observation, not by attempt start time.
# --------------------------------------------------------------------------
class CacheOrderTest(TempCase):
    """E6: a later-observed failure always outranks an earlier pass."""

    def setUp(self):
        super().setUp()
        self.store = store_module.open_store(self.home)
        self.addCleanup(self.store.close)

    def record(self, *, passed: bool, started_at: int):
        return evidence.CommandEvidence(
            kind="command", check_id="unit", check_version="1",
            repository="github.com/acme/widget", commit_sha="a" * 40,
            tree_sha="b" * 40, policy_digest="c" * 64, argv_digest="d" * 64,
            exit_code=0 if passed else 1, timed_out=False, launch_failed=False,
            duration_ms=5, stdout_sha256="e" * 64, stderr_sha256="f" * 64,
            stdout_bytes=0, stderr_bytes=0, output_truncated=False,
            started_at=started_at, finished_at=started_at + 1,
            attempt_id=f"attempt-{started_at}")

    def lookup(self):
        return self.store.cached_command_evidence(
            repository="github.com/acme/widget", commit_sha="a" * 40,
            tree_sha="b" * 40, policy_digest="c" * 64, check_id="unit",
            check_version="1", argv_digest="d" * 64,
            environment_fingerprint="fp", now=10_000)

    def test_a_failure_observed_later_invalidates_an_earlier_pass(self):
        # The slow attempt started *first* (t=100) and failed *last*. Its
        # recorded_at is lower than the pass it must invalidate, so anything
        # that compares timestamps resurrects the pass.
        self.store.cache_command_evidence(
            self.record(passed=True, started_at=500), recorded_at=500,
            environment_fingerprint="fp")
        self.assertIsNotNone(self.lookup())
        self.store.cache_command_evidence(
            self.record(passed=False, started_at=100), recorded_at=100,
            environment_fingerprint="fp")
        self.assertIsNone(self.lookup())

    def test_a_pass_recorded_after_a_failure_is_reusable_again(self):
        self.store.cache_command_evidence(
            self.record(passed=False, started_at=100), recorded_at=100,
            environment_fingerprint="fp")
        self.store.cache_command_evidence(
            self.record(passed=True, started_at=900), recorded_at=900,
            environment_fingerprint="fp")
        self.assertIsNotNone(self.lookup())

    def test_the_sequence_is_monotone_across_both_tables(self):
        with self.assertRaises(store_module.StoreError):
            self.store.next_cache_sequence()
        self.assertEqual(
            self.store.connection.execute(
                "SELECT COUNT(*) FROM cache_order").fetchone()[0], 0)


# --------------------------------------------------------------------------
# 7. Attempt and evidence identity are closed at issuance.
# --------------------------------------------------------------------------
class ExactIssuanceTest(BoundedCase):
    """E7: a receipt names one attempt and exactly the evidence it decided on."""

    def evaluate_arguments(self):
        artifact_class = config_module.load_config(
            self.root).select_class("default")
        document = self.preview_document()
        return {
            "artifact_class": artifact_class,
            "repository": document["repository"],
            "commit_sha": document["commit_sha"],
            "tree_sha": document["tree_sha"],
            "policy_digest": document["policy_digest"],
            "commands": evidence.parse_bundle(document["evidence"]).commands,
            "reviews": (),
            "now": int(time.time()),
        }

    def test_evaluate_refuses_an_empty_attempt(self):
        arguments = self.evaluate_arguments()
        with self.assertRaises(ValueError) as caught:
            decision.evaluate(attempt_id="", **arguments)
        self.assertIn("attempt", str(caught.exception).lower())

    def test_evaluate_refuses_a_missing_attempt(self):
        arguments = self.evaluate_arguments()
        with self.assertRaises(TypeError):
            decision.evaluate(**arguments)

    def test_issue_receipt_refuses_evidence_it_was_not_given(self):
        arguments = self.evaluate_arguments()
        document = self.preview_document()
        result = decision.evaluate(
            attempt_id=document["decision"]["attempt_id"], **arguments)
        self.assertEqual(result.state, decision.CHECKS_PASSED)
        with self.assertRaises(receipt.ReceiptError) as caught:
            receipt.issue_receipt(
                self.store, repository=result.repository,
                commit_sha=result.commit_sha, tree_sha=result.tree_sha,
                class_id=result.class_id, policy_digest=result.policy_digest,
                result=result, signer=self.signer, now=int(time.time()))
        self.assertIn("evidence", str(caught.exception).lower())

    def test_issue_receipt_refuses_an_extra_record(self):
        arguments = self.evaluate_arguments()
        document = self.preview_document()
        result = decision.evaluate(
            attempt_id=document["decision"]["attempt_id"], **arguments)
        stray = evidence.ReviewEvidence(
            kind="review", review_id="r-stray", reviewer_id="rev",
            reviewer_version="1", author_id="dev", verdict="approve",
            repository=result.repository, commit_sha=result.commit_sha,
            tree_sha=result.tree_sha, policy_digest=result.policy_digest,
            findings_digest="0" * 64, issued_at=int(time.time()),
            attempt_id="")
        with self.assertRaises(receipt.ReceiptError) as caught:
            receipt.issue_receipt(
                self.store, repository=result.repository,
                commit_sha=result.commit_sha, tree_sha=result.tree_sha,
                class_id=result.class_id, policy_digest=result.policy_digest,
                result=result, commands=arguments["commands"],
                reviews=(stray,), signer=self.signer, now=int(time.time()))
        self.assertIn("evidence", str(caught.exception).lower())

    def test_issue_receipt_accepts_exactly_the_decided_records(self):
        arguments = self.evaluate_arguments()
        document = self.preview_document()
        result = decision.evaluate(
            attempt_id=document["decision"]["attempt_id"], **arguments)
        issued = receipt.issue_receipt(
            self.store, repository=result.repository,
            commit_sha=result.commit_sha, tree_sha=result.tree_sha,
            class_id=result.class_id, policy_digest=result.policy_digest,
            result=result, commands=arguments["commands"],
            signer=self.signer, now=int(time.time()))
        self.assertEqual(sorted(issued.evidence_digests),
                         sorted(result.evidence_digests))


# --------------------------------------------------------------------------
# 8. authenticated_reviews records approvals and nothing else.
# --------------------------------------------------------------------------
class AuthenticatedReviewTest(TempCase):
    """E8: an abstention is never attributed as an approval."""

    def test_an_abstaining_reviewer_is_not_recorded_as_an_approver(self):
        approvals = ghmod.approving_reviews((
            evidence.VerifiedReview(record=self._review("approve"),
                                    key_id="rev-a"),
            evidence.VerifiedReview(record=self._review("abstain"),
                                    key_id="rev-b"),
        ))
        self.assertEqual([key for _digest, key in approvals], ["rev-a"])

    def test_a_rejecting_reviewer_is_not_recorded_as_an_approver(self):
        approvals = ghmod.approving_reviews((
            evidence.VerifiedReview(record=self._review("reject"),
                                    key_id="rev-c"),
        ))
        self.assertEqual(approvals, ())

    def _review(self, verdict):
        return evidence.ReviewEvidence(
            kind="review", review_id=f"r-{verdict}", reviewer_id="rev",
            reviewer_version="1", author_id="dev", verdict=verdict,
            repository="github.com/acme/widget", commit_sha="a" * 40,
            tree_sha="b" * 40, policy_digest="c" * 64,
            findings_digest="d" * 64, issued_at=1, attempt_id="")


# --------------------------------------------------------------------------
# 9. One defect, one signed event, one record — under concurrency.
# --------------------------------------------------------------------------
class DefectConcurrencyTest(TempCase):
    """E9: the duplicate check lives inside the compare-and-set transaction."""

    def setUp(self):
        super().setUp()
        self.signer = receipt.signer_from_secret("k1", SECRET)
        self.store = store_module.open_store(self.home)
        self.addCleanup(self.store.close)
        self.repository = "github.com/acme/widget"
        self.document = {
            "kind": "defect", "defect_id": "d-1",
            "repository": self.repository, "commit_sha": "a" * 40,
            "severity": "high", "summary": "the gate missed this",
            "missed_check_ids": ["unit"], "regression_test_id": "t-1",
            "discovered_at": 1000,
        }

    def journal_length(self):
        return len(self.store.journal_events(
            receipt.journal_id_for(self.repository)))

    def test_filing_the_same_defect_twice_writes_one_event(self):
        standing_module.file_defect(self.store, self.document,
                                    signer=self.signer, now=1000)
        standing_module.file_defect(self.store, self.document,
                                    signer=self.signer, now=1001)
        self.assertEqual(self.journal_length(), 1)
        self.assertEqual(self.store.defect_count(self.repository), 1)

    def test_a_racing_filing_still_writes_one_event(self):
        # A real race, two connections, made deterministic at the call edge.
        # There is deliberately no pre-transaction row hint anymore: each
        # writer classifies the row/event correspondence only after SQLite has
        # serialized it under BEGIN IMMEDIATE.
        import threading

        barrier = threading.Barrier(2, timeout=30)
        failures: list[BaseException] = []

        def file(moment):
            opened = store_module.open_store(self.home)
            try:
                barrier.wait()
                standing_module.file_defect(opened, self.document,
                                            signer=self.signer, now=moment)
            except BaseException as error:  # noqa: BLE001 - reported below
                failures.append(error)
            finally:
                opened.close()

        threads = [threading.Thread(target=file, args=(moment,))
                   for moment in (1000, 1001)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        self.assertEqual(failures, [])
        self.assertEqual(self.journal_length(), 1)
        self.assertEqual(self.store.defect_count(self.repository), 1)

    def test_a_second_event_for_a_recorded_defect_aborts_the_transaction(self):
        """The row is the last word, not the idempotency hint above it.

        ``file_defect`` re-reads under the write lock, so this goes around it
        and anchors the second event directly -- which is what a caller that
        forgot the precondition, or a racing writer whose hint went stale
        between the read and the write, actually does. A defect row that
        silently vanishes leaves a signed event with no record behind it, and
        import can only read that as a forgery.
        """

        standing_module.file_defect(self.store, self.document,
                                    signer=self.signer, now=1000)
        record = evidence.defect_from_dict(self.document)
        digest = evidence.evidence_digest(record)
        event = {
            "domain": receipt.RECEIPT_DOMAIN, "type": receipt.EVENT_DEFECT,
            "defect_digest": digest, "defect_id": record.defect_id,
            "repository": record.repository, "commit_sha": record.commit_sha,
            "severity": record.severity,
            "discovered_at": record.discovered_at, "filed_at": 1001,
        }
        statement, parameters = self.store.defect_row(
            digest=digest, defect_id=record.defect_id,
            repository=record.repository, commit_sha=record.commit_sha,
            filed_at=1001, record=evidence.defect_to_dict(record))
        with self.assertRaises(store_module.StoreError):
            receipt.anchor(
                self.store, receipt.journal_id_for(self.repository), event,
                signer=self.signer, now=1001,
                attach=lambda proposal: [(statement, parameters)])
        # Aborted, so the event that would have had no record is not there.
        self.assertEqual(self.journal_length(), 1)
        self.assertEqual(self.store.defect_count(self.repository), 1)

    def test_import_refuses_two_signed_events_for_one_defect_record(self):
        record = evidence.defect_from_dict(self.document)
        digest = evidence.evidence_digest(record)
        event = {
            "domain": receipt.RECEIPT_DOMAIN, "type": receipt.EVENT_DEFECT,
            "defect_digest": digest, "defect_id": record.defect_id,
            "repository": record.repository, "commit_sha": record.commit_sha,
            "severity": record.severity,
            "discovered_at": record.discovered_at, "filed_at": 1000,
        }
        journal_id = receipt.journal_id_for(self.repository)
        statement, parameters = self.store.defect_row(
            digest=digest, defect_id=record.defect_id,
            repository=record.repository, commit_sha=record.commit_sha,
            filed_at=1000, record=evidence.defect_to_dict(record),
            idempotent=True)
        receipt.anchor(self.store, journal_id, event, signer=self.signer,
                       now=1000,
                       attach=lambda proposal: [(statement, parameters)])
        # A second, byte-identical signed event for the same record. One event,
        # one record is the invariant; two events for one record is not history.
        receipt.anchor_event(self.store, journal_id, event, signer=self.signer,
                             now=1001)
        bundle = self.store.export_journal(journal_id)
        other = store_module.open_store(self.tmp / "other-home")
        self.addCleanup(other.close)
        with self.assertRaises(store_module.StoreError) as caught:
            other.import_journal(bundle, self.signer)
        self.assertIn("defect", str(caught.exception).lower())


# --------------------------------------------------------------------------
# 10. Finalize retried after a crash is the same act.
# --------------------------------------------------------------------------
class FinalizeIdempotencyTest(BoundedCase):
    """E10: a retry one second later is not a second admission."""

    def journal_length(self):
        return len(self.store.journal_events(
            receipt.journal_id_for(self.repository)))

    def observed(self, offset=1):
        """An observation moment just after the evaluation finished."""

        return self.preview_document()["issued_at"] + offset

    def test_a_retry_at_a_later_clock_issues_the_same_receipt(self):
        moment = self.observed()
        attestation_path = self.attestation(observed_at=moment)
        first = self.finalize(attestation_path=attestation_path,
                              now=moment + 100)
        second = self.finalize(attestation_path=attestation_path,
                               now=moment + 9_999)
        self.assertEqual(first.receipt_hash, second.receipt_hash)
        self.assertEqual(first.body_digest, second.body_digest)
        self.assertEqual(self.journal_length(), 1)

    def test_the_receipt_is_issued_at_the_observation_moment(self):
        moment = self.observed()
        issued = self.finalize(
            attestation_path=self.attestation(observed_at=moment),
            now=moment + 500)
        self.assertEqual(issued.issued_at, moment)

    def test_an_observation_from_the_future_is_refused(self):
        moment = self.observed(10_000)
        attestation_path = self.attestation(observed_at=moment)
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=attestation_path,
                          now=moment - 9_000)
        message = str(caught.exception).lower()
        self.assertIn("future", message)
        self.assertIn(
            "observation nobody has reached yet cannot issue one", message)

    def test_an_observation_before_the_evaluation_is_refused(self):
        document = self.preview_document()
        attestation_path = self.attestation(
            observed_at=document["issued_at"] - 10_000)
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=attestation_path,
                          now=document["issued_at"] + 10)
        self.assertIn("observ", str(caught.exception).lower())


# --------------------------------------------------------------------------
# 11. init writes every target or none of them, and never outside the tree.
# --------------------------------------------------------------------------
class InitContainmentTest(TempCase):
    """E11: a candidate-controlled symlink is not a write primitive."""

    def setUp(self):
        super().setUp()
        self.root = self.tmp / "repo"
        self.root.mkdir()
        self.outside = self.tmp / "outside"
        self.outside.mkdir()

    def init(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["init", "--repo", str(self.root), "--profile",
                         "python-library", "--json", *extra],
                        stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_a_symlinked_gitignore_is_refused_and_nothing_is_written(self):
        target = self.outside / "victim"
        target.write_text("keep me\n", encoding="utf-8")
        (self.root / ".gitignore").symlink_to(target)
        code, out, _ = self.init()
        self.assertEqual(code, 2, out)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep me\n")
        self.assertFalse((self.root / ".admissible.json").exists())

    def test_a_symlinked_policy_file_is_refused(self):
        target = self.outside / "policy.json"
        target.write_text("{}\n", encoding="utf-8")
        (self.root / ".admissible.json").symlink_to(target)
        code, out, _ = self.init("--force")
        self.assertEqual(code, 2, out)
        self.assertEqual(target.read_text(encoding="utf-8"), "{}\n")

    def test_a_symlinked_workflow_directory_is_refused(self):
        (self.root / ".github").symlink_to(self.outside, target_is_directory=True)
        code, out, _ = self.init("--ci", "github", "--tool-sha", "a" * 40)
        self.assertEqual(code, 2, out)
        self.assertFalse((self.outside / "workflows").exists())
        self.assertFalse((self.root / ".admissible.json").exists())

    def test_a_failing_later_target_leaves_no_earlier_file(self):
        # `.gitignore` is a directory: unwritable, and discovered by preflight
        # rather than half-way through.
        (self.root / ".gitignore").mkdir()
        code, out, _ = self.init("--ci", "github", "--tool-sha", "a" * 40)
        self.assertEqual(code, 2, out)
        self.assertFalse((self.root / ".admissible.json").exists())
        self.assertFalse((self.root / ".github").exists())

    def test_a_successful_init_writes_every_target(self):
        code, out, err = self.init("--ci", "github", "--tool-sha", "a" * 40)
        self.assertEqual(code, 0, out + err)
        self.assertTrue((self.root / ".admissible.json").exists())
        self.assertTrue(
            (self.root / ".github" / "workflows" / "admissible.yml").exists())
        self.assertIn("__pycache__/",
                      (self.root / ".gitignore").read_text(encoding="utf-8"))

    def test_planning_refuses_an_unwritable_target_before_planning_ends(self):
        """Preflight is part of the plan, not part of the writing.

        ``apply_init`` can undo a partial write, so a check that only happens
        while writing still ends with the tree intact -- and that is why the
        CLI-level tests cannot tell the two apart. What they cannot do is tell
        the operator *before* anything moves. The plan refuses, or the
        all-or-nothing promise is an apology issued afterwards.

        Both targets are tried: the first one in the plan and the last, so a
        preflight that checked only the file it happened to start with would
        still be caught.
        """

        for relative in (".admissible.json", ".github/workflows/admissible.yml"):
            with self.subTest(relative=relative):
                blocker = self.root / relative
                blocker.mkdir(parents=True)
                try:
                    with self.assertRaises(config_module.ConfigError) as caught:
                        config_module.plan_init(
                            self.root, "python-library", ci="github",
                            tool_sha="a" * 40, force=True)
                    message = str(caught.exception)
                    self.assertIn("not a regular file", message)
                    self.assertIn("Nothing was written", message)
                    self.assertFalse((self.root / ".gitignore").exists())
                finally:
                    blocker.rmdir()

    def test_preflight_names_every_target_it_would_write(self):
        targets = config_module.init_targets(
            self.root, "python-library", ci="github", tool_sha="a" * 40)
        names = {Path(item).name for item in targets}
        self.assertEqual(
            names, {".admissible.json", "admissible.yml", ".gitignore"})


# --------------------------------------------------------------------------
# 12. An interrupt after a possible durable commit never says "nothing".
# --------------------------------------------------------------------------
class InterruptedFinalizeTest(BoundedCase):
    """E12: UNKNOWN_COMMIT_OUTCOME, or the locator of what was committed."""

    def finalize_argv(self, *extra):
        return ["finalize", "--preview", str(self.preview), "--sha", self.sha,
                "--policy-root", str(self.root),
                "--evaluation-attestation", str(self.attestation()), *extra]

    def setUp(self):
        super().setUp()
        os.environ["ADMISSIBLE_DURABLE_HOME"] = "1"
        keyring = self.tmp / "observers.json"
        keyring.write_text(
            json.dumps({OBSERVER_KEY_ID: OBSERVER_SECRET.decode("utf-8")}),
            encoding="utf-8")
        keyring.chmod(0o600)
        os.environ["ADMISSIBLE_EVALUATION_KEYRING"] = str(keyring)
        self.store.close()

    def test_an_interrupt_before_the_commit_reports_unknown_outcome(self):
        original = ghmod.finalize

        def interrupt(*args, **kwargs):
            raise KeyboardInterrupt

        ghmod.finalize = interrupt
        self.addCleanup(lambda: setattr(ghmod, "finalize", original))
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(self.finalize_argv("--json"), stdout=out, stderr=err)
        ghmod.finalize = original
        document = json.loads(out.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(document["state"], "UNKNOWN_COMMIT_OUTCOME")
        self.assertIn("verify", " ".join(document["remediation"]).lower())

    def test_an_interrupt_after_the_commit_reports_the_receipt(self):
        original = ghmod.finalize

        def commit_then_interrupt(*args, **kwargs):
            original(*args, **kwargs)
            raise KeyboardInterrupt

        ghmod.finalize = commit_then_interrupt
        self.addCleanup(lambda: setattr(ghmod, "finalize", original))
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(self.finalize_argv("--json"), stdout=out, stderr=err)
        ghmod.finalize = original
        document = json.loads(out.getvalue())
        self.assertEqual(document["state"], decision.ADMITTED)
        self.assertEqual(code, 0)
        self.assertTrue(document["receipt_hash"])

    def test_an_interrupted_run_still_honours_json(self):
        original = cli._command_run

        def interrupt(*args, **kwargs):
            raise KeyboardInterrupt

        cli._COMMANDS["run"] = interrupt
        self.addCleanup(lambda: cli._COMMANDS.__setitem__("run", original))
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["run", "--preview", "--repo", str(self.root),
                         "--json"], stdout=out, stderr=err)
        self.assertEqual(code, 2)
        document = json.loads(out.getvalue())
        self.assertEqual(document["state"], "INTERRUPTED")


# --------------------------------------------------------------------------
# 13. The hosted workflow is evaluate-only and says so exactly.
# --------------------------------------------------------------------------
class HostedWorkflowTest(unittest.TestCase):
    """E13: no impossible transport, no secret in the caller."""

    def workflows(self):
        return (GATE, TEMPLATE)

    def test_the_gate_and_the_packaged_template_are_byte_identical(self):
        self.assertEqual(GATE.read_bytes(), TEMPLATE.read_bytes())

    def test_no_workflow_claims_a_committed_review_bundle_is_supported(self):
        for path in self.workflows():
            text = path.read_text(encoding="utf-8").lower()
            with self.subTest(path=path.name):
                self.assertNotIn("committing them to the candidate tree", text)
                self.assertNotIn("supported transport", text)

    def test_the_gate_explains_why_a_review_cannot_travel_in_the_tree(self):
        text = GATE.read_text(encoding="utf-8").lower()
        self.assertIn("binds the commit and tree", text)
        self.assertIn("out-of-band", text)

    def test_the_gate_names_the_transport_as_an_unimplemented_boundary(self):
        text = GATE.read_text(encoding="utf-8").lower()
        self.assertIn("not implemented by this workflow", text)

    def test_the_scratch_directory_is_not_visible_to_candidate_commands(self):
        text = GATE.read_text(encoding="utf-8")
        # The directory holding the preview is named only inside the namespace
        # a check never sees. A bare `SCRATCH` would be handed straight to
        # every candidate command the job starts.
        self.assertNotIn("\n          SCRATCH:", text)
        self.assertNotIn("$SCRATCH", text)
        self.assertIn("ADMISSIBLE_SCRATCH", text)
        stripped = runner_module.child_environment(
            {"ADMISSIBLE_SCRATCH": "/tmp/secret", "PATH": "/usr/bin"})
        self.assertNotIn("ADMISSIBLE_SCRATCH", stripped)

    def test_the_consumer_caller_passes_no_secret(self):
        text = (ROOT / "admissible" / "templates"
                / "consumer-workflow.yml").read_text(encoding="utf-8")
        self.assertNotIn("secrets", text)
        self.assertNotIn("${{ secrets", text)


# --------------------------------------------------------------------------
# 14. Author identity is authenticated, never merely populated.
# --------------------------------------------------------------------------
class AuthorAttestationTest(TempCase):
    """E14: no author attestation, no independent-review admission."""

    def setUp(self):
        super().setUp()
        self.artifact_class = config_module.parse_config(policy(
            required_independent_reviews=1,
            reviewer_key_ids=["rev-1"], author_key_ids=["author-1"],
        )).select_class("default")
        self.identity = {
            "repository": "github.com/acme/widget", "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
            "policy_digest": self.artifact_class.policy_digest,
        }

    def command(self):
        return evidence.CommandEvidence(
            kind="command", check_id="unit", check_version="1",
            argv_digest=self.artifact_class.checks[0].argv_digest,
            exit_code=0, timed_out=False, launch_failed=False, duration_ms=1,
            stdout_sha256="0" * 64, stderr_sha256="0" * 64, stdout_bytes=0,
            stderr_bytes=0, output_truncated=False, started_at=1000,
            finished_at=1001, attempt_id="attempt-1", **self.identity)

    def approving_review(self):
        return evidence.VerifiedReview(
            record=evidence.ReviewEvidence(
                kind="review", review_id="r-1", reviewer_id="rev",
                reviewer_version="1", author_id="dev", verdict="approve",
                findings_digest="0" * 64, issued_at=1000, attempt_id="",
                **self.identity),
            key_id="rev-1")

    def authorship(self, key_id="author-1"):
        return evidence.AttestedAuthorship(
            record=evidence.AuthorshipEvidence(
                kind="authorship", author_id="dev", issued_at=1000,
                **self.identity),
            key_id=key_id)

    def evaluate(self, **extra):
        return decision.evaluate(
            artifact_class=self.artifact_class, commands=(self.command(),),
            reviews=(self.approving_review(),), now=1010,
            attempt_id="attempt-1", **{**self.identity, **extra})

    def test_without_an_author_attestation_there_is_no_admission(self):
        result = self.evaluate()
        self.assertNotEqual(result.state, decision.CHECKS_PASSED)
        self.assertIn("missing_author_attestation",
                      {reason.code for reason in result.reasons})

    def test_an_authenticated_author_attestation_completes_the_admission(self):
        result = self.evaluate(authorships=(self.authorship(),))
        self.assertEqual(result.state, decision.CHECKS_PASSED, result.reasons)

    def test_an_author_key_the_policy_does_not_pin_never_counts(self):
        result = self.evaluate(authorships=(self.authorship("stranger"),))
        self.assertNotEqual(result.state, decision.CHECKS_PASSED)
        self.assertIn("unpinned_author_key",
                      {reason.code for reason in result.reasons})

    def test_an_unauthenticated_claim_is_reported_as_pending(self):
        claim = evidence.UnverifiedAuthorship(
            record=self.authorship().record, key_id="author-1")
        result = self.evaluate(authorships=(claim,))
        self.assertNotEqual(result.state, decision.CHECKS_PASSED)
        self.assertIn("unauthenticated_authorship",
                      {reason.code for reason in result.reasons})

    def test_a_class_with_no_required_review_needs_no_author_attestation(self):
        artifact_class = config_module.parse_config(
            policy()).select_class("default")
        identity = dict(self.identity, policy_digest=artifact_class.policy_digest)
        command = evidence.CommandEvidence(
            kind="command", check_id="unit", check_version="1",
            argv_digest=artifact_class.checks[0].argv_digest, exit_code=0,
            timed_out=False, launch_failed=False, duration_ms=1,
            stdout_sha256="0" * 64, stderr_sha256="0" * 64, stdout_bytes=0,
            stderr_bytes=0, output_truncated=False, started_at=1000,
            finished_at=1001, attempt_id="attempt-1", **identity)
        result = decision.evaluate(
            artifact_class=artifact_class, commands=(command,), reviews=(),
            now=1010, attempt_id="attempt-1", **identity)
        self.assertEqual(result.state, decision.CHECKS_PASSED, result.reasons)

    def test_the_policy_keeps_author_and_reviewer_keys_disjoint(self):
        with self.assertRaises(config_module.ConfigError):
            config_module.parse_config(policy(
                required_independent_reviews=1,
                reviewer_key_ids=["shared"], author_key_ids=["shared"]))


# --------------------------------------------------------------------------
# 15. The fork flag is signed, and nothing signs itself.
# --------------------------------------------------------------------------
class ForkBindingTest(BoundedCase):
    """E15: a fork can evaluate and can never be finalised."""

    def test_a_fork_preview_is_refused_even_when_signed_as_a_fork(self):
        self.rewrite_preview(fork=True)
        path = self.attestation()
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=path)
        self.assertIn("fork", str(caught.exception).lower())

    def test_the_preview_always_carries_an_exact_boolean_fork_flag(self):
        self.assertIs(self.preview_document()["fork"], False)

    def test_a_fork_flag_that_is_not_a_boolean_is_never_signed(self):
        # The signed statement is where the prohibition finally rests, so the
        # observer cannot be allowed to sign a fork flag that is merely
        # falsy. `null`, `0` and `"false"` all read as "not a fork" to a
        # careless comparison and none of them is `false`.
        for value in (None, 0, 1, "false", "true"):
            with self.subTest(value=value):
                with self.assertRaises(
                        attestation_module.EvaluationError) as caught:
                    attestation_module.attest_preview(
                        self.preview_document(), key_id=OBSERVER_KEY_ID,
                        secret=OBSERVER_SECRET,
                        isolation="pid-namespace",
                        source_receipt=self.source_receipt(), observed_at=1,
                        fork=value)
                self.assertIn("fork must be exactly true or false",
                              str(caught.exception))

    def test_an_attestation_signed_over_a_fork_cannot_finalise_this_preview(self):
        # The preview says `fork: false`, so the prohibition that reads the
        # preview passes. The observer signed for a *fork* evaluation, and
        # only comparing the signed flag against the presented one can say so.
        path = self.attestation(fork=True)
        self.assertIs(self.preview_document()["fork"], False)
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=path)
        message = str(caught.exception)
        self.assertIn("fork=True", message)
        self.assertIn("fails open", message)
        self.assertEqual(self.store.receipt_count(self.repository), 0)

    def test_the_workflow_never_reports_a_green_awaiting_review(self):
        for path in (GATE, TEMPLATE):
            lines = path.read_text(encoding="utf-8").splitlines()
            with self.subTest(path=path.name):
                start = next(index for index, line in enumerate(lines)
                             if 'READINESS" = "AWAITING_REVIEW"' in line)
                end = next(index for index, line in enumerate(lines)
                           if index > start and line.strip() == "fi")
                block = [line.strip() for line in lines[start:end]]
                self.assertIn("exit 1", block)
                self.assertNotIn("exit 0", block)


# --------------------------------------------------------------------------
# 16. History is answered from what was recorded, not from today's tree.
# --------------------------------------------------------------------------
class HistoricalExplainTest(BoundedCase):
    """E16: explain re-judges a recorded attempt or says it cannot."""

    def test_explain_uses_the_recorded_attempt(self):
        self.finalize()
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["explain", self.sha, "--repo", str(self.root),
                         "--json"], stdout=out, stderr=err)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        document = json.loads(out.getvalue())
        self.assertTrue(document["decision_attempt_id"])
        self.assertEqual(document["decision"]["attempt_id"],
                         document["decision_attempt_id"])

    def test_explain_declines_to_re_judge_when_no_attempt_was_recorded(self):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["explain", "d" * 40, "--repo", str(self.root),
                         "--json"], stdout=out, stderr=err)
        self.assertEqual(code, 1)
        document = json.loads(out.getvalue())
        self.assertIsNone(document["decision"])
        self.assertIn("attempt", document["policy_note"].lower())


# --------------------------------------------------------------------------
# 17/18/19. Packaging, first-run and the counts the README states.
# --------------------------------------------------------------------------
class PackagingContractTest(unittest.TestCase):
    """E17: the envelope, the counts and the build metadata are exact."""

    def test_the_readme_states_the_real_command_count(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(len(cli._COMMANDS), 18)
        self.assertIn("18 CLI commands", text)
        self.assertNotIn("13 CLI commands", text)

    def test_the_help_lists_every_command(self):
        for name in cli._COMMANDS:
            with self.subTest(name=name):
                self.assertIn(name, cli._HELP)

    def test_the_envelope_claim_is_narrowed_to_the_commands_that_keep_it(self):
        text = (ROOT / "docs" / "DEVELOPER_WORKFLOW.md").read_text(
            encoding="utf-8")
        self.assertNotIn(
            "the document always carries `state`, `readiness`, `exit_code`,\n"
            "`message` and `remediation`", text)
        self.assertIn(
            "**`verify`, `status` and `explain` emit a human summary on "
            "nonzero exits.**", text)
        self.assertIn("**usage and operational envelopes carry**", text)
        self.assertIn("`message` is **not** in that universal rule", text)

    def test_the_build_requires_a_setuptools_that_reads_this_metadata(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('requires = ["setuptools==83.0.0"]', text)
        self.assertIn('dev = ["build==1.4.0"', text)

    def test_the_python_profile_ships_a_required_packaging_check(self):
        document = config_module.profile_document("python-library")
        checks = {check["id"]: check
                  for check in document["classes"][0]["checks"]}
        self.assertTrue(checks["packaging"]["required"])
        self.assertIn("packaging", checks)

    def test_the_licence_ships(self):
        self.assertTrue((ROOT / "LICENSE").is_file())


class FirstRunContractTest(BoundedCase):
    """E18: what the CLI tells somebody who has nothing yet."""

    def test_unknown_standing_names_the_preview_and_finalize_flow(self):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["status", "--repo", str(self.root)], stdout=out,
                        stderr=err)
        self.assertEqual(code, 1)
        text = out.getvalue()
        self.assertIn("run --preview", text)
        self.assertIn("finalize", text)

    def test_the_readme_quickstart_runs_as_written(self):
        """Every command in the README quickstart, in order, in a real repo.

        "Those run as written, in that order" is a promise, and the way to keep
        it is to run them. A refusal is fine and expected -- the profile names
        tools this machine may not have -- but exit 2 with a usage error is a
        command line the README got wrong.
        """

        block = self._quickstart()
        self.assertTrue(block, "the README quickstart block was not found")
        fresh = self.tmp / "quickstart"
        make_repo(fresh, files={"README.md": "widget\n"})
        (fresh / "defect.json").write_text(json.dumps({
            "kind": "defect", "defect_id": "d-1",
            "repository": "github.com/acme/widget",
            "commit_sha": self.sha, "severity": "high", "summary": "x",
            "missed_check_ids": [], "regression_test_id": "unit",
            "discovered_at": 1}), encoding="utf-8")
        for argv in block:
            with self.subTest(argv=" ".join(argv)):
                # `--repo` is a common option on every command that reads one;
                # `profiles` reads none, and the README does not pass it one.
                if argv[0] != "profiles":
                    argv = [*argv, "--repo", str(fresh)]
                out, err = io.StringIO(), io.StringIO()
                code = cli.main(argv, stdout=out, stderr=err)
                self.assertIn(code, (0, 1, 2))
                self.assertNotIn("is not a usable command line",
                                 out.getvalue() + err.getvalue())
                self.assertNotIn("the following arguments are required",
                                 out.getvalue() + err.getvalue())
                self.assertNotIn("unrecognized arguments",
                                 out.getvalue() + err.getvalue())

    #: The heading the quickstart block lives under.  It is named rather than
    #: counted, because "the first fenced block in the file" stopped being the
    #: quickstart the moment the README grew an installation section above it,
    #: and a positional slice that silently selects the wrong block returns an
    #: empty command list -- which is a test that passes by finding nothing.
    QUICKSTART_HEADING = "## Admissible Ready"

    @classmethod
    def _quickstart(cls):
        import shlex

        text = (ROOT / "README.md").read_text(encoding="utf-8")
        section = text.split(cls.QUICKSTART_HEADING, 1)
        assert len(section) > 1, f"README has no {cls.QUICKSTART_HEADING}"
        block = section[1].split("```bash", 1)[1].split("```", 1)[0]
        found = []
        for line in block.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line.startswith("admissible "):
                continue
            words = shlex.split(line.replace('"$(git rev-parse HEAD)"', "HEAD"))
            found.append(words[1:])
        return found

    def test_the_quickstart_in_the_generated_policy_is_executable(self):
        # Every argv the shipped Python profile configures must resolve to a
        # program on this machine, or the "first run" the README documents
        # cannot work as written.
        import shutil

        document = config_module.profile_document("python-library")
        for check in document["classes"][0]["checks"]:
            with self.subTest(check=check["id"]):
                self.assertIsNotNone(
                    shutil.which(check["argv"][0]),
                    f"{check['argv'][0]} is not on PATH")

    def test_preview_audit_behaviour_is_described_honestly(self):
        fresh = self.tmp / "fresh"
        fresh.mkdir()
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["init", "--repo", str(fresh), "--profile",
                         "python-library"], stdout=out, stderr=err)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        text = out.getvalue() + err.getvalue()
        self.assertIn("run --preview", text)
        self.assertIn("owner-only logs", text)


class DiscoveredCountsTest(unittest.TestCase):
    """E19: the README states counts this checkout can derive.

    Searching the README for a number somebody typed proves that somebody typed
    it. These derive the numbers from collection and compare, so a suite that
    grows and a README that does not is a red test rather than a stale claim.
    """

    #: Directories under ``tests/`` that hold Admissible product suites. The
    #: runtime split moves product checks out of ``test_admissible_*.py`` and
    #: into one package per wheel, so the filename prefix alone no longer says
    #: which scope a check belongs to. A split directory missing from this set
    #: would be counted against the research kernel the paper cites, which is
    #: why ``test_the_split_product_directories_are_product_owned`` requires
    #: every directory that exists on disk to be declared here.
    PRODUCT_DIRECTORIES = frozenset({
        "architecture", "core", "ready", "trust", "compatibility"})

    @classmethod
    def setUpClass(cls):
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.ids = cls._collect("tests")

    @classmethod
    def _is_product(cls, item):
        """Whether a collected id belongs to the Admissible developer product.

        Two owners, one rule: a check inside a declared split directory is
        product-owned whatever it is named, and a top-level check is
        product-owned only under the legacy ``test_admissible_`` prefix.
        """

        parts = item.split("::", 1)[0].split("/")
        if len(parts) > 2:
            return parts[1] in cls.PRODUCT_DIRECTORIES
        return parts[-1].startswith("test_admissible_")

    def test_the_total_under_tests_is_what_the_readme_states(self):
        self.assertIn(f"| **{len(self.ids) + 37 + 71}** | {len(self.ids)} under "
                      "`tests/`, 37 atlas, 71 cockpit |", self.readme)

    def test_the_developer_product_count_is_what_the_readme_states(self):
        product = sum(1 for item in self.ids if self._is_product(item))
        self.assertIn(f"| Developer product (`admissible/`) | {product} |",
                      self.readme)
        self.assertIn(f"including {product} for the developer product",
                      self.readme)

    def test_the_split_product_directories_are_product_owned(self):
        # The split suites are product tests that do not carry the legacy
        # filename prefix. Classifying by prefix alone would file them under
        # the research kernel and move a number the paper cites.
        for directory in sorted(self.PRODUCT_DIRECTORIES):
            with self.subTest(directory=directory):
                self.assertTrue(self._is_product(
                    f"tests/{directory}/test_anything.py::Case::test_x"))
        self.assertTrue(self._is_product(
            "tests/test_admissible_ready.py::Case::test_x"))
        self.assertFalse(self._is_product(
            "tests/test_rga_invariants.py::Case::test_x"))
        self.assertFalse(self._is_product(
            "tests/kernel_only/test_anything.py::Case::test_x"))
        # Any split directory that appears on disk without being declared
        # would leak into the kernel scope, so require the set to be complete.
        on_disk = {entry.name for entry in (ROOT / "tests").iterdir()
                   if entry.is_dir() and any(entry.glob("test_*.py"))}
        self.assertEqual(on_disk - self.PRODUCT_DIRECTORIES, set(),
                         "undeclared test directory would count as kernel")
        # And the collected ids must actually be classifiable by directory.
        collected = {item.split("/")[1] for item in self.ids
                     if len(item.split("::", 1)[0].split("/")) > 2}
        self.assertEqual(collected - self.PRODUCT_DIRECTORIES, set())

    def test_the_research_kernel_count_is_what_the_paper_cites(self):
        # 579 is the number the paper cites, and the kernel scope is where a
        # cockpit-server or release-integrity check lands when its top-level
        # filename carries neither the product prefix nor a product directory.
        # The paper, README, and this assertion move with those guards instead
        # of holding the count still by leaving release fixes untested.
        kernel = sum(1 for item in self.ids if not self._is_product(item))
        self.assertEqual(kernel + 37 + 71, 579)
        self.assertIn("| Research kernel — the number the paper cites | 579 |",
                      self.readme)

    def test_the_atlas_count_is_what_the_readme_states(self):
        self.assertEqual(len(self._collect("atlas/tests")), 37)

    @staticmethod
    def _collect(path):
        """Every test method under ``path``, by unittest's own discovery.

        Deliberately not by shelling out to pytest. The README documents
        ``python3 -m unittest discover`` as the test command, so the count it
        states should be the count that command finds — and a derivation that
        needs a dev-only extra installed would skip on exactly the stripped
        interpreter where the claim is most worth checking. Both loaders agree
        on this tree; this one is the one the README promises.
        """

        directory = ROOT / path
        loader = unittest.TestLoader()
        found = []

        def walk(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    walk(item)
                else:
                    module = type(item).__module__.replace(".", "/")
                    found.append(f"{path}/{module}.py::"
                                 f"{type(item).__name__}::"
                                 f"{item._testMethodName}")

        saved = list(sys.path)
        sys.path.insert(0, str(directory))
        try:
            walk(loader.discover(str(directory), pattern="test_*.py"))
        finally:
            sys.path[:] = saved
        if loader.errors:
            raise AssertionError(
                "discovery failed: " + "; ".join(str(e) for e in loader.errors))
        if not found:
            raise AssertionError(f"no tests discovered under {directory}")
        return found


# --------------------------------------------------------------------------
# Signed impeachment needs storage that outlives the job.
# --------------------------------------------------------------------------
class ImpeachDurabilityTest(BoundedCase):
    """A revocation nobody can read back is not a revocation."""

    def test_impeach_refuses_a_disposable_home(self):
        os.environ["GITHUB_ACTIONS"] = "true"
        os.environ["GITHUB_WORKSPACE"] = str(self.tmp)
        os.environ["ADMISSIBLE_HOME"] = str(self.tmp / "throwaway")
        defect = self.tmp / "defect.json"
        defect.write_text(json.dumps({
            "kind": "defect", "defect_id": "d-1",
            "repository": self.repository, "commit_sha": self.sha,
            "severity": "high", "summary": "missed",
            "missed_check_ids": ["unit"], "regression_test_id": "t-1",
            "discovered_at": 1000}), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["impeach", self.sha, "--repo", str(self.root),
                         "--evidence", str(defect), "--json"],
                        stdout=out, stderr=err)
        self.assertEqual(code, 2, out.getvalue())
        self.assertIn("durable", out.getvalue().lower())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
