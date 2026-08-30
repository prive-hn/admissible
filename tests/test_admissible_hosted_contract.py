"""Frozen public contract for the hosted evaluate-only workflow.

These tests deliberately inspect the artefacts a consumer receives.  The
hosted workflow is candidate-adjacent, so it may publish evidence but may not
let its caller manufacture an isolation assertion or smuggle a credential into
the job.  Admission remains an out-of-band, durable, separately authenticated
operation.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / ".github" / "workflows" / "admissible-gate.yml"
GATE_TEMPLATE = ROOT / "admissible" / "templates" / "reusable-workflow.yml"
ACTION = ROOT / ".github" / "actions" / "admissible" / "action.yml"
ACTION_TEMPLATE = ROOT / "admissible" / "templates" / "action.yml"
CONSUMER = ROOT / "admissible" / "templates" / "consumer-workflow.yml"
UPLOAD_ARTIFACT_SHA = "ea165f8d65b6e75b540449e92b4886f43607fa02"


def read(relative: str | Path) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class HostedWorkflowAuthorityTest(unittest.TestCase):
    def setUp(self):
        self.body = GATE.read_text(encoding="utf-8")

    def test_the_hosted_caller_cannot_assert_isolation(self):
        inputs = self.body[self.body.index("    inputs:"):
                           self.body.index("    outputs:")]
        self.assertNotIn("      isolation:", inputs)
        self.assertNotIn("inputs.isolation", self.body)
        self.assertIn("ADMISSIBLE_ISOLATION: none", self.body)

    def test_every_preview_is_uploaded_even_when_the_gate_is_red(self):
        self.assertEqual(
            self.body.count(
                f"uses: actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}"), 1)
        upload = self.body[self.body.index(
            "      - name: persist the preview handoff"):]
        upload = upload[:upload.index("\n      - ", 1)]
        self.assertIn("always()", upload)
        self.assertIn("steps.gate.outputs.preview", upload)
        self.assertIn("steps.preview_receipt.outputs.path", upload)
        self.assertIn("if-no-files-found: error", upload)

    def test_the_artifact_name_binds_full_sha_and_run_attempt(self):
        self.assertIn(
            "name: admissible-preview-${{ steps.head.outputs.sha }}-attempt-${{ github.run_attempt }}",
            self.body)
        head = self.body[self.body.index("      - id: head"):
                         self.body.index("      - id: scratch")]
        self.assertIn('${#EVALUATED_SHA}', head)
        self.assertIn('-eq 40', head)

    def test_the_uploaded_preview_has_a_sha256_receipt(self):
        receipt = self.body[self.body.index("      - id: preview_receipt"):
                            self.body.index("uses: actions/upload-artifact@")]
        self.assertIn("hashlib.sha256", receipt)
        self.assertIn("preview.sha256", receipt)
        self.assertIn('print("path="', receipt)

    def test_the_hosted_job_has_no_secret_channel(self):
        self.assertNotIn("${{ secrets.", self.body)
        self.assertNotIn("secrets:", self.body)
        permissions = self.body[self.body.index("permissions:"):
                                self.body.index("jobs:")]
        self.assertEqual(permissions.strip(), "permissions:\n  contents: read")

    def test_the_packaged_workflow_is_byte_identical(self):
        self.assertEqual(GATE.read_bytes(), GATE_TEMPLATE.read_bytes())


class PublicHandoffContractTest(unittest.TestCase):
    MATRIX = (
        "READY_FOR_ATTESTATION -> success only",
        "AWAITING_REVIEW -> success or failure",
        "NOT_READY -> no provider conclusion is admissible",
    )

    def test_the_generated_caller_does_not_suggest_in_tree_reviews(self):
        body = CONSUMER.read_text(encoding="utf-8")
        self.assertNotIn(".admissible/reviews.json", body)
        self.assertIn("out-of-band", body)
        self.assertIn("admissible finalize", body)
        self.assertIn("--reviews", body)

    def test_action_and_template_publish_state_and_readiness(self):
        for path in (ACTION, ACTION_TEMPLATE):
            with self.subTest(path=path):
                body = path.read_text(encoding="utf-8")
                outputs = body[body.index("outputs:"):body.index("runs:")]
                for value in ("CHECKS_PASSED", "REFUSED", "BLOCKED",
                              "READY_FOR_ATTESTATION", "AWAITING_REVIEW",
                              "NOT_READY"):
                    self.assertIn(value, outputs)
                for row in self.MATRIX:
                    self.assertIn(row, outputs)
                self.assertIn(
                    "readiness it independently recomputes from evidence and\n"
                    "      trusted policy", outputs)

    def test_readme_and_guides_publish_the_exact_provider_matrix(self):
        for relative in ("README.md", "docs/GITHUB_ACTIONS.md",
                         "docs/DEVELOPER_WORKFLOW.md"):
            with self.subTest(relative=relative):
                body = read(relative)
                for row in self.MATRIX:
                    self.assertIn(row, body)

    def test_provider_acceptance_uses_trusted_policy_recomputation(self):
        for relative in ("README.md", "docs/GITHUB_ACTIONS.md",
                         "docs/DEVELOPER_WORKFLOW.md"):
            with self.subTest(relative=relative):
                body = read(relative)
                self.assertIn("readiness the finalizer recomputes", body)
                self.assertIn("trusted policy", body)

        schema = json.loads(read(
            "protocol/evaluation-attestation.schema.json"))
        conclusion = schema["$defs"]["source_receipt"]["properties"][
            "conclusion"]["description"]
        self.assertIn("finalizer applies the matrix only to readiness it "
                      "independently recomputes", conclusion)
        self.assertIn("trusted policy", conclusion)

    # The trust-side verbs are spelled with the distribution that installs
    # them.  Since 0.8.0 the machine running these lines has `admissible-trust`
    # and nothing else on it: the umbrella that answers a bare `admissible` is
    # the one package a finalizer, reviewer or observer environment must not
    # have, so a copyable line written the old way names a command that is not
    # there.
    def test_durable_home_is_selected_before_trust_or_finalize(self):
        sequence = (
            "export ADMISSIBLE_HOME=/var/lib/admissible\n"
            "export ADMISSIBLE_DURABLE_HOME=1\n"
            "admissible-trust policy trust"
        )
        for relative in ("README.md", "docs/GITHUB_ACTIONS.md",
                         "docs/DEVELOPER_WORKFLOW.md"):
            with self.subTest(relative=relative):
                body = read(relative)
                self.assertIn(sequence, body)
                tail = body[body.index(sequence):]
                self.assertIn("admissible-trust finalize", tail)

    def test_docs_make_isolation_an_independent_observer_assertion(self):
        for relative in ("README.md", "docs/GITHUB_ACTIONS.md",
                         "docs/DEVELOPER_WORKFLOW.md"):
            with self.subTest(relative=relative):
                body = read(relative)
                self.assertIn("admissible-trust attest-evaluation", body)
                self.assertIn("--isolation", body)
                self.assertIn("observer independently asserts isolation", body)

    def test_reviews_and_authorship_do_not_require_observer_resigning(self):
        for relative in ("README.md", "docs/GITHUB_ACTIONS.md",
                         "docs/DEVELOPER_WORKFLOW.md"):
            with self.subTest(relative=relative):
                body = read(relative)
                self.assertIn("separate authenticated roles", body)
                self.assertIn("no observer re-sign", body)

    def test_moving_state_uses_a_bounded_signed_prefix(self):
        body = read("docs/DEVELOPER_WORKFLOW.md")
        self.assertIn("full export is capped at **64 MiB**", body)
        self.assertIn("refuses before creating or replacing\n`--out`", body)
        export = (
            "admissible-trust export --through-head HEAD_HASH "
            "--out journal-prefix.json")
        imported = "admissible-trust import --in journal-prefix.json"
        self.assertIn(export, body)
        self.assertIn(imported, body)
        self.assertLess(body.index(export), body.index(imported))
        self.assertNotIn("then repeat with a later head", body)
        self.assertIn(
            "A selected prefix is a historical cut, not a path around the "
            "ceiling", body)


class PublicPackageAndDemoTest(unittest.TestCase):
    def test_bundled_defect_ids_match_the_standalone_schema_and_runtime(self):
        bundled = json.loads(read("protocol/workflow-evidence.schema.json"))
        standalone = json.loads(read("protocol/defect-record.schema.json"))
        embedded_items = bundled["$defs"]["defect"]["properties"][
            "missed_check_ids"]["items"]
        standalone_items = standalone["properties"]["missed_check_ids"][
            "items"]
        self.assertEqual(embedded_items.get("minLength"), 1)
        self.assertEqual(embedded_items.get("minLength"),
                         standalone_items.get("minLength"))

        sys.path.insert(0, str(ROOT))
        from admissible import evidence
        with self.assertRaises(evidence.EvidenceError):
            evidence.defect_from_dict({
                "kind": "defect", "defect_id": "HOSTED-1",
                "repository": "github.com/acme/widget",
                "commit_sha": "a" * 40, "severity": "high",
                "summary": "empty check ids name no check",
                "missed_check_ids": [""], "regression_test_id": "unit",
                "discovered_at": 1,
            })

    def test_package_and_wheel_suites_name_the_evaluation_schema(self):
        needle = '"protocol/evaluation-attestation.schema.json"'
        self.assertIn(needle, read("tests/test_admissible_packaging.py"))
        self.assertIn(needle, read("tests/test_admissible_quality.py"))

        schema = json.loads(read(
            "protocol/evaluation-attestation.schema.json"))
        statement = schema["$defs"]["statement"]
        for field in ("preview_schema", "issued_at", "isolation"):
            self.assertIn(field, statement["required"])
        self.assertNotIn("attestation_digests", statement["properties"])
        self.assertNotIn("author_attestation_digests",
                         statement["properties"])
        pairs = {
            (item["properties"]["state"]["const"],
             item["properties"]["readiness"]["const"])
            for item in statement["oneOf"]
        }
        self.assertEqual(pairs, {
            ("CHECKS_PASSED", "READY_FOR_ATTESTATION"),
            ("REFUSED", "AWAITING_REVIEW"),
            ("REFUSED", "NOT_READY"),
            ("BLOCKED", "NOT_READY"),
        })

    def test_the_external_consumer_contract_really_installs_the_wheel(self):
        body = read("tests/test_admissible_external_consumer.py")
        self.assertIn("class InstalledExternalConsumerTest", body)
        self.assertIn('"pip", "install"', body)
        self.assertIn("self.console", body)
        self.assertNotIn(
            "def test_the_installed_console_command_reports_the_same_profiles(self):\n"
            "        _, out, _ = self.tool",
            body)

    def test_the_demo_names_its_real_payment_floors_and_temporary_store(self):
        demo = read("examples/developer-workflow/demo.sh")
        helper = read("examples/developer-workflow/show.py")
        self.assertIn("deleted at script exit", " ".join(demo.split()))
        self.assertIn("temporary demonstration store", demo)
        self.assertIn("export PYTHONDONTWRITEBYTECODE=1", demo)
        for literal in ("two required independent reviews", "two-day",
                        "18-unit", "5400-second"):
            self.assertIn(literal, helper)
        self.assertIn("runs no real payment tests", helper)


if __name__ == "__main__":
    unittest.main()
