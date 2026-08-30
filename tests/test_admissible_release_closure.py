"""Final frozen release-closure contracts for the developer product.

These tests stay deliberately close to the public boundary.  Earlier repair
suites prove the lower-level arithmetic; this file makes the last operator and
machine-facing promises executable.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import TempCase, make_repo, require_module  # noqa: E402

cli_module = require_module("admissible.cli")
store_module = require_module("admissible.store")


class PublicExitContractTest(TempCase):
    def invoke(self, *argv: str):
        out, err = io.StringIO(), io.StringIO()
        code = cli_module.main(list(argv), stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_global_help_says_run_zero_is_only_checks_passed(self):
        code, out, err = self.invoke("--help")
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("0 admitted or current", out)
        self.assertIn("run", out)
        self.assertIn("CHECKS_PASSED", out)
        self.assertIn("never admission", out.lower())
        self.assertIn("verify", out)
        self.assertIn("CURRENT", out)

    def test_unknown_verify_json_has_the_stable_nonzero_envelope(self):
        root = self.tmp / "repo"
        make_repo(root)
        code, out, err = self.invoke(
            "verify", "9" * 40, "--repo", str(root), "--json")
        self.assertEqual(code, 1, out + err)
        document = json.loads(out)
        for key in ("state", "readiness", "exit_code", "message",
                    "remediation"):
            self.assertIn(key, document)
        self.assertEqual(document["readiness"], "NOT_READY")
        self.assertTrue(document["message"])
        self.assertTrue(document["remediation"])

    def test_unknown_explain_json_has_the_stable_nonzero_envelope(self):
        root = self.tmp / "repo"
        make_repo(root)
        code, out, err = self.invoke(
            "explain", "8" * 40, "--repo", str(root), "--json")
        self.assertEqual(code, 1, out + err)
        document = json.loads(out)
        for key in ("state", "readiness", "exit_code", "message",
                    "remediation"):
            self.assertIn(key, document)
        self.assertEqual(document["readiness"], "NOT_READY")
        self.assertTrue(document["message"])
        self.assertTrue(document["remediation"])

    def test_unknown_status_json_has_the_stable_nonzero_envelope(self):
        root = self.tmp / "repo"
        make_repo(root)
        code, out, err = self.invoke(
            "status", "--repo", str(root), "--json")
        self.assertEqual(code, 1, out + err)
        document = json.loads(out)
        for key in ("state", "readiness", "exit_code", "message",
                    "remediation"):
            self.assertIn(key, document)
        self.assertEqual(document["readiness"], "NOT_READY")
        self.assertTrue(document["message"])
        self.assertTrue(document["remediation"])

    def test_explain_turns_corrupt_stored_json_into_a_machine_failure(self):
        root = self.tmp / "repo"
        sha = make_repo(root)
        opened = store_module.open_store(self.home)
        opened.connection.execute("PRAGMA foreign_keys=OFF")
        opened.connection.execute(
            "INSERT INTO workflow_receipts(receipt_hash, body_digest, "
            "journal_id, repository, commit_sha, tree_sha, policy_digest, "
            "class_id, state, issued_at, receipt_json, head_receipt_hash) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            ("a" * 64, "b" * 64, "journal", "github.com/acme/widget", sha,
             "c" * 40, "d" * 64, "default", "ADMITTED", 1,
             "{not-json", "e" * 64))
        opened.close()

        code, out, err = self.invoke(
            "explain", sha, "--repo", str(root), "--json")
        self.assertEqual(code, 2, out + err)
        document = json.loads(out)
        self.assertEqual(document["state"], "BLOCKED")
        self.assertEqual(document["readiness"], "NOT_READY")
        self.assertNotIn("Traceback", out + err)


class ObserverCliContractTest(TempCase):
    def test_observer_isolation_is_an_explicit_required_input(self):
        parser = cli_module._build_parser()
        base = [
            "attest-evaluation", "--preview", "preview.json",
            "--source-receipt", "source.json", "--out", "evaluation.json",
        ]
        with self.assertRaises(cli_module._Usage):
            parser.parse_args(base)
        options = parser.parse_args(base + ["--isolation", "pid-namespace"])
        self.assertEqual(options.isolation, "pid-namespace")

    def test_operator_next_steps_name_the_required_observer_fact(self):
        steps = cli_module._status_next_steps("UNKNOWN", "a" * 40, "")
        handoff = " ".join(steps)
        self.assertIn("--isolation MODE", handoff)
        self.assertIn("independently validating", handoff)


class BoundedImportContractTest(TempCase):
    def test_oversized_import_is_refused_before_its_bytes_are_read(self):
        source = self.tmp / "oversized.json"
        with source.open("wb") as handle:
            handle.truncate(store_module.MAX_JOURNAL_BYTES + 1)
        os.environ["ADMISSIBLE_HMAC_KEY"] = "bounded-import-test-key"
        options = argparse.Namespace(source=str(source), json=True)
        out, err = io.StringIO(), io.StringIO()
        original = Path.read_bytes

        def guarded(path: Path):
            if path == source:
                raise AssertionError("oversized input was read before refusal")
            return original(path)

        Path.read_bytes = guarded
        self.addCleanup(setattr, Path, "read_bytes", original)
        code = cli_module._command_import(options, out, err)
        self.assertEqual(code, 2, out.getvalue() + err.getvalue())
        document = json.loads(out.getvalue())
        self.assertEqual(document["state"], "BLOCKED")
        self.assertIn("ceiling", document["message"])

    def test_import_uses_a_bounded_read_even_after_the_stat_check(self):
        source = (Path(__file__).resolve().parent.parent
                  / "admissible" / "cli.py").read_text(encoding="utf-8")
        section = source[source.index("def _command_import"):
                         source.index("def _command_status")]
        self.assertIn(".read(store_module.MAX_JOURNAL_BYTES + 1)", section)
        self.assertNotIn("Path(options.source).read_bytes()", section)


class BoundedExportContractTest(TempCase):
    def test_public_cli_exposes_the_deterministic_signed_prefix(self):
        options = cli_module._build_parser().parse_args([
            "export", "--out", "journal.json", "--through-head", "a" * 64,
        ])
        self.assertEqual(options.through_head, "a" * 64)
        source = (Path(__file__).resolve().parent.parent
                  / "admissible" / "cli.py").read_text(encoding="utf-8")
        section = source[source.index("def _command_export"):
                         source.index("def _command_import")]
        self.assertIn("through_head=through_head", section)
        self.assertIn("Nothing was written", section)

    def test_prefix_help_calls_the_selection_historical_not_incremental(self):
        parser = cli_module._build_parser()
        subparsers = next(
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction))
        export = subparsers.choices["export"]
        through_head = next(
            action for action in export._actions
            if action.dest == "through_head")
        self.assertIn("historical", through_head.help)
        self.assertNotIn("later prefix", through_head.help)

        source = (Path(__file__).resolve().parent.parent
                  / "admissible" / "cli.py").read_text(encoding="utf-8")
        section = source[source.index("def _command_export"):
                         source.index("def _command_import")]
        self.assertIn("historical cut", section)
        self.assertNotIn("later prefix", section)


class InterruptedReceiptIdentityContractTest(TempCase):
    def test_recovery_queries_only_the_exact_expected_receipt_body(self):
        source = (Path(__file__).resolve().parent.parent
                  / "admissible" / "cli.py").read_text(encoding="utf-8")
        section = source[source.index("def _report_interrupted_finalize"):
                         source.index("def _command_finalize")]
        self.assertIn(
            "workflow_receipt_by_body(expected_body_digest)", section)
        self.assertNotIn("receipts_for(", section)

    def test_finalize_precomputes_identity_with_the_same_issued_time(self):
        source = (Path(__file__).resolve().parent.parent
                  / "admissible" / "cli.py").read_text(encoding="utf-8")
        section = source[source.index("def _command_finalize"):
                         source.index("# What an interrupt leaves behind")]
        prepare = section.index("expected_finalization_receipt_body_digest")
        uncertain = section.index("github_module.finalize")
        self.assertLess(prepare, uncertain)
        self.assertGreaterEqual(section.count("now=finalize_now"), 2)
        self.assertIn(
            "expected_body_digest=expected_body_digest",
            section[uncertain:])


class AnchoredPartialOutputContractTest(TempCase):
    def test_output_copy_failure_does_not_relabel_admission_as_ready(self):
        source = (Path(__file__).resolve().parent.parent
                  / "admissible" / "cli.py").read_text(encoding="utf-8")
        section = source[source.index("except OSError as error:",
                                      source.index("def _command_finalize")):
                         source.index("if options.json:",
                                      source.index("except OSError as error:",
                                                   source.index("def _command_finalize")))
                         + 1200]
        self.assertIn("receipt_module.receipt_to_dict(issued)", section)
        self.assertIn('document["readiness"] = READINESS_NOT_READY', section)
        self.assertNotIn(
            'document["readiness"] = READINESS_READY_FOR_ATTESTATION', section)


if __name__ == "__main__":
    import unittest

    unittest.main()
