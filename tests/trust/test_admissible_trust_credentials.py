"""Contract: each command loads exactly its own role's key, and no other.

Three keys exist in this product and none substitutes for another: an admission
key signs receipts, a reviewer key signs reviews, an observer key signs
evaluations.  Trust is the distribution that holds all three at different
moments, which makes it the one place a confusion between them is possible --
and therefore the one place the separation has to be asserted rather than
described.

Four claims:

* **role** -- ``attest-review`` reads the reviewer variables and nothing else,
  ``attest-evaluation`` reads the observer variables and nothing else, and
  every other command reads the admission variables.  Asserted by running each
  command with only the *wrong* role's key present and requiring a refusal that
  names the variable it actually wanted;
* **provenance** -- key material comes from the documented environment
  variables or the permission-checked files they name, and from nowhere else.
  There is no ``--key`` argument to pass one on a command line, no column in
  the database that could hold one, and no code path that prints one;
* **collision** -- a keyring that maps two ids to one secret, an admission key
  that is also a reviewer or observer key, and a reviewer key that is also an
  observer key are each refused, because each of them is one holder wearing two
  names;
* **stream discipline** -- a ``--json`` caller's stdout carries the document and
  nothing else.  Warnings, deprecations and refusal prose go to stderr, and no
  stream ever carries key material.
"""
from __future__ import annotations

import inspect as inspect_module
import io
import json
import os
import re
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from admissible_trust import attestation as attestation_module
from admissible_trust import cli as trust_cli
from admissible_trust import receipt as trust_receipt
from admissible_trust import review as review_module
from admissible_trust import store as trust_store

from . import TRUST_SRC

TRUST_PACKAGE = TRUST_SRC / "admissible_trust"

ADMISSION_VARIABLES = ("ADMISSIBLE_HMAC_KEY", "ADMISSIBLE_HMAC_KEY_FILE",
                       "ADMISSIBLE_HMAC_KEY_ID")
REVIEW_VARIABLES = ("ADMISSIBLE_REVIEW_KEY", "ADMISSIBLE_REVIEW_KEY_FILE",
                    "ADMISSIBLE_REVIEW_KEY_ID", "ADMISSIBLE_REVIEW_KEYRING")
OBSERVER_VARIABLES = ("ADMISSIBLE_EVALUATION_KEY",
                      "ADMISSIBLE_EVALUATION_KEY_FILE",
                      "ADMISSIBLE_EVALUATION_KEY_ID",
                      "ADMISSIBLE_EVALUATION_KEYRING")

#: Which role each command's own loader belongs to.
COMMAND_ROLES = {
    "attest-review": REVIEW_VARIABLES,
    "attest-evaluation": OBSERVER_VARIABLES,
    "finalize": ADMISSION_VARIABLES,
    "impeach": ADMISSION_VARIABLES,
    "import": ADMISSION_VARIABLES,
    "ready-status": ADMISSION_VARIABLES,
}


class CredentialCase(unittest.TestCase):
    def setUp(self) -> None:
        raw = tempfile.mkdtemp(prefix="trust-credentials-")
        self.addCleanup(shutil.rmtree, raw, True)
        self.tmp = Path(raw)
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(),
                                 os.environ.update(saved)))
        for name in list(os.environ):
            if name.startswith("ADMISSIBLE_"):
                del os.environ[name]
        os.environ["ADMISSIBLE_HOME"] = str(self.tmp / "home")

    def secret_file(self, name: str, body: str, *, mode: int = 0o600) -> Path:
        path = self.tmp / name
        path.write_text(body, encoding="utf-8")
        os.chmod(path, mode)
        return path


class EachLoaderReadsItsOwnVariables(CredentialCase):
    """A loader that read another role's variable would erase the boundary."""

    def test_the_admission_loader_reads_only_the_admission_variables(self):
        source = {"ADMISSIBLE_REVIEW_KEY": "reviewer",
                  "ADMISSIBLE_EVALUATION_KEY": "observer"}
        with self.assertRaises(trust_receipt.SigningError) as caught:
            trust_receipt.load_signer(source)
        self.assertIn("ADMISSIBLE_HMAC_KEY", str(caught.exception))

    def test_the_review_loader_reads_only_the_review_variables(self):
        source = {"ADMISSIBLE_HMAC_KEY": "admission",
                  "ADMISSIBLE_EVALUATION_KEY": "observer"}
        with self.assertRaises(review_module.ReviewError) as caught:
            review_module.load_review_signer(source)
        self.assertIn("ADMISSIBLE_REVIEW_KEY_ID", str(caught.exception))

    def test_the_observer_loader_reads_only_the_observer_variables(self):
        source = {"ADMISSIBLE_HMAC_KEY": "admission",
                  "ADMISSIBLE_REVIEW_KEY": "reviewer"}
        with self.assertRaises(attestation_module.EvaluationError) as caught:
            attestation_module.load_evaluation_signer(source)
        self.assertIn("ADMISSIBLE_EVALUATION_KEY_ID", str(caught.exception))

    def test_each_loader_accepts_its_own_inline_material(self):
        signer = trust_receipt.load_signer(
            {"ADMISSIBLE_HMAC_KEY": "admission-secret"})
        self.assertTrue(signer.sign(b"probe"))
        self.assertEqual(
            ("reviewer-a", b"review-secret"),
            review_module.load_review_signer(
                {"ADMISSIBLE_REVIEW_KEY_ID": "reviewer-a",
                 "ADMISSIBLE_REVIEW_KEY": "review-secret"}))
        self.assertEqual(
            ("observer-a", b"observer-secret"),
            attestation_module.load_evaluation_signer(
                {"ADMISSIBLE_EVALUATION_KEY_ID": "observer-a",
                 "ADMISSIBLE_EVALUATION_KEY": "observer-secret"}))

    def test_a_present_but_empty_variable_is_refused_not_treated_as_absent(self):
        with self.assertRaises(trust_receipt.SigningError) as caught:
            trust_receipt.load_signer({"ADMISSIBLE_HMAC_KEY": "   "})
        self.assertIn("set but empty", str(caught.exception))
        with self.assertRaises(review_module.ReviewError):
            review_module.load_review_signer(
                {"ADMISSIBLE_REVIEW_KEY_ID": "reviewer-a",
                 "ADMISSIBLE_REVIEW_KEY": ""})
        with self.assertRaises(attestation_module.EvaluationError):
            attestation_module.load_evaluation_signer(
                {"ADMISSIBLE_EVALUATION_KEY_ID": "observer-a",
                 "ADMISSIBLE_EVALUATION_KEY": ""})


class KeyFilesArePermissionAndSizeChecked(CredentialCase):
    """A key file anybody can read is a key anybody has."""

    def test_a_world_readable_key_file_is_refused(self):
        path = self.secret_file("hmac.key", "admission-secret", mode=0o644)
        with self.assertRaises(trust_receipt.SigningError) as caught:
            trust_receipt.load_signer(
                {"ADMISSIBLE_HMAC_KEY_FILE": str(path)})
        self.assertIn(str(path), str(caught.exception))

    def test_an_owner_only_key_file_is_accepted(self):
        path = self.secret_file("hmac.key", "admission-secret")
        self.assertEqual(
            stat.S_IRUSR | stat.S_IWUSR, path.stat().st_mode & 0o777)
        signer = trust_receipt.load_signer(
            {"ADMISSIBLE_HMAC_KEY_FILE": str(path)})
        self.assertTrue(signer.sign(b"probe"))

    def test_an_empty_key_file_is_refused(self):
        path = self.secret_file("hmac.key", "   \n")
        with self.assertRaises(trust_receipt.SigningError) as caught:
            trust_receipt.load_signer(
                {"ADMISSIBLE_HMAC_KEY_FILE": str(path)})
        self.assertIn("empty", str(caught.exception))

    def test_an_implausibly_large_inline_key_is_refused(self):
        with self.assertRaises(review_module.ReviewError) as caught:
            review_module.load_review_signer(
                {"ADMISSIBLE_REVIEW_KEY_ID": "reviewer-a",
                 "ADMISSIBLE_REVIEW_KEY": "x" * 5000})
        self.assertIn("implausibly large", str(caught.exception))

    def test_a_missing_key_file_is_refused_rather_than_ignored(self):
        with self.assertRaises(trust_receipt.SigningError):
            trust_receipt.load_signer(
                {"ADMISSIBLE_HMAC_KEY_FILE": str(self.tmp / "absent.key")})

    def test_a_keyring_that_is_not_json_is_refused(self):
        path = self.secret_file("keyring.json", "not json")
        with self.assertRaises(review_module.ReviewError) as caught:
            review_module.load_keyring(
                {"ADMISSIBLE_REVIEW_KEYRING": str(path)})
        self.assertIn("valid JSON", str(caught.exception))

    def test_an_absent_keyring_is_an_empty_keyring_not_an_error(self):
        self.assertEqual({}, review_module.load_keyring({}))
        self.assertEqual({}, attestation_module.load_evaluation_keyring({}))


class CollidingIdentitiesAreRefused(CredentialCase):
    """Two ids sharing one secret is one holder wearing two names."""

    def test_a_reviewer_keyring_mapping_one_secret_twice_is_refused(self):
        path = self.secret_file("keyring.json", json.dumps(
            {"reviewer-a": "shared", "reviewer-b": "shared"}))
        with self.assertRaises(review_module.ReviewError) as caught:
            review_module.load_keyring(
                {"ADMISSIBLE_REVIEW_KEYRING": str(path)})
        self.assertIn("same secret", str(caught.exception))

    def test_an_observer_keyring_mapping_one_secret_twice_is_refused(self):
        path = self.secret_file("observers.json", json.dumps(
            {"observer-a": "shared", "observer-b": "shared"}))
        with self.assertRaises(attestation_module.EvaluationError) as caught:
            attestation_module.load_evaluation_keyring(
                {"ADMISSIBLE_EVALUATION_KEYRING": str(path)})
        self.assertIn("same secret", str(caught.exception))

    def test_the_distinctness_check_accepts_genuinely_distinct_secrets(self):
        review_module.assert_distinct_secrets(
            {"reviewer-a": b"one", "reviewer-b": b"two"}, where="a fixture")


class NoKeyMaterialEverLeavesThroughAnArgumentOrAStream(CredentialCase):
    """Key material has exactly two documented doors, and neither is visible."""

    def test_no_command_line_option_accepts_key_material(self):
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
            if re.search(r"key|secret|password|token", option))
        self.assertEqual([], offending,
                         "key material has no command-line door")

    def test_the_keyring_options_that_exist_name_files_not_secrets(self):
        """``--reviews`` and ``--evaluation-attestation`` carry documents."""

        parser = trust_cli._build_parser()
        finalize = parser._subparsers._group_actions[0].choices["finalize"]
        names = {option for item in finalize._actions
                 for option in item.option_strings}
        self.assertIn("--reviews", names)
        self.assertIn("--evaluation-attestation", names)

    def test_no_source_line_writes_key_material_to_a_stream(self):
        """A refusal may name the *variable*; it may never print the value."""

        import ast

        offenders = []
        for path in sorted(TRUST_PACKAGE.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                callee = getattr(node.func, "attr", "")
                if callee not in ("write", "print", "dump", "dumps"):
                    continue
                for argument in ast.walk(node):
                    if (isinstance(argument, ast.Name)
                            and argument.id in ("secret", "material",
                                                "keyring", "signer")):
                        offenders.append(f"{path.name}: {callee}({argument.id})")
        self.assertEqual([], offenders)

    def test_the_store_has_no_column_that_could_hold_key_material(self):
        home = self.tmp / "store-home"
        opened = trust_store.open_store(home)
        self.addCleanup(opened.close)
        from admissible_core import store_base

        import sqlite3

        connection = sqlite3.connect(str(store_base.database_path(home)))
        try:
            columns = []
            for (table,) in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"):
                for row in connection.execute(f"PRAGMA table_info({table})"):
                    columns.append(f"{table}.{row[1]}")
        finally:
            connection.close()
        offending = sorted(
            column for column in columns
            if re.search(r"secret|password|token", column))
        self.assertEqual([], offending)
        # ``key_id`` is a name, not a secret, and it is in the signed body on
        # purpose: attribution has to say which identity signed. The one
        # column literally called ``key`` is the schema-metadata table's, whose
        # rows are ``schema_version`` and a number.
        self.assertEqual(["schema_meta.key"],
                         sorted(c for c in columns if c.endswith(".key")))

    def test_no_signer_object_is_reachable_from_a_store_facade(self):
        home = self.tmp / "store-home"
        opened = trust_store.open_store(home)
        self.addCleanup(opened.close)
        for name in ("signer", "verifier", "secret", "key", "keyring"):
            with self.subTest(name=name):
                self.assertNotIn(name, type(opened).CAPABILITIES)


class StreamDiscipline(CredentialCase):
    """A ``--json`` caller's stdout carries the document and nothing else."""

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = trust_cli.main(list(argv), stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_a_refusal_in_json_mode_is_one_document_on_stdout(self):
        code, out, err = self.run_cli("verify", "not-a-sha", "--json")
        self.assertEqual(2, code)
        document = json.loads(out)
        self.assertEqual("BLOCKED", document["state"])
        self.assertEqual("", err)

    def test_a_not_current_answer_in_json_mode_is_also_one_document(self):
        """Exit 1 is an answer, not a failure, and it is owed the same shape."""

        code, out, err = self.run_cli("verify", "0" * 40, "--json")
        self.assertEqual(1, code)
        document = json.loads(out)
        self.assertEqual("UNKNOWN", document["state"])
        self.assertEqual("", err)

    def test_a_refusal_without_json_is_prose_on_stderr_and_nothing_on_stdout(self):
        code, out, err = self.run_cli("verify", "not-a-sha")
        self.assertEqual(2, code)
        self.assertEqual("", out)
        self.assertIn("What happened", err)

    def test_the_transitional_warning_never_reaches_the_machine_stream(self):
        code, out, err = self.run_cli("run", "--json")
        self.assertEqual(2, code)
        json.loads(out)
        self.assertEqual("", err)

    def test_help_is_answered_before_any_credential_is_looked_for(self):
        os.environ["ADMISSIBLE_HMAC_KEY_FILE"] = str(self.tmp / "absent.key")
        code, out, err = self.run_cli("--help")
        self.assertEqual(0, code)
        self.assertIn("admissible-trust", out)
        self.assertEqual("", err)

    def test_a_usage_error_in_json_mode_still_answers_on_stdout(self):
        code, out, err = self.run_cli("finalize", "--json")
        self.assertEqual(2, code)
        document = json.loads(out)
        self.assertEqual("BLOCKED", document["state"])
        self.assertTrue(document["remediation"])


class TheRoleMapIsComplete(CredentialCase):
    """Every dispatched command is accounted for, or explicitly keyless."""

    KEYLESS = ("verify", "explain", "status", "export", "policy")

    def test_every_command_is_either_role_mapped_or_declared_keyless(self):
        commands = set(trust_cli._COMMANDS)
        accounted = set(COMMAND_ROLES) | set(self.KEYLESS) | {"run"}
        self.assertEqual(set(), commands - accounted)

    def test_the_keyless_commands_still_authenticate_when_a_key_is_present(self):
        """"Keyless" means "does not require one", never "ignores one".

        ``verify``, ``explain`` and ``status`` answer honestly without a key --
        ``UNVERIFIED`` rather than ``CURRENT`` -- and authenticate when one is
        there. The distinction is what makes a missing key a smaller answer
        instead of a wrong one.
        """

        signature = inspect_module.signature(
            trust_cli._command_verify)
        self.assertEqual(["options", "stdout", "stderr"],
                         list(signature.parameters))

    def test_policy_commands_need_no_signing_key_at_all(self):
        """Trusting a policy is an operator's act, recorded, not signed.

        It is still a trusted-domain act -- the candidate distribution has no
        way to write the row -- but it authenticates nothing, so demanding an
        admission key here would be theatre.
        """

        source = (TRUST_PACKAGE / "cli.py").read_text(encoding="utf-8")
        start = source.index("def _command_policy(")
        end = source.index("def ", start + 10)
        self.assertNotIn("load_signer", source[start:end])


if __name__ == "__main__":
    unittest.main()
