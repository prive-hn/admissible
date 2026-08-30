"""Contract: the two domains hand work over as artefacts, in two processes.

Every other suite proves a property of one distribution.  This one proves the
product still works when the split is real: two throwaway environments, each
holding exactly one authority, one shared Admissible home, and a preview file
carried between them.

The candidate environment has Core and Ready and **no key of any kind** in its
environment.  It identifies the repository, runs the configured check, records
the attempt, writes the retained preview, and exits -- which closes its store,
because the home refuses a second opener while a sidecar is live.

The trusted environment has Core and Trust, and no ``admissible_ready`` at all.
It signs the observer's attestation, records the policy baseline, finalizes the
retained preview, verifies the receipt, reports authenticated ``CURRENT``
standing, and emits the authenticated ``ready`` document -- the one word the
other environment cannot say.

Three things are asserted that no single-process test can reach:

* **no co-installation** -- ``find_spec`` in each environment answers ``None``
  for the other authority, and the installed file lists share no package;
* **exact hashes** -- the preview digest the candidate wrote, the receipt hash
  and body digest the finalizer issued, and the journal head it anchored are
  compared as literals across the process boundary;
* **failure matrices** -- the refusals that matter are re-run against the
  installed command rather than against an imported function, because a
  refusal that only exists in a library call is a refusal a user never meets.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.architecture import inspect_wheel

from . import CORE_PROJECT, READY_PROJECT, TRUST_PROJECT

OBSERVER_KEY_ID = "observer-1"
OBSERVER_SECRET = "handoff-external-observer-secret-not-real"
ADMISSION_SECRET = "handoff-admission-secret-not-real"

POLICY = {
    "version": 1,
    "profile": "python-library",
    "title": "Widget",
    "summary": "A cross-domain handoff fixture, not a real policy.",
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

_STATE: dict = {}


def prepared() -> dict:
    """Build the three wheels and both single-authority environments once."""

    if _STATE:
        return _STATE
    workspace = tempfile.TemporaryDirectory(prefix="admissible-handoff-")
    atexit.register(workspace.cleanup)
    root = Path(workspace.name)
    _STATE["workspace"] = root
    _STATE["error"] = None
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True, exist_ok=True)
    try:
        core = inspect_wheel.build_wheel(CORE_PROJECT, wheelhouse)
        ready = inspect_wheel.build_wheel(READY_PROJECT, wheelhouse)
        trust = inspect_wheel.build_wheel(TRUST_PROJECT, wheelhouse)
        _STATE["ready_python"] = inspect_wheel.create_venv(root / "candidate")
        inspect_wheel.install_wheels(_STATE["ready_python"], [core, ready])
        _STATE["trust_python"] = inspect_wheel.create_venv(root / "trusted")
        inspect_wheel.install_wheels(_STATE["trust_python"], [core, trust])
    except (inspect_wheel.WheelError, OSError,
            subprocess.SubprocessError) as error:
        _STATE["error"] = f"could not prepare the two environments: {error}"
    return _STATE


class HandoffCase(unittest.TestCase):
    """One repository, one home, and two environments that never meet."""

    @classmethod
    def setUpClass(cls):
        cls.state = prepared()

    def setUp(self) -> None:
        if self.state["error"]:
            self.fail(self.state["error"])
        raw = tempfile.mkdtemp(prefix="handoff-work-")
        self.addCleanup(shutil.rmtree, raw, True)
        self.work = Path(raw)
        self.home = self.work / "home"
        self.repo = self.work / "repo"
        self.repo.mkdir(parents=True)
        self.git("init", "-q", "-b", "main")
        (self.repo / "README.md").write_text("widget\n", encoding="utf-8")
        (self.repo / ".admissible.json").write_text(
            json.dumps(POLICY, indent=2) + "\n", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "initial")
        self.git("remote", "add", "origin",
                 "https://github.com/acme/widget.git")
        self.sha = self.git("rev-parse", "HEAD")
        self.preview = self.work / "preview.json"
        self.attestation = self.work / "evaluation.json"
        self.keyring = self.work / "observers.json"
        self.keyring.write_text(
            json.dumps({OBSERVER_KEY_ID: OBSERVER_SECRET}), encoding="utf-8")
        os.chmod(self.keyring, 0o600)

    # -- process plumbing ---------------------------------------------------
    def git(self, *args: str) -> str:
        environment = dict(os.environ)
        environment.update({
            "GIT_AUTHOR_NAME": "Handoff", "GIT_AUTHOR_EMAIL": "h@example.com",
            "GIT_COMMITTER_NAME": "Handoff",
            "GIT_COMMITTER_EMAIL": "h@example.com",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
        })
        completed = subprocess.run(
            ("git", "-C", str(self.repo), *args), env=environment, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        return completed.stdout.decode("utf-8").strip()

    def script(self, python: Path, command: str) -> Path:
        return inspect_wheel.venv_script(python.parent.parent, command)

    def candidate(self, *args: str, **overrides) -> subprocess.CompletedProcess:
        """Run the Ready command with no Admissible credential in sight."""

        environment = {"ADMISSIBLE_HOME": str(self.home),
                       "ADMISSIBLE_ISOLATION": "pid-namespace"}
        environment.update(overrides)
        return self.run_in(self.state["ready_python"], "admissible-ready",
                           args, environment)

    def trusted(self, *args: str, **overrides) -> subprocess.CompletedProcess:
        """Run the Trust command in the domain that holds the keys."""

        environment = {
            "ADMISSIBLE_HOME": str(self.home),
            "ADMISSIBLE_DURABLE_HOME": "1",
            "ADMISSIBLE_HMAC_KEY": ADMISSION_SECRET,
            "ADMISSIBLE_HMAC_KEY_ID": "local",
            "ADMISSIBLE_EVALUATION_KEYRING": str(self.keyring),
        }
        environment.update(overrides)
        return self.run_in(self.state["trust_python"], "admissible-trust",
                           args, environment)

    def run_in(self, python: Path, command: str, args, environment
               ) -> subprocess.CompletedProcess:
        script = self.script(python, command)
        self.assertTrue(script.is_file(), f"{command} is not installed")
        return subprocess.run(
            [str(script), *args], capture_output=True, text=True,
            timeout=inspect_wheel.RUN_TIMEOUT, cwd=str(self.work),
            env=inspect_wheel.sanitized_env(environment))

    # -- the two halves ------------------------------------------------------
    def evaluate(self) -> dict:
        completed = self.candidate(
            "run", "--preview", "--repo", str(self.repo), "--sha", self.sha,
            "--preview-out", str(self.preview), "--json")
        self.assertEqual(0, completed.returncode,
                         completed.stdout + completed.stderr)
        return json.loads(self.preview.read_text(encoding="utf-8"))

    def observe(self) -> None:
        completed = self.trusted(
            "attest-evaluation", "--preview", str(self.preview),
            "--source-receipt", str(self.source_receipt()),
            "--isolation", "pid-namespace", "--out", str(self.attestation),
            "--repo", str(self.repo), "--json",
            ADMISSIBLE_EVALUATION_KEY_ID=OBSERVER_KEY_ID,
            ADMISSIBLE_EVALUATION_KEY=OBSERVER_SECRET)
        self.assertEqual(0, completed.returncode,
                         completed.stdout + completed.stderr)

    def source_receipt(self) -> Path:
        path = self.work / "source-receipt.json"
        path.write_text(json.dumps({
            "schema": "admissible/v0.6/external-source-receipt",
            "provider": "github-actions",
            "run_id": "17825349901",
            "commit_sha": self.sha,
            "conclusion": "success",
            "receipt_digest": "a1" * 32,
        }), encoding="utf-8")
        return path

    def trust_the_policy(self) -> None:
        completed = self.trusted("policy", "trust", "--repo", str(self.repo),
                                 "--json")
        self.assertEqual(0, completed.returncode,
                         completed.stdout + completed.stderr)

    def finalize(self, **overrides) -> subprocess.CompletedProcess:
        return self.trusted(
            "finalize", "--preview", str(self.preview), "--sha", self.sha,
            "--policy-root", str(self.repo), "--evaluation-attestation",
            str(self.attestation), "--repo", str(self.repo), "--json",
            **overrides)

    def admitted(self) -> dict:
        self.evaluate()
        self.observe()
        self.trust_the_policy()
        completed = self.finalize()
        self.assertEqual(0, completed.returncode,
                         completed.stdout + completed.stderr)
        return json.loads(completed.stdout)


class NeitherEnvironmentHoldsTheOther(HandoffCase):
    def test_the_candidate_environment_cannot_import_trust(self):
        self.assertEqual(
            {"admissible_core": True, "admissible_ready": True,
             "admissible_trust": False, "admissible": False},
            inspect_wheel.importable(
                self.state["ready_python"], "admissible_core",
                "admissible_ready", "admissible_trust", "admissible"))

    def test_the_trusted_environment_cannot_import_ready(self):
        self.assertEqual(
            {"admissible_core": True, "admissible_trust": True,
             "admissible_ready": False, "admissible": False},
            inspect_wheel.importable(
                self.state["trust_python"], "admissible_core",
                "admissible_trust", "admissible_ready", "admissible"))

    def test_the_two_environments_share_no_authority_package(self):
        probe = (
            "import json, sysconfig\n"
            "from pathlib import Path\n"
            "root = Path(sysconfig.get_paths()['purelib'])\n"
            "print(json.dumps(sorted(\n"
            "    p.name for p in root.iterdir()\n"
            "    if p.is_dir() and p.name.startswith('admissible')\n"
            "    and not p.name.endswith('.dist-info'))))\n"
        )
        candidate = json.loads(inspect_wheel.run_python(
            self.state["ready_python"], probe).stdout)
        trusted = json.loads(inspect_wheel.run_python(
            self.state["trust_python"], probe).stdout)
        self.assertEqual(["admissible_core", "admissible_ready"], candidate)
        self.assertEqual(["admissible_core", "admissible_trust"], trusted)
        self.assertEqual({"admissible_core"},
                         set(candidate) & set(trusted))

    def test_neither_environment_installs_the_other_s_command(self):
        self.assertFalse(self.script(self.state["ready_python"],
                                     "admissible-trust").exists())
        self.assertFalse(self.script(self.state["trust_python"],
                                     "admissible-ready").exists())


class TheCandidateHalfSignsNothing(HandoffCase):
    def test_the_preview_is_written_with_no_credential_in_the_environment(self):
        document = self.evaluate()
        self.assertEqual("admissible/v0.6/workflow-preview",
                         document["schema"])
        self.assertEqual(self.sha, document["commit_sha"])
        self.assertEqual("CHECKS_PASSED", document["state"])
        self.assertEqual("pid-namespace", document["isolation"])
        self.assertFalse(document["fork"])

    def test_the_candidate_reports_checks_complete_and_never_ready(self):
        self.evaluate()
        completed = self.candidate("check", "--repo", str(self.repo), "--json")
        self.assertEqual(0, completed.returncode, completed.stderr)
        document = json.loads(completed.stdout)
        self.assertEqual("checks_complete", document["status"])
        self.assertIn(document["canonical"]["standing"],
                      ("UNKNOWN", "UNVERIFIED"))

    def test_a_credential_makes_the_candidate_refuse_before_it_runs(self):
        completed = self.candidate(
            "run", "--preview", "--repo", str(self.repo), "--json",
            ADMISSIBLE_HMAC_KEY=ADMISSION_SECRET)
        self.assertEqual(2, completed.returncode)
        self.assertIn("ADMISSIBLE_HMAC_KEY", completed.stdout)

    def test_the_candidate_has_no_finalize_verb_at_all(self):
        for command in ("finalize", "attest-review", "policy", "impeach"):
            with self.subTest(command=command):
                completed = self.candidate(command, "--json")
                self.assertEqual(2, completed.returncode)


class TheTrustedHalfFinalizesAndSaysReady(HandoffCase):
    def test_the_whole_handoff_produces_an_authenticated_ready(self):
        preview = self.evaluate()
        self.observe()
        self.trust_the_policy()
        # The exact bytes the candidate retained, hashed before the finalizer
        # is allowed near them.
        preview_digest = hashlib.sha256(self.preview.read_bytes()).hexdigest()
        completed = self.finalize()
        self.assertEqual(0, completed.returncode,
                         completed.stdout + completed.stderr)
        issued = json.loads(completed.stdout)

        # Finalization consumes the retained file and never rewrites it.
        self.assertEqual(
            preview_digest,
            hashlib.sha256(self.preview.read_bytes()).hexdigest())
        self.assertEqual(preview["commit_sha"], issued["commit_sha"])
        self.assertEqual(preview["tree_sha"], issued["tree_sha"])
        self.assertEqual(preview["policy_digest"], issued["policy_digest"])
        self.assertEqual("ADMITTED", issued["state"])
        self.assertEqual(64, len(issued["receipt_hash"]))
        self.assertEqual(64, len(issued["body_digest"]))
        self.assertEqual(1, issued["head"]["event_count"])

        verified = self.trusted("verify", self.sha, "--repo", str(self.repo),
                                "--json")
        self.assertEqual(0, verified.returncode, verified.stderr)
        document = json.loads(verified.stdout)
        self.assertEqual("CURRENT", document["state"])
        self.assertEqual([issued["receipt_hash"]], document["receipt_hashes"])

        status = self.trusted("status", "--repo", str(self.repo), "--json")
        self.assertEqual(0, status.returncode, status.stderr)
        summary = json.loads(status.stdout)
        self.assertEqual("CURRENT", summary["state"])
        self.assertEqual(issued["head"]["receipt_hash"],
                         summary["head"]["receipt_hash"])

        ready = self.trusted("ready-status", "--repo", str(self.repo),
                             "--json")
        self.assertEqual(0, ready.returncode, ready.stderr)
        projection = json.loads(ready.stdout)
        self.assertEqual("ready", projection["status"])
        self.assertEqual("ADMITTED", projection["canonical"]["state"])
        self.assertEqual(issued["receipt_hash"],
                         projection["advanced"]["receipt_hash"])

    def test_the_candidate_still_cannot_say_ready_about_the_same_home(self):
        """The whole point, stated at the end of a successful handoff.

        The receipt exists, the journal is anchored, and the candidate
        environment reading the same home reports ``UNVERIFIED`` rather than
        ``CURRENT`` -- because verifying an HMAC needs the key that signs it,
        and that key is not in this process.
        """

        self.admitted()
        completed = self.candidate("check", "--repo", str(self.repo), "--json")
        self.assertEqual(0, completed.returncode, completed.stderr)
        document = json.loads(completed.stdout)
        self.assertNotEqual("ready", document["status"])
        self.assertIn(document["canonical"]["standing"],
                      ("UNKNOWN", "UNVERIFIED"))

        # And the sharper form of the same claim, through the candidate
        # distribution's own inspection entry point: it can see that receipts
        # exist for this commit and cannot say what they are.
        probe = (
            "import json\n"
            "from admissible_ready import ready\n"
            "found = ready.inspect_unsigned(%r)\n"
            "print(json.dumps([found['status'],\n"
            "                  found['canonical']['standing']]))\n"
        ) % (str(self.repo),)
        answered = subprocess.run(
            [str(self.state["ready_python"]), "-c", probe],
            capture_output=True, text=True,
            timeout=inspect_wheel.RUN_TIMEOUT, cwd=str(self.work),
            env=inspect_wheel.sanitized_env(
                {"ADMISSIBLE_HOME": str(self.home)}))
        self.assertEqual(0, answered.returncode, answered.stderr)
        status, standing = json.loads(answered.stdout)
        self.assertEqual("UNVERIFIED", standing)
        self.assertNotEqual("ready", status)

    def test_finalizing_twice_returns_the_same_receipt(self):
        first = self.admitted()
        again = self.finalize()
        self.assertEqual(0, again.returncode, again.stderr)
        self.assertEqual(first["receipt_hash"],
                         json.loads(again.stdout)["receipt_hash"])

    def test_the_journal_exports_and_imports_across_homes(self):
        issued = self.admitted()
        bundle = self.work / "journal.json"
        exported = self.trusted("export", "--out", str(bundle), "--repo",
                                str(self.repo), "--json")
        self.assertEqual(0, exported.returncode, exported.stderr)
        other_home = self.work / "other-home"
        imported = self.trusted(
            "import", "--in", str(bundle), "--repo", str(self.repo), "--json",
            ADMISSIBLE_HOME=str(other_home))
        self.assertEqual(0, imported.returncode, imported.stderr)
        self.assertEqual(issued["head"]["receipt_hash"],
                         json.loads(imported.stdout)["receipt_hash"])

    def test_impeaching_moves_standing_without_touching_the_receipt(self):
        issued = self.admitted()
        defect = self.work / "defect.json"
        defect.write_text(json.dumps({
            "kind": "defect", "defect_id": "DEF-1",
            "repository": issued["repository"], "commit_sha": self.sha,
            "severity": "high", "summary": "It melts.",
            "missed_check_ids": ["unit"],
            "discovered_at": int(issued["issued_at"]) + 1,
            "regression_test_id": "unit",
        }), encoding="utf-8")
        filed = self.trusted("impeach", self.sha, "--evidence", str(defect),
                             "--repo", str(self.repo), "--json")
        self.assertEqual(0, filed.returncode, filed.stderr)
        self.assertEqual("IMPEACHED", json.loads(filed.stdout)["state"])
        after = self.trusted("verify", self.sha, "--repo", str(self.repo),
                             "--json")
        self.assertEqual(1, after.returncode)
        self.assertEqual([issued["receipt_hash"]],
                         json.loads(after.stdout)["receipt_hashes"])


class TheHandoffFailureMatrix(HandoffCase):
    """The refusals a user actually meets, against the installed command."""

    def prepared_for_finalize(self) -> None:
        self.evaluate()
        self.observe()
        self.trust_the_policy()

    def assert_refused(self, completed, needle: str = "") -> dict:
        self.assertEqual(2, completed.returncode, completed.stdout)
        document = json.loads(completed.stdout)
        self.assertEqual("BLOCKED", document["state"])
        if needle:
            self.assertIn(needle, document["message"])
        return document

    def test_an_untrusted_policy_refuses(self):
        self.evaluate()
        self.observe()
        self.assert_refused(self.finalize(), "trusted policy baseline")

    def test_a_stale_sha_refuses(self):
        self.prepared_for_finalize()
        completed = self.trusted(
            "finalize", "--preview", str(self.preview), "--sha", "0" * 40,
            "--policy-root", str(self.repo), "--evaluation-attestation",
            str(self.attestation), "--repo", str(self.repo), "--json")
        self.assert_refused(completed, "nothing was signed")

    def test_a_dirty_trusted_checkout_refuses(self):
        self.prepared_for_finalize()
        (self.repo / "scratch.txt").write_text("dirty\n", encoding="utf-8")
        self.assert_refused(self.finalize(), "uncommitted")

    def test_a_missing_admission_key_refuses(self):
        self.prepared_for_finalize()
        completed = self.trusted(
            "finalize", "--preview", str(self.preview), "--sha", self.sha,
            "--policy-root", str(self.repo), "--evaluation-attestation",
            str(self.attestation), "--repo", str(self.repo), "--json",
            ADMISSIBLE_HMAC_KEY="")
        self.assert_refused(completed, "ADMISSIBLE_HMAC_KEY")

    def test_a_wrong_observer_keyring_refuses(self):
        self.prepared_for_finalize()
        other = self.work / "other-observers.json"
        other.write_text(json.dumps({OBSERVER_KEY_ID: "a-different-secret"}),
                         encoding="utf-8")
        os.chmod(other, 0o600)
        self.assert_refused(
            self.finalize(ADMISSIBLE_EVALUATION_KEYRING=str(other)),
            "not usable")

    def test_an_observer_nobody_pinned_refuses(self):
        self.prepared_for_finalize()
        empty = self.work / "empty-observers.json"
        empty.write_text("{}", encoding="utf-8")
        os.chmod(empty, 0o600)
        self.assert_refused(
            self.finalize(ADMISSIBLE_EVALUATION_KEYRING=str(empty)),
            "keyring")

    def test_an_edited_tree_in_the_preview_refuses(self):
        self.prepared_for_finalize()
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document["tree_sha"] = "b" * 40
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        self.assert_refused(self.finalize(), "tree")

    def test_a_fork_preview_refuses(self):
        self.prepared_for_finalize()
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document["fork"] = True
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        self.assert_refused(self.finalize(), "fork")

    def test_an_observer_asserting_no_isolation_refuses(self):
        self.evaluate()
        completed = self.trusted(
            "attest-evaluation", "--preview", str(self.preview),
            "--source-receipt", str(self.source_receipt()),
            "--isolation", "none", "--out", str(self.attestation),
            "--repo", str(self.repo), "--json",
            ADMISSIBLE_EVALUATION_KEY_ID=OBSERVER_KEY_ID,
            ADMISSIBLE_EVALUATION_KEY=OBSERVER_SECRET)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.trust_the_policy()
        self.assert_refused(self.finalize(), "isolation")

    def test_a_home_with_a_live_sidecar_refuses(self):
        self.prepared_for_finalize()
        database = self.home / "admissible.sqlite3"
        Path(str(database) + "-wal").write_bytes(b"\x00" * 32)
        self.assert_refused(self.finalize())

    def test_a_home_a_newer_build_wrote_refuses(self):
        import sqlite3

        self.prepared_for_finalize()
        connection = sqlite3.connect(str(self.home / "admissible.sqlite3"))
        connection.execute(
            "UPDATE schema_meta SET value='99' WHERE key='schema_version'")
        connection.commit()
        connection.close()
        self.assert_refused(self.finalize(), "newer Admissible")

    def test_a_forged_receipt_row_makes_the_answer_unknown(self):
        import sqlite3

        issued = self.admitted()
        connection = sqlite3.connect(str(self.home / "admissible.sqlite3"))
        try:
            connection.execute("DROP TRIGGER workflow_receipts_no_update")
            document = json.loads(connection.execute(
                "SELECT receipt_json FROM workflow_receipts WHERE "
                "receipt_hash=?", (issued["receipt_hash"],)).fetchone()[0])
            document["class_id"] = "tampered"
            connection.execute(
                "UPDATE workflow_receipts SET receipt_json=? WHERE "
                "receipt_hash=?", (json.dumps(document, sort_keys=True),
                                   issued["receipt_hash"]))
            connection.commit()
        finally:
            connection.close()
        completed = self.trusted("verify", self.sha, "--repo", str(self.repo),
                                 "--json")
        self.assertEqual(1, completed.returncode)
        self.assertIn(json.loads(completed.stdout)["state"],
                      ("UNKNOWN", "UNVERIFIED"))

    def test_a_deleted_evidence_row_makes_the_answer_unknown(self):
        import sqlite3

        self.admitted()
        connection = sqlite3.connect(str(self.home / "admissible.sqlite3"))
        try:
            connection.execute("DROP TRIGGER evidence_no_delete")
            connection.execute("DELETE FROM evidence")
            connection.commit()
        finally:
            connection.close()
        completed = self.trusted("ready-status", "--repo", str(self.repo),
                                 "--json")
        self.assertEqual(1, completed.returncode)
        self.assertNotEqual("ready", json.loads(completed.stdout)["status"])


if __name__ == "__main__":
    unittest.main()
