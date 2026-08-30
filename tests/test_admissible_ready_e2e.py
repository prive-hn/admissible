"""Real user → connected agent → review → trusted Ready journey."""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import time
from pathlib import Path

from tests.admissible_support import TempCase, admit, git, make_repo, require_module
from tests.test_admissible_cli import config_document

agent_mcp = require_module("admissible.agent_mcp")
cli = require_module("admissible.cli")
config_module = require_module("admissible.config")
ready = require_module("admissible.ready")
receipt_module = require_module("admissible.receipt")
review_module = require_module("admissible.review")


class HumanAgentReadyJourneyTest(TempCase):
    def setUp(self):
        super().setUp()
        self.repo = self.tmp / "repo"
        make_repo(self.repo)
        policy = config_document(
            [sys.executable, "-c",
             "from pathlib import Path; raise SystemExit(0 if Path('repair.ok').is_file() else 7)"],
            reviews=1, reviewer_key_ids=["reviewer-key"])
        (self.repo / ".admissible.json").write_text(
            json.dumps(policy), encoding="utf-8")
        git(self.repo, "add", ".admissible.json")
        git(self.repo, "commit", "-q", "-m", "require repair and review")
        self.server = agent_mcp.Server(
            repo=str(self.repo), agent_name="Builder", runtime="hermes",
            purpose="Implement the requested change")
        self.server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "journey-test", "version": "1"}},
        })
        self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, name, arguments):
        response = self.server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })
        self.assertNotIn("error", response)
        self.assertFalse(response["result"].get("isError", False), response)
        return response["result"]["structuredContent"]

    def review_bundle(self, sha):
        selected = config_module.load_config(self.repo).select_class("default")
        repository = "github.com/acme/widget"
        tree = git(self.repo, "rev-parse", "HEAD^{tree}")
        now = int(time.time())
        review = {
            "kind": "review", "review_id": "review-1",
            "reviewer_id": "reviewer-one", "reviewer_version": "1",
            "author_id": "author-one", "verdict": "approve",
            "repository": repository, "commit_sha": sha, "tree_sha": tree,
            "policy_digest": selected.policy_digest,
            "findings_digest": hashlib.sha256(b"").hexdigest(),
            "issued_at": now, "attempt_id": "",
        }
        authorship = {
            "kind": "authorship", "author_id": "author-one",
            "repository": repository, "commit_sha": sha, "tree_sha": tree,
            "policy_digest": selected.policy_digest, "issued_at": now,
        }
        return {
            "schema": "admissible/v0.6/workflow-evidence",
            "commands": [], "reviews": [], "defects": [],
            "attestations": [review_module.attest(
                review, key_id="reviewer-key", secret=b"reviewer-secret")],
            "author_attestations": [review_module.attest_authorship(
                authorship, key_id="author-key", secret=b"author-secret")],
        }

    def test_one_shared_loop_reaches_ready_without_giving_agent_authority(self):
        # Human asks the shared gate. The failure is concrete and repairable.
        code, first = ready.run_check(str(self.repo))
        self.assertEqual(code, 1)
        self.assertEqual(first["status"], "needs_attention")
        self.assertTrue(first["agent_can_continue"])

        package = self.call("admissible_get_work_package", {"task": "Repair the check"})
        self.assertEqual(package["identity"]["commit_sha"], git(self.repo, "rev-parse", "HEAD"))
        self.assertNotIn("sign", package["capabilities"]["allowed"])
        self.assertIn("sign", package["capabilities"]["forbidden"])
        check_arguments = dict(package["completion"]["check_arguments"])

        # The connected agent changes code and commits; it does not approve itself.
        (self.repo / "repair.ok").write_text("repaired\n", encoding="utf-8")
        git(self.repo, "add", "repair.ok")
        git(self.repo, "commit", "-q", "-m", "repair configured check")
        repaired_sha = git(self.repo, "rev-parse", "HEAD")
        package = self.call("admissible_get_work_package", {"task": "Repair the check"})
        check_arguments = dict(package["completion"]["check_arguments"])
        after_repair = self.call(
            "admissible_check", {**check_arguments, "no_cache": False})
        self.assertEqual(after_repair["status"], "waiting_for_review")
        self.assertFalse(after_repair["agent_can_continue"])

        # A separate reviewer signs existing evidence. The agent may attach it,
        # but evaluation still cannot authenticate or admit it.
        evidence = self.review_bundle(repaired_sha)
        package = self.call("admissible_get_work_package", {"task": "Attach review evidence"})
        check_arguments = dict(package["completion"]["check_arguments"])
        after_review = self.call(
            "admissible_check",
            {**check_arguments, "no_cache": False, "evidence": evidence})
        self.assertEqual(after_review["status"], "waiting_for_review")
        self.assertNotEqual(after_review["canonical"]["state"], "ADMITTED")

        evidence_path = self.tmp / "review-evidence.json"
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        os.environ["ADMISSIBLE_HMAC_KEY"] = "finalizer-secret"
        issued = admit(
            self, self.repo, repaired_sha, evidence=evidence_path,
            reviewer_keyring={"reviewer-key": b"reviewer-secret",
                              "author-key": b"author-secret"})
        self.assertEqual(issued.state, "ADMITTED")

        # The connected agent still cannot authenticate standing. A trusted,
        # read-only status domain can—and only then may the friendly state say Ready.
        agent_view = self.call("admissible_get_state", {})
        self.assertNotEqual(agent_view["status"], "ready")
        trusted = ready.inspect(str(self.repo), signer=receipt_module.load_signer())
        self.assertEqual(trusted["status"], "ready")
        self.assertEqual(trusted["canonical"]["state"], "ADMITTED")
        self.assertEqual(trusted["canonical"]["standing"], "CURRENT")
        self.assertTrue(trusted["identity"]["applies_to_current_commit"])

        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["ready-status", "--repo", str(self.repo), "--json"],
                        stdout=out, stderr=err)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["status"], "ready")
