"""Contract tests for the local Admissible Ready product surface."""
from __future__ import annotations

import io
import json
import os
import sys
import threading
import unittest
from unittest import mock
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import TempCase, git, make_repo, require_module  # noqa: E402

cli = require_module("admissible.cli")
ready_server = require_module("admissible.ready_server")


class ReadyServerTest(TempCase):
    def setUp(self):
        super().setUp()
        self.repo = self.tmp / "repo"
        make_repo(self.repo)
        config = {
            "version": 1,
            "profile": "python-library",
            "classes": [{
                "id": "default",
                "checks": [{
                    "id": "unit",
                    "argv": [sys.executable, "-c", "raise SystemExit(0)"],
                    "timeout_seconds": 30,
                    "cost_units": 1,
                    "required": True,
                    "version": "1",
                }],
                "required_independent_reviews": 0,
                "review_max_age_seconds": 86400,
                "max_cost_units": 10,
                "max_wall_seconds": 60,
            }],
        }
        (self.repo / ".admissible.json").write_text(
            json.dumps(config), encoding="utf-8")
        git(self.repo, "add", ".admissible.json")
        git(self.repo, "commit", "-q", "-m", "policy")
        self.server = ready_server.make_server(
            str(self.repo), host="127.0.0.1", port=0)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base = f"http://{host}:{port}"

    def tearDown(self):
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()
        if hasattr(self, "thread"):
            self.thread.join(timeout=2)
        super().tearDown()

    def get(self, path):
        headers = ({"X-Admissible-Ready": "1"}
                   if path.startswith("/api/") else {})
        request = Request(self.base + path, headers=headers)
        with urlopen(request, timeout=10) as response:
            return response.status, response.headers, response.read()

    def post(self, path, document, *, origin=None, host=None):
        headers = {
            "Content-Type": "application/json",
            "X-Admissible-Ready": "1",
        }
        if origin is not None:
            headers["Origin"] = origin
        if host is not None:
            headers["Host"] = host
        request = Request(
            self.base + path,
            data=json.dumps(document).encode("utf-8"),
            headers=headers,
            method="POST")
        with urlopen(request, timeout=30) as response:
            return response.status, response.headers, json.load(response)

    def test_state_endpoint_is_read_only_and_bound_to_exact_head(self):
        before = list((self.home / "logs").rglob("*.log"))
        status, headers, body = self.get("/api/v1/state")
        document = json.loads(body)
        after = list((self.home / "logs").rglob("*.log"))
        self.assertEqual(status, 200)
        self.assertEqual(document["schema"], "admissible/v0.7/ready-state")
        self.assertEqual(document["status"], "needs_attention")
        self.assertEqual(document["identity"]["commit_sha"],
                         git(self.repo, "rev-parse", "HEAD"))
        self.assertEqual(before, after)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])

    def test_cross_site_state_get_is_rejected_before_store_initialization(self):
        before = ({path.relative_to(self.home) for path in self.home.rglob("*")}
                  if self.home.exists() else set())
        request = Request(
            self.base + "/api/v1/state",
            headers={"Origin": "https://attacker.example"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=10)
        blocked = caught.exception
        try:
            self.assertEqual(blocked.code, 403)
        finally:
            blocked.close()
        after = ({path.relative_to(self.home) for path in self.home.rglob("*")}
                 if self.home.exists() else set())
        self.assertEqual(after, before)

    def test_check_endpoint_runs_the_same_gate(self):
        status, _, document = self.post("/api/v1/check", {})
        self.assertEqual(status, 200)
        self.assertEqual(document["status"], "checks_complete")
        self.assertEqual(document["canonical"]["state"], "CHECKS_PASSED")
        self.assertTrue(list((self.home / "logs").rglob("*.log")))

    def test_connect_endpoint_returns_copyable_setup_and_live_agents(self):
        status, _, document = self.post("/api/v1/connect", {
            "name": "Builder",
            "purpose": "Implement changes",
            "runtime": "hermes",
        })
        self.assertEqual(status, 200)
        self.assertEqual(document["schema"],
                         "admissible/v0.7/agent-connection")
        self.assertIn("mcp_servers:", document["snippet"])
        status, _, body = self.get("/api/v1/agents")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"agents": []})

    def test_post_boundaries_reject_cross_origin_and_unknown_fields(self):
        with self.assertRaises(HTTPError) as caught:
            self.post("/api/v1/check", {}, origin="https://attacker.example")
        cross_origin = caught.exception
        try:
            self.assertEqual(cross_origin.code, 403)
        finally:
            cross_origin.close()
        with self.assertRaises(HTTPError) as caught:
            self.post("/api/v1/connect", {
                "name": "Builder", "purpose": "Code", "runtime": "custom",
                "credential": "do-not-accept",
            })
        unknown_field = caught.exception
        try:
            self.assertEqual(unknown_field.code, 400)
        finally:
            unknown_field.close()

    def test_attacker_host_cannot_pass_origin_check_by_dns_rebinding(self):
        port = self.server.server_address[1]
        authority = f"attacker.example:{port}"
        with self.assertRaises(HTTPError) as caught:
            self.post("/api/v1/connect", {
                "name": "Builder", "purpose": "Code", "runtime": "custom",
            }, origin=f"http://{authority}", host=authority)
        rebound = caught.exception
        try:
            self.assertEqual(rebound.code, 403)
        finally:
            rebound.close()

    def test_static_product_is_friendly_and_progressively_discloses_trust(self):
        status, headers, body = self.get("/")
        html = body.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn("Admissible Ready", html)
        self.assertIn("Connect agent", html)
        self.assertIn("Technical details", html)
        self.assertNotIn("FCD cockpit", html)
        self.assertNotIn("Evidence Atlas", html)
        for asset in ("/ready.css", "/ready.js"):
            asset_status, _, asset_body = self.get(asset)
            self.assertEqual(asset_status, 200)
            self.assertGreater(len(asset_body), 1000)


class ReadyUISecurityTest(TempCase):
    def test_ready_assets_are_declared_as_package_data(self):
        pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(
            encoding="utf-8")
        self.assertIn('"ready_static/*.html"', pyproject)
        self.assertIn('"ready_static/*.css"', pyproject)
        self.assertIn('"ready_static/*.js"', pyproject)

    def test_hidden_setup_and_command_regions_cannot_be_overridden_by_layout_css(self):
        css = (Path(__file__).resolve().parent.parent / "admissible" /
               "ready_static" / "ready.css").read_text(encoding="utf-8")
        self.assertIn("[hidden]", css)
        self.assertIn("display: none !important", css)

    def test_dirty_head_is_not_presented_as_an_applicable_result(self):
        javascript = (Path(__file__).resolve().parent.parent / "admissible" /
                      "ready_static" / "ready.js").read_text(encoding="utf-8")
        self.assertIn("applies_to_current_commit", javascript)
        self.assertIn("uncommitted changes", javascript)

    def test_journey_completion_follows_ready_status_not_optional_failures(self):
        javascript = (Path(__file__).resolve().parent.parent / "admissible" /
                      "ready_static" / "ready.js").read_text(encoding="utf-8")
        self.assertIn(
            '["waiting_for_review", "checks_complete", "ready"].includes('
            "document.status)", javascript)
        self.assertIn("Required checks complete", javascript)
        self.assertIn("optional check", javascript)

    def test_authenticated_ready_does_not_label_unavailable_evidence_not_checked(self):
        javascript = (Path(__file__).resolve().parent.parent / "admissible" /
                      "ready_static" / "ready.js").read_text(encoding="utf-8")
        self.assertIn('advanced?.check_evidence === "unavailable"', javascript)
        self.assertIn("Detailed check evidence unavailable", javascript)
        self.assertNotIn(
            "failed === 0 && passed === total", javascript)

    def test_ui_refuses_to_start_with_signing_credentials(self):
        repo = self.tmp / "repo"
        make_repo(repo)
        old = os.environ.get("ADMISSIBLE_REVIEW_KEY")
        os.environ["ADMISSIBLE_REVIEW_KEY"] = "must-not-print"
        try:
            out, err = io.StringIO(), io.StringIO()
            with mock.patch(
                    "admissible.ready_server.make_server",
                    side_effect=AssertionError(
                        "credential guard reached server construction")):
                code = cli.main([
                    "ui", "--repo", str(repo), "--no-open", "--port", "0",
                ], stdout=out, stderr=err)
        finally:
            if old is None:
                os.environ.pop("ADMISSIBLE_REVIEW_KEY", None)
            else:
                os.environ["ADMISSIBLE_REVIEW_KEY"] = old
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("credential", err.getvalue().lower())
        self.assertNotIn("must-not-print", err.getvalue())


if __name__ == "__main__":
    unittest.main()
