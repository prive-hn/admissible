"""Contract: the agent and browser surfaces behave exactly as before the split.

Two protocols are asserted here against the same throwaway repository the
monolith is asserted against, because both are contracts with something outside
this repository -- an MCP client and a browser -- and neither notices that the
code moved.

The MCP claims:

* the ``2025-06-18`` handshake, the closed four-tool catalogue, and the
  argument validation, all identical to the monolith's;
* the work package is **connection-local** and **single-use**, and the first
  check attempt spends it *on refusal as well as on success*.  A package that
  survived a mismatch would let an agent retry until a moved HEAD lined up;
* stdout carries JSON-RPC and nothing else, so a client parsing it never has to
  tolerate a log line;
* there is no verb for review, attestation, policy, finalisation or signing --
  asserted as an equality on the catalogue, because a list of prohibitions
  cannot name a verb nobody has invented yet.

The loopback claims: the server binds only to a loopback address, refuses a
request that does not carry its own authority, refuses a cross-origin write,
and serves the real packaged assets rather than a placeholder.
"""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from admissible import agent_mcp as legacy_mcp

from admissible_ready import agent_mcp
from admissible_ready import ready as ready_state
from admissible_ready import ready_server
from admissible_ready import runner as runner_module

from .test_admissible_ready_parity import policy_document


class AgentCase(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(self.scratch("agent-home-"))
        self.repo = Path(self.scratch("agent-repo-"))
        self.git("init", "--quiet")
        self.git("config", "user.email", "agent@example.com")
        self.git("config", "user.name", "Agent")
        self.git("remote", "add", "origin",
                 "https://github.com/acme/widget.git")
        (self.repo / ".admissible.json").write_text(
            json.dumps(policy_document(["/usr/bin/true"]), indent=2) + "\n",
            encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "--quiet", "-m", "policy")
        patch = mock.patch.dict(
            os.environ, {"ADMISSIBLE_HOME": str(self.home)}, clear=False)
        patch.start()
        self.addCleanup(patch.stop)
        for name in runner_module.SIGNING_CREDENTIAL_NAMES:
            os.environ.pop(name, None)

    def scratch(self, prefix: str) -> str:
        raw = tempfile.mkdtemp(prefix=prefix)
        self.addCleanup(shutil.rmtree, raw, True)
        return raw

    def git(self, *args: str) -> None:
        subprocess.run(("git", "-C", str(self.repo), *args), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=60)

    def server(self) -> agent_mcp.Server:
        return agent_mcp.Server(repo=str(self.repo), agent_name="agent",
                                purpose="do the thing", runtime="local")

    def initialized(self) -> agent_mcp.Server:
        server = self.server()
        server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": agent_mcp.MCP_VERSION,
                       "capabilities": {}, "clientInfo": {"name": "t"}}})
        server.handle({"jsonrpc": "2.0",
                       "method": "notifications/initialized"})
        return server

    def call(self, server: agent_mcp.Server, name: str,
             arguments: dict | None = None) -> dict:
        return server.handle({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}}})


class ProtocolParity(AgentCase):
    """The wire contract is the monolith's, byte for byte."""

    def test_the_protocol_version_is_unchanged(self):
        self.assertEqual("2025-06-18", agent_mcp.MCP_VERSION)
        self.assertEqual(legacy_mcp.MCP_VERSION, agent_mcp.MCP_VERSION)

    def test_the_tool_catalogue_is_identical(self):
        self.assertEqual(legacy_mcp.Server.tools(), agent_mcp.Server.tools())

    def test_the_catalogue_is_exactly_four_named_tools(self):
        self.assertEqual(
            ["admissible_check", "admissible_get_remediation",
             "admissible_get_state", "admissible_get_work_package"],
            sorted(tool["name"] for tool in agent_mcp.Server.tools()))

    def test_no_tool_names_a_trust_verb(self):
        forbidden = ("review", "attest", "policy", "trust", "finalize",
                     "sign", "impeach", "merge", "deploy", "receipt",
                     "revoke", "verify")
        for tool in agent_mcp.Server.tools():
            for word in forbidden:
                with self.subTest(tool=tool["name"], verb=word):
                    self.assertNotIn(word, tool["name"])

    def test_the_catalogue_cannot_be_mutated_by_a_caller(self):
        first = agent_mcp.Server.tools()
        first[0]["name"] = "tampered"
        self.assertNotEqual(first, agent_mcp.Server.tools())

    def test_initialize_answers_with_the_ready_server_identity(self):
        server = self.server()
        response = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": agent_mcp.MCP_VERSION,
                       "capabilities": {}, "clientInfo": {"name": "t"}}})
        result = response["result"]
        self.assertEqual(agent_mcp.MCP_VERSION, result["protocolVersion"])
        self.assertEqual("admissible-ready", result["serverInfo"]["name"])
        self.assertEqual("Admissible Ready", result["serverInfo"]["title"])
        self.assertEqual("0.8.0", result["serverInfo"]["version"])

    def test_initialize_may_be_called_only_once(self):
        server = self.initialized()
        response = server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "initialize",
            "params": {"protocolVersion": agent_mcp.MCP_VERSION,
                       "capabilities": {}, "clientInfo": {"name": "t"}}})
        self.assertEqual(-32600, response["error"]["code"])

    def test_a_tool_call_before_initialization_is_refused(self):
        response = self.call(self.server(), "admissible_get_state")
        self.assertEqual(-32002, response["error"]["code"])

    def test_tools_list_matches_the_static_catalogue(self):
        server = self.initialized()
        response = server.handle({"jsonrpc": "2.0", "id": 3,
                                  "method": "tools/list", "params": {}})
        self.assertEqual(agent_mcp.Server.tools(),
                         response["result"]["tools"])

    def test_an_unknown_method_is_a_method_not_found(self):
        server = self.initialized()
        response = server.handle({"jsonrpc": "2.0", "id": 4,
                                  "method": "trust/policy", "params": {}})
        self.assertEqual(-32601, response["error"]["code"])

    def test_argument_validation_agrees_with_the_monolith(self):
        cases = (
            ("admissible_get_state", {"unexpected": 1}),
            ("admissible_get_work_package", {}),
            ("admissible_get_work_package", {"task": ""}),
            ("admissible_check", {}),
            ("admissible_check", {"package_id": "z" * 64, "class_id": "d",
                                  "policy_digest": "c" * 64,
                                  "config_path": ".admissible.json",
                                  "no_cache": "yes"}),
            ("nope", {}),
        )
        for name, arguments in cases:
            with self.subTest(tool=name, arguments=arguments):
                self.assertEqual(
                    legacy_mcp.Server._validate_arguments(name, arguments),
                    agent_mcp.Server._validate_arguments(name, arguments))


class WorkPackageLifecycle(AgentCase):
    """Issued into this connection's memory, spent once, never persisted."""

    def issue(self, server: agent_mcp.Server) -> dict:
        response = self.call(server, "admissible_get_work_package",
                             {"task": "fix the thing"})
        return response["result"]["structuredContent"]

    def test_a_package_is_bound_to_the_exact_artefact_and_policy(self):
        package = self.issue(self.initialized())
        from admissible_ready import git_reader

        found = git_reader.repository_identity(self.repo)
        self.assertEqual(found.repository, package["identity"]["repository"])
        self.assertEqual(found.commit_sha, package["identity"]["commit_sha"])
        self.assertEqual(found.tree_sha, package["identity"]["tree_sha"])
        self.assertEqual(".admissible.json",
                         package["identity"]["config_path"])

    def test_issuance_is_not_idempotent(self):
        server = self.initialized()
        self.assertNotEqual(self.issue(server)["package_id"],
                            self.issue(server)["package_id"])

    def test_a_package_is_unknown_to_another_connection(self):
        package = self.issue(self.initialized())
        other = self.initialized()
        response = self.call(other, "admissible_check", {
            "package_id": package["package_id"],
            "class_id": package["identity"]["class_id"],
            "policy_digest": package["identity"]["policy_digest"],
            "config_path": package["identity"]["config_path"]})
        self.assertTrue(response["result"]["isError"])
        self.assertIn("unknown or forged",
                      response["result"]["content"][0]["text"])

    def test_the_first_check_spends_it_and_the_second_is_refused(self):
        server = self.initialized()
        package = self.issue(server)
        arguments = {
            "package_id": package["package_id"],
            "class_id": package["identity"]["class_id"],
            "policy_digest": package["identity"]["policy_digest"],
            "config_path": package["identity"]["config_path"]}
        first = self.call(server, "admissible_check", arguments)
        self.assertFalse(first["result"]["isError"])
        self.assertEqual("checks_complete",
                         first["result"]["structuredContent"]["status"])
        second = self.call(server, "admissible_check", arguments)
        self.assertTrue(second["result"]["isError"])
        self.assertIn("already spent",
                      second["result"]["content"][0]["text"])

    def test_a_refused_check_spends_the_package_too(self):
        """The important half: a survivor could be retried until HEAD lined up."""

        server = self.initialized()
        package = self.issue(server)
        arguments = {
            "package_id": package["package_id"],
            "class_id": package["identity"]["class_id"],
            # A policy digest the package was not issued against.
            "policy_digest": "0" * 64,
            "config_path": package["identity"]["config_path"]}
        first = self.call(server, "admissible_check", arguments)
        self.assertTrue(first["result"]["isError"])
        self.assertIn("does not match", first["result"]["content"][0]["text"])
        second = self.call(server, "admissible_check", arguments)
        self.assertTrue(second["result"]["isError"])
        self.assertIn("already spent",
                      second["result"]["content"][0]["text"])

    def test_a_package_is_refused_after_head_moves(self):
        server = self.initialized()
        package = self.issue(server)
        (self.repo / "next.txt").write_text("x\n", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "--quiet", "-m", "moved")
        response = self.call(server, "admissible_check", {
            "package_id": package["package_id"],
            "class_id": package["identity"]["class_id"],
            "policy_digest": package["identity"]["policy_digest"],
            "config_path": package["identity"]["config_path"]})
        self.assertTrue(response["result"]["isError"])
        self.assertIn("does not match this exact repository HEAD",
                      response["result"]["content"][0]["text"])

    def test_the_package_carries_the_agent_that_asked_for_it(self):
        package = self.issue(self.initialized())
        self.assertEqual(
            {"name": "agent", "purpose": "do the thing", "runtime": "local"},
            package["agent"])

    def test_no_package_is_written_to_the_store(self):
        """Connection-local means memory: a restart loses every package."""
        self.issue(self.initialized())
        from admissible_ready import store as ready_store

        opened = ready_store.open_store(self.home)
        self.addCleanup(opened.close)
        import sqlite3

        from admissible_core import store_base

        with sqlite3.connect(
                str(store_base.database_path(self.home))) as raw:
            tables = {row[0] for row in raw.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertEqual(
            [], sorted(name for name in tables if "package" in name))


class StdioIsUncontaminated(AgentCase):
    """Every byte on stdout is one JSON-RPC frame."""

    def frames(self, requests: list[dict]) -> tuple[list[dict], str]:
        source = io.StringIO("".join(
            json.dumps(item) + "\n" for item in requests))
        out, err = io.StringIO(), io.StringIO()
        agent_mcp.serve_stdio(self.server(), stdin=source, stdout=out,
                              stderr=err)
        lines = [line for line in out.getvalue().splitlines() if line]
        return [json.loads(line) for line in lines], err.getvalue()

    def test_only_json_rpc_reaches_stdout(self):
        responses, _ = self.frames([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": agent_mcp.MCP_VERSION,
                        "capabilities": {}, "clientInfo": {"name": "t"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ])
        self.assertEqual(2, len(responses))
        for response in responses:
            self.assertEqual("2.0", response["jsonrpc"])

    def test_a_parse_error_is_a_frame_and_not_a_traceback(self):
        source = io.StringIO("{not json\n")
        out, err = io.StringIO(), io.StringIO()
        agent_mcp.serve_stdio(self.server(), stdin=source, stdout=out,
                              stderr=err)
        self.assertEqual(-32700,
                         json.loads(out.getvalue())["error"]["code"])

    def test_an_oversized_frame_is_bounded_and_answered(self):
        source = io.StringIO(" " * (1024 * 1024 + 10) + "\n")
        out, err = io.StringIO(), io.StringIO()
        agent_mcp.serve_stdio(self.server(), stdin=source, stdout=out,
                              stderr=err)
        self.assertEqual(-32600,
                         json.loads(out.getvalue())["error"]["code"])


class LoopbackServer(AgentCase):
    """The local product: loopback only, same-site only, real assets."""

    def running(self):
        server = ready_server.make_server(str(self.repo), port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return server, f"http://127.0.0.1:{server.server_address[1]}"

    def fetch(self, url: str, *, headers: dict | None = None,
              data: bytes | None = None) -> tuple[int, bytes, dict]:
        request = urllib.request.Request(url, data=data,
                                         headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read(), dict(response.headers)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.read(), dict(error.headers)

    def test_a_non_loopback_host_is_refused_before_a_socket_is_bound(self):
        for host in ("0.0.0.0", "example.com", "::"):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    ready_server.make_server(str(self.repo), host=host)

    def test_the_index_is_the_packaged_asset(self):
        from importlib import resources

        _, base = self.running()
        status, body, headers = self.fetch(f"{base}/")
        self.assertEqual(200, status)
        self.assertEqual(
            resources.files("admissible_ready.ready_static").joinpath(
                "index.html").read_bytes(), body)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])

    def test_every_declared_asset_is_served_from_the_wheel(self):
        _, base = self.running()
        for path, kind in (("/index.html", "text/html"),
                           ("/ready.css", "text/css"),
                           ("/ready.js", "text/javascript")):
            with self.subTest(path=path):
                status, body, headers = self.fetch(f"{base}{path}")
                self.assertEqual(200, status)
                self.assertTrue(body)
                self.assertIn(kind, headers["Content-Type"])

    def test_the_state_api_answers_an_unsigned_ready_document(self):
        _, base = self.running()
        status, body, _ = self.fetch(
            f"{base}/api/v1/state", headers={"X-Admissible-Ready": "1"})
        self.assertEqual(200, status)
        document = json.loads(body)
        self.assertEqual(ready_state.READY_SCHEMA, document["schema"])
        self.assertIn(document["status"], ready_state.UNSIGNED_STATUSES)

    def test_a_cross_origin_read_of_the_state_is_refused(self):
        _, base = self.running()
        status, _, _ = self.fetch(f"{base}/api/v1/state",
                                  headers={"Origin": "http://evil.example"})
        self.assertEqual(403, status)

    def test_a_cross_origin_check_is_refused(self):
        _, base = self.running()
        status, _, _ = self.fetch(
            f"{base}/api/v1/check", data=b"{}",
            headers={"Origin": "http://evil.example",
                     "Content-Type": "application/json"})
        self.assertEqual(403, status)

    def test_a_same_site_check_runs_and_stays_unsigned(self):
        _, base = self.running()
        status, body, _ = self.fetch(
            f"{base}/api/v1/check", data=b"{}",
            headers={"X-Admissible-Ready": "1",
                     "Content-Type": "application/json"})
        self.assertEqual(200, status)
        document = json.loads(body)
        self.assertEqual("checks_complete", document["status"])
        self.assertIn(document["status"], ready_state.UNSIGNED_STATUSES)

    def test_an_unknown_path_is_a_json_not_found(self):
        _, base = self.running()
        status, body, headers = self.fetch(f"{base}/api/v1/finalize")
        self.assertEqual(404, status)
        self.assertIn("application/json", headers["Content-Type"])
        self.assertEqual(404, json.loads(body)["status"])
