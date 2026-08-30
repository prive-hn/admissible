"""Dependency-free MCP stdio surface for Admissible Ready.

The server exposes a bounded workflow contract, never trusted admission
authority.  All diagnostics belong on stderr; :func:`serve_stdio` writes
JSON-RPC only, so a client parsing stdout never has to tolerate a log line.

Four tools, and the catalogue is closed: read the state, get a work package,
check this exact commit, read the ordered remediation.  There is no verb for
review, attestation, policy trust, finalisation, signing, merge or deploy --
not gated behind a capability, but absent, because the code that would
implement one is in a distribution this wheel does not depend on.

A work package is connection-local and single-use.  It is issued into this
process's memory, never persisted, and the *first* check attempt against it
spends it -- on success and on refusal alike.  Spending on refusal is the part
that matters: a package that survived a mismatched check would let an agent
retry against a moved HEAD until one attempt happened to line up.  Issuance is
not idempotent and is advertised as such in the tool annotations; the budget is
refillable, and this is a use-once token rather than a finite allowance.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Mapping, TextIO

from admissible_core import identity as identity_module
from admissible_core import schema as schema_module

from . import __version__
from . import agent_connection as connection_module
from . import git_reader
from . import ready as ready_module
from . import runner as runner_module

__all__ = ["MCP_VERSION", "Server", "serve_stdio"]

MCP_VERSION = "2025-06-18"
_MAX_MESSAGE_BYTES = 1024 * 1024

_READY_OUTPUT_SCHEMA: dict[str, Any] = schema_module.ready_schema()
_WORK_PACKAGE_OUTPUT_SCHEMA: dict[str, Any] = schema_module.work_package_schema()
_REMEDIATION_OUTPUT_SCHEMA: dict[str, Any] = schema_module.remediation_schema()
_LOCAL_STORE_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}

_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "admissible_get_state",
        "title": "Get Admissible Ready state",
        "description": (
            "Read the latest recorded state for the repository's exact HEAD. "
            "This does not run checks or grant admission authority."),
        "inputSchema": {"type": "object", "properties": {},
                        "additionalProperties": False},
        "outputSchema": _READY_OUTPUT_SCHEMA,
        "annotations": _LOCAL_STORE_ANNOTATIONS,
    },
    {
        "name": "admissible_get_work_package",
        "title": "Get an exact work package",
        "description": (
            "Create a bounded task contract tied to the exact repository, "
            "commit, tree, and policy."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "task": {"type": "string", "minLength": 1,
                         "maxLength": 8000},
                "class_id": {"type": "string", "minLength": 1,
                             "maxLength": 160},
                "config_path": {"type": "string", "minLength": 1,
                                "maxLength": 4096},
            },
            "required": ["task"],
            "additionalProperties": False,
        },
        "outputSchema": _WORK_PACKAGE_OUTPUT_SCHEMA,
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "admissible_check",
        "title": "Check this exact commit",
        "description": (
            "Run configured deterministic preview checks without signing or "
            "finalizing anything."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "class_id": {"type": "string", "minLength": 1,
                             "maxLength": 160},
                "policy_digest": {"type": "string",
                                  "pattern": "^[0-9a-f]{64}$"},
                "config_path": {"type": "string", "minLength": 1,
                                "maxLength": 4096},
                "no_cache": {"type": "boolean"},
                "package_id": {"type": "string",
                              "pattern": "^[0-9a-f]{64}$"},
                "evidence": {
                    "type": "object",
                    "description": (
                        "An existing bounded workflow-evidence document. "
                        "Attaching it never authenticates or signs it."),
                },
            },
            "required": ["package_id", "class_id", "policy_digest", "config_path"],
            "additionalProperties": False,
        },
        "outputSchema": _READY_OUTPUT_SCHEMA,
    },
    {
        "name": "admissible_get_remediation",
        "title": "Get ordered remediation",
        "description": (
            "Read stable reason codes and ordered next actions for exact HEAD. "
            "Agents must stop when the owner is not agent_or_human."),
        "inputSchema": {"type": "object", "properties": {},
                        "additionalProperties": False},
        "outputSchema": _REMEDIATION_OUTPUT_SCHEMA,
        "annotations": _LOCAL_STORE_ANNOTATIONS,
    },
)


def _error(request_id: Any, code: int, message: str,
           data: Any | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


class Server:
    """One stateful MCP connection over an external transport."""

    def __init__(self, *, repo: str, agent_name: str, purpose: str,
                 runtime: str) -> None:
        # First, before the repository path is even resolved: this server can
        # run candidate-owned checks, so constructing one beside a credential
        # is refused rather than deferred to the first tool call. A library
        # caller that builds a Server directly gets the same refusal the CLI
        # does.
        present = runner_module.present_signing_credentials()
        if present:
            raise ValueError(
                "this process contains a signing credential ("
                + ", ".join(present)
                + "). MCP can run candidate checks, so it will not start; keep "
                  "those credentials in their separate trusted domains")
        for key, value, maximum in (
            ("agent_name", agent_name, 120),
            ("purpose", purpose, 2000),
            ("runtime", runtime, 80),
        ):
            if type(value) is not str or not value.strip() or len(value) > maximum:
                raise ValueError(f"{key} must be a non-empty bounded string")
        if type(repo) is not str or not repo:
            raise ValueError("repo must be a non-empty string")
        self.repo = str(Path(repo).expanduser().resolve())
        self.agent_name = agent_name.strip()
        self.purpose = purpose.strip()
        self.runtime = runtime.strip()
        self._initialize_responded = False
        self._operating = False
        self._packages: dict[str, dict[str, Any]] = {}
        self._issue_seq = 0

    @staticmethod
    def tools() -> list[dict[str, Any]]:
        # Round-trip copy keeps callers from mutating the protocol catalogue.
        return json.loads(json.dumps(_TOOLS))

    def handle(self, message: Mapping[str, Any]) -> dict[str, Any] | None:
        """Handle one decoded JSON-RPC message."""

        if type(message) is not dict:
            return _error(None, -32600, "Request must be a JSON object")
        has_id = "id" in message
        request_id = message.get("id")
        if message.get("jsonrpc") != "2.0":
            return (_error(request_id, -32600, "jsonrpc must be '2.0'")
                    if has_id else None)
        method = message.get("method")
        if type(method) is not str:
            return (_error(request_id, -32600, "method must be a string")
                    if has_id else None)
        params = message.get("params", {})
        if type(params) is not dict:
            return (_error(request_id, -32602, "params must be an object")
                    if has_id else None)

        if method == "notifications/initialized":
            if has_id:
                return _error(request_id, -32600,
                              "notifications/initialized must not carry an id")
            if params or not self._initialize_responded:
                return None
            self._operating = True
            return None

        if not has_id:
            # Request-only methods, including initialize and tools/call, must
            # not execute when encoded as JSON-RPC notifications.
            return None

        if method == "initialize":
            if self._initialize_responded:
                return _error(request_id, -32600,
                              "initialize may be called only once")
            version = params.get("protocolVersion")
            if type(version) is not str or not version:
                return _error(request_id, -32602,
                              "protocolVersion must be a string")
            extra = set(params) - {
                "protocolVersion", "capabilities", "clientInfo", "_meta"}
            if extra:
                return _error(request_id, -32602,
                              "initialize received unknown arguments")
            if type(params.get("capabilities")) is not dict:
                return _error(request_id, -32602,
                              "client capabilities must be an object")
            if type(params.get("clientInfo")) is not dict:
                return _error(request_id, -32602,
                              "clientInfo must be an object")
            self._initialize_responded = True
            return {
                "jsonrpc": "2.0", "id": request_id,
                "result": {
                    "protocolVersion": MCP_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "admissible-ready",
                        "title": "Admissible Ready",
                        "version": __version__,
                    },
                    "instructions": (
                        "Use Ready state and ordered actions for this exact "
                        "commit. Stop when the next action belongs to a human, "
                        "reviewer, or trusted infrastructure."),
                },
            }

        if method == "ping":
            if not self._initialize_responded:
                return _error(request_id, -32002,
                              "Server is not initialized")
            if set(params) - {"_meta"}:
                return _error(request_id, -32602,
                              "ping received unknown arguments")
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}

        if not self._operating:
            return _error(request_id, -32002,
                          "Server is not initialized")
        if method == "tools/list":
            if set(params) - {"cursor", "_meta"}:
                return _error(request_id, -32602,
                              "tools/list received unknown arguments")
            return {"jsonrpc": "2.0", "id": request_id,
                    "result": {"tools": self.tools()}}
        if method == "tools/call":
            if "name" not in params or set(params) - {"name", "arguments", "_meta"}:
                return _error(request_id, -32602,
                              "tools/call requires name and optional arguments")
            name = params.get("name")
            arguments = params.get("arguments", {})
            if type(name) is not str or type(arguments) is not dict:
                return _error(request_id, -32602,
                              "tool name must be a string and arguments an object")
            validation = self._validate_arguments(name, arguments)
            if validation:
                return _error(request_id, -32602, validation)
            try:
                document = self._call_tool(name, arguments)
            except (ready_module.ReadyError, ValueError, OSError) as error:
                return {
                    "jsonrpc": "2.0", "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": str(error)}],
                        "isError": True,
                    },
                }
            text = json.dumps(document, separators=(",", ":"),
                              sort_keys=True, ensure_ascii=True,
                              allow_nan=False)
            return {
                "jsonrpc": "2.0", "id": request_id,
                "result": {
                    "content": [{"type": "text", "text": text}],
                    "structuredContent": document,
                    "isError": False,
                },
            }
        return _error(request_id, -32601, f"Unknown method: {method}")

    @staticmethod
    def _validate_arguments(name: str, arguments: Mapping[str, Any]) -> str:
        names = {item["name"] for item in _TOOLS}
        if name not in names:
            return f"Unknown tool: {name}"
        if name in {"admissible_get_state", "admissible_get_remediation"}:
            return "" if not arguments else f"{name} accepts no arguments"
        if name == "admissible_check":
            allowed = {"class_id", "policy_digest", "config_path",
                       "no_cache", "evidence", "package_id"}
            required = {"package_id", "class_id", "policy_digest", "config_path"}
            if set(arguments) - allowed:
                return "admissible_check received unknown arguments"
            if not required.issubset(arguments):
                return ("admissible_check requires package_id, class_id, "
                        "policy_digest, and config_path from the work package")
            if (type(arguments["class_id"]) is not str
                    or not arguments["class_id"].strip()
                    or len(arguments["class_id"]) > 160):
                return "class_id must be a non-empty bounded string"
            digest = arguments["policy_digest"]
            if (type(digest) is not str or len(digest) != 64
                    or any(item not in "0123456789abcdef" for item in digest)):
                return "policy_digest must be a lowercase SHA-256 digest"
            config_path = arguments["config_path"]
            if (type(config_path) is not str or not config_path.strip()
                    or len(config_path) > 4096):
                return "config_path must be a non-empty bounded string"
            if "no_cache" in arguments and type(arguments["no_cache"]) is not bool:
                return "no_cache must be a boolean"
            if "evidence" in arguments and type(arguments["evidence"]) is not dict:
                return "evidence must be a JSON object"
            package_id = arguments["package_id"]
            if (type(package_id) is not str or len(package_id) != 64
                    or any(item not in "0123456789abcdef"
                           for item in package_id)):
                return "package_id must be a lowercase SHA-256 digest"
            if "evidence" in arguments:
                try:
                    size = len(json.dumps(arguments["evidence"],
                                          ensure_ascii=True).encode("utf-8"))
                except (TypeError, ValueError):
                    return "evidence must contain only JSON values"
                if size > _MAX_MESSAGE_BYTES:
                    return "evidence is above the MCP message ceiling"
            return ""
        if (set(arguments) - {"task", "class_id", "config_path"}
                or "task" not in arguments):
            return ("admissible_get_work_package requires task and accepts "
                    "only optional class_id and config_path")
        task = arguments.get("task")
        if type(task) is not str or not task.strip() or len(task) > 8000:
            return "task must be a non-empty string of at most 8000 characters"
        for key, maximum in (("class_id", 160), ("config_path", 4096)):
            value = arguments.get(key)
            if value is not None and (type(value) is not str
                                      or not value.strip()
                                      or len(value) > maximum):
                return f"{key} must be a non-empty bounded string"
        return ""

    def _call_tool(self, name: str,
                   arguments: Mapping[str, Any]) -> dict[str, Any]:
        if name == "admissible_get_state":
            return ready_module.inspect_unsigned(self.repo)
        if name == "admissible_get_work_package":
            self._issue_seq += 1
            document = ready_module.work_package(
                self.repo, arguments["task"],
                class_id=arguments.get("class_id"),
                config_path=arguments.get("config_path"),
                principal=self.agent_name,
                issue_nonce=f"{self.agent_name}:{self._issue_seq}:{time.time_ns()}")
            document["agent"] = {
                "name": self.agent_name,
                "purpose": self.purpose,
                "runtime": self.runtime,
            }
            self._packages[document["package_id"]] = {
                "identity": dict(document["identity"]),
                "principal": self.agent_name,
                "spent": False,
            }
            return document
        if name == "admissible_check":
            package_id = arguments["package_id"]
            issued = self._packages.get(package_id)
            if issued is None:
                raise ready_module.ReadyError(
                    "unknown or forged work package")
            if issued["spent"]:
                raise ready_module.ReadyError(
                    "work package already spent; request a new work package")
            # Spent here, before the identity comparison below: a package that
            # survived a refusal would let an agent retry until one attempt
            # happened to line up with a moved HEAD.
            issued["spent"] = True
            identity = issued["identity"]
            try:
                current = git_reader.repository_identity(self.repo)
            except identity_module.IdentityError as error:
                raise ready_module.ReadyError(str(error)) from None
            if (identity.get("repository") != current.repository
                    or identity.get("commit_sha") != current.commit_sha
                    or identity.get("tree_sha") != current.tree_sha
                    or identity.get("class_id") != arguments["class_id"]
                    or identity.get("policy_digest") != arguments["policy_digest"]
                    or identity.get("config_path") != arguments["config_path"]):
                raise ready_module.ReadyError(
                    "work package does not match this exact repository HEAD")
            _, document = ready_module.run_check(
                self.repo, no_cache=arguments.get("no_cache", False),
                evidence=arguments.get("evidence"),
                class_id=arguments["class_id"],
                config_path=arguments["config_path"],
                expected_policy_digest=arguments["policy_digest"],
                package=identity)
            return document
        state = ready_module.inspect_unsigned(self.repo)
        return {
            "schema": "admissible/v0.7/remediation",
            "identity": state["identity"],
            "status": state["status"],
            "summary": state["summary"],
            "reasons": state["reasons"],
            "actions": state["next_actions"],
            "agent_can_continue": state["agent_can_continue"],
        }


def _strict_loads(text: str) -> Any:
    def _non_finite(_value: str) -> Any:
        raise ValueError("non-finite JSON number")
    return json.loads(text, parse_constant=_non_finite)


def _drain_line(source: TextIO) -> None:
    while True:
        more = source.readline(_MAX_MESSAGE_BYTES + 1)
        if more == "" or more.endswith("\n"):
            return


def _read_frame(source: TextIO) -> str | None:
    """Read one bounded JSON-RPC frame. None is EOF."""

    line = source.readline(_MAX_MESSAGE_BYTES + 1)
    if line == "":
        return None
    try:
        size = len(line.encode("utf-8"))
    except UnicodeEncodeError:
        if not line.endswith("\n"):
            _drain_line(source)
        return "invalid"
    oversized = size > _MAX_MESSAGE_BYTES
    if not line.endswith("\n") and len(line) >= _MAX_MESSAGE_BYTES + 1:
        oversized = True
    if oversized:
        if not line.endswith("\n"):
            _drain_line(source)
        return "oversized"
    return line


def serve_stdio(server: Server, *, stdin: TextIO | None = None,
                stdout: TextIO | None = None,
                stderr: TextIO | None = None) -> int:
    """Serve newline-delimited UTF-8 JSON-RPC until stdin closes."""

    source = sys.stdin if stdin is None else stdin
    target = sys.stdout if stdout is None else stdout
    log = sys.stderr if stderr is None else stderr
    session = None
    try:
        while True:
            frame = _read_frame(source)
            if frame is None:
                break
            if frame == "oversized":
                response = _error(None, -32600, "Message exceeds size limit")
            elif frame == "invalid":
                response = _error(None, -32700, "Parse error")
            else:
                try:
                    decoded = _strict_loads(frame)
                except (json.JSONDecodeError, ValueError, UnicodeError):
                    response = _error(None, -32700, "Parse error")
                else:
                    response = server.handle(decoded)
            if response is not None:
                target.write(json.dumps(
                    response, separators=(",", ":"),
                    ensure_ascii=True, allow_nan=False) + "\n")
                target.flush()
            if server._operating and session is None:
                candidate = connection_module.live_session(
                    server.repo, name=server.agent_name,
                    purpose=server.purpose, runtime=server.runtime)
                candidate.__enter__()
                session = candidate
    except connection_module.ConnectionError as error:
        log.write(f"Unable to register agent connection: {error}\n")
        return 2
    finally:
        if session is not None:
            session.__exit__(None, None, None)
    log.flush()
    return 0
