"""Agent connection instructions and the local live-session registry.

Connection setup contains no credentials.  A live session proves only that an
MCP client process is connected; it confers no admission, review, signing,
merge, or deployment authority.

The registry is a directory of owner-only files under the Admissible home, one
per connected process, and every field is re-validated on read: the pid must
still exist, its process-start token must still match the one recorded when the
session opened, and the heartbeat must be recent.  A stale or unreadable file
is removed rather than reported, because "an agent is connected" is a claim
about right now and a leftover file is a claim about a process that has exited.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from admissible_core import identity as identity_module

from . import git_reader
from . import store as store_module

__all__ = [
    "ConnectionError",
    "RUNTIMES",
    "active_sessions",
    "instructions",
    "live_session",
]

RUNTIMES = ("claude-code", "codex", "hermes", "local", "custom")
_SCHEMA = "admissible/v0.7/agent-connection"
_SESSION_SCHEMA = "admissible/v0.7/agent-session"
_MAX_NAME = 120
_MAX_PURPOSE = 2000
_HEARTBEAT_MAX_AGE_SECONDS = 120

#: The console command this distribution installs. It is what an MCP client is
#: told to run, and it is a Ready command: an agent connects to the executing
#: half of the product and there is no verb here that reaches the other half.
DEFAULT_EXECUTABLE = "admissible-ready"


def _process_start_token(pid: int) -> str:
    """Return the OS start identity for ``pid``, or empty if it cannot be read.

    A pid alone is not an identity: pids are reused, and a stale session file
    naming a recycled pid would otherwise read as a live agent. The argv is
    fixed and carries only the integer this function was given.
    """

    if type(pid) is not int or type(pid) is bool or pid <= 0:
        return ""
    try:
        completed = subprocess.run(
            ("ps", "-p", str(pid), "-o", "lstart="),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=2, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout.decode("utf-8", "replace").strip()


class ConnectionError(ValueError):
    """A requested connector is unsafe, ambiguous, or malformed."""


def _field(value: str, label: str, maximum: int) -> str:
    if type(value) is not str or not value.strip():
        raise ConnectionError(f"{label} must be a non-empty string")
    cleaned = value.strip()
    if len(cleaned) > maximum:
        raise ConnectionError(f"{label} must be at most {maximum} characters")
    if any(ord(character) < 32 for character in cleaned):
        raise ConnectionError(f"{label} must not contain control characters")
    return cleaned


def _target(repo: str) -> tuple[str, str]:
    try:
        found = git_reader.repository_identity(repo, allow_dirty=True)
    except identity_module.IdentityError as error:
        raise ConnectionError(str(error)) from None
    return str(found.root), found.repository


def _slug(name: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48]
    return value or "agent"


def _json_snippet(command: list[str], slug: str) -> str:
    return json.dumps({
        "mcpServers": {
            f"admissible-{slug}": {
                "type": "stdio",
                "command": command[0],
                "args": command[1:],
            },
        },
    }, indent=2, ensure_ascii=False)


def _quoted(value: str) -> str:
    """Quote one JSON/TOML/YAML basic string with Unicode scalars intact."""

    encoded = json.dumps(value, ensure_ascii=False)
    return encoded.replace("\x7f", "\\u007f")


def _codex_snippet(command: list[str], slug: str) -> str:
    return "\n".join((
        f"[mcp_servers.admissible-{slug}]",
        f"command = {_quoted(command[0])}",
        "args = [" + ", ".join(_quoted(item) for item in command[1:]) + "]",
        "connect_timeout_sec = 60",
        "tool_timeout_sec = 3600",
    )) + "\n"


def _hermes_snippet(command: list[str], slug: str) -> str:
    args = ", ".join(_quoted(item) for item in command[1:])
    return "\n".join((
        "mcp_servers:",
        f"  admissible-{slug}:",
        f"    command: {_quoted(command[0])}",
        f"    args: [{args}]",
        "    connect_timeout: 60",
        "    timeout: 3600",
    )) + "\n"


def instructions(repo: str, *, name: str, purpose: str, runtime: str,
                 executable: str = DEFAULT_EXECUTABLE) -> dict[str, Any]:
    """Return copyable setup for a local stdio MCP client."""

    name = _field(name, "name", _MAX_NAME)
    purpose = _field(purpose, "purpose", _MAX_PURPOSE)
    if runtime not in RUNTIMES:
        raise ConnectionError(
            "runtime must be one of " + ", ".join(RUNTIMES))
    executable = _field(executable, "executable", 1000)
    root, repository = _target(repo)
    command = [
        executable, "mcp", "--repo", root, "--agent-name", name,
        "--purpose", purpose, "--runtime", runtime,
    ]
    slug = _slug(name)
    if runtime == "codex":
        snippet = _codex_snippet(command, slug)
        location = "Add this block to ~/.codex/config.toml, then restart Codex."
    elif runtime == "hermes":
        snippet = _hermes_snippet(command, slug)
        location = "Add this block under your Hermes config, then restart Hermes."
    else:
        snippet = _json_snippet(command, slug)
        if runtime == "claude-code":
            location = "Add this server to the project's .mcp.json, then reconnect Claude Code."
        elif runtime == "local":
            location = "Use this stdio server object in the local agent's MCP client."
        else:
            location = "Use this standard stdio server object in any MCP client."
    return {
        "schema": _SCHEMA,
        "runtime": runtime,
        "name": name,
        "purpose": purpose,
        "repository": repository,
        "root": root,
        "command": command,
        "snippet": snippet,
        "instructions": location,
        "verification": (
            "The agent appears in Ready after its MCP client starts this command. "
            "Connected means reachable, not approved or trusted."),
    }


def _session_directory() -> Path:
    directory = store_module.default_home() / "ready" / "sessions"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        directory.chmod(0o700)
    except OSError as error:
        raise ConnectionError(f"cannot protect session directory: {error}") from None
    return directory


def _write_private(path: Path, document: dict[str, Any]) -> None:
    payload = (json.dumps(document, separators=(",", ":"), sort_keys=True)
               + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def live_session(repo: str, *, name: str, purpose: str,
                 runtime: str) -> Iterator[dict[str, Any]]:
    """Publish one process-local connection for the lifetime of the context."""

    setup = instructions(repo, name=name, purpose=purpose, runtime=runtime)
    session_id = uuid.uuid4().hex
    path = _session_directory() / f"{session_id}.json"
    document = {
        "schema": _SESSION_SCHEMA,
        "session_id": session_id,
        "name": setup["name"],
        "purpose": setup["purpose"],
        "runtime": setup["runtime"],
        "repository": setup["repository"],
        "root": setup["root"],
        "pid": os.getpid(),
        "connected_at": int(time.time()),
        "process_started_at": _process_start_token(os.getpid()),
        "heartbeat_at": int(time.time()),
    }
    _write_private(path, document)
    try:
        yield {**document, "path": str(path)}
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (OSError, ValueError):
        return False
    return True


def active_sessions(repo: str) -> list[dict[str, Any]]:
    """Return bounded live sessions for this repository, removing stale files."""

    root, repository = _target(repo)
    directory = _session_directory()
    active: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            stat = path.lstat()
            if path.is_symlink() or stat.st_size > 32_768:
                continue
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            continue
        pid = document.get("pid")
        heartbeat_at = document.get("heartbeat_at")
        now = int(time.time())
        valid = (
            type(document) is dict
            and document.get("schema") == _SESSION_SCHEMA
            and type(pid) is int and type(pid) is not bool and pid > 0
            and type(document.get("session_id")) is str
            and type(document.get("name")) is str
            and type(document.get("purpose")) is str
            and document.get("runtime") in RUNTIMES
            and type(document.get("connected_at")) is int
            and type(document.get("process_started_at")) is str
            and document.get("process_started_at") == _process_start_token(pid)
            and type(heartbeat_at) is int and type(heartbeat_at) is not bool
            and 0 <= now - heartbeat_at <= _HEARTBEAT_MAX_AGE_SECONDS
        )
        if not valid or not _alive(pid):
            try:
                path.unlink()
            except OSError:
                pass
            continue
        if document.get("repository") != repository or document.get("root") != root:
            continue
        active.append({key: document[key] for key in (
            "schema", "session_id", "name", "purpose", "runtime",
            "repository", "root", "pid", "connected_at")})
    return active
