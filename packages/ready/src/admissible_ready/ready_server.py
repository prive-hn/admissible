"""Dependency-free local HTTP service for the Admissible Ready product.

The service is loopback-only, enforced here rather than by the CLI that starts
it: :func:`make_server` refuses any host that is not a loopback address, so a
library caller cannot bind it to an interface a network can reach.  Every
request must additionally carry the local server's own authority in ``Host``,
and every state-changing request must be same-site, so a page on another origin
cannot drive it through a browser that happens to have it open.

It presents the same unsigned Ready document the CLI and the MCP tools present.
It receives no signing credential -- ``make_server`` refuses to construct while
one is in the environment, because the API can start candidate-owned checks --
and it issues no admission.  ``POST /api/v1/check`` is deliberately *not* a
package-authorized MCP check: it is the local operator pressing a button, it is
serialised behind one lock, and it produces the same unsigned document.
"""
from __future__ import annotations

import json
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from urllib.parse import urlparse

from . import agent_connection
from . import ready as ready_module
from . import runner as runner_module

__all__ = ["ReadyService", "make_server"]

_MAX_BODY = 8192
_STATIC_PACKAGE = "admissible_ready.ready_static"
_ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/ready.css": ("ready.css", "text/css; charset=utf-8"),
    "/ready.js": ("ready.js", "text/javascript; charset=utf-8"),
}
_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'self'")


class ReadyService:
    """One repository-bound service shared by all request handlers."""

    def __init__(self, repo: str):
        self.repo = repo
        self._check_lock = threading.Lock()

    def state(self) -> dict[str, Any]:
        return ready_module.inspect_unsigned(self.repo)

    def agents(self) -> dict[str, Any]:
        return {"agents": agent_connection.active_sessions(self.repo)}

    def connect(self, document: dict[str, Any]) -> dict[str, Any]:
        if set(document) != {"name", "purpose", "runtime"}:
            raise ValueError("connect requires only name, purpose, and runtime")
        return agent_connection.instructions(
            self.repo, name=document["name"], purpose=document["purpose"],
            runtime=document["runtime"])

    def check(self, document: dict[str, Any]) -> dict[str, Any]:
        if document:
            raise ValueError("check accepts an empty JSON object")
        if not self._check_lock.acquire(blocking=False):
            raise RuntimeError("a check is already running for this repository")
        try:
            _, result = ready_module.run_check(self.repo)
            return result
        finally:
            self._check_lock.release()


def _handler(service: ReadyService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AdmissibleReady/0.8"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

        def _headers(self, status: int, content_type: str,
                     length: int, *, api: bool = True) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store" if api else "no-cache")
            self.send_header("Content-Security-Policy", _CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.end_headers()

        def _json(self, status: int, document: dict[str, Any]) -> None:
            body = (json.dumps(document, separators=(",", ":"),
                               sort_keys=True, ensure_ascii=True)
                    + "\n").encode("utf-8")
            self._headers(status, "application/json; charset=utf-8", len(body))
            self.wfile.write(body)

        def _error(self, status: int, message: str) -> None:
            self._json(status, {"message": message, "status": status})

        def _local_authority(self) -> tuple[str, int] | None:
            raw = self.headers.get("Host") or ""
            try:
                parsed = urlparse("//" + raw)
                hostname = (parsed.hostname or "").lower()
                port = parsed.port
            except ValueError:
                return None
            bound_port = int(getattr(self.server, "server_port"))
            if hostname not in ("127.0.0.1", "localhost", "::1"):
                return None
            if port is None:
                port = 80
            return (hostname, port) if port == bound_port else None

        def _same_site(self) -> bool:
            authority = self._local_authority()
            if authority is None:
                return False
            origin = self.headers.get("Origin")
            if not origin:
                return self.headers.get("X-Admissible-Ready") == "1"
            try:
                parsed = urlparse(origin)
                origin_authority = ((parsed.hostname or "").lower(),
                                    parsed.port or 80)
            except ValueError:
                return False
            return parsed.scheme == "http" and origin_authority == authority

        def _body(self) -> dict[str, Any] | None:
            content_type = self.headers.get("Content-Type", "")
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                            "Content-Type must be application/json")
                return None
            raw_length = self.headers.get("Content-Length")
            try:
                length = int(raw_length or "")
            except ValueError:
                self._error(HTTPStatus.LENGTH_REQUIRED,
                            "Content-Length is required")
                return None
            if length < 2 or length > _MAX_BODY:
                self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                            "request body is outside the allowed size")
                return None
            body = self.rfile.read(length)
            try:
                document = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._error(HTTPStatus.BAD_REQUEST, "body must be valid JSON")
                return None
            if type(document) is not dict:
                self._error(HTTPStatus.BAD_REQUEST, "body must be a JSON object")
                return None
            return document

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self._local_authority() is None:
                self._error(HTTPStatus.FORBIDDEN,
                            "Ready requests require the local server authority")
                return
            path = urlparse(self.path).path
            if path == "/api/v1/state" and not self._same_site():
                self._error(HTTPStatus.FORBIDDEN,
                            "cross-origin Ready requests are not allowed")
                return
            if path == "/api/v1/state":
                self._json(HTTPStatus.OK, service.state())
                return
            if path == "/api/v1/agents":
                self._json(HTTPStatus.OK, service.agents())
                return
            asset = _ASSETS.get(path)
            if asset is None:
                self._error(HTTPStatus.NOT_FOUND, "not found")
                return
            name, content_type = asset
            try:
                body = resources.files(_STATIC_PACKAGE).joinpath(
                    name).read_bytes()
            except (FileNotFoundError, OSError):
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR,
                            "Ready assets are not installed")
                return
            self._headers(HTTPStatus.OK, content_type, len(body), api=False)
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if not self._same_site():
                self._error(HTTPStatus.FORBIDDEN,
                            "cross-origin Ready requests are not allowed")
                return
            path = urlparse(self.path).path
            if path not in ("/api/v1/check", "/api/v1/connect"):
                self._error(HTTPStatus.NOT_FOUND, "not found")
                return
            document = self._body()
            if document is None:
                return
            try:
                if path == "/api/v1/check":
                    result = service.check(document)
                else:
                    result = service.connect(document)
            except (ValueError, agent_connection.ConnectionError) as error:
                self._error(HTTPStatus.BAD_REQUEST, str(error))
                return
            except RuntimeError as error:
                self._error(HTTPStatus.CONFLICT, str(error))
                return
            self._json(HTTPStatus.OK, result)

        def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._error(HTTPStatus.METHOD_NOT_ALLOWED,
                        "cross-origin preflight is not supported")

    return Handler


def make_server(repo: str, *, host: str = "127.0.0.1",
                port: int = 8765) -> ThreadingHTTPServer:
    """Create, but do not start, one repository-bound Ready server.

    The credential check is first, before the address is validated and long
    before a socket is bound: this service can start candidate-owned checks
    through ``POST /api/v1/check``, so a process holding an admission, review
    or observer credential must not get as far as listening.
    """

    present = runner_module.present_signing_credentials()
    if present:
        raise ValueError(
            "this process contains a signing credential ("
            + ", ".join(present)
            + "). The Ready UI can run candidate checks, so it will not "
              "start; keep trusted credentials in their separate domains")
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError("Ready may bind only to a loopback address")
    if type(port) is not int or type(port) is bool or not 0 <= port <= 65535:
        raise ValueError("port must be an integer from 0 through 65535")
    service = ReadyService(repo)
    server = ThreadingHTTPServer((host, port), _handler(service))
    server.daemon_threads = True
    server.service = service  # type: ignore[attr-defined]
    return server
