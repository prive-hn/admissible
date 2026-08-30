"""Reference cockpit server tests — TDD RED."""
from __future__ import annotations

import dataclasses
import io
import json
import socket
import sys
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from server import app
from server.app import (MAX_BODY_BYTES, CockpitEngine, Handler,
                        allowed_hosts_for, make_server)
from server.execution import DemoExecutionAdapter, ExecutionResult


REPO = Path(__file__).resolve().parents[1]
PROJECT = {"id": "adapter-test", "name": "Adapter test", "local_path": str(REPO),
           "github": "prive-hn/admissible", "base_branch": "main"}


class WrongReviewerExecutionAdapter(DemoExecutionAdapter):
    def run(self, request):
        result = super().run(request)
        if request.specialist != "reviewer":
            return result
        return ExecutionResult(
            receipt=dataclasses.replace(result.receipt, executed_provider="other", executed_model="reviewer"),
            artifact=result.artifact, evidence=result.evidence, question=result.question,
        )


class CockpitEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = CockpitEngine(seed=True)

    def test_state_has_three_pane_data_and_real_seeded_evidence(self):
        s = self.engine.state()
        self.assertEqual(s["connection"], "live")
        self.assertIn("atlas", s)
        self.assertGreaterEqual(len(s["workItems"]), 2)
        self.assertTrue(any(w["status"] == "accepted" for w in s["workItems"]))
        failed = next(w for w in s["workItems"] if w["status"] == "failed")
        failure = next(st["failure"] for st in failed["stages"] if st.get("failure"))
        self.assertTrue(failure["impact"]["observed"])
        self.assertTrue(failure["impact"]["reachable"])
        self.assertTrue(failure["impact"]["unknown"])

    def test_prompt_compiles_visible_contract_and_question(self):
        r = self.engine.create_work_item("Add export controls to the report")
        self.assertIn("contract", r)
        self.assertEqual(r["workItem"]["contract"]["summary"], "Add export controls to the report")
        self.assertIsNotNone(r["workItem"]["openQuestionId"])
        self.assertEqual(r["workItem"]["stages"][0]["pc"], "Open")

    def test_answer_resumes_and_produces_runnable_candidate_artifact(self):
        r = self.engine.create_work_item("Create a customer status panel")
        qid = r["workItem"]["openQuestionId"]
        self.engine.answer_question(qid, "Show status, evidence, and next action")
        s = self.engine.state()
        item = next(w for w in s["workItems"] if w["id"] == r["workItem"]["id"])
        self.assertEqual(item["stages"][0]["pc"], "Passed")
        self.assertEqual(item["stages"][1]["pc"], "Open")
        artifact = self.engine.artifacts[item["id"]]
        self.assertIn("<html", artifact["srcDoc"])
        self.assertEqual(artifact["state"], "candidate")

    def test_steer_is_explicit_event_and_does_not_accept(self):
        r = self.engine.create_work_item("Add filter")
        iid = r["workItem"]["id"]
        self.engine.steer(iid, f"{iid}.0", "Keep keyboard navigation")
        self.assertEqual(self.engine.interactions[-1]["type"], "steer")
        self.assertNotIn(iid, self.engine.enforcer.store)

    def test_accept_before_machine_passes_is_refused(self):
        r = self.engine.create_work_item("Add filter")
        with self.assertRaises(ValueError):
            self.engine.action(r["workItem"]["id"], f"{r['workItem']['id']}.0", "/accept")

    def test_retry_after_answer_runs_review_and_accepts(self):
        r = self.engine.create_work_item("Add filter")
        iid = r["workItem"]["id"]
        self.engine.answer_question(r["workItem"]["openQuestionId"], "Use existing semantics")
        self.engine.action(iid, f"{iid}.1", "/retry")
        self.assertIn(iid, self.engine.enforcer.store)
        self.assertEqual(self.engine.artifacts[iid]["state"], "accepted")

    def test_reviewer_observation_comes_from_adapter_and_mismatch_refuses_accept(self):
        engine = CockpitEngine(seed=False, execution=WrongReviewerExecutionAdapter())
        engine.load_project(PROJECT)
        r = engine.create_work_item("Review must report what actually ran")
        iid = r["workItem"]["id"]
        engine.answer_question(r["workItem"]["openQuestionId"], "Proceed")
        engine.action(iid, f"{iid}.1", "/retry")
        self.assertNotIn(iid, engine.enforcer.store)
        check = engine.enforcer.items[iid].stages[1]
        self.assertEqual(check.m_exec, "other:reviewer")
        self.assertEqual((check.pc, check.fault), ("Closed", "F1"))

    def test_discard_is_explicit_and_never_adds_store(self):
        r = self.engine.create_work_item("Throwaway experiment")
        iid = r["workItem"]["id"]
        self.engine.action(iid, f"{iid}.0", "/discard")
        self.assertNotIn(iid, self.engine.enforcer.store)
        self.assertEqual(self.engine.meta[iid]["status_override"], "failed")


class ServerAddressFamilyTests(unittest.TestCase):
    @unittest.skipUnless(socket.has_ipv6, "IPv6 is unavailable on this host")
    def test_make_server_binds_an_ipv6_literal_with_an_ipv6_socket(self):
        httpd = make_server("::1", 0, CockpitEngine(seed=True))
        try:
            self.assertEqual(httpd.address_family, socket.AF_INET6)
            self.assertEqual(httpd.server_address[0], "::1")
        finally:
            httpd.server_close()


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = CockpitEngine(seed=True)
        cls.httpd = make_server("127.0.0.1", 0, cls.engine)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.thread.join(timeout=2)
        cls.httpd.server_close()

    def request(self, path: str, method="GET", body=None):
        data = None if body is None else json.dumps(body).encode()
        req = Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
                      headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=2) as res:
            return res.status, json.loads(res.read())

    def test_get_state(self):
        status, body = self.request("/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(body["connection"], "live")

    def test_post_work_item_and_steer(self):
        status, body = self.request("/api/work-items", "POST", {"prompt": "Build a compact settings view", "contract": {"client": "visible"}})
        self.assertEqual(status, 201)
        iid = body["id"]
        self.assertEqual(iid, body["workItem"]["id"])
        status, ev = self.request(f"/api/work-items/{iid}/steer", "POST",
                                  {"nodeId": f"{iid}.0", "command": "impact", "text": "/impact"})
        self.assertEqual(status, 200)
        self.assertEqual(ev["event"]["type"], "steer")


def _handler_for(host: str, allow_hosts: tuple[str, ...] = ()):
    """A Handler carrying the host set `make_server` would give this address.

    Built without binding: `allowed_hosts_for` is the decision under test, and
    a listening socket is not part of it. Binding 0.0.0.0 merely to read back
    a class would open every interface for the length of a unit test.
    """
    return type("ProbeHandler", (Handler,),
                {"allowed_hosts": allowed_hosts_for(host, allow_hosts)})


def _same_site(handler_cls, **headers) -> bool:
    """`_same_site` for one set of request headers, with no socket involved.

    `headers` is a plain dict, which a real request's is not: `email.message.
    Message.get` is case-insensitive and keeps duplicates. Both differences
    fail *closed* here, so a negative result from this helper is weaker
    evidence than it looks -- a misspelled header name would also return
    False. `SameSiteOverHttpTests` serves the real thing for that reason.
    """
    probe = handler_cls.__new__(handler_cls)
    probe.headers = headers
    return handler_cls._same_site(probe)


class SameSiteTests(unittest.TestCase):
    """Which Host and Origin pairs count as this server's own page.

    Binding to 0.0.0.0 used to accept every Host header, on the reasoning that
    requiring Origin to equal Host still refused cross-site writes. It does not:
    a DNS-rebinding page is served from the attacker's own name, so it sets both
    headers to that name and they agree.
    """

    def test_rebinding_name_is_refused_when_bound_to_every_interface(self):
        handler = _handler_for("0.0.0.0")
        self.assertFalse(_same_site(
            handler, Host="evil.com:8791", Origin="http://evil.com:8791"))

    def test_address_literal_is_accepted_when_bound_to_every_interface(self):
        handler = _handler_for("0.0.0.0")
        self.assertTrue(_same_site(
            handler, Host="192.168.1.50:8791", Origin="http://192.168.1.50:8791"))
        self.assertTrue(_same_site(handler, Host="[::1]:8791"))

    def test_a_name_is_accepted_only_when_the_operator_allowed_it(self):
        self.assertFalse(_same_site(
            _handler_for("0.0.0.0"),
            Host="box.local:8791", Origin="http://box.local:8791"))
        self.assertTrue(_same_site(
            _handler_for("0.0.0.0", allow_hosts=["box.local"]),
            Host="box.local:8791", Origin="http://box.local:8791"))

    def test_cross_origin_is_refused_at_an_accepted_host(self):
        handler = _handler_for("0.0.0.0")
        self.assertFalse(_same_site(
            handler, Host="192.168.1.50:8791", Origin="http://evil.com"))

    def test_absent_host_header_is_refused(self):
        self.assertFalse(_same_site(_handler_for("127.0.0.1"),
                                    Origin="http://evil.com"))
        self.assertFalse(_same_site(_handler_for("127.0.0.1")))

    def test_loopback_binding_still_serves_its_own_page(self):
        handler = _handler_for("127.0.0.1")
        self.assertTrue(_same_site(
            handler, Host="127.0.0.1:8791", Origin="http://127.0.0.1:8791"))
        self.assertTrue(_same_site(handler, Host="localhost:8791"))
        self.assertFalse(_same_site(
            handler, Host="127.0.0.1:8791", Origin="http://evil.com"))

    def test_a_malformed_host_is_refused_rather_than_raised(self):
        # `urlsplit("//[::1")` raises; unguarded it escapes `_same_site` and
        # answers the request by dropping the connection.
        self.assertFalse(_same_site(_handler_for("127.0.0.1"), Host="[::1"))

    def test_a_malformed_origin_is_refused_rather_than_raised(self):
        self.assertFalse(_same_site(
            _handler_for("127.0.0.1"), Host="127.0.0.1:8791", Origin="http://["))

    def test_an_origin_that_is_not_http_is_refused(self):
        handler = _handler_for("127.0.0.1")
        for origin in ("file://", "null", "chrome-extension://abc"):
            with self.subTest(origin=origin):
                self.assertFalse(_same_site(
                    handler, Host="127.0.0.1:8791", Origin=origin))

    def test_a_single_bound_address_does_not_accept_other_addresses(self):
        # Only the every-interface case widens to address literals. A server
        # bound to one address keeps a closed set.
        self.assertFalse(_same_site(
            _handler_for("127.0.0.1"), Host="192.168.1.50:8791"))
        self.assertTrue(_same_site(
            _handler_for("0.0.0.0"), Host="192.168.1.50:8791"))


class RequestBodyLimitTests(unittest.TestCase):
    """Content-Length is the client's claim, and it bounds what is read."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = make_server("127.0.0.1", 0, CockpitEngine(seed=True))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.thread.join(timeout=2)
        cls.httpd.server_close()

    def post(self, length: str, payload: bytes = b"{}") -> tuple[int, str]:
        """Status and the refusal `_body` gave, not the status alone.

        400 is `do_POST`'s catch-all for every ValueError, the engine's
        included, so a bare `== 400` passes whether or not the check under
        test exists: with the ceiling deleted, an over-large length falls
        through to the short-read refusal and answers 400 just the same.
        The message is what distinguishes them, so the message is asserted.
        """
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            sock.sendall(
                b"POST /api/work-items HTTP/1.1\r\n"
                + f"Host: 127.0.0.1:{self.port}\r\n".encode()
                + b"Content-Type: application/json\r\n"
                + f"Content-Length: {length}\r\n".encode()
                + b"Connection: close\r\n\r\n" + payload)
            # Half-close so a body shorter than its declared length reaches the
            # server as the end of the request rather than as a pause in it.
            sock.shutdown(socket.SHUT_WR)
            received = b""
            while True:
                block = sock.recv(4096)
                if not block:
                    break
                received += block
        finally:
            sock.close()
        head, _, body = received.partition(b"\r\n\r\n")
        status = int(head.split(b" ")[1])
        return status, json.loads(body or b"{}").get("error", "")

    def test_negative_length_is_refused_before_anything_is_read(self):
        self.assertEqual(self.post("-1", b"A" * 4096),
                         (400, "Content-Length must not be negative"))

    def test_length_beyond_the_ceiling_is_refused_before_anything_is_read(self):
        expected = f"request body is larger than the {MAX_BODY_BYTES}-byte limit"
        self.assertEqual(self.post(str(MAX_BODY_BYTES + 1)), (400, expected))
        self.assertEqual(self.post("10737418240"), (400, expected))

    def test_unparseable_length_is_refused(self):
        self.assertEqual(self.post("not-a-number"),
                         (400, "Content-Length must be an integer"))

    def test_body_shorter_than_its_length_is_refused(self):
        self.assertEqual(self.post("4096", b"{}"),
                         (400, "request body is shorter than its Content-Length"))

    def test_the_ceiling_is_one_megabyte(self):
        # The tests above are all relative to this constant, so its value has
        # to be pinned somewhere or it could be raised to no effect.
        self.assertEqual(MAX_BODY_BYTES, 1 << 20)

    def test_a_body_within_the_ceiling_is_accepted(self):
        payload = json.dumps({"prompt": "Add a compact settings view"}).encode()
        self.assertEqual(self.post(str(len(payload)), payload)[0], 201)

    def test_a_stalled_connection_is_released_by_the_socket_timeout(self):
        """A client that announces a body and then sends none is hung up on.

        The shipped expiry is 30s, too slow to wait for, so this serves the
        same handler with a short one: `StreamRequestHandler.setup` applies
        whatever `timeout` says, so the mechanism under test is identical and
        only the number differs. The shipped number is pinned below.
        """
        brief = type("Stalled", (self.httpd.RequestHandlerClass,), {"timeout": 0.3})
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), brief)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(httpd.shutdown)
        port = httpd.server_address[1]
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.addCleanup(sock.close)
        sock.sendall(b"POST /api/work-items HTTP/1.1\r\n"
                     + f"Host: 127.0.0.1:{port}\r\n".encode()
                     + b"Content-Type: application/json\r\n"
                     + b"Content-Length: 4096\r\n\r\n")   # ...and never send it
        started = time.monotonic()
        # Empty read means the server closed on us. Without a timeout this
        # blocks until the client's own 5s budget raises instead.
        self.assertEqual(sock.recv(4096), b"")
        self.assertLess(time.monotonic() - started, 5)

    def test_the_shipped_timeout_is_finite_and_short(self):
        # `assertIsNotNone` would accept a 24-hour expiry, which releases
        # nothing in practice.
        self.assertLessEqual(self.httpd.RequestHandlerClass.timeout, 60)


class SameSiteOverHttpTests(unittest.TestCase):
    """The same-site rule as a served request, not as a called function.

    `SameSiteTests` proves `_same_site` decides correctly. It cannot prove
    anything calls it: with the guard deleted from `do_GET` and `do_POST` the
    unit tests stay green while a rebound page reads state and creates work.
    So these go through the socket, and they carry the every-interface host
    set -- the configuration the bypass needed -- while still listening only
    on loopback, because a unit test should not open every interface.
    """

    @classmethod
    def setUpClass(cls) -> None:
        handler = type("AnyAddressHandler", (Handler,),
                       {"engine": CockpitEngine(seed=True),
                        "allowed_hosts": allowed_hosts_for("0.0.0.0")})
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.thread.join(timeout=2)
        cls.httpd.server_close()

    def request(self, method: str, path: str, headers, body: bytes = b"") -> bytes:
        """The raw response head. `headers` is a list, so duplicates are sayable."""
        raw = f"{method} {path} HTTP/1.1\r\n".encode()
        for name, value in headers:
            raw += f"{name}: {value}\r\n".encode()
        raw += (b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n" + body)
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            sock.sendall(raw)
            sock.shutdown(socket.SHUT_WR)
            received = b""
            while b"\r\n\r\n" not in received:
                block = sock.recv(4096)
                if not block:
                    break
                received += block
        finally:
            sock.close()
        return received.partition(b"\r\n\r\n")[0]

    def status(self, method: str, path: str, headers, body: bytes = b"") -> int:
        return int(self.request(method, path, headers, body).split(b" ")[1])

    def body(self, method: str, path: str, headers, body: bytes = b"") -> dict:
        """The decoded JSON body, for asserting on what a refusal actually says."""
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        raw = f"{method} {path} HTTP/1.1\r\n".encode()
        for name, value in headers:
            raw += f"{name}: {value}\r\n".encode()
        raw += (b"Content-Length: " + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n" + body)
        try:
            sock.sendall(raw)
            sock.shutdown(socket.SHUT_WR)
            received = b""
            while True:
                block = sock.recv(4096)
                if not block:
                    break
                received += block
        finally:
            sock.close()
        return json.loads(received.partition(b"\r\n\r\n")[2] or b"{}")

    def test_a_rebound_name_cannot_read_state(self):
        self.assertEqual(self.status(
            "GET", "/api/state",
            [("Host", "evil.com"), ("Origin", "http://evil.com")]), 403)

    def test_an_unlisted_host_is_told_which_name_was_refused(self):
        """The refusal names the host and points at `--allow-host`.

        An operator reaching their own cockpit by its machine name lands
        here, and "cross-site request" would send them hunting an attacker.
        It must not hand back a paste-able command, though: the same branch
        answers a rebound name, and that one must not be made easy to allow.
        """
        body = self.body("GET", "/api/state", [("Host", "box.local")])
        self.assertIn("box.local", body["error"])
        self.assertIn("--allow-host", body["error"])
        self.assertNotIn("--allow-host box.local", body["error"])
        # A same-named host that IS allowed is not refused at all.
        handler = _handler_for("0.0.0.0", ("box.local",))
        self.assertTrue(_same_site(handler, Host="box.local:8791"))

    def test_a_rebound_name_cannot_write(self):
        self.assertEqual(self.status(
            "POST", "/api/work-items",
            [("Host", "evil.com"), ("Origin", "http://evil.com")],
            b'{"prompt": "x"}'), 403)

    def test_the_servers_own_address_still_reads_and_writes(self):
        own = [("Host", f"127.0.0.1:{self.port}"),
               ("Origin", f"http://127.0.0.1:{self.port}")]
        self.assertEqual(self.status("GET", "/api/state", own), 200)
        self.assertEqual(self.status(
            "POST", "/api/work-items", own, b'{"prompt": "x"}'), 201)

    def test_the_host_check_reads_the_header_case_insensitively(self):
        # A real request's headers are an email.message.Message, not a dict:
        # the name's case is not part of it.
        self.assertEqual(self.status(
            "GET", "/api/state", [("hOsT", "evil.com")]), 403)
        self.assertEqual(self.status(
            "GET", "/api/state", [("hOsT", f"127.0.0.1:{self.port}")]), 200)

    def test_no_cors_header_is_echoed_to_a_foreign_origin(self):
        head = self.request("GET", "/api/state",
                            [("Host", f"127.0.0.1:{self.port}"),
                             ("Origin", "http://evil.com")])
        self.assertNotIn(b"access-control-allow-origin", head.lower())

    def test_the_pages_own_origin_is_echoed_back(self):
        origin = f"http://127.0.0.1:{self.port}"
        head = self.request("GET", "/api/state",
                            [("Host", f"127.0.0.1:{self.port}"),
                             ("Origin", origin)])
        self.assertIn(f"Access-Control-Allow-Origin: {origin}".encode(), head)


class AllowHostFlagTests(unittest.TestCase):
    """`--allow-host` has to reach the server, not just parse."""

    def test_the_flag_is_passed_through_to_the_server(self):
        argv = ["app", "--allow-host", "box.local", "--allow-host", "nas.lan"]
        with mock.patch.object(app, "make_server") as made, \
                mock.patch.object(sys, "argv", argv), \
                mock.patch.object(sys, "stdout", io.StringIO()):
            made.return_value.serve_forever.side_effect = KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                app.main()
        self.assertEqual(made.call_args.kwargs["allow_hosts"],
                         ["box.local", "nas.lan"])

    def test_a_named_host_reaches_the_allowed_set(self):
        self.assertIn("box.local", allowed_hosts_for("0.0.0.0", ["box.local"]))
        self.assertNotIn("box.local", allowed_hosts_for("0.0.0.0"))


if __name__ == "__main__":
    unittest.main()
