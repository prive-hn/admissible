"""Contract: Ready refuses beside a credential, before any side effect.

The rule this suite enforces is not "Ready reports an error". It is that the
refusal happens *before* the process has done anything: before it reads the
repository, before it opens the store, before it writes a file, before it binds
a socket, and before it starts a child. A guard that refuses after the first
`git rev-parse` has already started a subprocess in a process that holds a
signing key, and the boundary the key was protecting is a boundary about
processes.

So every case below installs traps in the four places a side effect could
happen and asserts that none of them fired:

* :func:`subprocess.Popen` and :func:`subprocess.run` -- the runner's child, and
  the git adapter's;
* :func:`sqlite3.connect` -- the durable home;
* :meth:`socket.socket.bind` -- the loopback server;
* :func:`os.open` -- every owner-only write this distribution makes, including
  the scaffolded policy, the preview artefact, the private check logs and the
  MCP session file.

The matrix is a real product: **every** name in the closed credential list
against **every** candidate-capable entry point. A guard that was added to
``run`` and forgotten on ``connect`` is exactly the shape this catches, and
listing the entry points here rather than deriving them from the ones that
happen to have a guard is what makes the omission visible.

Both values are exercised. A credential with material in it is the obvious
case; a credential that is *set and empty* is the one that matters, because the
name being present means something arranged for a signing identity to be in
this process, and the value can change under a long-lived MCP or UI process
while the arrangement does not.

``--help`` is the documented exception, and it is asserted as one: it names
commands and variables, reads nothing about this machine, and starts nothing.
A ``--help`` that refused would be a ``--help`` nobody could use to find out
why.

:class:`RunnerRefusesFirst` covers the layer underneath all of that.
``admissible_ready.runner.run_check`` is public: it is exported by name, it is
what starts a candidate's command, and a caller reaches it directly without
passing any of the guards above. So it is not enough that every *caller* in
this distribution refuses first -- the callable that starts the child has to
refuse for itself, and it has to refuse *before* it does anything at all. That
"anything" is asserted rather than assumed: the clocks, the digest, the log
name, the filesystem and the child are each trapped, and every argument the
function validates is passed in deliberately broken, so a guard placed one line
too late reports the broken argument instead of the credential and the test
says which.
"""
from __future__ import annotations

import io
import os
import shutil
import sqlite3
import subprocess
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from admissible_core.config import Check

from admissible_ready import agent_mcp
from admissible_ready import cli as ready_cli
from admissible_ready import ready as ready_state
from admissible_ready import ready_server
from admissible_ready import runner as runner_module

CREDENTIALS = runner_module.SIGNING_CREDENTIAL_NAMES

# Both shapes: material, and merely present. The second is the one a value-only
# guard would let through.
VALUES = {"with material": "not-a-real-key", "present but empty": ""}


class TrapFired(AssertionError):
    """A side effect happened in a process that should have refused first."""


class SideEffectTraps:
    """Every way this distribution could touch the world, wired to fail.

    Patched at the module the callee resolves at call time -- ``subprocess.run``
    rather than a bound copy -- so a lazily imported helper is covered too.
    """

    def __init__(self) -> None:
        self.fired: list[str] = []
        self._patches: list = []

    def _trap(self, label: str):
        def fail(*args, **kwargs):
            self.fired.append(f"{label}{args[:1]}")
            raise TrapFired(
                f"{label} was reached in a credential-bearing process")
        return fail

    def __enter__(self) -> "SideEffectTraps":
        for target in ("subprocess.Popen", "subprocess.run",
                       "sqlite3.connect", "socket.socket.bind", "os.open"):
            patch = mock.patch(target, self._trap(target))
            patch.start()
            self._patches.append(patch)
        return self

    def __exit__(self, *exception) -> bool:
        for patch in reversed(self._patches):
            patch.stop()
        return False

    def assert_quiet(self, case: unittest.TestCase, where: str) -> None:
        case.assertEqual([], self.fired, f"{where} had a side effect")


class CredentialCase(unittest.TestCase):
    """A repository and a home neither of which any case here may touch."""

    def setUp(self) -> None:
        self.repo = Path(self.scratch("credential-repo-"))
        self.home = Path(self.scratch("credential-home-"))
        # A real repository is not needed: nothing here may get as far as
        # reading one. Creating the directory proves the refusal is not simply
        # "there is no repository".
        (self.repo / ".admissible.json").write_text("{}\n", encoding="utf-8")
        patch = mock.patch.dict(
            os.environ, {"ADMISSIBLE_HOME": str(self.home)}, clear=False)
        patch.start()
        self.addCleanup(patch.stop)
        for name in CREDENTIALS:
            os.environ.pop(name, None)

    def scratch(self, prefix: str) -> str:
        raw = tempfile.mkdtemp(prefix=prefix)
        self.addCleanup(shutil.rmtree, raw, True)
        return raw

    def with_credential(self, name: str, value: str):
        return mock.patch.dict(os.environ, {name: value}, clear=False)


# -- the entry points ---------------------------------------------------------
#
# Written out rather than derived. Deriving them from "the callables that have a
# guard" would make the matrix pass by construction, and the failure this suite
# exists to catch is an entry point somebody forgot to guard.
def _run_cli(case: CredentialCase, argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = ready_cli.main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _cli_run(case: CredentialCase):
    return _run_cli(case, ["run", "--preview", "--repo", str(case.repo),
                           "--json"])


def _cli_check(case: CredentialCase):
    return _run_cli(case, ["check", "--repo", str(case.repo), "--json"])


def _cli_init(case: CredentialCase):
    return _run_cli(case, ["init", "--repo", str(case.repo), "--profile",
                           "python-library", "--json"])


def _cli_mcp(case: CredentialCase):
    return _run_cli(case, ["mcp", "--repo", str(case.repo), "--agent-name",
                           "a", "--purpose", "b", "--runtime", "local"])


def _cli_connect(case: CredentialCase):
    return _run_cli(case, ["connect", "--repo", str(case.repo), "--name", "a",
                           "--purpose", "b", "--runtime", "local", "--json"])


def _cli_ui(case: CredentialCase):
    return _run_cli(case, ["ui", "--repo", str(case.repo), "--no-open"])


def _server_direct(case: CredentialCase):
    try:
        ready_server.make_server(str(case.repo), port=0)
    except ValueError as error:
        return 2, "", str(error)
    raise AssertionError("make_server returned beside a credential")


def _mcp_direct(case: CredentialCase):
    try:
        agent_mcp.Server(repo=str(case.repo), agent_name="a", purpose="b",
                         runtime="local")
    except ValueError as error:
        return 2, "", str(error)
    raise AssertionError("Server was constructed beside a credential")


def _library_run_check(case: CredentialCase):
    import json

    code, document = ready_state.run_check(str(case.repo))
    return code, json.dumps(document), ""


ENTRY_POINTS = {
    "cli run --preview": _cli_run,
    "cli check": _cli_check,
    "cli init": _cli_init,
    "cli mcp": _cli_mcp,
    "cli connect": _cli_connect,
    "cli ui": _cli_ui,
    "server direct": _server_direct,
    "MCP direct": _mcp_direct,
    "library run_check": _library_run_check,
}


class CredentialMatrix(CredentialCase):
    """Every credential, against every candidate-capable entry point."""

    def test_every_entry_point_refuses_every_credential_without_side_effects(self):
        for name in CREDENTIALS:
            for shape, value in VALUES.items():
                for where, call in ENTRY_POINTS.items():
                    with self.subTest(variable=name, shape=shape, entry=where):
                        with self.with_credential(name, value):
                            with SideEffectTraps() as traps:
                                code, out, err = call(self)
                            traps.assert_quiet(self, where)
                        self.assertEqual(
                            2, code,
                            f"{where} did not refuse with exit 2: {out}{err}")
                        self.assertTrue(
                            name in out or name in err,
                            f"{where} refused without naming {name}")

    def test_the_matrix_covers_every_credential_the_product_documents(self):
        """The closed list is the whole list, and it is what is exercised."""
        self.assertEqual(
            sorted((
                "ADMISSIBLE_EVALUATION_KEY",
                "ADMISSIBLE_EVALUATION_KEYRING",
                "ADMISSIBLE_EVALUATION_KEY_FILE",
                "ADMISSIBLE_EVALUATION_KEY_ID",
                "ADMISSIBLE_HMAC_KEY",
                "ADMISSIBLE_HMAC_KEY_FILE",
                "ADMISSIBLE_HMAC_KEY_ID",
                "ADMISSIBLE_REVIEW_KEY",
                "ADMISSIBLE_REVIEW_KEYRING",
                "ADMISSIBLE_REVIEW_KEY_FILE",
                "ADMISSIBLE_REVIEW_KEY_ID",
            )),
            sorted(CREDENTIALS))

    def test_the_matrix_covers_every_command_this_cli_dispatches(self):
        """No command escapes the matrix by being added and not listed here.

        ``profiles`` is the one command that reads nothing about this machine
        -- it prints the shipped profile documents -- so it is named as an
        exception rather than omitted silently.
        """
        covered = {name.partition(" ")[2].partition(" ")[0]
                   for name in ENTRY_POINTS if name.startswith("cli ")}
        self.assertEqual(
            sorted(set(ready_cli._COMMANDS) - {"profiles"}),
            sorted(covered))


class TrapsAreLoadBearing(CredentialCase):
    """The control: without a credential, the traps really do fire.

    A trap that never fires would make every assertion above vacuous -- the
    matrix would pass just as well against an entry point that does nothing.
    """

    def test_a_clean_check_reaches_the_git_adapter(self):
        with SideEffectTraps() as traps:
            with self.assertRaises(TrapFired):
                _cli_check(self)
        self.assertTrue(any("subprocess.run" in item for item in traps.fired))

    def test_a_clean_server_construction_reaches_the_socket(self):
        with SideEffectTraps() as traps:
            with self.assertRaises(TrapFired):
                ready_server.make_server(str(self.repo), port=0)
        self.assertTrue(any("socket" in item for item in traps.fired))

    def test_a_clean_mcp_construction_does_not_refuse(self):
        server = agent_mcp.Server(repo=str(self.repo), agent_name="a",
                                  purpose="b", runtime="local")
        self.assertEqual("local", server.runtime)


class MetadataStillAnswers(CredentialCase):
    """Help and the shipped profiles are metadata, and are answered anyway.

    Both read the installation rather than the machine: ``--help`` prints a
    fixed string, and ``profiles`` prints documents shipped inside the kernel.
    Neither starts a process, opens a store, writes a file or binds a socket,
    so refusing them would cost a user the one output that explains the
    refusal they just got.
    """

    def test_help_answers_beside_every_credential(self):
        for name in CREDENTIALS:
            with self.subTest(variable=name):
                with self.with_credential(name, "material"):
                    with SideEffectTraps() as traps:
                        code, out, _ = _run_cli(self, ["--help"])
                    traps.assert_quiet(self, "--help")
                self.assertEqual(0, code)
                self.assertIn("admissible-ready", out)

    def test_help_says_which_variables_it_refuses_to_run_beside(self):
        _, out, _ = _run_cli(self, ["--help"])
        for name in ("ADMISSIBLE_HMAC_KEY", "ADMISSIBLE_REVIEW_KEY",
                     "ADMISSIBLE_EVALUATION_KEY"):
            with self.subTest(variable=name):
                self.assertIn(name, out)

    def test_profiles_answers_beside_a_credential_and_touches_nothing(self):
        with self.with_credential("ADMISSIBLE_HMAC_KEY", "material"):
            with SideEffectTraps() as traps:
                code, out, _ = _run_cli(self, ["profiles", "--json"])
            traps.assert_quiet(self, "profiles")
        self.assertEqual(0, code)
        self.assertIn("python-library", out)

    def test_a_static_asset_read_is_pure_package_data(self):
        """The browser assets are files in the wheel; serving one starts nothing.

        The credential guard is on ``make_server``, so no request is ever
        handled in a credential-bearing process. This asserts the other half:
        the asset read itself is a package-resource read with no machine state
        in it.
        """
        from importlib import resources

        for name in ("index.html", "ready.css", "ready.js"):
            with self.subTest(asset=name):
                with self.with_credential("ADMISSIBLE_HMAC_KEY", "material"):
                    body = resources.files(
                        "admissible_ready.ready_static").joinpath(
                            name).read_bytes()
                self.assertTrue(body)


class RefusalWording(CredentialCase):
    """The refusal names what is wrong and what to do, in every shape."""

    def test_the_json_refusal_is_a_blocked_envelope(self):
        import json

        with self.with_credential("ADMISSIBLE_HMAC_KEY", "material"):
            code, out, _ = _cli_run(self)
        document = json.loads(out)
        self.assertEqual(2, code)
        self.assertEqual("BLOCKED", document["state"])
        self.assertEqual("NOT_READY", document["readiness"])
        self.assertIn("ADMISSIBLE_HMAC_KEY", document["message"])
        self.assertTrue(any("unset" in step for step in document["remediation"]))

    def test_the_check_refusal_is_an_unsigned_ready_document(self):
        import json

        with self.with_credential("ADMISSIBLE_REVIEW_KEYRING", "material"):
            code, out, _ = _cli_check(self)
        document = json.loads(out)
        self.assertEqual(2, code)
        self.assertEqual(ready_state.READY_SCHEMA, document["schema"])
        self.assertEqual("unable_to_check", document["status"])
        self.assertEqual("signing_credential_present",
                         document["reasons"][0]["code"])

    def test_several_credentials_at_once_are_all_named(self):
        with self.with_credential("ADMISSIBLE_HMAC_KEY", "a"):
            with self.with_credential("ADMISSIBLE_REVIEW_KEY", "b"):
                _, out, _ = _cli_run(self)
        self.assertIn("ADMISSIBLE_HMAC_KEY", out)
        self.assertIn("ADMISSIBLE_REVIEW_KEY", out)


class PresenceIsWiderThanMaterial(CredentialCase):
    """The two credential predicates, and why the guard uses the wider one."""

    def test_material_is_a_subset_of_presence(self):
        environment = {"ADMISSIBLE_HMAC_KEY": "", "ADMISSIBLE_REVIEW_KEY": "x",
                       "ADMISSIBLE_EVALUATION_KEY": "   "}
        self.assertEqual(("ADMISSIBLE_REVIEW_KEY",),
                         runner_module.ambient_signing_credentials(environment))
        self.assertEqual(
            ("ADMISSIBLE_HMAC_KEY", "ADMISSIBLE_REVIEW_KEY",
             "ADMISSIBLE_EVALUATION_KEY"),
            runner_module.present_signing_credentials(environment))

    def test_both_report_in_the_declared_order(self):
        environment = {name: "x" for name in reversed(CREDENTIALS)}
        self.assertEqual(
            list(CREDENTIALS),
            list(runner_module.present_signing_credentials(environment)))

    def test_an_unrelated_variable_is_not_a_credential(self):
        environment = {"ADMISSIBLE_HOME": "/tmp", "ADMISSIBLE_ISOLATION": "none",
                       "GITHUB_TOKEN": "x"}
        self.assertEqual(
            (), runner_module.present_signing_credentials(environment))


# -- the runner itself --------------------------------------------------------
class RunnerTraps:
    """Everything ``run_check`` does, in order, wired to fail when touched.

    The world-facing traps come from :class:`SideEffectTraps` unchanged. What
    is added here is the part of ``run_check`` that happens *before* the world
    is touched and would therefore go unnoticed by them: the two clocks, the
    argv digest, the hashing, the ``Path`` the log name is built against and
    the private log write. Reading a clock beside a signing key is not a
    breach; being the kind of function that reads one before deciding whether
    it is allowed to run is, because the next line does start a process.

    Each patch replaces the *module global* ``run_check`` resolves at call
    time, so a trap covers the real call site rather than a copy of it.
    """

    _MODULE_TRAPS = ("time", "hashlib", "argv_digest", "Path",
                     "_write_private_log")

    def __init__(self) -> None:
        self.fired: list[str] = []
        self._world = SideEffectTraps()
        self._patches: list = []

    def _callable(self, label: str):
        def fail(*args, **kwargs):
            self.fired.append(label)
            raise TrapFired(f"{label} was reached beside a credential")
        return fail

    def __enter__(self) -> "RunnerTraps":
        self._world.__enter__()
        self.fired = self._world.fired
        for name in self._MODULE_TRAPS:
            replacement = (_TrapNamespace(f"runner.{name}", self.fired)
                           if name in ("time", "hashlib")
                           else self._callable(f"runner.{name}"))
            patch = mock.patch.object(runner_module, name, replacement)
            patch.start()
            self._patches.append(patch)
        return self

    def __exit__(self, *exception) -> bool:
        for patch in reversed(self._patches):
            patch.stop()
        self._world.__exit__(*exception)
        return False

    def assert_quiet(self, case: unittest.TestCase, where: str) -> None:
        case.assertEqual([], self.fired, f"{where} had a side effect")


class _TrapNamespace:
    """A stand-in module whose every attribute is a trap.

    Used for ``time`` and ``hashlib`` so that a new clock read or a new digest
    added to ``run_check`` is caught as well, without this test having to be
    told which function name was chosen.
    """

    def __init__(self, label: str, fired: list[str]) -> None:
        self._label = label
        self._fired = fired

    def __getattr__(self, attribute: str):
        def fail(*args, **kwargs):
            self._fired.append(f"{self._label}.{attribute}")
            raise TrapFired(
                f"{self._label}.{attribute} was reached beside a credential")
        return fail


class RunnerRefusesFirst(CredentialCase):
    """``runner.run_check`` refuses beside a credential before anything else.

    Every call below passes arguments that are *also* invalid -- an unparsed
    check, a non-positive output bound, a working directory that does not
    exist. That is the point: those are the refusals ``run_check`` already had,
    and they run early. If the credential guard is anywhere but first, the
    caller is told about the argument instead, and a message about the wrong
    problem is how a missing boundary stays missing.
    """

    def broken_arguments(self) -> dict:
        return {
            "cwd": self.repo / "no-such-directory",
            "log_dir": self.repo / "no-such-log-directory",
            "max_output_bytes": 0,
        }

    def valid_check(self):
        return Check(id="ok", argv=("true",), timeout_seconds=5, cost_units=1,
                     required=True, version="1")

    def test_every_credential_refuses_before_any_argument_is_judged(self):
        for name in CREDENTIALS:
            for shape, value in VALUES.items():
                with self.subTest(variable=name, shape=shape):
                    with self.with_credential(name, value):
                        with RunnerTraps() as traps:
                            with self.assertRaises(
                                    runner_module.RunnerError) as caught:
                                runner_module.run_check(
                                    "not a parsed check",
                                    **self.broken_arguments())
                        traps.assert_quiet(self, "runner.run_check")
                    message = str(caught.exception)
                    self.assertIn(name, message)
                    self.assertNotIn("needs a parsed Check", message)
                    self.assertNotIn("max_output_bytes", message)

    def test_a_valid_check_is_refused_the_same_way(self):
        """Nothing about the refusal depends on the arguments being broken."""
        for name in CREDENTIALS:
            with self.subTest(variable=name):
                with self.with_credential(name, "material"):
                    with RunnerTraps() as traps:
                        with self.assertRaises(
                                runner_module.RunnerError) as caught:
                            runner_module.run_check(
                                self.valid_check(), cwd=self.repo,
                                log_dir=self.repo / "logs")
                    traps.assert_quiet(self, "runner.run_check")
                self.assertIn(name, str(caught.exception))

    def test_the_refusal_names_every_credential_and_says_what_to_do(self):
        with self.with_credential("ADMISSIBLE_HMAC_KEY", "a"):
            with self.with_credential("ADMISSIBLE_REVIEW_KEYRING", ""):
                with self.assertRaises(runner_module.RunnerError) as caught:
                    runner_module.run_check(self.valid_check(), cwd=self.repo)
        message = str(caught.exception)
        self.assertIn("ADMISSIBLE_HMAC_KEY", message)
        self.assertIn("ADMISSIBLE_REVIEW_KEYRING", message)
        self.assertIn("unset", message.lower())
        self.assertIn("separate trusted domain", message)

    def test_the_refusal_is_the_runner_s_own_error_type(self):
        """A caller that already handles ``RunnerError`` handles this too."""
        with self.with_credential("ADMISSIBLE_EVALUATION_KEY", "material"):
            with self.assertRaises(runner_module.RunnerError):
                runner_module.run_check(self.valid_check(), cwd=self.repo)

    def test_without_a_credential_the_first_trap_is_reached(self):
        """The control: the traps are load-bearing, not decorative.

        Without this, every assertion above would pass just as well against a
        ``run_check`` that had been broken into doing nothing at all.
        """
        with RunnerTraps() as traps:
            with self.assertRaises(TrapFired):
                runner_module.run_check(self.valid_check(), cwd=self.repo,
                                        log_dir=self.repo / "logs")
        self.assertTrue(traps.fired, "no trap fired without a credential")

    def test_without_a_credential_the_argument_refusals_still_stand(self):
        """The guard was inserted, not substituted for what was already there."""
        with self.assertRaises(runner_module.RunnerError) as unparsed:
            runner_module.run_check("not a parsed check", cwd=self.repo)
        self.assertIn("needs a parsed Check", str(unparsed.exception))
        with self.assertRaises(runner_module.RunnerError) as bound:
            runner_module.run_check(self.valid_check(), cwd=self.repo,
                                    max_output_bytes=0)
        self.assertIn("max_output_bytes", str(bound.exception))

    def test_without_a_credential_a_real_check_still_runs(self):
        """The higher-level behaviour this guard sits under is unchanged."""
        result = runner_module.run_check(
            Check(id="ok", argv=("python3", "-c", "print('hi')"),
                  timeout_seconds=30, cost_units=1, required=True,
                  version="1"),
            cwd=self.repo)
        self.assertEqual(0, result.exit_code)
        self.assertFalse(result.launch_failed)
