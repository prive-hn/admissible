"""Contract: importing Core loads no authority and no execution surface.

The census proves that Core's *source* does not name Ready or Trust.  That is
not the same claim as this one.  An import is transitive, so a Core module that
imports something innocuous which imports the runner has pulled candidate
execution into every process that touches the kernel, and no source-level rule
about Core's own file would have seen it.

So the measurements below are made in a fresh interpreter and read back from
``sys.modules``: what is actually loaded, after the import, in a process whose
only job was to perform it.  The checkout is on the path deliberately -- every
forbidden module *is* importable there -- because a probe that could not have
found the thing it reports absent proves nothing.

Two source-level claims are kept alongside, because they are about capability
rather than about load order: that *no* Core module can start a process, and
that no Core module reads a signing credential out of the environment.

Starting a process is the sharper of the two.  Core used to be allowed one
exception -- ``identity`` ran git to find out what a tree was -- and an
exception is not a capability boundary: a module that may spawn ``git`` today
is a module whose argv is one edit away from spawning whatever a policy names,
in a distribution whose whole claim is that it cannot run a candidate's
commands.  So the kernel now takes an injected reader for those six questions,
and the assertions below are unconditional: no Core module imports a
process-starting module, no Core module calls a launcher, and importing every
Core module in a fresh interpreter does not so much as load ``subprocess``.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
import unittest
from pathlib import Path

from . import CORE_SRC, REPO_ROOT

CORE_PACKAGE = CORE_SRC / "admissible_core"

# Loading any of these is Core holding the machinery to start a program. Named
# separately from the sweep below because the source-level checks use the same
# list: a module that cannot import these cannot start anything with them.
PROCESS_MODULES = (
    "subprocess",
    "multiprocessing",
    "pty",
    "_posixsubprocess",
)

# Loading any of these means Core acquired a capability it is defined by not
# having.  ``admissible`` is on the list because a Core that imports the
# monolith has re-created the monolith's dependency graph under a new name.
FORBIDDEN_MODULES = (
    "admissible",
    "admissible_ready",
    "admissible_trust",
    "server",
    "http",
    "http.server",
    "socketserver",
    "socket",
    "ssl",
    "urllib.request",
    "wsgiref",
    "asyncio",
    "mcp",
    *PROCESS_MODULES,
)

# Substrings that make an environment variable a credential.  Core may not read
# one -- and, now that it starts no process, has no reason to name one either.
CREDENTIAL_MARKERS = ("key", "token", "secret", "password", "credential",
                      "keyring")

_PROBE = """
import json, sys

before = set(sys.modules)
for name in sys.argv[2:]:
    __import__(name)
loaded = set(sys.modules) - before
print(json.dumps(sorted(loaded)))
"""


def core_files() -> dict[str, Path]:
    """Dotted module name -> source file, for every module Core ships."""
    found = {}
    for path in sorted(CORE_PACKAGE.rglob("*.py")):
        parts = list(path.relative_to(CORE_SRC).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        found[".".join(parts)] = path
    return found


def core_modules() -> tuple[str, ...]:
    return tuple(core_files())


def core_sources() -> dict[str, ast.Module]:
    return {
        name: ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for name, path in core_files().items()
    }


class CoreSourceIsPresent(unittest.TestCase):
    """The probes below are only evidence if there is something to probe."""

    def test_the_core_package_exists_with_modules_in_it(self):
        self.assertTrue(CORE_PACKAGE.is_dir(), f"{CORE_PACKAGE} is missing")
        self.assertIn("admissible_core", core_modules())
        self.assertGreater(len(core_modules()), 5)

    def test_every_forbidden_module_that_is_importable_here_really_is(self):
        """The control: absence must be a fact about Core, not about the tree."""
        available = importable_here(("admissible", "server", "http.server",
                                     "socketserver", "asyncio"))
        self.assertEqual(
            {"admissible": True, "server": True, "http.server": True,
             "socketserver": True, "asyncio": True},
            available,
        )


class ImportingCoreLoadsNothingItMustNotHave(unittest.TestCase):
    """Measured in a fresh interpreter, from ``sys.modules``."""

    def loaded_by(self, *names: str) -> set[str]:
        completed = subprocess.run(
            [sys.executable, "-c", _PROBE, "--", *names],
            capture_output=True, text=True, timeout=300,
            cwd=str(REPO_ROOT), env=probe_env(),
        )
        self.assertEqual(0, completed.returncode,
                         f"probe failed:\n{completed.stderr}")
        return set(json.loads(completed.stdout))

    def test_importing_the_package_loads_no_forbidden_module(self):
        loaded = self.loaded_by("admissible_core")
        self.assertEqual(
            [], sorted(loaded & set(FORBIDDEN_MODULES)),
            "importing admissible_core pulled in a forbidden module",
        )

    def test_importing_every_core_module_loads_no_forbidden_module(self):
        loaded = self.loaded_by(*core_modules())
        self.assertEqual([], sorted(loaded & set(FORBIDDEN_MODULES)))

    def test_importing_the_package_alone_does_not_load_subprocess(self):
        """``import admissible_core`` must not arm a process-starting path."""
        self.assertNotIn("subprocess", self.loaded_by("admissible_core"))

    def test_importing_every_core_module_loads_no_process_starting_module(self):
        """The claim with no exception left in it.

        Stated separately from the forbidden-module sweep because this is the
        one that changed: ``identity`` used to load ``subprocess`` by importing
        it, so every process that touched the kernel for any reason had the
        machinery to start a program sitting in ``sys.modules``.
        """
        loaded = self.loaded_by(*core_modules())
        self.assertEqual([], sorted(loaded & set(PROCESS_MODULES)))

    def test_importing_the_identity_module_by_itself_loads_no_subprocess(self):
        """Named on its own, because it is the module that used to fail this."""
        loaded = self.loaded_by("admissible_core.identity")
        self.assertEqual([], sorted(loaded & set(PROCESS_MODULES)))

    def test_the_probe_would_notice_a_module_that_was_loaded(self):
        """The control for the probe itself."""
        loaded = self.loaded_by("admissible_core", "http.server")
        self.assertIn("http.server", loaded)

    def test_the_probe_would_notice_subprocess_if_it_were_loaded(self):
        """The control for the claim that matters most in this file."""
        loaded = self.loaded_by("admissible_core", "subprocess")
        self.assertIn("subprocess", loaded)


def imports_of(tree: ast.Module, roots: tuple[str, ...]) -> list[str]:
    """Top-level module names this source imports out of ``roots``."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and not node.level:
            found.add((node.module or "").split(".")[0])
    return sorted(found & set(roots))


def launcher_calls(tree: ast.Module) -> list[str]:
    """Every call in this source that would start a process."""
    return sorted(
        dotted(node.func) for node in ast.walk(tree)
        if isinstance(node, ast.Call) and dotted(node.func) in LAUNCHERS
    )


# Every spelling of "start a program" that reaches an exec or a fork. Written
# out rather than matched by prefix so that the control below can prove the
# detector fires on each one.
LAUNCHERS = (
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output", "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "os.system", "os.popen",
    "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
    "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "os.posix_spawn", "os.posix_spawnp", "os.fork", "os.forkpty",
    "pty.fork", "pty.spawn",
    "multiprocessing.Process",
    "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
)


class CoreStartsNoProcessAtAll(unittest.TestCase):
    """Not "only git", and not "only in one module": none, anywhere.

    Repository identity still needs git run somewhere.  Core takes an injected
    reader for it, so the process is started by whoever supplies the adapter --
    the Ready distribution, or a test -- and the kernel keeps the part that is
    arithmetic: validating the answers and refusing what cannot be identified.
    """

    def test_no_core_module_imports_a_process_starting_module(self):
        offenders = sorted(
            f"{name}: {', '.join(imported)}"
            for name, tree in core_sources().items()
            if (imported := imports_of(tree, PROCESS_MODULES))
        )
        self.assertEqual([], offenders)

    def test_no_core_module_calls_a_process_launcher(self):
        offenders = sorted(
            f"{name}: {', '.join(calls)}"
            for name, tree in core_sources().items()
            if (calls := launcher_calls(tree))
        )
        self.assertEqual([], offenders)

    def test_the_import_detector_sees_an_import_when_there_is_one(self):
        """The control: absence must be a finding, not a broken detector."""
        for statement in ("import subprocess",
                          "import subprocess.run",
                          "from subprocess import run",
                          "import multiprocessing as mp",
                          "from pty import spawn"):
            with self.subTest(statement=statement):
                self.assertTrue(
                    imports_of(ast.parse(statement), PROCESS_MODULES),
                    f"{statement!r} was not detected",
                )

    def test_the_launcher_detector_sees_every_launcher_it_names(self):
        """The control: each spelling must actually match."""
        for launcher in LAUNCHERS:
            source = f"import os\n{launcher}('true')\n"
            with self.subTest(launcher=launcher):
                self.assertEqual([launcher], launcher_calls(ast.parse(source)))

    def test_the_identity_module_takes_its_git_reader_by_injection(self):
        """Read off the signature: a defaulted reader is a runner in the floor."""
        tree = core_sources()["admissible_core.identity"]
        functions = {node.name: node for node in tree.body
                     if isinstance(node, ast.FunctionDef)}
        self.assertIn("repository_identity", functions)
        arguments = functions["repository_identity"].args
        names = [argument.arg for argument in arguments.kwonlyargs]
        self.assertIn("git", names, "the reader must be keyword-only")
        self.assertIsNone(
            arguments.kw_defaults[names.index("git")],
            "the git reader must have no default at all",
        )

    def test_core_declares_no_command_line_entry_point(self):
        """A library with a ``main`` is a command waiting for a wrapper."""
        offenders = sorted(
            name for name, tree in core_sources().items()
            if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and node.name == "main" for node in tree.body)
            or any(isinstance(node, ast.Import)
                   and any(alias.name == "argparse" for alias in node.names)
                   for node in ast.walk(tree))
        )
        self.assertEqual([], offenders)


class CoreReadsNoCredentialFromTheEnvironment(unittest.TestCase):
    """Signing material never reaches an authority-neutral kernel."""

    READERS = ("os.environ.get", "os.getenv", "environ.get", "getenv")

    def test_no_core_module_reads_a_credential_named_variable(self):
        offenders = []
        for name, tree in core_sources().items():
            for node in ast.walk(tree):
                for read in self.reads(node):
                    if any(marker in read.lower()
                           for marker in CREDENTIAL_MARKERS):
                        offenders.append(f"{name}: {read}")
        self.assertEqual([], offenders)

    def test_the_check_sees_a_read_when_there_is_one(self):
        """The control: the AST shapes above must actually match a read."""
        tree = ast.parse(
            "import os\n"
            "a = os.environ.get('ADMISSIBLE_HMAC_KEY')\n"
            "b = os.environ['ADMISSIBLE_REVIEW_KEY']\n"
            "c = os.getenv('ADMISSIBLE_EVALUATION_KEY')\n"
        )
        found = sorted(
            read for node in ast.walk(tree) for read in self.reads(node)
        )
        self.assertEqual(
            ["ADMISSIBLE_EVALUATION_KEY", "ADMISSIBLE_HMAC_KEY",
             "ADMISSIBLE_REVIEW_KEY"],
            found,
        )

    def test_the_identity_module_reads_no_environment_variable_at_all(self):
        """Stripping a credential was the old defence; not having one is better.

        ``identity`` used to build the environment for a git subprocess, which
        meant naming every signing variable in order to remove it -- correct,
        and one forgotten name away from leaking a key into a process the
        kernel started.  It now starts no process, so it composes no
        environment, so there is nothing to forget.  That obligation moved to
        whoever supplies the adapter, and the adapter's own tests assert it.
        """
        tree = core_sources()["admissible_core.identity"]
        touches = sorted(
            reference for node in ast.walk(tree)
            if (reference := dotted(node)) in ("os.environ", "os.getenv",
                                               "os.environb")
        )
        self.assertEqual([], touches)
        self.assertEqual([], imports_of(tree, ("os",)))

    def reads(self, node: ast.AST) -> list[str]:
        """Every environment-variable name this node reads outright."""
        if isinstance(node, ast.Subscript):
            if dotted(node.value) in ("os.environ", "environ"):
                return [literal(node.slice)] if literal(node.slice) else []
            return []
        if isinstance(node, ast.Call) and dotted(node.func) in self.READERS:
            name = literal(node.args[0]) if node.args else None
            return [name] if name else []
        return []


def dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def probe_env() -> dict[str, str]:
    """The checkout on the path, and nothing inherited that could confuse it."""
    import os

    environment = {
        key: value for key, value in os.environ.items()
        if key not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")
    }
    environment["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{CORE_SRC}"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def importable_here(names) -> dict[str, bool]:
    completed = subprocess.run(
        [sys.executable, "-c",
         "import importlib.util, json, sys;"
         "print(json.dumps({n: importlib.util.find_spec(n) is not None"
         " for n in sys.argv[1:]}))", *names],
        capture_output=True, text=True, timeout=300,
        cwd=str(REPO_ROOT), env=probe_env(),
    )
    if completed.returncode != 0:  # pragma: no cover - diagnostic path
        raise AssertionError(completed.stderr)
    return json.loads(completed.stdout)


if __name__ == "__main__":
    unittest.main()
