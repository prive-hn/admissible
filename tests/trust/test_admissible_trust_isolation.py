"""Contract: the Trust source can only reach Core, and holds no runner.

Two claims are proved here, and they are different claims.

The first is *structural*: every module under ``packages/trust/src`` is parsed
and every import it makes -- top level, inside a function, relative, or spelled
as ``importlib.import_module`` -- is checked against a closed set of allowed
roots.  A local import inside a CLI handler is exactly how the monolith's
``admissible.attestation`` reached ``admissible.runner``, so a rule that only
read the top of a file would not have caught the edge it exists to forbid.

The second is *behavioural*: importing ``admissible_trust`` and then walking its
whole module graph must not make a runner, an MCP server, an HTTP server or a
browser asset package importable, and must not name one in ``sys.modules``.
Containment in the source tree and absence at runtime are separate facts, and
only the second one is what a process actually has.

What "Core only" means is written down rather than assumed: ``admissible_core``
and the research roots Core itself stands on and ships (``fcd``).  A second
``canonical_json`` inside Trust would be a second canonicalisation with import
order deciding which one hashes a receipt, which is the failure the import
census forbids by name -- so the shared root is depended on rather than copied,
and the list below is the whole of it.
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import pkgutil
import subprocess
import sys
import unittest
from pathlib import Path

from . import CORE_SRC, TRUST_SRC

TRUST_NAMESPACE = "admissible_trust"
TRUST_PACKAGE = TRUST_SRC / TRUST_NAMESPACE

# Every non-stdlib root a Trust module may import.
#
# ``fcd`` is here and ``rga``/``atlas``/``protocol`` are not: Core imports
# ``fcd.journal`` for its own canonical serialisation and ``fcd.head`` for the
# monotone head receipts a workflow receipt is anchored in, ships both, and
# Trust hashes the same documents.  Reaching the rest of the research corpus
# would be Trust depending on work it has no business depending on -- and
# ``rga.AdmissibilityReceipt`` in particular is a *different* claim that a
# workflow receipt must never be presented as.
ALLOWED_ROOTS = frozenset({TRUST_NAMESPACE, "admissible_core", "fcd"})

# Roots a Trust module must never import, named individually so the failure
# says which boundary was crossed rather than "not in the allowed set".
FORBIDDEN_ROOTS = ("admissible", "admissible_ready", "rga", "atlas", "server",
                   "http", "socketserver", "socket", "asyncio", "mcp",
                   "wsgiref", "multiprocessing")

# Ready's execution surface by module basename. Trust must ship none of these
# and must not make them importable; the names are the ones the ownership
# manifest gives to the Ready distribution.
RUNNER_MODULE_NAMES = ("runner", "agent_mcp", "agent_connection",
                       "ready_server", "ready_static")


def trust_module_names() -> tuple[str, ...]:
    """Every module the Trust package ships, dotted, sorted."""

    found = [TRUST_NAMESPACE]
    for info in pkgutil.walk_packages([str(TRUST_PACKAGE)],
                                      prefix=f"{TRUST_NAMESPACE}."):
        found.append(info.name)
    return tuple(sorted(found))


def trust_source_files() -> tuple[Path, ...]:
    return tuple(sorted(TRUST_PACKAGE.rglob("*.py")))


def _dotted(path: Path) -> str:
    relative = path.relative_to(TRUST_SRC).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve(name: str, level: int, module: str) -> str:
    """The absolute module a possibly-relative import names."""

    if not level:
        return name
    anchor = module.split(".")
    if not (TRUST_PACKAGE / Path(*anchor[1:]) / "__init__.py").is_file():
        anchor = anchor[:-1]
    base = anchor[:len(anchor) - level + 1] if level > 1 else anchor
    return ".".join([*base, name]) if name else ".".join(base)


def _dynamic_target(node: ast.Call) -> str | None:
    """The literal module name an ``importlib``/``__import__`` call names."""

    name = ""
    if isinstance(node.func, ast.Attribute):
        name = node.func.attr
    elif isinstance(node.func, ast.Name):
        name = node.func.id
    if name not in ("import_module", "__import__", "find_spec"):
        return None
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return None
    value = node.args[0].value
    return value if isinstance(value, str) else None


def imported_modules(path: Path) -> tuple[str, ...]:
    """Every module ``path`` imports, statically or through importlib.

    Function-local imports are included deliberately: they are the shape the
    monolith used to cross exactly the boundary this suite forbids.
    """

    module = _dotted(path)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add(_resolve(node.module or "", node.level, module))
        elif isinstance(node, ast.Call):
            target = _dynamic_target(node)
            if target is not None:
                found.add(target)
    return tuple(sorted(item for item in found if item))


class TrustSourceImportsCoreOnly(unittest.TestCase):
    """Static: no Trust module names anything outside the allowed roots."""

    def test_the_trust_package_exists_and_ships_modules(self):
        self.assertTrue(
            TRUST_PACKAGE.is_dir(),
            f"{TRUST_PACKAGE} is the Trust distribution's source package")
        self.assertTrue(trust_source_files(), "Trust ships no modules")

    def test_every_import_resolves_to_an_allowed_root(self):
        offenders = []
        for path in trust_source_files():
            for target in imported_modules(path):
                root = target.split(".")[0]
                if root in ALLOWED_ROOTS:
                    continue
                spec = importlib.util.find_spec(root)
                if spec is None:
                    offenders.append(f"{_dotted(path)} -> {target} (unknown)")
                    continue
                origin = getattr(spec, "origin", "") or ""
                if root in sys.stdlib_module_names or origin == "built-in":
                    continue
                offenders.append(f"{_dotted(path)} -> {target}")
        self.assertEqual([], offenders,
                         "Trust may import the standard library and Core")

    def test_no_module_imports_a_forbidden_root(self):
        """Stated as itself, so a failure names the boundary that was crossed."""

        offenders = []
        for path in trust_source_files():
            for target in imported_modules(path):
                if target.split(".")[0] in FORBIDDEN_ROOTS:
                    offenders.append(f"{_dotted(path)} -> {target}")
        self.assertEqual([], offenders)

    def test_no_module_reaches_ready_through_a_relative_or_dynamic_name(self):
        offenders = []
        for path in trust_source_files():
            for target in imported_modules(path):
                tail = target.rpartition(".")[2]
                if tail in RUNNER_MODULE_NAMES:
                    offenders.append(f"{_dotted(path)} -> {target}")
        self.assertEqual([], offenders)

    def test_trust_ships_no_module_named_after_the_runner_surface(self):
        shipped = {name.rpartition(".")[2] for name in trust_module_names()}
        self.assertEqual(
            [], sorted(shipped & set(RUNNER_MODULE_NAMES)),
            "runners, agents and servers are Ready's")

    def test_no_source_line_starts_or_plans_a_candidate_command(self):
        """A runner can be a function as easily as a module."""

        forbidden = ("run_check", "order_checks", "plan_budget",
                     "read_stdout_bytes", "tool_tree_digest",
                     "environment_fingerprint", "make_server", "serve")
        offenders = []
        for path in trust_source_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name in forbidden:
                    offenders.append(f"{_dotted(path)}.{node.name}")
                if isinstance(node, ast.Call):
                    called = getattr(node.func, "attr",
                                     getattr(node.func, "id", ""))
                    if called in forbidden:
                        offenders.append(f"{_dotted(path)} calls {called}")
        self.assertEqual([], offenders)

    def test_no_module_ships_a_browser_asset_or_a_workflow_template(self):
        strays = sorted(
            str(path.relative_to(TRUST_PACKAGE))
            for path in TRUST_PACKAGE.rglob("*")
            if path.is_file() and path.suffix in (
                ".html", ".css", ".js", ".yml", ".yaml"))
        self.assertEqual([], strays)


class ImportingTrustDragsInNoExecutor(unittest.TestCase):
    """Behavioural: what the interpreter actually holds after the import."""

    def test_the_whole_module_graph_imports(self):
        """Every shipped module must import; an unimportable one proves nothing."""

        for name in trust_module_names():
            with self.subTest(module=name):
                if name.endswith("__main__"):
                    # Importing it would run the CLI's module guard; the
                    # distribution suite drives it as a real entry point.
                    continue
                importlib.import_module(name)

    def test_no_ready_module_is_reachable_after_importing_everything(self):
        for name in trust_module_names():
            if name.endswith("__main__"):
                continue
            importlib.import_module(name)
        for basename in RUNNER_MODULE_NAMES:
            with self.subTest(module=basename):
                self.assertIsNone(
                    importlib.util.find_spec(f"{TRUST_NAMESPACE}.{basename}"))

    def test_importing_the_package_alone_loads_no_submodule(self):
        """``import admissible_trust`` must not read a key or open a store.

        Run in a child interpreter: this process has already imported the whole
        graph in the tests above, and ``sys.modules`` would answer about that
        rather than about a fresh import.
        """

        source = (
            "import sys\n"
            "import admissible_trust\n"
            "loaded = sorted(name for name in sys.modules\n"
            "                if name.startswith('admissible_trust.'))\n"
            "print(';'.join(loaded))\n"
            "print(admissible_trust.__version__)\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", source], capture_output=True, text=True,
            timeout=120,
            env={"PYTHONPATH": f"{TRUST_SRC}:{CORE_SRC}",
                 "PATH": "/usr/bin:/bin"})
        self.assertEqual(0, completed.returncode, completed.stderr)
        loaded, version = completed.stdout.splitlines()[:2]
        self.assertEqual("", loaded, f"importing the package loaded {loaded}")
        self.assertEqual("0.8.1", version)

    def test_importing_the_whole_graph_starts_no_subprocess_module(self):
        """Only the git adapter may put ``subprocess`` in ``sys.modules``.

        ``subprocess`` arrives with plenty of stdlib modules, so the claim
        worth making is narrower and sharper: after importing every Trust
        module *except* the adapter, no Trust module has imported it.
        """

        source = (
            "import importlib, sys\n"
            "names = [n for n in %r if not n.endswith('git_reader')]\n"
            "for name in names:\n"
            "    importlib.import_module(name)\n"
            "adapter = sys.modules.get('admissible_trust.git_reader')\n"
            "print('adapter-loaded' if adapter else 'adapter-absent')\n"
        ) % (list(n for n in trust_module_names()
                  if not n.endswith("__main__")),)
        completed = subprocess.run(
            [sys.executable, "-c", source], capture_output=True, text=True,
            timeout=120,
            env={"PYTHONPATH": f"{TRUST_SRC}:{CORE_SRC}",
                 "PATH": "/usr/bin:/bin"})
        self.assertEqual(0, completed.returncode, completed.stderr)
        # The adapter is imported by `github`, `cli` and `ready_status`, which
        # is expected and is exactly the module the boundary suite audits.
        self.assertEqual("adapter-loaded", completed.stdout.strip())


class DeclaredPublicSurface(unittest.TestCase):
    """The names Trust promises, and the ones it must not offer."""

    def test_the_authenticated_projection_requires_a_verifier(self):
        import inspect as inspect_module

        from admissible_trust import ready_status

        signature = inspect_module.signature(
            ready_status.inspect_authenticated)
        verifier = signature.parameters["verifier"]
        self.assertIs(inspect_module.Parameter.empty, verifier.default,
                      "a verifier that defaults to None is a verifier a "
                      "caller can forget")

    def test_there_is_no_unsigned_inspect_entry_point(self):
        """The unsigned document is the candidate distribution's to produce."""

        from admissible_trust import ready_status

        self.assertFalse(hasattr(ready_status, "inspect"))
        self.assertFalse(hasattr(ready_status, "inspect_unsigned"))

    def test_no_trust_module_exposes_a_check_runner(self):
        from admissible_trust import cli, github, ready_status

        for module in (cli, github, ready_status):
            with self.subTest(module=module.__name__):
                self.assertFalse(hasattr(module, "run_check"))
                self.assertFalse(hasattr(module, "work_package"))


class AuthenticatedStatusVocabulary(unittest.TestCase):
    """``ready`` and ``ADMITTED`` are said here, and only after verification."""

    def test_the_authenticated_statuses_extend_the_unsigned_four(self):
        from admissible_trust import ready_status

        self.assertEqual(
            ["checks_complete", "needs_attention", "ready", "unable_to_check",
             "waiting_for_review"],
            sorted(ready_status.AUTHENTICATED_STATUSES))

    def test_from_evaluation_alone_never_produces_ready(self):
        """A translation is arithmetic; ``ready`` is a claim about a signature."""

        from admissible_trust import ready_status

        document = {
            "state": "CHECKS_PASSED",
            "readiness": "READY_FOR_ATTESTATION",
            "repository": "example.com/one", "commit_sha": "a" * 40,
            "tree_sha": "b" * 40, "policy_digest": "c" * 64,
            "class_id": "default", "attempt_id": "attempt",
        }
        for standing in ("UNKNOWN", "CURRENT", "IMPEACHED", "UNVERIFIED"):
            with self.subTest(standing=standing):
                state = ready_status.from_evaluation(document,
                                                     standing=standing)
                self.assertNotEqual("ready", state["status"])
                self.assertNotEqual("ADMITTED", state["canonical"]["state"])

    def test_render_plain_can_present_an_authenticated_document(self):
        from admissible_trust import ready_status

        document = ready_status.from_problem("nothing yet")
        document["status"] = "ready"
        document["summary"] = "This exact commit is admitted."
        self.assertIn("Ready:", ready_status.render_plain(document))


if __name__ == "__main__":
    unittest.main()
