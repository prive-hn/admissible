"""Contract: the Ready source can only reach Core, and holds no credential.

Two claims are proved here, and they are different claims.

The first is *structural*: every module under ``packages/ready/src`` is parsed
and every import it makes -- top level, inside a function, relative, or spelled
as ``importlib.import_module`` -- is checked against a closed set of allowed
roots.  A local import inside a CLI handler is exactly how the monolith's
``admissible.ready`` reached ``admissible.cli`` and ``admissible.standing``, so
a rule that only reads the top of a file would not have caught the edge it
exists to forbid.

The second is *behavioural*: importing ``admissible_ready`` and then walking
its whole module graph must not make a Trust module, a credential loader or a
receipt importable, and must not name one in ``sys.modules``.  Containment in
the source tree and absence at runtime are separate facts, and only the second
one is what a process actually has.

What "Core only" means is written down rather than assumed: ``admissible_core``
and the research roots Core itself stands on and ships (``fcd``).  A second
``canonical_json`` inside Ready would be a second canonicalisation with import
order deciding which one hashes an attempt, which is the failure the import
census forbids by name -- so the shared root is depended on rather than copied,
and the list below is the whole of it.
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import pkgutil
import sys
import unittest
from pathlib import Path

from . import READY_SRC

READY_NAMESPACE = "admissible_ready"
READY_PACKAGE = READY_SRC / READY_NAMESPACE

# Every non-stdlib root a Ready module may import.
#
# ``fcd`` is here and ``rga``/``atlas``/``protocol`` are not: Core imports
# ``fcd.journal`` for its own canonical serialisation, ships it, and Ready
# hashes the same documents.  Reaching the rest of the research corpus would be
# Ready depending on work it has no business depending on.
ALLOWED_ROOTS = frozenset({READY_NAMESPACE, "admissible_core", "fcd"})

# Roots a Ready module must never import, named individually so the failure
# says which boundary was crossed rather than "not in the allowed set".
FORBIDDEN_ROOTS = ("admissible", "admissible_trust", "rga", "atlas", "server")

# Trust surface by module basename. Ready must ship none of these and must not
# make them importable; the names are the ones the ownership manifest gives to
# the Trust distribution.
TRUST_MODULE_NAMES = ("attestation", "receipt", "review", "standing")

# Substrings that mark a module as a credential loader. The Ready distribution
# exists to not have one, so a new loader under a new name is still caught.
CREDENTIAL_MARKERS = ("credential", "signing", "keyring", "secret")


def ready_module_names() -> tuple[str, ...]:
    """Every module the Ready package ships, dotted, sorted."""

    found = [READY_NAMESPACE]
    for info in pkgutil.walk_packages([str(READY_PACKAGE)],
                                      prefix=f"{READY_NAMESPACE}."):
        found.append(info.name)
    return tuple(sorted(found))


def ready_source_files() -> tuple[Path, ...]:
    return tuple(sorted(READY_PACKAGE.rglob("*.py")))


def _dotted(path: Path) -> str:
    relative = path.relative_to(READY_SRC).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve(name: str, level: int, module: str) -> str:
    """The absolute module a possibly-relative import names."""

    if not level:
        return name
    anchor = module.split(".")
    # A relative import inside a package module climbs from the package.
    if not (READY_PACKAGE / Path(*anchor[1:]) / "__init__.py").is_file():
        anchor = anchor[:-1]
    base = anchor[:len(anchor) - level + 1] if level > 1 else anchor
    return ".".join([*base, name]) if name else ".".join(base)


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


class ReadySourceImportsCoreOnly(unittest.TestCase):
    """Static: no Ready module names anything outside the allowed roots."""

    def test_the_ready_package_exists_and_ships_modules(self):
        self.assertTrue(
            READY_PACKAGE.is_dir(),
            f"{READY_PACKAGE} is the Ready distribution's source package")
        self.assertTrue(ready_source_files(), "Ready ships no modules")

    def test_every_import_resolves_to_an_allowed_root(self):
        offenders = []
        for path in ready_source_files():
            for target in imported_modules(path):
                root = target.split(".")[0]
                if root in ALLOWED_ROOTS:
                    continue
                if importlib.util.find_spec(root) is None:
                    offenders.append(f"{_dotted(path)} -> {target} (unknown)")
                    continue
                spec = importlib.util.find_spec(root)
                origin = getattr(spec, "origin", "") or ""
                if root in sys.stdlib_module_names or origin == "built-in":
                    continue
                offenders.append(f"{_dotted(path)} -> {target}")
        self.assertEqual([], offenders,
                         "Ready may import the standard library and Core")

    def test_no_module_imports_a_forbidden_root(self):
        """Stated as itself, so a failure names the boundary that was crossed."""
        offenders = []
        for path in ready_source_files():
            for target in imported_modules(path):
                if target.split(".")[0] in FORBIDDEN_ROOTS:
                    offenders.append(f"{_dotted(path)} -> {target}")
        self.assertEqual([], offenders)

    def test_no_module_reaches_trust_through_a_relative_or_dynamic_name(self):
        offenders = []
        for path in ready_source_files():
            for target in imported_modules(path):
                tail = target.rpartition(".")[2]
                if tail in TRUST_MODULE_NAMES and target.startswith(
                        READY_NAMESPACE):
                    offenders.append(f"{_dotted(path)} -> {target}")
        self.assertEqual([], offenders)

    def test_ready_ships_no_module_named_after_the_trust_surface(self):
        shipped = {name.rpartition(".")[2] for name in ready_module_names()}
        self.assertEqual(
            [], sorted(shipped & set(TRUST_MODULE_NAMES)),
            "receipts, reviews, attestations and standing are Trust's")

    def test_ready_ships_no_credential_loader_module(self):
        offenders = sorted(
            name for name in ready_module_names()
            if any(marker in name.rpartition(".")[2]
                   for marker in CREDENTIAL_MARKERS))
        self.assertEqual([], offenders)

    def test_no_source_line_loads_a_signing_key(self):
        """A loader can be a function as easily as a module."""
        forbidden = ("load_signer", "load_keyring", "load_review_signer",
                     "load_evaluation_keyring", "load_evaluation_signer")
        offenders = []
        for path in ready_source_files():
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


class ImportingReadyDragsInNoAuthority(unittest.TestCase):
    """Behavioural: what the interpreter actually holds after the import."""

    def test_the_whole_module_graph_imports(self):
        """Every shipped module must import; an unimportable one proves nothing."""
        for name in ready_module_names():
            with self.subTest(module=name):
                importlib.import_module(name)

    def test_no_trust_module_is_reachable_after_importing_everything(self):
        for name in ready_module_names():
            importlib.import_module(name)
        for basename in TRUST_MODULE_NAMES:
            with self.subTest(module=basename):
                self.assertIsNone(
                    importlib.util.find_spec(f"{READY_NAMESPACE}.{basename}"))

    def test_importing_the_package_alone_loads_no_submodule(self):
        """``import admissible_ready`` must not start a server or open a store.

        Run in a child interpreter: this process has already imported the whole
        graph in the tests above, and ``sys.modules`` would answer about that
        rather than about a fresh import.
        """
        import subprocess

        source = (
            "import sys\n"
            "import admissible_ready\n"
            "loaded = sorted(name for name in sys.modules\n"
            "                if name.startswith('admissible_ready.'))\n"
            "print(';'.join(loaded))\n"
            "print(admissible_ready.__version__)\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", source], capture_output=True, text=True,
            timeout=120,
            env={"PYTHONPATH": _import_path(), "PATH": "/usr/bin:/bin"})
        self.assertEqual(0, completed.returncode, completed.stderr)
        loaded, version = completed.stdout.splitlines()[:2]
        self.assertEqual("", loaded, f"importing the package loaded {loaded}")
        self.assertEqual("0.8.1", version)


def _import_path() -> str:
    from . import CORE_SRC

    return f"{READY_SRC}:{CORE_SRC}"


class DeclaredPublicSurface(unittest.TestCase):
    """The names Ready promises, and the ones it must not offer."""

    def test_ready_state_exposes_the_unsigned_api(self):
        from admissible_ready import ready

        for name in ("inspect_unsigned", "run_check", "from_evaluation",
                     "from_problem", "render_plain", "work_package"):
            with self.subTest(name=name):
                self.assertTrue(callable(getattr(ready, name, None)))
                self.assertIn(name, ready.__all__)

    def test_there_is_no_inspect_that_takes_a_signer(self):
        """The signer parameter is removed, not defaulted to None.

        A parameter that exists and defaults to ``None`` is a parameter a
        caller can pass, and the whole point of the split is that no Ready
        callable has one.
        """
        import inspect as inspect_module

        from admissible_ready import ready

        self.assertFalse(hasattr(ready, "inspect"),
                         "the signer-accepting entry point must be gone")
        for name in dir(ready):
            value = getattr(ready, name)
            if not callable(value) or getattr(value, "__module__",
                                              "") != ready.__name__:
                continue
            try:
                signature = inspect_module.signature(value)
            except (TypeError, ValueError):  # pragma: no cover - builtins
                continue
            with self.subTest(callable=name):
                self.assertEqual(
                    [], [p for p in signature.parameters
                         if p in ("signer", "verifier", "keyring", "secret")])

    def test_no_ready_callable_anywhere_accepts_a_credential_parameter(self):
        import inspect as inspect_module

        offenders = []
        for name in ready_module_names():
            module = importlib.import_module(name)
            for attribute in dir(module):
                value = getattr(module, attribute)
                if not callable(value):
                    continue
                if getattr(value, "__module__", "") != name:
                    continue
                try:
                    signature = inspect_module.signature(value)
                except (TypeError, ValueError):  # pragma: no cover
                    continue
                for parameter in signature.parameters:
                    if parameter in ("signer", "verifier", "keyring"):
                        offenders.append(f"{name}.{attribute}({parameter})")
        self.assertEqual([], offenders)


class UnsignedStatusVocabulary(unittest.TestCase):
    """Ready may not say ``ready``, ``ADMITTED`` or authenticated ``CURRENT``."""

    ALLOWED = ("needs_attention", "waiting_for_review", "checks_complete",
               "unable_to_check")

    def test_the_allowed_product_statuses_are_exactly_the_four(self):
        from admissible_ready import ready

        self.assertEqual(sorted(self.ALLOWED),
                         sorted(ready.UNSIGNED_STATUSES))

    def test_no_ready_source_line_can_emit_the_admitted_state(self):
        """``ADMITTED`` is a receipt's word, and Ready issues no receipt."""
        offenders = []
        for path in ready_source_files():
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                code = line.split("#", 1)[0]
                if '"ADMITTED"' in code or "'ADMITTED'" in code:
                    offenders.append(f"{_dotted(path)}:{number}")
        self.assertEqual([], offenders)

    def test_no_ready_source_line_assigns_the_ready_status(self):
        offenders = []
        for path in ready_source_files():
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                code = line.split("#", 1)[0]
                if '"status"] = "ready"' in code or "= 'ready'" in code:
                    offenders.append(f"{_dotted(path)}:{number}")
        self.assertEqual([], offenders)

    def test_from_evaluation_never_produces_ready(self):
        from admissible_ready import ready

        document = {
            "state": "CHECKS_PASSED",
            "readiness": "READY_FOR_ATTESTATION",
            "repository": "example.com/one", "commit_sha": "a" * 40,
            "tree_sha": "b" * 40, "policy_digest": "c" * 64,
            "class_id": "default", "attempt_id": "attempt",
        }
        for standing in ("UNKNOWN", "CURRENT", "IMPEACHED", "UNVERIFIED"):
            with self.subTest(standing=standing):
                state = ready.from_evaluation(document, standing=standing)
                self.assertIn(state["status"], self.ALLOWED)
                self.assertNotEqual("ADMITTED", state["canonical"]["state"])
