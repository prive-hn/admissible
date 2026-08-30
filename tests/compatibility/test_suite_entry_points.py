"""Contract: this suite loads under the command the plan prescribes.

The compatibility suite is the one that says the legacy ``admissible`` command
and the legacy ``admissible.*`` imports still work.  It is therefore the suite
a release runs on its own, with the command the plan writes down::

    .venv/bin/python -m unittest discover -s tests/compatibility -p 'test_*.py' -v

That invocation gives :meth:`unittest.TestLoader.discover` no ``-t``, so the
top-level directory *is* ``tests/compatibility``, and every module under it is
imported as a top-level module with no parent package.  A ``from . import`` in
any of them is then an ``ImportError`` at load time -- and unittest reports a
failed *import* as a passing-shaped ``_FailedTest``, so the suite that proves
compatibility would report three errors and nothing else while every real
assertion in it went unrun.

So the suite is loaded here both ways it is ever loaded -- by discovery under
that exact ``-s``, and by dotted module name -- and the loader's own report is
the evidence.  Nothing below *runs* a test: discovery imports, and importing is
the step that was broken.
"""
from __future__ import annotations

import ast
import json
import subprocess
import unittest
from pathlib import Path

from tests.architecture import inspect_wheel
from tests.compatibility import REPO_ROOT

SUITE_DIRECTORY = REPO_ROOT / "tests" / "compatibility"
SUITE_RELATIVE = "tests/compatibility"
PATTERN = "test_*.py"
PACKAGE = "tests.compatibility"

#: Every test module the prescribed command must be able to import.  Derived
#: from the directory rather than retyped, so a module added tomorrow is
#: covered by this contract on the day it is added.
def suite_modules() -> list[str]:
    return sorted(path.stem for path in SUITE_DIRECTORY.glob(PATTERN))


#: Load the suite the way ``unittest discover -s <dir> -p <pattern>`` loads it,
#: and report what the loader made of it.  ``discover`` imports every matching
#: module and substitutes a ``unittest.loader._FailedTest`` for each one that
#: raised, so a failure here is an import failure and is reported as one.
DISCOVERY_PROBE = """
import json, sys, unittest

start_dir, pattern = sys.argv[1], sys.argv[2]
loader = unittest.TestLoader()
suite = loader.discover(start_dir=start_dir, pattern=pattern)

failed, modules = [], set()


def walk(item):
    if isinstance(item, unittest.TestSuite):
        for child in item:
            walk(child)
        return
    kind = type(item)
    if kind.__module__ == "unittest.loader":
        exception = getattr(item, "_exception", None)
        failed.append({"id": item.id(), "error": f"{exception}"})
        return
    modules.add(kind.__module__)


walk(suite)
sys.stdout.write(json.dumps({
    "failed": failed,
    "modules": sorted(modules),
    "loader_errors": [f"{error}" for error in loader.errors],
    # What the loader made each module's parent package: the empty string when
    # there is none, which is the condition a relative import cannot survive.
    "parents": {name: sys.modules[name].__package__ for name in sorted(modules)},
}))
"""

#: Load one module by the dotted name a developer types, which is the other
#: invocation the plan names.  Same reporting shape, so the two are comparable.
BY_NAME_PROBE = """
import json, sys, unittest

loader = unittest.TestLoader()
suite = loader.loadTestsFromName(sys.argv[1])

failed, modules = [], set()


def walk(item):
    if isinstance(item, unittest.TestSuite):
        for child in item:
            walk(child)
        return
    kind = type(item)
    if kind.__module__ == "unittest.loader":
        exception = getattr(item, "_exception", None)
        failed.append({"id": item.id(), "error": f"{exception}"})
        return
    modules.add(kind.__module__)


walk(suite)
sys.stdout.write(json.dumps({"failed": failed, "modules": sorted(modules)}))
"""


def _probe(code: str, *args: str) -> dict:
    """Run one loader probe from the repository root and read its report.

    The working directory is the checkout because that is where the prescribed
    command is typed, and ``python -c`` puts the working directory on
    ``sys.path`` -- which is exactly what makes ``tests.compatibility``
    importable by its absolute name under both invocations.
    """
    completed = subprocess.run(
        [inspect_wheel.sys.executable, "-c", code, *args],
        capture_output=True, text=True, timeout=inspect_wheel.RUN_TIMEOUT,
        cwd=str(REPO_ROOT), env=inspect_wheel.sanitized_env())
    if completed.returncode != 0:
        raise AssertionError(f"the loader probe failed:\n{completed.stderr}")
    return json.loads(completed.stdout)


class DiscoveryUnderThePrescribedCommandImportsEveryModule(unittest.TestCase):
    """``-s tests/compatibility`` with no ``-t``: the release invocation."""

    @classmethod
    def setUpClass(cls):
        cls.report = _probe(DISCOVERY_PROBE, SUITE_RELATIVE, PATTERN)

    def test_the_modules_are_imported_with_no_parent_package(self):
        """Stated, because it is the reason a relative import cannot work.

        If unittest resolved a parent package here, ``from . import`` would be
        fine and this contract would be about nothing.  It does not: with no
        ``-t``, the top-level directory is the start directory, so each module
        is imported as a top-level module whose ``__package__`` is empty.
        """
        self.assertEqual({name: "" for name in suite_modules()},
                         self.report["parents"])

    def test_no_module_fails_to_import(self):
        self.assertEqual([], self.report["failed"])

    def test_the_loader_records_no_error(self):
        self.assertEqual([], self.report["loader_errors"])

    def test_every_module_in_the_directory_contributed_tests(self):
        """A module that imported but yielded nothing is a module unrun."""
        self.assertEqual(suite_modules(), self.report["modules"])


class LoadingByDottedNameStillWorks(unittest.TestCase):
    """The other invocation: ``python -m unittest tests.compatibility.x``.

    Absolute imports have to serve both.  Discovery would also be satisfied by
    a ``sys.path`` hack in each module; the dotted form is what keeps the
    package importable as a package, so both are asserted rather than one.
    """

    def test_each_module_loads_under_its_package_qualified_name(self):
        for module in suite_modules():
            dotted = f"{PACKAGE}.{module}"
            with self.subTest(module=dotted):
                report = _probe(BY_NAME_PROBE, dotted)
                self.assertEqual([], report["failed"])
                self.assertEqual([dotted], report["modules"])

    def test_the_package_itself_imports_by_its_absolute_name(self):
        completed = subprocess.run(
            [inspect_wheel.sys.executable, "-c",
             f"import {PACKAGE} as package; print(package.__name__)"],
            capture_output=True, text=True, timeout=inspect_wheel.RUN_TIMEOUT,
            cwd=str(REPO_ROOT), env=inspect_wheel.sanitized_env())
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(PACKAGE, completed.stdout.strip())


class NoModuleHereUsesARelativeImport(unittest.TestCase):
    """The invariant behind both invocations, checked where it is written.

    The probes above are the authority; this is the one-line reason they pass,
    stated so that a reviewer adding a module sees the rule without having to
    rediscover it from a ``_FailedTest``.
    """

    def sources(self) -> list[Path]:
        return sorted(SUITE_DIRECTORY.rglob("*.py"))

    def test_the_sources_are_the_package_and_its_test_modules(self):
        self.assertEqual(
            sorted(["__init__.py", *(f"{name}.py" for name in suite_modules())]),
            sorted(path.name for path in self.sources()))

    def test_no_import_in_this_package_is_relative(self):
        offenders = []
        for path in self.sources():
            tree = ast.parse(path.read_text(encoding="utf-8"),
                             filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level:
                    offenders.append(
                        f"{path.name}:{node.lineno}: "
                        f"{'.' * node.level}{node.module or ''}")
        self.assertEqual(
            [], offenders,
            "a relative import here is unimportable under `-s tests/"
            "compatibility`, which is the command the plan prescribes")

    def test_every_cross_module_import_names_the_package_absolutely(self):
        """``tests.compatibility``/``tests.architecture`` and nothing shorter."""
        offenders = []
        for path in self.sources():
            tree = ast.parse(path.read_text(encoding="utf-8"),
                             filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or not node.module:
                    continue
                if node.module.split(".")[0] != "tests":
                    continue
                if not node.module.startswith("tests."):
                    offenders.append(f"{path.name}:{node.lineno}: {node.module}")
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
