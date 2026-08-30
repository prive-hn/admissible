"""Contract: every ``admissible.*`` import this repository documents resolves.

The umbrella's facade set used to be two modules -- ``evidence`` and
``receipt`` -- because those are the two imports the plan's migration section
writes out.  They are not the only ones this repository publishes.  The shipped
CI template and the workflow built from it run ``from admissible.ready import
ReadyError, from_evaluation, from_problem`` inside a job; the worked example
runs ``from admissible.config import load_config`` and ``from
admissible.identity import repository_identity``; and ``docs/GITHUB_ACTIONS.md``
names ``admissible.github.evaluation_context()`` and
``admissible.github.assert_trusted_tool()`` as the code that applies two of the
rules it describes.  A promise printed in a template a user copies is a promise
whether or not a plan section repeated it.

So the inventory is taken mechanically rather than remembered.  Every text file
under the documenting roots is read for the three shapes a documented import
takes -- ``from admissible.x import a, b``, ``import admissible.x``, and a
prose reference of the form ``admissible.x.name`` -- and the result is compared,
as an equality, against the table below.  The table is the decision: it names
each documented module's split owner and each documented symbol.  An equality
in both directions is what makes this a census and not a spot check: a new
documented import fails here on the day it is written, and a facade nobody
documents cannot quietly accumulate either.

A dotted reference only counts when its first component is a module the legacy
package actually has.  ``admissible.json``, ``admissible.sqlite`` and
``admissible.py`` appear throughout the docs as filenames, and a filename is
not an import; the filter is the package's own module list, and the rejected
spellings are asserted below so the filter cannot silently widen.

The repository's own tests are inventoried too, and classified as what they
are: the legacy package's tests, importing the legacy package at the repository
root.  They retire with it.  They are not promises to a consumer, and no facade
is owed to them -- but they are counted here, rather than excluded by a rule
nobody can see, so that "which ``admissible`` imports exist?" has one answer.
"""
from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path

from tests.compatibility import REPO_ROOT, UMBRELLA_PACKAGE, run_python

#: Where this repository publishes an import to somebody who is not it.
#: ``admissible/templates`` is here because those files are copied into a
#: consumer's repository verbatim by ``admissible init --ci``; ``.github`` is
#: here because the workflow it holds is the worked instance of that template.
DOCUMENTING_ROOTS = ("README.md", "docs", "examples", "admissible/templates",
                     ".github")

#: Text this scanner can read.  A binary asset holds no import, and reading one
#: as UTF-8 would be a decoding error rather than a finding.
DOCUMENTING_SUFFIXES = (".md", ".py", ".yml", ".yaml", ".txt", ".toml", ".cfg",
                        ".json", ".sh", ".rst", ".html", ".js", ".css")

LEGACY_PACKAGE = REPO_ROOT / "admissible"

CORE = "admissible_core"
READY = "admissible_ready"
TRUST = "admissible_trust"


class Facade:
    """One documented ``admissible.x``: its owner or owners, and its symbols.

    ``owners`` maps each documented symbol to the module that implements it
    after the split.  For every facade but one that map has a single value; the
    exception is ``admissible.github``, whose surface the split cut in half,
    and writing the owner per symbol is what lets that facade stay a facade
    instead of becoming a place where the two halves meet.
    """

    def __init__(self, module: str, owners: dict[str, str]):
        self.module = module
        self.owners = owners

    @property
    def symbols(self) -> set[str]:
        return set(self.owners)

    @property
    def distributions(self) -> set[str]:
        return {owner.split(".")[0] for owner in self.owners.values()}


#: The decision, retyped here on purpose: this file is where the ownership of
#: the documented surface is asserted, so it must say what that ownership is
#: rather than read it back out of the code under test.
DOCUMENTED = {
    facade.module: facade for facade in (
        Facade("admissible.config", {"load_config": "admissible_core.config"}),
        Facade("admissible.evidence",
               {"ReviewEvidence": "admissible_core.evidence"}),
        # The one cut surface.  ``evaluation_context`` derives what a workflow
        # may do from named environment inputs, which is candidate-side work
        # and holds no key; ``assert_trusted_tool`` refuses a policy root that
        # ships its own ``admissible`` package, which is a check only the half
        # that holds the key has any reason to make.
        Facade("admissible.github",
               {"assert_trusted_tool": "admissible_trust.github",
                "evaluation_context": "admissible_ready.github"}),
        Facade("admissible.identity",
               {"repository_identity": "admissible_core.identity"}),
        Facade("admissible.ready",
               {"ReadyError": "admissible_ready.ready",
                "from_evaluation": "admissible_ready.ready",
                "from_problem": "admissible_ready.ready"}),
        Facade("admissible.receipt",
               {"WorkflowReceipt": "admissible_trust.receipt"}),
    )
}

#: Names both halves of the split ``github`` module define, and therefore names
#: no facade can answer.  ``GitHubError`` is a distinct class in each -- an
#: ``except`` clause naming one would not catch the other -- and
#: ``PREVIEW_SCHEMA`` is a constant each half owns for its own artefact.
#: Neither is documented, so neither is promised; they are named here so that
#: the facade refuses them by decision rather than by omission.
AMBIGUOUS_GITHUB_NAMES = ("GitHubError", "PREVIEW_SCHEMA")

#: Spellings the filter must keep rejecting.  Each is a filename this
#: repository documents, and each would otherwise be read as a module.
NON_MODULE_SPELLINGS = ("admissible.json", "admissible.py", "admissible.sqlite")

_FROM_IMPORT = re.compile(
    r"\bfrom\s+(admissible(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s+import\s+([^\n#]*)")
_PLAIN_IMPORT = re.compile(
    r"\bimport\s+(admissible(?:\.[A-Za-z_][A-Za-z0-9_]*)+)")
_ATTRIBUTE = re.compile(
    r"\badmissible\.([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)")


def legacy_modules() -> set[str]:
    """Every module name the legacy package actually provides."""
    names = {path.stem for path in LEGACY_PACKAGE.glob("*.py")
             if path.stem != "__init__"}
    names |= {path.name for path in LEGACY_PACKAGE.iterdir()
              if path.is_dir() and (path / "__init__.py").is_file()}
    return names


def documenting_files() -> list[Path]:
    files: list[Path] = []
    for name in DOCUMENTING_ROOTS:
        root = REPO_ROOT / name
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files += [path for path in sorted(root.rglob("*"))
                      if path.is_file() and path.suffix in DOCUMENTING_SUFFIXES]
    return sorted(files)


def scan_documented_imports() -> tuple[dict[str, dict[str, list[str]]],
                                       set[str]]:
    """``{module: {symbol: [where]}}`` and the dotted spellings rejected.

    A ``from admissible import x`` -- the legacy package imported whole, with
    a submodule named -- is deliberately not a facade reference: the name it
    binds is ``admissible.x``, so it is recorded under that module with no
    symbol, exactly as ``import admissible.x`` is.
    """
    modules = legacy_modules()
    found: dict[str, dict[str, list[str]]] = {}
    rejected: set[str] = set()

    def record(module: str, symbol: str | None, where: str) -> None:
        entry = found.setdefault(module, {})
        if symbol is not None:
            entry.setdefault(symbol, []).append(where)

    for path in documenting_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        relative = path.relative_to(REPO_ROOT).as_posix()
        for number, line in enumerate(text.splitlines(), 1):
            where = f"{relative}:{number}"
            for module, names in _FROM_IMPORT.findall(line):
                head, _, tail = module.partition(".")
                if not tail:
                    for name in names.split(","):
                        name = name.strip()
                        if name in modules:
                            record(f"admissible.{name}", None, where)
                    continue
                if tail.split(".")[0] not in modules:
                    rejected.add(module)
                    continue
                found.setdefault(module, {})
                for name in names.split(","):
                    name = name.strip()
                    if name.isidentifier():
                        record(module, name, where)
            for module in _PLAIN_IMPORT.findall(line):
                if module.partition(".")[2].split(".")[0] not in modules:
                    rejected.add(module)
                    continue
                found.setdefault(module, {})
            for module, symbol in _ATTRIBUTE.findall(line):
                if module not in modules:
                    rejected.add(f"admissible.{module}")
                    continue
                record(f"admissible.{module}", symbol, where)
    return found, rejected


def scan_repository_test_imports() -> dict[str, set[str]]:
    """``{module: {symbol}}`` for every ``admissible`` import under ``tests``.

    Parsed rather than matched: these are Python files, so the AST is available
    and a comment or a docstring cannot be mistaken for an import.
    """
    found: dict[str, set[str]] = {}
    for path in sorted((REPO_ROOT / "tests").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "admissible":
                        found.setdefault(alias.name, set())
            elif isinstance(node, ast.ImportFrom) and not node.level:
                module = node.module or ""
                if module.split(".")[0] != "admissible":
                    continue
                names = {alias.name for alias in node.names}
                if module == "admissible":
                    for name in names:
                        found.setdefault(f"admissible.{name}", set())
                else:
                    found.setdefault(module, set()).update(names)
    return found


class TheInventoryIsMechanical(unittest.TestCase):
    """The scan, and the filter it applies, asserted before it is used."""

    @classmethod
    def setUpClass(cls):
        cls.found, cls.rejected = scan_documented_imports()

    def test_the_documenting_roots_all_exist(self):
        for name in DOCUMENTING_ROOTS:
            with self.subTest(root=name):
                self.assertTrue((REPO_ROOT / name).exists())

    def test_the_scan_reads_more_than_a_handful_of_files(self):
        """A scanner that silently matched nothing would pass every equality."""
        self.assertGreater(len(documenting_files()), 20)

    def test_the_filename_spellings_are_rejected_as_modules(self):
        for spelling in NON_MODULE_SPELLINGS:
            with self.subTest(spelling=spelling):
                self.assertNotIn(spelling, self.found)

    def test_the_filter_is_the_legacy_package_s_own_module_list(self):
        for module in sorted(self.found):
            with self.subTest(module=module):
                self.assertIn(module.partition(".")[2].split(".")[0],
                              legacy_modules())


class TheDocumentedSurfaceIsExactlyTheFacadeSet(unittest.TestCase):
    """Two equalities, so neither direction can drift."""

    @classmethod
    def setUpClass(cls):
        cls.found, _ = scan_documented_imports()

    def test_every_documented_module_has_a_facade_and_no_facade_is_unused(self):
        self.assertEqual(sorted(DOCUMENTED), sorted(self.found))

    def test_every_documented_symbol_is_in_the_table(self):
        for module, symbols in sorted(self.found.items()):
            with self.subTest(module=module):
                self.assertEqual(sorted(DOCUMENTED[module].symbols),
                                 sorted(symbols))

    def test_every_table_entry_is_actually_documented_somewhere(self):
        """A promise nobody printed is a promise nobody made."""
        for module, facade in sorted(DOCUMENTED.items()):
            for symbol in sorted(facade.symbols):
                with self.subTest(module=module, symbol=symbol):
                    self.assertTrue(self.found[module][symbol],
                                    "no documenting file names it")

    def test_the_umbrella_ships_a_module_for_each_documented_import(self):
        shipped = sorted(path.stem for path in UMBRELLA_PACKAGE.glob("*.py")
                         if path.stem not in ("__init__", "__main__", "cli"))
        self.assertEqual(sorted(name.rpartition(".")[2] for name in DOCUMENTED),
                         shipped)


class EveryDocumentedSymbolHasOneSplitOwner(unittest.TestCase):
    """Classification: each symbol belongs to exactly one distribution."""

    def test_each_owner_module_is_a_source_file_in_its_distribution(self):
        for facade in sorted(DOCUMENTED.values(), key=lambda f: f.module):
            for symbol, owner in sorted(facade.owners.items()):
                with self.subTest(symbol=f"{facade.module}.{symbol}"):
                    distribution, _, module = owner.partition(".")
                    project = {CORE: "core", READY: "ready",
                               TRUST: "trust"}[distribution]
                    path = (REPO_ROOT / "packages" / project / "src"
                            / distribution / f"{module}.py")
                    self.assertTrue(path.is_file(), f"{owner} has no source")

    def test_each_owner_declares_the_symbol_in_its_public_surface(self):
        for facade in sorted(DOCUMENTED.values(), key=lambda f: f.module):
            for symbol, owner in sorted(facade.owners.items()):
                with self.subTest(symbol=f"{facade.module}.{symbol}"):
                    self.assertIn(symbol, self.public_surface(owner))

    def test_only_the_github_facade_is_split_between_distributions(self):
        split = sorted(facade.module for facade in DOCUMENTED.values()
                       if len(facade.distributions) > 1)
        self.assertEqual(["admissible.github"], split)

    def test_the_names_both_github_halves_define_are_owned_by_neither(self):
        """The fail-closed set, derived rather than asserted from memory."""
        shared = (self.public_surface("admissible_ready.github")
                  & self.public_surface("admissible_trust.github"))
        self.assertEqual(sorted(AMBIGUOUS_GITHUB_NAMES), sorted(shared))
        self.assertEqual(
            set(), shared & DOCUMENTED["admissible.github"].symbols,
            "a documented symbol both halves define would have no owner")

    @staticmethod
    def public_surface(owner: str) -> set[str]:
        distribution, _, module = owner.partition(".")
        project = {CORE: "core", READY: "ready", TRUST: "trust"}[distribution]
        path = (REPO_ROOT / "packages" / project / "src" / distribution
                / f"{module}.py")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if (isinstance(node, ast.Assign)
                    and any(getattr(target, "id", "") == "__all__"
                            for target in node.targets)):
                return set(ast.literal_eval(node.value))
        raise AssertionError(f"{owner} declares no __all__")


class EveryDocumentedImportResolves(unittest.TestCase):
    """The claim a consumer cares about, made in a child process.

    The repository root still holds the legacy package under the name
    ``admissible``, so this runs the way :mod:`tests.compatibility` explains:
    a child with the umbrella first on its import path, and JSON back.
    """

    PROBE = """
import importlib, json, sys

module, symbols = sys.argv[1], json.loads(sys.argv[2])
facade = importlib.import_module(module)
resolved = {}
for symbol in symbols:
    owner_name = json.loads(sys.argv[3])[symbol]
    owner = importlib.import_module(owner_name)
    resolved[symbol] = getattr(facade, symbol) is getattr(owner, symbol)
sys.stdout.write(json.dumps({
    "resolved": resolved,
    "all": sorted(getattr(facade, "__all__", [])),
}))
"""

    def probe(self, facade) -> dict:
        completed = run_python(self.PROBE, facade.module,
                               json.dumps(sorted(facade.symbols)),
                               json.dumps(facade.owners))
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)

    def test_every_documented_symbol_is_its_owner_s_own_object(self):
        for facade in sorted(DOCUMENTED.values(), key=lambda f: f.module):
            with self.subTest(module=facade.module):
                report = self.probe(facade)
                self.assertEqual(
                    {symbol: True for symbol in sorted(facade.symbols)},
                    report["resolved"])

    def test_every_documented_symbol_is_declared_by_the_facade(self):
        for facade in sorted(DOCUMENTED.values(), key=lambda f: f.module):
            with self.subTest(module=facade.module):
                self.assertLessEqual(facade.symbols,
                                     set(self.probe(facade)["all"]))

    def test_the_documented_import_lines_run_verbatim(self):
        """The exact lines, copied out of the files that print them."""
        for line, sources in (
                ("from admissible.ready import ReadyError, from_evaluation, "
                 "from_problem",
                 ("admissible/templates/reusable-workflow.yml",
                  ".github/workflows/admissible-gate.yml")),
                ("from admissible.config import load_config",
                 ("examples/developer-workflow/show.py",)),
                ("from admissible.identity import repository_identity",
                 ("examples/developer-workflow/show.py",)),
                ("from admissible.evidence import ReviewEvidence",
                 ("docs/plans/ADMISSIBLE_RUNTIME_AUTHORITY_SEPARATION.md",)),
                ("from admissible.receipt import WorkflowReceipt",
                 ("docs/plans/ADMISSIBLE_RUNTIME_AUTHORITY_SEPARATION.md",))):
            with self.subTest(line=line):
                for source in sources:
                    self.assertIn(
                        line, (REPO_ROOT / source).read_text(encoding="utf-8"),
                        f"{source} no longer prints this line")
                completed = run_python(f"{line}\nprint('ok')\n")
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual("ok", completed.stdout.strip())

    def test_the_documented_prose_calls_are_reachable_attributes(self):
        """``docs/GITHUB_ACTIONS.md`` names two functions; both are callable."""
        completed = run_python(
            "import admissible.github as github\n"
            "print(callable(github.evaluation_context) "
            "and callable(github.assert_trusted_tool))\n")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("True", completed.stdout.strip())


class TheRepositorySOwnTestsAreNotPromises(unittest.TestCase):
    """Counted, classified, and owed nothing.

    These import the legacy package at the repository root, which is the thing
    being retired.  They are inventoried so that the answer to "what imports
    ``admissible``?" is complete, and separated so that a facade is never added
    because an internal test happened to reach for a module.
    """

    @classmethod
    def setUpClass(cls):
        cls.found = scan_repository_test_imports()

    def test_every_module_they_import_is_the_legacy_package_s_own(self):
        for module in sorted(self.found):
            with self.subTest(module=module):
                self.assertIn(module.partition(".")[2].split(".")[0],
                              legacy_modules())

    def test_they_reach_modules_the_umbrella_deliberately_does_not_ship(self):
        """Proof the two inventories are different sets, not one restated."""
        shipped = {f"admissible.{path.stem}"
                   for path in UMBRELLA_PACKAGE.glob("*.py")}
        self.assertTrue(set(self.found) - shipped,
                        "the test surface reaches only facades, so this "
                        "distinction is no longer carrying anything")

    def test_no_test_here_imports_a_module_the_legacy_package_lacks(self):
        missing = sorted(
            module for module in self.found
            if not (LEGACY_PACKAGE / f"{module.partition('.')[2]}.py").exists()
            and not (LEGACY_PACKAGE / module.partition(".")[2]).is_dir())
        self.assertEqual([], missing)


if __name__ == "__main__":
    unittest.main()
