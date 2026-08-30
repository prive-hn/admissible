"""Contract: the documented ``admissible.*`` imports still resolve, finitely.

The migration window keeps the imports this repository publishes alive.
:mod:`tests.compatibility.test_documented_imports` takes that inventory
mechanically, out of the README, the docs, the worked example, the shipped CI
template and the workflow built from it; this file is where each one's
behaviour is asserted.

Five of the six are facades over a single owner.  A facade re-exports one
owner's public surface and holds no implementation of its own, so
``admissible.receipt.WorkflowReceipt`` and
``admissible_trust.receipt.WorkflowReceipt`` are one class and not two.  Two
classes would be two receipt formats with import order deciding which one a
consumer hashed.

The sixth is ``admissible.github``, and it is the one the split cut in half.
``evaluation_context`` derives what a workflow may do from named environment
inputs and holds no key, so it went to Ready; ``assert_trusted_tool`` refuses a
policy root that ships its own ``admissible`` package, which is a check only
the half holding the key makes, so it went to Trust.  A facade that imported
both halves would put a runner and a signer in one process -- so this one
imports neither at import time, and resolves each documented name to its own
half, by literal module name, on the attribute access that asks for it.  The
table is written down; there is no delegation to a computed module, and no name
outside the table is answered at all.

Two names -- ``GitHubError`` and ``PREVIEW_SCHEMA`` -- exist in *both* halves,
as two different objects.  Nothing documents them, and a facade cannot answer
them without picking an authority on the caller's behalf: an ``except
GitHubError`` bound to the wrong half catches nothing.  So they fail closed,
naming both replacements, and the failure is asserted below rather than left to
fall out of a lookup miss.

What no facade may do is the whole point of the split:

* not reconnect the domains -- no module here imports both statically, no
  module reaches both in one attribute access, and importing the evidence
  facade must not drag the signing distribution in behind it;
* not load a domain nobody asked for -- ``import admissible`` alone imports
  neither, and so does ``import admissible.github``;
* not guess -- a facade re-exports from a named owner, never from whichever
  distribution happens to be installed or whichever credential is set;
* not contaminate stdout -- the deprecation notice is a warning, which is
  stderr, because a caller reading JSON off stdout is reading a wire format.

The set is finite by construction: exactly the imports this repository
documents.  A facade nobody documented is a promise nobody made.
"""
from __future__ import annotations

import ast
import json
import unittest

from tests.architecture.test_import_census import analyze_source, census

from tests.compatibility import (READY_TARGET, REPO_ROOT, TRUST_TARGET,
                                 UMBRELLA_PACKAGE, UMBRELLA_PROJECT,
                                 run_python)

#: ``facade -> the module it re-exports``, for the facades with one owner.
#: The owner is named, and it is the distribution the split gave that surface
#: to.  ``admissible.github`` is deliberately absent: it has two.
FACADE_OWNERS = {
    "admissible.config": "admissible_core.config",
    "admissible.evidence": "admissible_core.evidence",
    "admissible.identity": "admissible_core.identity",
    "admissible.ready": "admissible_ready.ready",
    "admissible.receipt": "admissible_trust.receipt",
}

#: The facade the split cut in half, and the owner of each documented name in
#: it.  Per symbol, because per module is the question that has no answer.
GITHUB_FACADE = "admissible.github"
GITHUB_OWNERS = {
    "assert_trusted_tool": "admissible_trust.github",
    "evaluation_context": "admissible_ready.github",
}

#: Names both halves define as different objects.  Undocumented, unanswerable,
#: and refused by name rather than by absence.
AMBIGUOUS_GITHUB_NAMES = ("GitHubError", "PREVIEW_SCHEMA")

#: ``facade -> every owner its deprecation notice must name``.
FACADE_NOTICE_OWNERS = {
    **{facade: (owner,) for facade, owner in FACADE_OWNERS.items()},
    GITHUB_FACADE: tuple(sorted(set(GITHUB_OWNERS.values()))),
}

#: Everything the compatibility namespace is allowed to contain.
EXPECTED_MODULE_FILES = sorted([
    "__init__.py", "__main__.py", "cli.py", "config.py", "evidence.py",
    "github.py", "identity.py", "ready.py", "receipt.py",
])

#: The static import roots each umbrella module is allowed to have.  The
#: dispatcher names both distributions but imports neither statically: it
#: resolves one and imports that one, which is what keeps a Trust invocation
#: from loading a runner.  ``github.py`` is the same shape for the same reason,
#: one attribute access at a time.
#:
#: No entry here contains ``os``.  A facade that could read the environment
#: could choose an owner from a credential, and choosing an authority from what
#: the machine happens to hold is the failure the split exists to prevent.
EXPECTED_IMPORT_ROOTS = {
    "__init__.py": {"__future__"},
    "__main__.py": {"__future__", "sys"},
    "cli.py": {"__future__", "importlib", "json", "sys", "typing",
               "admissible_core"},
    "config.py": {"__future__", "warnings", "admissible_core"},
    "evidence.py": {"__future__", "warnings", "admissible_core"},
    "github.py": {"__future__", "importlib", "warnings"},
    "identity.py": {"__future__", "warnings", "admissible_core"},
    "ready.py": {"__future__", "warnings", "admissible_ready"},
    "receipt.py": {"__future__", "warnings", "admissible_trust"},
}

#: The owner modules ``github.py`` may name in a dynamic import, and the only
#: ones.  The census reads the literals back out of the source.
GITHUB_TARGETS = sorted(set(GITHUB_OWNERS.values()))

DOMAIN_ROOTS = ("admissible_ready", "admissible_trust")


def _import_roots(entry: dict) -> set[str]:
    """Top-level names one module imports statically."""
    roots = set()
    for record in entry["imports"]:
        module = record.get("module")
        if module and not record.get("level"):
            roots.add(module.split(".")[0])
    return roots


class CompatibilityNamespaceIsFinite(unittest.TestCase):
    """What the umbrella ships is enumerated, and nothing else is there."""

    def test_the_package_exists_where_the_project_says_it_does(self):
        self.assertTrue(
            (UMBRELLA_PACKAGE / "__init__.py").is_file(),
            f"{UMBRELLA_PACKAGE} must hold the compatibility namespace")

    def test_the_module_files_are_exactly_the_documented_set(self):
        found = sorted(path.name
                       for path in UMBRELLA_PACKAGE.rglob("*.py"))
        self.assertEqual(EXPECTED_MODULE_FILES, found)

    def test_the_facade_set_is_exactly_the_documented_imports(self):
        facades = sorted(path.stem for path in UMBRELLA_PACKAGE.glob("*.py")
                         if path.stem not in ("__init__", "__main__", "cli"))
        self.assertEqual(
            sorted(name.rpartition(".")[2] for name in FACADE_NOTICE_OWNERS),
            facades, "a facade nobody documented is a promise nobody made")

    def test_no_asset_or_data_file_rides_along(self):
        """No template, no browser asset, no schema: it re-exports, it holds
        nothing.  Byte-code caches are not source and are not checked in."""
        strays = sorted(
            str(path.relative_to(UMBRELLA_PACKAGE))
            for path in UMBRELLA_PACKAGE.rglob("*")
            if path.is_file() and path.suffix != ".py"
            and "__pycache__" not in path.parts)
        self.assertEqual([], strays)


class UmbrellaSourceCensus(unittest.TestCase):
    """The sources the repository census cannot see, censused here.

    ``tests/architecture/test_import_census`` names modules under
    ``packages/*/src`` by their dotted import name, and the legacy monolith
    still claims ``admissible.*`` at the repository root.  Two permanent files
    claiming one dotted name is exactly what that census refuses, so these
    sources live beside ``src`` rather than in it -- and are read here with the
    same parser, so nothing is unclassified merely because it is unscanned.
    """

    def entries(self) -> dict[str, dict]:
        return {
            path.name: analyze_source(path.read_text(encoding="utf-8"),
                                      package="admissible",
                                      filename=str(path))
            for path in sorted(UMBRELLA_PACKAGE.rglob("*.py"))
        }

    def test_every_module_has_a_declared_import_surface(self):
        self.assertEqual(sorted(EXPECTED_IMPORT_ROOTS), sorted(self.entries()))

    def test_each_module_imports_exactly_what_it_declares(self):
        for name, entry in sorted(self.entries().items()):
            with self.subTest(module=name):
                self.assertEqual(EXPECTED_IMPORT_ROOTS[name],
                                 _import_roots(entry))

    def test_the_dispatcher_imports_no_domain_statically(self):
        """A static import is a load, and a load is not a dispatch.

        A facade is different: it *is* its owner's surface, so importing
        ``admissible.receipt`` is meant to import ``admissible_trust.receipt``.
        The dispatcher and the package marker carry no such promise, and a
        static import in either would load both authorities into every process
        that ran any command at all.
        """
        entries = self.entries()
        for name in ("__init__.py", "__main__.py", "cli.py"):
            with self.subTest(module=name):
                self.assertEqual(
                    set(), _import_roots(entries[name]) & set(DOMAIN_ROOTS))

    def test_no_module_imports_both_domains(self):
        for name, entry in sorted(self.entries().items()):
            with self.subTest(module=name):
                self.assertLess(
                    len(_import_roots(entry) & set(DOMAIN_ROOTS)), 2,
                    "a module that has both domains has reconnected them")

    def test_the_dispatcher_reaches_its_domains_by_literal_dynamic_import(self):
        dynamic = self.entries()["cli.py"]["dynamic"]
        targets = sorted(record["target"] for record in dynamic)
        self.assertEqual([], [record for record in dynamic
                              if record["target"] is None],
                         "a computed import target is a target nobody can read")
        self.assertEqual(sorted({READY_TARGET, TRUST_TARGET}),
                         sorted(set(targets)))

    def test_the_split_facade_reaches_its_halves_by_literal_dynamic_import(self):
        """``github.py`` names its two owners the way the dispatcher does.

        A computed target would make the set of modules this file can reach
        unreadable -- by a reviewer and by the census -- and "no dynamic
        arbitrary delegation" is precisely the property that keeps a facade
        from becoming a bridge.
        """
        dynamic = self.entries()["github.py"]["dynamic"]
        self.assertEqual([], [record for record in dynamic
                              if record["target"] is None],
                         "a computed import target is a target nobody can read")
        self.assertEqual(GITHUB_TARGETS,
                         sorted({record["target"] for record in dynamic}))

    def test_no_facade_but_the_split_one_imports_dynamically(self):
        """Every other facade is its owner's surface, so it says so statically."""
        entries = self.entries()
        for name in sorted(EXPECTED_IMPORT_ROOTS):
            if name in ("cli.py", "github.py"):
                continue
            with self.subTest(module=name):
                self.assertEqual([], entries[name]["dynamic"])

    def test_no_module_here_can_read_the_environment(self):
        """No ``os``, anywhere: a facade that can read a credential can route
        on one, and routing on a credential is choosing an authority from what
        the machine happens to hold."""
        for name, roots in sorted(EXPECTED_IMPORT_ROOTS.items()):
            with self.subTest(module=name):
                self.assertNotIn("os", roots)
        for name, entry in sorted(self.entries().items()):
            with self.subTest(module=name):
                self.assertNotIn("os", _import_roots(entry))

    def test_the_umbrella_sources_stay_out_of_the_censused_src_path(self):
        """The collision guard, stated so it cannot be recreated by accident.

        When the legacy package retires, this directory moves to ``src`` and
        this test is the one that says so.
        """
        self.assertFalse(
            (UMBRELLA_PROJECT / "src").exists(),
            "packages/umbrella/src would claim `admissible.cli`, which the "
            "repository root still claims; move it there when the monolith "
            "retires")

    def test_the_repository_census_still_reads_one_module_per_name(self):
        """The census runs; a duplicate would raise instead of answering."""
        modules = census()
        self.assertIn("admissible.cli", modules)
        self.assertIn("admissible_ready.cli", modules)


class FacadesHoldNoImplementation(unittest.TestCase):
    """A facade named ``config`` must not *be* a config parser.

    The umbrella now ships modules whose names -- ``config``, ``identity``,
    ``github``, ``ready`` -- are the names of real implementations in the three
    distributions.  A file called ``admissible/config.py`` that defined a
    ``Config`` would be a second policy parser with no authority behind it, and
    the one a process got would depend on import order.  So the shape is
    asserted rather than trusted to the name: a facade is a docstring, imports,
    assignments, one ``warnings.warn``, and the two dunder hooks.
    """

    #: The only functions a facade may define.  Both are lookup hooks; neither
    #: computes anything a caller could mistake for behaviour.
    ALLOWED_FUNCTIONS = {"__getattr__", "__dir__"}

    def facade_sources(self) -> dict[str, ast.Module]:
        return {
            path.name: ast.parse(path.read_text(encoding="utf-8"),
                                 filename=str(path))
            for path in sorted(UMBRELLA_PACKAGE.glob("*.py"))
            if path.stem not in ("__init__", "__main__", "cli")
        }

    def test_the_facades_are_exactly_the_documented_modules(self):
        self.assertEqual(
            sorted(f"{name.rpartition('.')[2]}.py"
                   for name in FACADE_NOTICE_OWNERS),
            sorted(self.facade_sources()))

    def test_no_facade_defines_a_class(self):
        for name, tree in sorted(self.facade_sources().items()):
            with self.subTest(module=name):
                self.assertEqual(
                    [], [node.name for node in ast.walk(tree)
                         if isinstance(node, ast.ClassDef)],
                    "a class here is a second definition of somebody's type")

    def test_no_facade_defines_a_function_but_the_lookup_hooks(self):
        for name, tree in sorted(self.facade_sources().items()):
            with self.subTest(module=name):
                defined = {node.name for node in ast.walk(tree)
                           if isinstance(node, (ast.FunctionDef,
                                                ast.AsyncFunctionDef))}
                self.assertEqual(set(), defined - self.ALLOWED_FUNCTIONS)

    def test_every_facade_declares_an_explicit_all(self):
        for name, tree in sorted(self.facade_sources().items()):
            with self.subTest(module=name):
                self.assertTrue(
                    any(isinstance(node, ast.Assign)
                        and any(getattr(target, "id", "") == "__all__"
                                for target in node.targets)
                        for node in tree.body),
                    "a facade without __all__ has no stated surface")

    def test_every_facade_warns_exactly_once_at_import(self):
        for name, tree in sorted(self.facade_sources().items()):
            with self.subTest(module=name):
                warns = [node for node in ast.walk(tree)
                         if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Attribute)
                         and node.func.attr == "warn"]
                self.assertEqual(1, len(warns))

    def test_no_facade_writes_to_a_stream(self):
        """``print`` and ``sys.stdout`` are both absent, not merely unused."""
        for name, tree in sorted(self.facade_sources().items()):
            with self.subTest(module=name):
                calls = [node.func.id for node in ast.walk(tree)
                         if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Name)]
                self.assertNotIn("print", calls)
                self.assertNotIn("sys", _import_roots(
                    analyze_source(
                        (UMBRELLA_PACKAGE / name).read_text(encoding="utf-8"),
                        package="admissible", filename=name)))


class FacadesReExportTheirOwner(unittest.TestCase):
    """One surface, one owner, one object."""

    IDENTITY = """
import json, sys
facade, owner, names = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
import importlib
facade_module = importlib.import_module(facade)
owner_module = importlib.import_module(owner)
sys.stdout.write(json.dumps({
    "same": {name: getattr(facade_module, name) is getattr(owner_module, name)
             for name in names},
    "facade_all": sorted(getattr(facade_module, "__all__", [])),
    "owner_all": sorted(getattr(owner_module, "__all__", [])),
}))
"""

    def probe(self, facade: str, owner: str, names: list[str]) -> dict:
        completed = run_python(self.IDENTITY, facade, owner, json.dumps(names))
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)

    def test_the_documented_names_are_the_owner_s_own_objects(self):
        for facade, owner, name in (
                ("admissible.config", "admissible_core.config", "load_config"),
                ("admissible.evidence", "admissible_core.evidence",
                 "ReviewEvidence"),
                ("admissible.identity", "admissible_core.identity",
                 "repository_identity"),
                ("admissible.ready", "admissible_ready.ready", "ReadyError"),
                ("admissible.receipt", "admissible_trust.receipt",
                 "WorkflowReceipt")):
            with self.subTest(facade=facade):
                report = self.probe(facade, owner, [name])
                self.assertEqual({name: True}, report["same"])

    def test_each_facade_re_exports_its_owner_s_whole_public_surface(self):
        for facade, owner in sorted(FACADE_OWNERS.items()):
            with self.subTest(facade=facade):
                report = self.probe(facade, owner, [])
                self.assertTrue(report["owner_all"], "the owner declares none")
                self.assertEqual(report["owner_all"], report["facade_all"])

    def test_every_re_exported_name_is_the_owner_s_object(self):
        for facade, owner in sorted(FACADE_OWNERS.items()):
            with self.subTest(facade=facade):
                names = self.probe(facade, owner, [])["owner_all"]
                report = self.probe(facade, owner, names)
                self.assertEqual({name: True for name in names},
                                 report["same"])

    def test_a_name_the_owner_does_not_export_is_an_attribute_error(self):
        for facade in sorted(FACADE_OWNERS):
            with self.subTest(facade=facade):
                completed = run_python(
                    f"import {facade} as facade\n"
                    "try:\n"
                    "    facade.no_such_name\n"
                    "except AttributeError:\n"
                    "    print('AttributeError')\n")
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual("AttributeError", completed.stdout.strip())


class TheSplitFacadeResolvesPerSymbol(unittest.TestCase):
    """``admissible.github``: one name at a time, to one half, by name.

    The evidence is ``sys.modules`` in a child process.  A symbol that reached
    the wrong half would have imported it, and no amount of matching output
    would hide that; a symbol that reached *both* would have reconnected the
    two authorities in one process, which is the outcome the whole split is
    arranged to prevent.
    """

    RESOLVE = """
import importlib, json, sys

name = sys.argv[1]
facade = importlib.import_module("admissible.github")
before = sorted(
    module for module in sys.modules
    if module.split(".")[0] in ("admissible_ready", "admissible_trust"))
value = getattr(facade, name)
owner = importlib.import_module(sys.argv[2])
sys.stdout.write(json.dumps({
    "before": before,
    "after": sorted(
        module for module in sys.modules
        if module.split(".")[0] in ("admissible_ready", "admissible_trust")),
    "same": value is getattr(owner, name),
    "callable": callable(value),
    "all": sorted(getattr(facade, "__all__", [])),
}))
"""

    REFUSED = """
import importlib, json, sys

name = sys.argv[1]
facade = importlib.import_module("admissible.github")
try:
    getattr(facade, name)
    raised = None
except AttributeError as error:
    raised = str(error)
sys.stdout.write(json.dumps({
    "raised": raised,
    "loaded": sorted(
        module.split(".")[0] for module in sys.modules
        if module.split(".")[0] in ("admissible_ready", "admissible_trust")),
}))
"""

    def resolve(self, name: str) -> dict:
        completed = run_python(self.RESOLVE, name, GITHUB_OWNERS[name])
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)

    def refuse(self, name: str) -> dict:
        completed = run_python(self.REFUSED, name)
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)

    def test_the_declared_surface_is_exactly_the_documented_names(self):
        report = self.resolve("evaluation_context")
        self.assertEqual(sorted(GITHUB_OWNERS), report["all"])

    def test_importing_the_facade_loads_neither_half(self):
        for name in sorted(GITHUB_OWNERS):
            with self.subTest(symbol=name):
                self.assertEqual([], self.resolve(name)["before"])

    def test_each_symbol_loads_its_own_half_and_only_that_half(self):
        for name, owner in sorted(GITHUB_OWNERS.items()):
            with self.subTest(symbol=name):
                report = self.resolve(name)
                loaded = {module.split(".")[0] for module in report["after"]}
                self.assertEqual({owner.split(".")[0]}, loaded)

    def test_no_symbol_ever_loads_the_opposite_package(self):
        for name, owner in sorted(GITHUB_OWNERS.items()):
            opposite = ({"admissible_ready", "admissible_trust"}
                        - {owner.split(".")[0]}).pop()
            with self.subTest(symbol=name, opposite=opposite):
                self.assertEqual(
                    [], [module for module in self.resolve(name)["after"]
                         if module.split(".")[0] == opposite])

    def test_each_symbol_is_its_half_s_own_callable(self):
        """Identity, not equivalence: one function, reachable by two names."""
        for name in sorted(GITHUB_OWNERS):
            with self.subTest(symbol=name):
                report = self.resolve(name)
                self.assertTrue(report["same"])
                self.assertTrue(report["callable"])

    def test_a_name_both_halves_define_fails_closed_naming_both(self):
        for name in AMBIGUOUS_GITHUB_NAMES:
            with self.subTest(symbol=name):
                report = self.refuse(name)
                self.assertIsNotNone(
                    report["raised"],
                    "a name with two owners must not resolve to one of them")
                for owner in GITHUB_TARGETS:
                    self.assertIn(owner, report["raised"])
                self.assertEqual([], report["loaded"],
                                 "refusing must not load a half either")

    def test_an_unknown_name_is_an_attribute_error(self):
        report = self.refuse("no_such_name")
        self.assertIsNotNone(report["raised"])
        self.assertIn("no_such_name", report["raised"])
        self.assertEqual([], report["loaded"])

    def test_an_undocumented_name_one_half_defines_is_still_refused(self):
        """``finalize`` is Trust's and ``preview_document`` is Ready's; neither
        is documented, so neither is promised, and a facade that answered them
        would be publishing a surface nobody wrote down."""
        for name in ("finalize", "preview_document", "approving_reviews",
                     "policy_anchor"):
            with self.subTest(symbol=name):
                report = self.refuse(name)
                self.assertIsNotNone(report["raised"])
                self.assertEqual([], report["loaded"])


class FacadesLoadOneDomainAtMost(unittest.TestCase):
    """Importing a compatibility name must not install an authority."""

    LOADED = """
import json, sys
import importlib
for name in json.loads(sys.argv[1]):
    importlib.import_module(name)
sys.stdout.write(json.dumps(sorted(
    name for name in sys.modules
    if name.split(".")[0] in ("admissible_ready", "admissible_trust"))))
"""

    def loaded(self, *names: str) -> set[str]:
        completed = run_python(self.LOADED, json.dumps(list(names)))
        self.assertEqual(0, completed.returncode, completed.stderr)
        return {name.split(".")[0] for name in json.loads(completed.stdout)}

    def test_importing_the_package_loads_no_domain_at_all(self):
        self.assertEqual(set(), self.loaded("admissible"))

    def test_the_kernel_facades_load_no_domain_at_all(self):
        for facade in ("admissible.config", "admissible.evidence",
                       "admissible.identity"):
            with self.subTest(facade=facade):
                self.assertEqual(set(), self.loaded(facade))

    def test_the_receipt_facade_loads_the_signing_distribution_alone(self):
        self.assertEqual({"admissible_trust"},
                         self.loaded("admissible.receipt"))

    def test_the_ready_facade_loads_the_candidate_distribution_alone(self):
        self.assertEqual({"admissible_ready"}, self.loaded("admissible.ready"))

    def test_both_facades_together_still_reach_no_runner(self):
        self.assertEqual({"admissible_trust"},
                         self.loaded("admissible.evidence",
                                     "admissible.receipt"))

    def test_importing_the_split_facade_loads_neither_domain(self):
        self.assertEqual(set(), self.loaded(GITHUB_FACADE))

    def test_every_facade_but_the_two_domain_ones_loads_nothing(self):
        """The equality, stated once over the whole set."""
        expected = {
            "admissible.config": set(),
            "admissible.evidence": set(),
            "admissible.github": set(),
            "admissible.identity": set(),
            "admissible.ready": {"admissible_ready"},
            "admissible.receipt": {"admissible_trust"},
        }
        self.assertEqual(sorted(expected), sorted(FACADE_NOTICE_OWNERS))
        for facade, domains in sorted(expected.items()):
            with self.subTest(facade=facade):
                self.assertEqual(domains, self.loaded(facade))

    def test_importing_the_dispatcher_loads_neither_domain(self):
        self.assertEqual(set(), self.loaded("admissible.cli"))


class FacadesDoNotContaminateMachineOutput(unittest.TestCase):
    """A deprecation notice is prose, and prose never goes on the wire."""

    SENTINEL = "the only thing this program prints"

    def imported(self, name: str):
        return run_python(f"import {name}\n"
                          "import sys\n"
                          f"sys.stdout.write({self.SENTINEL!r})\n")

    def test_importing_a_facade_writes_nothing_to_stdout(self):
        for name in sorted(FACADE_NOTICE_OWNERS):
            with self.subTest(facade=name):
                completed = self.imported(name)
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual(self.SENTINEL, completed.stdout)

    def test_the_deprecation_notice_is_a_warning_and_not_a_print(self):
        """Proved by turning warnings into errors: a print would survive it."""
        for name, owners in sorted(FACADE_NOTICE_OWNERS.items()):
            with self.subTest(facade=name):
                completed = run_python(
                    "import warnings, sys\n"
                    "warnings.simplefilter('error', DeprecationWarning)\n"
                    "try:\n"
                    f"    import {name}\n"
                    "except DeprecationWarning as raised:\n"
                    "    sys.stdout.write(str(raised))\n")
                self.assertEqual(0, completed.returncode, completed.stderr)
                for owner in owners:
                    self.assertIn(owner, completed.stdout)

    def test_the_notice_reaches_stderr_when_warnings_are_shown(self):
        for name, owners in sorted(FACADE_NOTICE_OWNERS.items()):
            with self.subTest(facade=name):
                completed = run_python(
                    "import warnings\n"
                    "warnings.simplefilter('always', DeprecationWarning)\n"
                    f"import {name}\n")
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual("", completed.stdout)
                for owner in owners:
                    self.assertIn(owner, completed.stderr)

    def test_the_notice_is_silenceable_the_way_a_warning_is(self):
        """A print cannot be filtered; this can, so it is not a print.

        The notice is attributed to the importer's own line -- ``stacklevel=2``
        -- which is why an ``import`` typed straight into ``python -c`` shows
        it: the default filters show a deprecation raised in ``__main__``.  A
        consumer that does not want it turns it off, and nothing here writes
        past the filter.
        """
        for name in sorted(FACADE_NOTICE_OWNERS):
            with self.subTest(facade=name):
                completed = run_python(
                    "import warnings\n"
                    "warnings.simplefilter('ignore', DeprecationWarning)\n"
                    f"import {name}\n")
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual("", completed.stdout)
                self.assertEqual("", completed.stderr)


class TrustedInfrastructureDoesNotUseTheFacades(unittest.TestCase):
    """Installing a facade installs the umbrella, and with it both domains."""

    def test_the_package_readme_states_the_prohibition(self):
        readme = (UMBRELLA_PROJECT / "README.md").read_text(encoding="utf-8")
        lowered = readme.lower()
        self.assertIn("forbidden", lowered)
        self.assertIn("trusted", lowered)
        self.assertIn("admissible-ready", readme)
        self.assertIn("admissible-trust", readme)

    def test_no_split_distribution_imports_the_compatibility_namespace(self):
        offenders = []
        for project in ("core", "ready", "trust"):
            root = REPO_ROOT / "packages" / project / "src"
            for path in sorted(root.rglob("*.py")):
                tree = ast.parse(path.read_text(encoding="utf-8"),
                                 filename=str(path))
                for node in ast.walk(tree):
                    modules = []
                    if isinstance(node, ast.Import):
                        modules = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom) and not node.level:
                        modules = [node.module or ""]
                    for module in modules:
                        if module == "admissible" or module.startswith(
                                "admissible."):
                            offenders.append(f"{path}: {module}")
        self.assertEqual([], offenders)

    def test_no_trusted_domain_test_reaches_through_a_facade(self):
        offenders = []
        for suite in ("core", "ready", "trust"):
            for path in sorted((REPO_ROOT / "tests" / suite).rglob("*.py")):
                text = path.read_text(encoding="utf-8")
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.startswith(("import admissible.",
                                            "from admissible.")):
                        offenders.append(f"{path.name}: {stripped}")
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
