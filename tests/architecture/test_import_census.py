"""Deterministic import census and authority-owner conformance test.

The census walks every ``*.py`` under the configured roots, parses the full
AST (imports inside function bodies included), and resolves each import to a
scanned module.  ``expected_module_owners.json`` is the manifest under test:
it classifies every scanned module into an authority owner, records explicit
umbrella/mixed transitional edges instead of waving them through, and pins the
target-state edge policy that later tasks must converge to.

Roots are scanned exactly once each.  Top-level roots are named relative to the
repository root, so ``admissible/ready.py`` is ``admissible.ready``.  Future
split packages live under ``packages/<dist>/src`` and are named relative to
that ``src`` directory, so ``packages/admissible-core/src/admissible_core/
journal.py`` is ``admissible_core.journal`` -- the name the code will actually
import, not a path-shaped stand-in.
"""

from __future__ import annotations

import ast
import json
import sys
import tempfile
import unittest
from fnmatch import fnmatch
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = Path(__file__).resolve().parent / "expected_module_owners.json"

# Top-level roots, named relative to the repository root.
TOP_LEVEL_ROOTS = ("admissible", "fcd", "rga", "atlas", "server", "tests")
# Future split distributions; each ``packages/*/src`` is its own naming base.
PACKAGES_DIR = "packages"

# Owner labels; production surfaces other than __init__ package markers.
CORE = "Core"
READY = "Ready"
TRUST = "Trust"
UMBRELLA = "Umbrella"
EXISTING_RESEARCH = "Existing Research Surface"
TEST = "Test Surface"
OWNERS = (CORE, READY, TRUST, UMBRELLA, EXISTING_RESEARCH, TEST)

# Owners that must map onto exactly one target import namespace.
NAMESPACE_OWNERS = (CORE, READY, TRUST, UMBRELLA)

TARGET_FORBIDDEN = (
    (READY, TRUST),
    (TRUST, READY),
    (CORE, READY),
    (CORE, TRUST),
)

# The only call shapes treated as dynamic imports or packaged-resource reads.
# Everything else is an ordinary function call and is deliberately ignored --
# classifying every ``ast.Call`` would drown the census in noise.
#
# Each supported call declares the exact parameters it is read through, as
# ``field -> (position, accepted keyword names)``.  Reading a parameter at its
# own position or under its own keyword, and nowhere else, is what keeps a
# file location from being recorded as a module name and a resource filename
# from being recorded as a package.  ``target`` is always the module or
# package the call reaches; the remaining fields are kept because they change
# what that target means.
DYNAMIC_IMPORT_CALLS = {
    "importlib.import_module": {
        "target": (0, ("name",)),
        # The anchor a relative ``name`` resolves against: without it
        # ``import_module(".journal", package=...)`` names nothing resolvable.
        "package": (1, ("package",)),
    },
    "__import__": {"target": (0, ("name",))},
    "importlib.util.spec_from_file_location": {
        # arg 0 is the module this call creates; arg 1 only says where its
        # source lives, and a path is not a module name.
        "target": (0, ("name",)),
        "location": (1, ("location",)),
    },
}
RESOURCE_MODULE = "importlib.resources"
# ``anchor`` is the modern spelling of the package parameter and ``package``
# the pre-3.12 one; both name the same thing.
_ANCHOR = {"target": (0, ("anchor", "package"))}
RESOURCE_CALLS = {
    # ``as_file`` takes a Traversable, never a package, so it records no
    # target rather than a plausible-looking wrong one.
    "as_file": {"target": None},
    "contents": _ANCHOR,
    "files": _ANCHOR,
    "is_resource": _ANCHOR,
    "open_binary": _ANCHOR,
    "open_text": _ANCHOR,
    "path": _ANCHOR,
    "read_binary": _ANCHOR,
    "read_text": _ANCHOR,
}


class DuplicateModuleError(RuntimeError):
    """Two scanned files claim the same dotted module name."""


def declared_scan_roots() -> list[str]:
    """The scan-root contract, spelled the way the manifest records it.

    Deterministic and derived: the top-level roots in declaration order,
    followed by the one pattern every split distribution is scanned under.
    """
    return [*TOP_LEVEL_ROOTS, f"{PACKAGES_DIR}/*/src"]


def _scan_roots() -> list[tuple[Path, Path]]:
    """``(base, root)`` pairs to scan; ``base`` is the module-naming base.

    ``packages/`` is never scanned as a top-level root, so a file under
    ``packages/<dist>/src`` is visited once, under its own naming base.
    """
    roots: list[tuple[Path, Path]] = []
    for name in TOP_LEVEL_ROOTS:
        root = REPO_ROOT / name
        if root.is_dir():
            roots.append((REPO_ROOT, root))
    packages = REPO_ROOT / PACKAGES_DIR
    if packages.is_dir():
        for distribution in sorted(p for p in packages.iterdir() if p.is_dir()):
            src = distribution / "src"
            if src.is_dir():
                roots.append((src, src))
    return roots


def _module_name(path: Path, base: Path) -> str:
    """Dotted module path relative to its naming base.

    ``__init__.py`` names the package itself, so ``atlas/tests/__init__.py`` is
    ``atlas.tests`` rather than ``atlas.tests.__init__``.
    """
    relative = path.relative_to(base).with_suffix("")
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve(name: str, scanned: set[str]) -> str | None:
    """Map an imported dotted name onto a scanned module or None (external)."""
    parts = name.split(".")
    for size in range(len(parts), 0, -1):
        candidate = ".".join(parts[:size])
        if candidate in scanned:
            return candidate
    return None


def _alias_bindings(tree: ast.AST) -> dict[str, str]:
    """Local name -> fully qualified module, for import statements.

    ``from importlib import resources`` binds ``resources`` to
    ``importlib.resources``; without this the resource calls below would be
    invisible.
    """
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bindings[alias.asname] = alias.name
                else:
                    root = alias.name.split(".")[0]
                    bindings[root] = root
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                bindings[alias.asname or alias.name] = (
                    f"{node.module}.{alias.name}"
                )
    return bindings


def _dotted_callee(func: ast.AST) -> str | None:
    """Dotted callee name for an attribute/name call, else None."""
    parts: list[str] = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _dynamic_call(
    func: ast.AST, bindings: dict[str, str]
) -> tuple[str, dict] | None:
    """``(qualified callee, parameter signature)`` for a supported call."""
    dotted = _dotted_callee(func)
    if dotted is None:
        return None
    head, separator, rest = dotted.partition(".")
    base = bindings.get(head, head)
    qualified = f"{base}.{rest}" if separator else base
    if qualified in DYNAMIC_IMPORT_CALLS:
        return qualified, DYNAMIC_IMPORT_CALLS[qualified]
    prefix, _, attribute = qualified.rpartition(".")
    if prefix == RESOURCE_MODULE and attribute in RESOURCE_CALLS:
        return qualified, RESOURCE_CALLS[attribute]
    return None


def _literal(node: ast.expr | None) -> str | None:
    """The string a node spells outright, or None if it is computed."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _parameter(call: ast.Call, slot: tuple[int, tuple[str, ...]] | None) -> str | None:
    """String literal bound to one positional-or-keyword parameter, else None.

    The parameter is read at its own position or under one of its own
    keywords and nowhere else, so ``import_module(name="x")`` reads exactly
    like ``import_module("x")`` and neither reads a neighbouring argument.
    ``*args`` at or before the position makes that position unknowable, and
    unknowable is None rather than a guess.
    """
    if slot is None:
        return None
    index, keywords = slot
    if any(isinstance(arg, ast.Starred) for arg in call.args[: index + 1]):
        return None
    if index < len(call.args):
        return _literal(call.args[index])
    for keyword in call.keywords:
        if keyword.arg in keywords:
            return _literal(keyword.value)
    return None


def analyze_source(source: str, *, package: str = "",
                   filename: str = "<census>") -> dict:
    """Census entry for one module's source text.

    Separate from :func:`census` so the supported call shapes can be proved
    against synthetic sources: this tree spells every one of them
    positionally, so a keyword-form regression would stay invisible until
    some future module used one.
    """
    entry: dict = {
        "package": package,
        "imports": [],
        "dynamic": [],
        "resource_packages": [],
    }
    tree = ast.parse(source, filename=filename)
    bindings = _alias_bindings(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                entry["imports"].append(
                    {"module": alias.name, "level": 0, "names": []}
                )
        elif isinstance(node, ast.ImportFrom):
            entry["imports"].append(
                {
                    # ``module`` stays None for ``from . import x``.
                    "module": node.module,
                    "level": node.level,
                    "names": [a.name for a in node.names],
                }
            )
        elif isinstance(node, ast.Call):
            call = _dynamic_call(node.func, bindings)
            if call is None:
                continue
            what, signature = call
            record = {"what": what}
            for field, slot in signature.items():
                record[field] = _parameter(node, slot)
            entry["dynamic"].append(record)
            if record["target"] is not None and what.startswith(RESOURCE_MODULE):
                entry["resource_packages"].append(record["target"])
    return entry


def census() -> dict[str, dict]:
    """Import graph of every scanned module keyed by dotted module name.

    A dotted name claimed twice raises :class:`DuplicateModuleError` naming
    both source files.  Keying on the name means the second file would
    otherwise overwrite the first, and a module dropped this way takes its
    edges and its owner with it while every manifest assertion still balances.
    Identical bytes are not an exception: two files are two modules, and which
    one wins at import time is the ambiguity being rejected.
    """
    modules: dict[str, dict] = {}
    sources: dict[str, Path] = {}
    for base, root in _scan_roots():
        for path in sorted(root.rglob("*.py")):
            if ".venv" in path.parts:
                continue
            name = _module_name(path, base)
            if name in sources:
                raise DuplicateModuleError(
                    f"duplicate module {name!r} claimed by two source files: "
                    f"{sources[name]} and {path}"
                )
            sources[name] = path
            # Anchor for relative imports: a package anchors on itself, a
            # plain module on its parent package.
            package = (
                name if path.name == "__init__.py" else name.rpartition(".")[0]
            )
            modules[name] = analyze_source(
                path.read_text(encoding="utf-8"),
                package=package,
                filename=str(path),
            )
    return modules


def _edge_targets(imp: dict, entry: dict, scanned: set[str]) -> set[str]:
    """Scanned modules reached by one import statement.

    The deepest resolution wins: ``from . import evidence`` is an edge to
    ``admissible.evidence``, not to the ``admissible`` package marker, so a
    namespace shell does not collect an edge from every sibling.  ``from pkg
    import SomeClass`` still records ``pkg``, because that is the real target.

    A named child is resolved whether or not its parent is itself a scanned
    module.  Under PEP 420 a ``packages/*/src`` distribution need not ship a
    package ``__init__.py``, and resolving only through the parent would drop
    every intra-package edge such a distribution has.
    """
    module = imp.get("module")
    level = imp.get("level") or 0
    names = imp.get("names") or []
    if level:
        anchor = entry["package"].split(".")
        trimmed = anchor[: len(anchor) - (level - 1)]
        prefix = ".".join(trimmed)
        absolute = f"{prefix}.{module}" if module else prefix
    else:
        absolute = module
    if not absolute:
        return set()
    submodules = {
        f"{absolute}.{name}"
        for name in names
        if f"{absolute}.{name}" in scanned
    }
    if submodules:
        return submodules
    base = _resolve(absolute, scanned)
    return {base} if base is not None else set()


def _absolute_dynamic(record: dict, entry: dict) -> str | None:
    """Absolute module a dynamic import names, or None if it is not literal.

    ``import_module(".journal", package="admissible_core")`` reaches
    ``admissible_core.journal``; the anchor is the call's own ``package``
    argument when it gives one, and the importing module's package otherwise.
    """
    target = record.get("target")
    if not target:
        return None
    if not target.startswith("."):
        return target
    stripped = target.lstrip(".")
    level = len(target) - len(stripped)
    anchor = record.get("package") or entry["package"]
    parts = anchor.split(".") if anchor else []
    prefix = ".".join(parts[: len(parts) - (level - 1)])
    if not prefix:
        return None
    return f"{prefix}.{stripped}" if stripped else prefix


def module_edges(modules: dict[str, dict]) -> dict[str, list[str]]:
    """Observed importer -> sorted scanned targets, self-edges dropped."""
    scanned = set(modules)
    observed: dict[str, list[str]] = {}
    for name, entry in sorted(modules.items()):
        edges: set[str] = set()
        for imp in entry["imports"]:
            edges |= _edge_targets(imp, entry, scanned)
        for dyn in entry["dynamic"]:
            absolute = _absolute_dynamic(dyn, entry)
            if absolute:
                resolved = _resolve(absolute, scanned)
                if resolved:
                    edges.add(resolved)
        edges.discard(name)
        if edges:
            observed[name] = sorted(edges)
    return observed


def _owner_of(name: str, manifest: dict) -> str | None:
    owners = manifest["module_owners"]
    if name in owners:
        return owners[name]
    for prefix in sorted(owners, key=len, reverse=True):
        if name.startswith(prefix + "."):
            return owners[prefix]
    return None


def invalid_target_owners(manifest: dict) -> dict[str, str]:
    """``target_owners`` entries whose owner is not a namespace owner label.

    ``TARGET_FORBIDDEN`` matches on owner pairs, so an owner label the policy
    does not know silently exempts that module from every forbidden-edge
    check.  Unknown labels are therefore a manifest error, not a no-op.
    """
    return {
        name: owner
        for name, owner in manifest["target_policy"]["target_owners"].items()
        if owner not in NAMESPACE_OWNERS
    }


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


CLI_PATH = REPO_ROOT / "admissible" / "cli.py"


def cli_tree() -> ast.Module:
    """Parsed ``admissible/cli.py``; the only source the CLI facts come from."""
    return ast.parse(CLI_PATH.read_text(encoding="utf-8"), filename=str(CLI_PATH))


def _function_defs(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    return {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }


def _keyword_literal(call: ast.Call, name: str) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return _literal(keyword.value)
    return None


def command_hierarchy(tree: ast.Module) -> list[dict]:
    """Parser tree of ``_build_parser``: one record per subparsers group.

    Read off the construction calls in source order, so ``policy trust`` is
    recorded as a child of ``policy`` under its own ``policy_command`` dest
    rather than flattened in with the top-level commands it is not one of.
    Each record is ``{"path", "dest", "commands"}``, ``path`` being the
    enclosing commands (empty at the top level).
    """
    builder = _function_defs(tree)["_build_parser"]
    # Which call each variable is bound to, so ``policy = commands.add_parser(
    # "policy")`` makes ``policy`` a parser whose own subparsers nest under it.
    assigned = {
        id(node.value): node.targets[0].id
        for node in ast.walk(builder)
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    }
    parsers: dict[str, tuple[str, ...]] = {}
    groups: dict[str, tuple[str, ...]] = {}
    found: dict[tuple[str, ...], tuple[str | None, set[str]]] = {}
    calls = sorted(
        (node for node in ast.walk(builder) if isinstance(node, ast.Call)),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for call in calls:
        variable = assigned.get(id(call))
        function = call.func
        if isinstance(function, ast.Name) and function.id == "_Parser":
            if variable:
                parsers[variable] = ()
            continue
        if not isinstance(function, ast.Attribute):
            continue
        if not isinstance(function.value, ast.Name):
            continue
        owner = function.value.id
        if function.attr == "add_subparsers" and owner in parsers and variable:
            path = parsers[owner]
            groups[variable] = path
            found[path] = (_keyword_literal(call, "dest"), set())
        elif function.attr == "add_parser" and owner in groups:
            path = groups[owner]
            name = _parameter(call, (0, ("name",)))
            if name is None:
                continue
            found[path][1].add(name)
            if variable:
                parsers[variable] = path + (name,)
    return [
        {"path": list(path), "dest": dest, "commands": sorted(names)}
        for path, (dest, names) in sorted(found.items())
    ]


def dispatch_map(tree: ast.Module) -> dict[str, str]:
    """``_COMMANDS`` read from the AST: top-level command -> handler name."""
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Dict):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "_COMMANDS"
            for target in node.targets
        ):
            continue
        return {
            key.value: _dotted_callee(value)
            for key, value in zip(node.value.keys, node.value.values)
            if _literal(key) is not None
        }
    raise AssertionError("admissible.cli must define a _COMMANDS map")


def _returned_callee(body: list[ast.stmt]) -> str | None:
    for statement in body:
        if isinstance(statement, ast.Return) and isinstance(statement.value, ast.Call):
            return _dotted_callee(statement.value.func)
    return None


def _reads_dest(node: ast.expr, dest: str) -> bool:
    """``getattr(options, "<dest>", ...)`` or ``options.<dest>``."""
    if isinstance(node, ast.Attribute):
        return node.attr == dest
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and _literal(node.args[1]) == dest
    )


def _subcommand_branches(function: ast.FunctionDef, dest: str) -> dict[str, str]:
    """Sub-command -> the function that actually runs it, read off branches.

    ``if sub == "revoke": return _command_policy_revoke(...)`` binds a callee.
    ``if sub != "trust": return _fail(...)`` binds no new callee: it rejects
    every other sub-command, which is precisely how the dispatcher says it
    handles ``trust`` itself, inline, in the rest of its own body.
    """
    reads = {
        target.id
        for node in ast.walk(function)
        if isinstance(node, ast.Assign) and _reads_dest(node.value, dest)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    branches: dict[str, str] = {}
    for node in ast.walk(function):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        test = node.test
        if len(test.ops) != 1 or len(test.comparators) != 1:
            continue
        left = test.left
        if not (isinstance(left, ast.Name) and left.id in reads) and not _reads_dest(
            left, dest
        ):
            continue
        value = _literal(test.comparators[0])
        if value is None:
            continue
        if isinstance(test.ops[0], ast.Eq):
            callee = _returned_callee(node.body)
            if callee is not None:
                branches[value] = callee
        elif isinstance(test.ops[0], ast.NotEq):
            branches[value] = function.name
    return branches


def nested_dispatch(tree: ast.Module) -> dict[str, str]:
    """``"policy trust"`` -> the function that runs it, derived from the AST.

    The parent command's handler comes from ``_COMMANDS``; that function's
    body is then read for branches over the dest the parser declared for its
    sub-commands.  Nothing here is a list of names typed a second time, so a
    sub-command that stopped dispatching would show up as a missing key.
    """
    functions = _function_defs(tree)
    handlers = dispatch_map(tree)
    mapping: dict[str, str] = {}
    # Records are sorted by path, so a parent is always resolved before the
    # groups nested inside it.
    for record in command_hierarchy(tree):
        path = tuple(record["path"])
        if not path:
            continue
        prefix = " ".join(path)
        parent = handlers.get(path[0]) if len(path) == 1 else mapping.get(prefix)
        if parent is None or parent not in functions:
            continue
        branches = _subcommand_branches(functions[parent], record["dest"])
        for name, callee in branches.items():
            mapping[f"{prefix} {name}"] = callee
    return mapping


class ImportCensus(unittest.TestCase):
    def test_every_scanned_module_is_classified(self):
        manifest = load_manifest()
        modules = census()
        unclassified = [
            name for name in sorted(modules) if _owner_of(name, manifest) is None
        ]
        self.assertEqual([], unclassified, "unclassified scanned modules")

    def test_module_owners_match_scanned_modules_exactly(self):
        """No stale manifest rows and no unclassified new modules."""
        manifest = load_manifest()
        modules = census()
        self.assertEqual(sorted(modules), sorted(manifest["module_owners"]))

    def test_owners_use_only_known_labels(self):
        manifest = load_manifest()
        bad = {
            name: owner
            for name, owner in manifest["module_owners"].items()
            if owner not in OWNERS
        }
        self.assertEqual({}, bad, "unknown owner labels in manifest")

    def test_manifest_pins_base_commit_and_tree(self):
        meta = load_manifest()["metadata"]
        self.assertEqual(
            "76ad2950c53c82e105aabe2be345f5ce1ef5e910", meta["base_commit"]
        )
        self.assertEqual(
            "67a63b597d670cc9f66b9169ac92d90deb7b8ee7", meta["base_tree"]
        )

    def test_manifest_enumerates_cli_surface(self):
        manifest = load_manifest()
        cli = manifest["cli_surface"]
        modules = census()
        self.assertIn("admissible.cli", modules, "admissible/cli.py must be scanned")

        # Both halves come from the parsed CLI, the single source of truth for
        # the command surface; a regex over the source would only re-derive
        # the same facts more fragilely.
        tree = cli_tree()
        add_parser = sorted(
            {name for record in command_hierarchy(tree) for name in record["commands"]}
        )
        self.assertEqual(add_parser, cli["add_parser_commands"])

        handler_map = dispatch_map(tree)
        self.assertEqual(handler_map, cli["commands_map"])
        # Every dispatchable command must also be a declared subparser.
        self.assertEqual(
            sorted(handler_map), sorted(cli["dispatched_commands"])
        )
        self.assertEqual([], sorted(set(handler_map) - set(add_parser)),
                         "handler map keys must all be declared subparsers")

    def test_target_policy_namespaces_are_unique(self):
        """Core/Ready/Trust/Umbrella each own exactly one import namespace."""
        namespaces = load_manifest()["target_policy"]["namespaces"]
        self.assertEqual(sorted(NAMESPACE_OWNERS), sorted(namespaces))
        self.assertEqual(
            len(namespaces), len(set(namespaces.values())),
            "namespaces must be unique per owner",
        )

    def test_target_edge_policy(self):
        manifest = load_manifest()
        target_policy = manifest["target_policy"]
        self.assertEqual(
            sorted(TARGET_FORBIDDEN),
            sorted(tuple(edge) for edge in target_policy["forbidden_edges"]),
        )
        target_owners = target_policy["target_owners"]
        # The umbrella distribution survives as a dispatcher, but it owns no
        # module: once the split lands every module maps to a unique namespace.
        umbrella = [
            name for name, owner in target_owners.items() if owner == UMBRELLA
        ]
        self.assertEqual([], umbrella, "target policy must not keep umbrella owners")
        # The target policy governs exactly the modules that carry authority
        # today; research and test surfaces stay outside the namespace split.
        self.assertEqual(
            sorted(
                name
                for name, owner in manifest["module_owners"].items()
                if owner in NAMESPACE_OWNERS
            ),
            sorted(target_owners),
            "every authority-owned module needs a target owner",
        )

    def test_current_edges_match_manifest_exactly(self):
        """Census edges equal manifest edges; no silent drift in either direction."""
        manifest = load_manifest()
        recorded: dict[str, list] = manifest["current_edges"]
        observed = module_edges(census())

        self.assertEqual(
            sorted(recorded),
            sorted(observed),
            "manifest current_edges keys must match observed importers",
        )
        for importer in sorted(observed):
            self.assertEqual(
                sorted(recorded[importer]),
                observed[importer],
                f"current_edges drift for {importer}",
            )

    def test_umbrella_and_transitional_edges_are_explicit_and_bounded(self):
        """Mixed modules keep honest Umbrella classification plus bounded waivers."""
        manifest = load_manifest()
        owners = manifest["module_owners"]
        self.assertEqual(UMBRELLA, owners.get("admissible.ready"))
        self.assertEqual(UMBRELLA, owners.get("admissible.cli"))

        transitional = manifest["transitional_edges"]
        recorded = manifest["current_edges"]
        target_owners = manifest["target_policy"]["target_owners"]
        forbidden = {tuple(e) for e in manifest["target_policy"]["forbidden_edges"]}
        for source, target in transitional["allowed"]:
            self.assertIn(target, recorded.get(source, []),
                          f"transitional edge {source}->{target} not observed")
            # Target-owner view of the same edge must be forbidden; that is
            # exactly what makes the waiver transitional rather than permanent.
            pair = (target_owners.get(source), target_owners.get(target))
            self.assertIn(
                pair, forbidden,
                f"transitional edge {source}->{target} is not target-forbidden",
            )
        # Umbrella classification and the waiver list must name the same modules.
        for module in ("admissible.ready", "admissible.cli"):
            self.assertIn(module, transitional["modules"])
        self.assertEqual(
            sorted(transitional["modules"]),
            sorted(m for m, o in owners.items() if o == UMBRELLA),
        )
        # Waivers are bounded: every waived source is an enumerated mixed module.
        outside = sorted(
            {s for s, _ in transitional["allowed"]} - set(transitional["modules"])
        )
        self.assertEqual([], outside, "waivers outside the mixed-module set")

    def test_no_target_forbidden_edges_outside_transitional_waivers(self):
        """Under CURRENT ownership the only forbidden-owner edges allowed are the
        explicitly enumerated transitional waivers."""
        manifest = load_manifest()
        transitional = {
            (source, target)
            for source, target in manifest["transitional_edges"]["allowed"]
        }
        violations = []
        for name, targets in sorted(module_edges(census()).items()):
            src_owner = _owner_of(name, manifest)
            for target in targets:
                dst_owner = _owner_of(target, manifest)
                if (src_owner, dst_owner) in TARGET_FORBIDDEN and (
                    name,
                    target,
                ) not in transitional:
                    violations.append(
                        f"{name} ({src_owner}) -> {target} ({dst_owner})"
                    )
        self.assertEqual([], violations)

    def test_target_ownership_forbids_ready_trust_and_core_dependence(self):
        """The waived edges are the complete set of target-policy violations."""
        manifest = load_manifest()
        target_owners = manifest["target_policy"]["target_owners"]
        waived = {
            (source, target)
            for source, target in manifest["transitional_edges"]["allowed"]
        }
        remaining = []
        for name, targets in sorted(module_edges(census()).items()):
            for target in targets:
                pair = (target_owners.get(name), target_owners.get(target))
                if pair in TARGET_FORBIDDEN and (name, target) not in waived:
                    remaining.append(f"{name} -> {target} {pair}")
        self.assertEqual([], remaining, "unwaived target-policy violations")

    def test_dynamic_imports_are_recorded_not_ignored(self):
        """Literal dynamic targets resolve into current_edges; unresolved ones are
        kept as explicit dynamic entries in the manifest."""
        manifest = load_manifest()
        modules = census()
        dynamic = {
            name: entry["dynamic"]
            for name, entry in sorted(modules.items())
            if entry["dynamic"]
        }
        self.assertEqual(
            sorted(manifest["dynamic_imports"]), sorted(dynamic),
            "dynamic import entries must match manifest exactly",
        )
        key = lambda entry: (entry["what"], entry["target"] or "")  # noqa: E731
        for name, entries in dynamic.items():
            self.assertEqual(
                sorted(entries, key=key),
                sorted(manifest["dynamic_imports"][name], key=key),
                f"dynamic import drift for {name}",
            )

    def test_resource_package_ownership_is_recorded(self):
        manifest = load_manifest()
        modules = census()
        observed = {
            name: sorted(entry["resource_packages"])
            for name, entry in sorted(modules.items())
            if entry["resource_packages"]
        }
        self.assertEqual(
            observed,
            {k: sorted(v) for k, v in manifest["resource_packages"].items()},
        )


class ImplicitNamespacePackages(unittest.TestCase):
    """A ``packages/*/src`` distribution need not ship package ``__init__.py``.

    Under PEP 420 a directory with no ``__init__.py`` is still an importable
    package, so ``from . import helper`` is a real edge to
    ``<package>.helper`` even though ``<package>`` itself is not a scanned
    module.  Resolving only through the parent would silently drop every
    intra-package edge of a future split distribution -- the exact graph the
    census exists to prove.
    """

    def test_relative_import_reaches_child_of_unscanned_package(self):
        scanned = {"admissible_core.helper", "admissible_core.user"}
        entry = {"package": "admissible_core"}
        self.assertEqual(
            {"admissible_core.helper"},
            _edge_targets(
                {"module": None, "level": 1, "names": ["helper"]}, entry, scanned
            ),
        )

    def test_relative_import_of_absent_child_is_not_invented(self):
        scanned = {"admissible_core.user"}
        entry = {"package": "admissible_core"}
        self.assertEqual(
            set(),
            _edge_targets(
                {"module": None, "level": 1, "names": ["missing"]}, entry, scanned
            ),
        )

    def test_census_of_a_package_root_without_any_init(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            package = root / PACKAGES_DIR / "admissible-core" / "src" / "admissible_core"
            package.mkdir(parents=True)
            (package / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
            (package / "user.py").write_text(
                "from . import helper\n\nUSES = helper.VALUE\n", encoding="utf-8"
            )
            self.assertEqual([], sorted(package.rglob("__init__.py")))
            with mock.patch.object(sys.modules[__name__], "REPO_ROOT", root):
                modules = census()
                edges = module_edges(modules)
        self.assertEqual(
            ["admissible_core.helper", "admissible_core.user"], sorted(modules)
        )
        self.assertEqual({"admissible_core.user": ["admissible_core.helper"]}, edges)


class DynamicCallArguments(unittest.TestCase):
    """Call shapes are read off the exact parameter, positional or keyword.

    The real tree only uses the positional spellings today, so every keyword
    form here is synthetic: without these the parser could quietly stop seeing
    ``import_module(name="x")`` and no existing module would notice.
    """

    def dynamic(self, source: str) -> list[dict]:
        return analyze_source(source)["dynamic"]

    def test_import_module_name_positional_and_keyword(self):
        expected = [
            {"what": "importlib.import_module", "target": "x", "package": None}
        ]
        self.assertEqual(
            expected, self.dynamic("import importlib\nimportlib.import_module('x')\n")
        )
        self.assertEqual(
            expected,
            self.dynamic("import importlib\nimportlib.import_module(name='x')\n"),
        )

    def test_import_module_keeps_the_relative_anchor_package(self):
        self.assertEqual(
            [{
                "what": "importlib.import_module",
                "target": ".journal",
                "package": "admissible_core",
            }],
            self.dynamic(
                "import importlib\n"
                "importlib.import_module('.journal', 'admissible_core')\n"
            ),
        )
        self.assertEqual(
            [{
                "what": "importlib.import_module",
                "target": ".journal",
                "package": "admissible_core",
            }],
            self.dynamic(
                "import importlib\n"
                "importlib.import_module('.journal', package='admissible_core')\n"
            ),
        )

    def test_relative_dynamic_import_resolves_against_its_anchor(self):
        modules = {
            "admissible_core.journal": {
                "package": "admissible_core",
                "imports": [],
                "dynamic": [],
                "resource_packages": [],
            },
            "admissible_core.loader": {
                "package": "admissible_core",
                "imports": [],
                "dynamic": [{
                    "what": "importlib.import_module",
                    "target": ".journal",
                    "package": "admissible_core",
                }],
                "resource_packages": [],
            },
        }
        self.assertEqual(
            {"admissible_core.loader": ["admissible_core.journal"]},
            module_edges(modules),
        )

    def test_dunder_import_name_positional_and_keyword(self):
        expected = [{"what": "__import__", "target": "x"}]
        self.assertEqual(expected, self.dynamic("__import__('x')\n"))
        self.assertEqual(expected, self.dynamic("__import__(name='x')\n"))

    def test_spec_from_file_location_records_the_module_name(self):
        """arg0 is the module this call creates; arg1 is only where it lives."""
        expected = [{
            "what": "importlib.util.spec_from_file_location",
            "target": "paper_build",
            "location": "scripts/paper_build.py",
        }]
        self.assertEqual(
            expected,
            self.dynamic(
                "import importlib.util\n"
                "importlib.util.spec_from_file_location("
                "'paper_build', 'scripts/paper_build.py')\n"
            ),
        )
        self.assertEqual(
            expected,
            self.dynamic(
                "import importlib.util\n"
                "importlib.util.spec_from_file_location("
                "name='paper_build', location='scripts/paper_build.py')\n"
            ),
        )

    def test_resource_anchor_positional_and_keyword(self):
        for call in (
            "resources.files('protocol')",
            "resources.files(anchor='protocol')",
            "resources.files(package='protocol')",
        ):
            with self.subTest(call=call):
                entry = analyze_source(f"from importlib import resources\n{call}\n")
                self.assertEqual(
                    [{"what": "importlib.resources.files", "target": "protocol"}],
                    entry["dynamic"],
                )
                self.assertEqual(["protocol"], entry["resource_packages"])

    def test_resource_read_text_anchor_is_not_the_resource_name(self):
        entry = analyze_source(
            "from importlib import resources\n"
            "resources.read_text('protocol', 'schema.json')\n"
        )
        self.assertEqual(["protocol"], entry["resource_packages"])

    def test_as_file_takes_a_traversable_and_names_no_package(self):
        entry = analyze_source(
            "from importlib import resources\nresources.as_file('whatever')\n"
        )
        self.assertEqual(
            [{"what": "importlib.resources.as_file", "target": None}],
            entry["dynamic"],
        )
        self.assertEqual([], entry["resource_packages"])

    def test_non_literal_arguments_stay_unresolved(self):
        self.assertEqual(
            [{"what": "importlib.import_module", "target": None, "package": None}],
            self.dynamic("import importlib\nimportlib.import_module(name)\n"),
        )
        self.assertEqual(
            [{
                "what": "importlib.util.spec_from_file_location",
                "target": None,
                "location": None,
            }],
            self.dynamic(
                "import importlib.util\n"
                "importlib.util.spec_from_file_location(name, path)\n"
            ),
        )


class CliCommandHierarchy(unittest.TestCase):
    """Nested commands are bound to the branch that actually runs them.

    ``policy trust``/``revoke``/``list`` are subparsers of ``policy``, so they
    never appear in ``_COMMANDS``; a flat name list cannot tell whether they
    dispatch anywhere at all.  Both halves below are derived from the parsed
    ``admissible/cli.py``, never retyped.
    """

    def tree(self) -> ast.Module:
        return cli_tree()

    def test_hierarchy_matches_manifest(self):
        manifest = load_manifest()
        derived = command_hierarchy(self.tree())
        self.assertEqual(manifest["cli_surface"]["command_hierarchy"], derived)

    def test_hierarchy_names_the_policy_subparser_and_its_dest(self):
        records = {tuple(r["path"]): r for r in command_hierarchy(self.tree())}
        self.assertEqual("command", records[()]["dest"])
        self.assertEqual(["list", "revoke", "trust"], records[("policy",)]["commands"])
        self.assertEqual("policy_command", records[("policy",)]["dest"])

    def test_top_level_parsers_are_exactly_the_dispatch_map(self):
        tree = self.tree()
        records = {tuple(r["path"]): r for r in command_hierarchy(tree)}
        self.assertEqual(sorted(dispatch_map(tree)), records[()]["commands"])

    def test_ast_dispatch_map_agrees_with_the_manifest(self):
        self.assertEqual(
            load_manifest()["cli_surface"]["commands_map"], dispatch_map(self.tree())
        )

    def test_flat_add_parser_names_are_the_hierarchy_flattened(self):
        cli = load_manifest()["cli_surface"]
        flattened = sorted(
            {name for r in command_hierarchy(self.tree()) for name in r["commands"]}
        )
        self.assertEqual(cli["add_parser_commands"], flattened)

    def test_nested_dispatch_matches_manifest(self):
        manifest = load_manifest()
        self.assertEqual(
            manifest["cli_surface"]["nested_dispatch"], nested_dispatch(self.tree())
        )

    def test_every_nested_command_dispatches_to_a_real_function(self):
        tree = self.tree()
        derived = nested_dispatch(tree)
        expected = sorted(
            " ".join(list(record["path"]) + [name])
            for record in command_hierarchy(tree)
            if record["path"]
            for name in record["commands"]
        )
        self.assertEqual(expected, sorted(derived))
        self.assertEqual(
            ["policy list", "policy revoke", "policy trust"], sorted(derived)
        )
        defined = {
            node.name for node in tree.body if isinstance(node, ast.FunctionDef)
        }
        self.assertEqual([], sorted(set(derived.values()) - defined))
        # ``policy trust`` has no callee of its own: the dispatcher handles it
        # inline after rejecting every other sub-command.
        self.assertEqual("_command_policy", derived["policy trust"])
        self.assertEqual("_command_policy_revoke", derived["policy revoke"])
        self.assertEqual("_command_policy_list", derived["policy list"])


class CensusRejectsDuplicateModules(unittest.TestCase):
    """Two files claiming one dotted name is a census failure, never a merge.

    ``census()`` keys on the dotted name, so a second file with the same name
    would overwrite the first and the census would silently under-report a
    module, its edges and its owner -- the manifest would still balance.
    """

    def build(self, root: Path, relative: str, source: str = "VALUE = 1\n") -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def census_of(self, root: Path) -> dict[str, dict]:
        with mock.patch.object(sys.modules[__name__], "REPO_ROOT", root):
            return census()

    def assert_duplicate(self, root: Path, module: str, first: Path, second: Path):
        with self.assertRaises(DuplicateModuleError) as caught:
            self.census_of(root)
        message = str(caught.exception)
        self.assertIn(module, message)
        for path in (first, second):
            self.assertIn(str(path), message)

    def test_two_split_roots_yielding_the_same_module(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first = self.build(
                root, f"{PACKAGES_DIR}/admissible-core/src/admissible_core/journal.py"
            )
            second = self.build(
                root,
                f"{PACKAGES_DIR}/admissible-forked/src/admissible_core/journal.py",
                "VALUE = 2\n",
            )
            self.assert_duplicate(root, "admissible_core.journal", first, second)

    def test_top_level_and_split_package_collision(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first = self.build(root, "admissible/ready.py")
            second = self.build(
                root, f"{PACKAGES_DIR}/admissible/src/admissible/ready.py", "VALUE = 2\n"
            )
            self.assert_duplicate(root, "admissible.ready", first, second)

    def test_identical_bytes_are_still_a_duplicate(self):
        """Equal contents do not make two source files one module."""
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = "from . import helper\n"
            first = self.build(
                root, f"{PACKAGES_DIR}/a/src/admissible_core/user.py", source
            )
            second = self.build(
                root, f"{PACKAGES_DIR}/b/src/admissible_core/user.py", source
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assert_duplicate(root, "admissible_core.user", first, second)

    def test_symlinked_distribution_alias_is_a_duplicate(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            real = self.build(
                root, f"{PACKAGES_DIR}/admissible-core/src/admissible_core/journal.py"
            )
            alias = root / PACKAGES_DIR / "admissible-alias"
            try:
                alias.symlink_to(root / PACKAGES_DIR / "admissible-core")
            except (OSError, NotImplementedError) as error:  # pragma: no cover
                self.skipTest(f"symlinks unsupported here: {error}")
            aliased = alias / "src" / "admissible_core" / "journal.py"
            self.assertTrue(aliased.is_file())
            self.assert_duplicate(root, "admissible_core.journal", aliased, real)

    def test_distinct_modules_still_census_cleanly(self):
        """The guard rejects collisions only; two real modules are unaffected."""
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.build(root, f"{PACKAGES_DIR}/a/src/admissible_core/journal.py")
            self.build(root, f"{PACKAGES_DIR}/b/src/admissible_trust/journal.py")
            self.assertEqual(
                ["admissible_core.journal", "admissible_trust.journal"],
                sorted(self.census_of(root)),
            )


class TargetPolicyOwnerLabels(unittest.TestCase):
    """Every ``target_owners`` value must be a label the edge policy knows.

    ``TARGET_FORBIDDEN`` is a set of owner pairs, so a misspelt owner label
    simply never matches: the module's forbidden edges stop being checked and
    every assertion still passes.  A typo must fail loudly instead.
    """

    def mutated(self, module: str, owner: str) -> dict:
        manifest = load_manifest()
        self.assertIn(module, manifest["target_policy"]["target_owners"])
        manifest["target_policy"]["target_owners"][module] = owner
        return manifest

    def test_manifest_target_owners_use_known_labels(self):
        self.assertEqual({}, invalid_target_owners(load_manifest()))

    def test_a_misspelt_owner_label_is_rejected(self):
        module = sorted(load_manifest()["target_policy"]["target_owners"])[0]
        self.assertEqual(
            {module: "Redy"}, invalid_target_owners(self.mutated(module, "Redy"))
        )

    def test_an_out_of_scope_label_is_rejected_in_the_target_policy(self):
        """``Test Surface`` is a real owner label, but not a namespace owner."""
        module = sorted(load_manifest()["target_policy"]["target_owners"])[0]
        self.assertEqual(
            {module: TEST}, invalid_target_owners(self.mutated(module, TEST))
        )

    def test_a_misspelt_label_would_have_disabled_a_forbidden_edge(self):
        """Why the check exists: the typo silences a real violation."""
        manifest = load_manifest()
        waived = {
            (source, target)
            for source, target in manifest["transitional_edges"]["allowed"]
        }
        source, target = sorted(waived)[0]
        owners = manifest["target_policy"]["target_owners"]
        self.assertIn((owners[source], owners[target]), TARGET_FORBIDDEN)
        typo = self.mutated(source, owners[source].upper())
        typo_owners = typo["target_policy"]["target_owners"]
        self.assertNotIn(
            (typo_owners[source], typo_owners[target]),
            TARGET_FORBIDDEN,
            "a typo must not be able to make an edge unforbidden unnoticed",
        )
        self.assertNotEqual({}, invalid_target_owners(typo))


class MetadataDiagnostics(unittest.TestCase):
    """The metadata counters are assertions, not decoration."""

    def test_module_count_matches_the_census(self):
        manifest = load_manifest()
        self.assertEqual(len(census()), manifest["metadata"]["module_count"])

    def test_scan_roots_match_the_declared_contract(self):
        manifest = load_manifest()
        self.assertEqual(declared_scan_roots(), manifest["metadata"]["scan_roots"])

    def test_declared_contract_covers_every_scanned_root(self):
        """The declared roots are the roots actually walked, in order."""
        declared = declared_scan_roots()
        self.assertEqual(
            [*TOP_LEVEL_ROOTS, f"{PACKAGES_DIR}/*/src"], declared,
            "scan-root contract is TOP_LEVEL_ROOTS then the packages pattern",
        )
        for _, root in _scan_roots():
            relative = root.relative_to(REPO_ROOT).as_posix()
            self.assertTrue(
                any(fnmatch(relative, pattern) for pattern in declared),
                f"scanned root {relative} matches no declared scan root",
            )


if __name__ == "__main__":
    unittest.main()
