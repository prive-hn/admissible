"""Contract: the isolation boundary vocabulary has exactly one definition.

``isolation`` is the one field in the evaluation attestation that both
authorities compare on.  Ready writes it into a preview and refuses a value it
does not know; Trust reads the observer's assertion, refuses a value it does not
know, and refuses ``none`` outright before issuing a receipt.  Two spellings of
that closed set is two gates: a mode one distribution accepts and the other
rejects is a preview that evaluates here and cannot be finalized there, and --
worse in the other direction -- a mode Ready would refuse that Trust would
admit.

So the set lives in the kernel, where a shared vocabulary belongs, and the
distributions import it.  This suite asserts both halves of that: the kernel's
set is the monolith's set, and no split distribution defines its own.

Nothing here is a capability change.  ``declared_isolation`` reads an
environment variable to decide what an *evaluating* process should record, and
that stays in the Ready runner beside the code that starts the commands the
boundary is supposed to confine.  The kernel owns the names and nothing else.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

from admissible import runner as legacy_runner

from admissible_core import isolation as core_isolation

from . import REPO_ROOT

PACKAGES = REPO_ROOT / "packages"

#: The names a distribution must not bind for itself.
VOCABULARY = ("ISOLATION_MODES", "ISOLATION_NONE")


def split_sources() -> dict[str, ast.Module]:
    """Every module of every split distribution, parsed, keyed by path."""

    found: dict[str, ast.Module] = {}
    for path in sorted(PACKAGES.glob("*/src/**/*.py")):
        if "build" in path.parts or "__pycache__" in path.parts:
            continue
        relative = path.relative_to(REPO_ROOT).as_posix()
        found[relative] = ast.parse(path.read_text(encoding="utf-8"),
                                    filename=str(path))
    return found


def assigned_names(tree: ast.Module) -> set[str]:
    """Every module-level name this source binds by assignment."""

    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names |= {target.id for target in node.targets
                      if isinstance(target, ast.Name)}
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


class TheKernelOwnsTheVocabulary(unittest.TestCase):
    def test_the_kernel_set_is_the_monolith_set(self):
        """Observational parity, in the one direction that can drift."""

        self.assertEqual(legacy_runner.ISOLATION_MODES,
                         core_isolation.ISOLATION_MODES)
        self.assertEqual(legacy_runner.ISOLATION_NONE,
                         core_isolation.ISOLATION_NONE)

    def test_none_is_a_member_and_is_first(self):
        """The refusable default has to be in the set it is refused from."""

        self.assertIn(core_isolation.ISOLATION_NONE,
                      core_isolation.ISOLATION_MODES)
        self.assertEqual(core_isolation.ISOLATION_NONE,
                         core_isolation.ISOLATION_MODES[0])

    def test_the_set_is_closed_and_non_empty(self):
        modes = core_isolation.ISOLATION_MODES
        self.assertIsInstance(modes, tuple)
        self.assertTrue(modes, "an empty vocabulary accepts nothing")
        self.assertEqual(len(modes), len(set(modes)))
        for mode in modes:
            with self.subTest(mode=mode):
                self.assertIsInstance(mode, str)
                self.assertTrue(mode.strip())


class NoSplitDistributionDefinesItsOwn(unittest.TestCase):
    """A second definition is a second gate; there must be exactly one.

    Checked statically, over the source of every split distribution, because
    the failure this prevents is a *rebinding* -- a module that assigns
    ``ISOLATION_MODES`` itself instead of importing it -- and after import both
    spellings look identical from the outside until the day they differ.
    """

    def test_the_sources_exist_to_be_checked(self):
        sources = split_sources()
        self.assertTrue(sources, f"no split sources under {PACKAGES}")
        self.assertTrue(
            any(name.endswith("admissible_core/isolation.py")
                for name in sources),
            "the kernel must ship the vocabulary it owns")

    def test_only_the_kernel_binds_the_vocabulary(self):
        offenders = []
        for relative, tree in sorted(split_sources().items()):
            if relative.endswith("admissible_core/isolation.py"):
                continue
            for name in sorted(assigned_names(tree) & set(VOCABULARY)):
                offenders.append(f"{relative} binds {name}")
        self.assertEqual(
            [], offenders,
            "the isolation vocabulary is imported from admissible_core, never "
            "re-declared")

    def test_every_user_reaches_it_through_the_kernel(self):
        """Whoever names a mode constant must import it from Core."""

        problems = []
        for relative, tree in sorted(split_sources().items()):
            if relative.endswith("admissible_core/isolation.py"):
                continue
            uses = {node.id for node in ast.walk(tree)
                    if isinstance(node, ast.Name) and node.id in VOCABULARY}
            uses |= {node.attr for node in ast.walk(tree)
                     if isinstance(node, ast.Attribute)
                     and node.attr in VOCABULARY}
            if not uses:
                continue
            imported = any(
                isinstance(node, ast.ImportFrom)
                and (node.module or "").startswith("admissible_core")
                for node in ast.walk(tree))
            if not imported:
                problems.append(f"{relative} uses {sorted(uses)}")
        self.assertEqual([], problems)


if __name__ == "__main__":
    unittest.main()
