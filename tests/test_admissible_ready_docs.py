"""Public documentation contract for the Ready product and the 0.8.0 split.

The first class here is the original v0.7 product contract and is unchanged.
Everything after it is the *installation and authority* contract the runtime
split created: which distribution installs which command, which environment is
allowed to hold which credential, and which of the honest limits are limits
rather than defences.

Two rules shape how these are written.

*Derive, do not remember.*  A documentation test that greps for a sentence
somebody typed proves only that somebody typed it.  Where a claim has an
executable source -- the console scripts in
``tests/architecture/test_distribution_separation``, the ``add_parser`` tables
in each CLI, the credential list in ``admissible_ready.runner``, the module
files under ``packages/core/src`` -- the claim is compared against that source
as an equality, so a command added to a parser and not to the docs is red here
on the day it is added.

*Name the false wording, not only the true wording.*  Several of these
statements replace a sentence that was wrong rather than missing.  A positive
assertion alone would pass on a document that says both things, so the exact
stale spellings are asserted absent beside the corrections.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
import unittest

from tests.architecture.test_distribution_separation import (
    EXPECTED_REQUIREMENTS, PROJECTS, PROJECTS_BY_NAME, VERSION)

ROOT = Path(__file__).resolve().parent.parent

#: The operator-facing documents this contract governs.  Package READMEs are
#: named separately where a statement belongs to one distribution alone.
OPERATOR_DOCS = ("README.md", "docs/READY.md", "docs/DEVELOPER_WORKFLOW.md",
                 "docs/GITHUB_ACTIONS.md")

#: Every Markdown file whose local links must resolve.  ``paper/`` is included
#: because the Ready addendum links between its three files, and
#: ``packages/*/README.md`` because those are published on an index page where
#: a broken relative link is a 404 rather than a missing file.
LINKED_MARKDOWN_ROOTS = ("README.md", "docs", "paper", "packages")

_CODE_FENCE = re.compile(r"^\s*```")
_BACKTICKED = re.compile(r"`([^`]+)`")
_PIP_INSTALL = re.compile(r"pip install (admissible[a-z-]*)")
_DEPENDENCY_CLAIM = re.compile(r"\b(zero|no)\b[^.\n]*\bdependenc")
_MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def subcommands(module_path: str, receiver: str) -> set[str]:
    """The literal names ``receiver.add_parser("x")`` registers in a CLI.

    Parsed rather than imported: the split distributions are not installed in
    the interpreter running this suite, and the question is what the source
    declares anyway.  ``receiver`` distinguishes the top-level subparsers from
    a nested one, which is how ``policy trust`` is told apart from ``trust``.
    """
    tree = ast.parse(read(module_path), filename=module_path)
    found = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_parser"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == receiver
                and node.args
                and isinstance(node.args[0], ast.Constant)):
            found.add(node.args[0].value)
    return found


def module_dict_keys(module_path: str, name: str) -> set[str]:
    """The literal keys of a module-level dict, read out of the source.

    ``_COMMANDS`` is the dispatch table a CLI actually consults, which is a
    stronger source than the parser for "what does this distribution install":
    a verb with a parser and no handler is refused, and a verb in this table is
    one the wheel really runs.
    """
    tree = ast.parse(read(module_path), filename=module_path)
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and any(getattr(target, "id", "") == name
                        for target in node.targets)
                and isinstance(node.value, ast.Dict)):
            return {key.value for key in node.value.keys
                    if isinstance(key, ast.Constant)}
    raise AssertionError(f"{module_path} declares no {name} dict")


def function_docstring(module_path: str, name: str) -> str:
    """One module-level function's docstring, read out of the source."""
    tree = ast.parse(read(module_path), filename=module_path)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_docstring(node) or ""
    raise AssertionError(f"{module_path} defines no {name}")


def module_constant(module_path: str, name: str) -> tuple[str, ...]:
    """A module-level tuple/list literal, read out of the source."""
    tree = ast.parse(read(module_path), filename=module_path)
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and any(getattr(target, "id", "") == name
                        for target in node.targets)):
            return tuple(ast.literal_eval(node.value))
    raise AssertionError(f"{module_path} declares no {name}")


READY_COMMANDS = subcommands(
    "packages/ready/src/admissible_ready/cli.py", "commands")
TRUST_COMMANDS = subcommands(
    "packages/trust/src/admissible_trust/cli.py", "commands")
TRUST_POLICY_COMMANDS = subcommands(
    "packages/trust/src/admissible_trust/cli.py", "policy_commands")
SIGNING_CREDENTIAL_NAMES = module_constant(
    "packages/ready/src/admissible_ready/runner.py",
    "SIGNING_CREDENTIAL_NAMES")

#: Verbs the signing distribution owns *outright*, and therefore verbs a
#: copyable operator line must spell ``admissible-trust``.  ``run`` is excluded
#: because both distributions implement it: the umbrella tells the two apart by
#: the argument list, so ``admissible run --preview`` is a legitimate
#: candidate-side invocation and no table can call it a Trust line.  The run
#: surface is asserted separately, by shape, in
#: :class:`TheRunSurfaceIsDescribedAsItIs`.
SHARED_VERBS = READY_COMMANDS & TRUST_COMMANDS
TRUST_VERBS = (TRUST_COMMANDS - SHARED_VERBS) | {"policy"}

#: The verbs the signing wheel's dispatch table really runs, which is what
#: "the whole surface" in ``packages/trust/README.md`` has to equal.
TRUST_INSTALLED_COMMANDS = module_dict_keys(
    "packages/trust/src/admissible_trust/cli.py", "_COMMANDS")

#: The negative capability claims the operator documents actually make about
#: ``run``.  Every one of them is true of Ready's preview evaluation and false
#: of the bare ``run`` Trust installs as its ``finalize`` alias -- that command
#: signs, issues a receipt, reads the admission key and holds the reviewer
#: keyring -- so a block making one of these claims has to say which of the two
#: commands it is talking about.
RUN_NEGATIVE_CLAIMS = (
    "never signs", "signs nothing", "no signer", "never admission",
    "never mean admitted", "reads no key", "takes no key",
    "reads none of them", "only an evaluation", "never holds one",
    "checks passed only", "produces a receipt, ever",
    "means only that the checks passed", "produces an evaluation",
)

#: Spellings that say which ``run`` a block means.  A bare ``--preview`` flag
#: is Ready's evaluation by the umbrella's own dispatch rule
#: (``admissible.cli._resolve_run``), so ``run --preview`` disambiguates a
#: block exactly as well as naming the distribution does.
RUN_QUALIFIERS = ("admissible-ready", "admissible-trust", "run --preview")

_BARE_RUN = re.compile(r"\brun\b")

#: External-state verbs.  This repository builds and versions four
#: distributions; it has not released, published or deployed any of them, and a
#: document may not say otherwise.  ``release window`` is deliberately not
#: matched: a migration window is a plan, not a publication.
_PUBLICATION_CLAIM = re.compile(
    r"\breleased\b|\bdeployed\b|\bPyPI\b|\bpackage index\b", re.IGNORECASE)


def code_lines(text: str) -> list[str]:
    """Every line inside a fenced block, with the fences dropped."""
    inside, lines = False, []
    for line in text.splitlines():
        if _CODE_FENCE.match(line):
            inside = not inside
            continue
        if inside:
            lines.append(line)
    return lines


def flat(text: str) -> str:
    """One line, so a claim can be asserted without depending on its wrapping."""
    return re.sub(r"\s+", " ", text)


def says(relative: str, phrase: str) -> bool:
    """Does this document carry ``phrase``, regardless of how it wraps?

    A predicate rather than ``assertIn`` because the subject is a whole
    document: an ``assertIn`` that fails here prints the file, and a receipt
    nobody can read is a receipt nobody checks.  Callers assert on the boolean
    and name the phrase themselves.
    """
    return phrase in flat(read(relative))


def prose_blocks(text: str) -> list[str]:
    """Every blank-line-separated block outside a fence, wrapping collapsed.

    A block rather than a sentence, because these documents carry the subject
    in one sentence and the claim in the next -- "``run`` is the explicit
    evaluator. It never signs." -- and a sentence-level reader would score the
    second half as being about nothing.  A Markdown table is one block, which
    is what makes a cell's claim readable beside the verb in its own row.
    """
    inside, block, blocks = False, [], []
    for line in text.splitlines():
        if _CODE_FENCE.match(line):
            inside = not inside
            if block:
                blocks.append(" ".join(block))
                block = []
            continue
        if inside:
            continue
        if line.strip():
            block.append(line.strip())
        elif block:
            blocks.append(" ".join(block))
            block = []
    if block:
        blocks.append(" ".join(block))
    return blocks


def table_cell(text: str, first_cell: str, column: int) -> str:
    """One cell of the Markdown row whose first cell is ``first_cell``."""
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and cells[0] == first_cell:
            return cells[column]
    raise AssertionError(f"no table row starts with {first_cell!r}")


class ReadyDocumentationContractTest(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_readme_leads_with_the_one_command_product(self):
        text = self.read("README.md")
        self.assertIn("v0.7.0", text)
        self.assertIn("admissible check", text)
        self.assertIn("admissible ui", text)
        self.assertIn("admissible connect", text)
        self.assertIn("docs/READY.md", text)
        self.assertLess(text.index("admissible check"),
                        text.index("admissible run --preview"))

    def test_ready_guide_documents_humans_agents_and_exact_stop_conditions(self):
        text = self.read("docs/READY.md")
        for expected in (
            "change → check → fix the next item → recheck → ready",
            "admissible/v0.7/ready-state",
            "admissible check --json",
            "admissible ui",
            "Claude Code",
            "Codex",
            "Hermes",
            "admissible_get_state",
            "admissible_get_work_package",
            "admissible_check",
            "admissible_get_remediation",
            "agent_or_human",
            "reviewer",
            "trusted_infrastructure",
            "ready-status",
        ):
            self.assertIn(expected, text)
        self.assertIn("never receives", text)
        self.assertIn("signing", text)

    def test_ready_guide_discloses_local_store_initialization_on_read_tools(self):
        text = self.read("docs/READY.md")
        cli = self.read("admissible/cli.py")
        self.assertIn("may initialize or migrate the local Admissible store", text)
        self.assertNotIn(
            "| `admissible_get_state` | Read the latest exact-HEAD Ready state | none |",
            text)
        self.assertNotIn("in a read-only process", text)
        self.assertNotIn("trusted read-only Ready projection", cli)
        self.assertNotIn("trusted read-only status process", self.read("README.md"))
        self.assertNotIn("trusted read-only status over", self.read("README.md"))
        self.assertNotIn("trusted read-only status",
                         self.read("docs/DEVELOPER_WORKFLOW.md"))
        self.assertIn("package_id", text)

    def test_developer_quickstart_uses_check_but_preserves_advanced_commands(self):
        text = self.read("docs/DEVELOPER_WORKFLOW.md")
        quickstart = text.split("## Exit codes", 1)[0]
        self.assertIn("admissible check", quickstart)
        self.assertIn("admissible run --preview", text)
        self.assertIn("admissible ready-status", text)
        self.assertIn("checks_complete", text)
        self.assertIn("waiting_for_review", text)

    def test_github_docs_describe_the_friendly_card_without_claiming_automation(self):
        text = self.read("docs/GITHUB_ACTIONS.md")
        self.assertIn("Admissible Ready", text)
        self.assertIn("What should happen next", text)
        self.assertIn("exact commit", text)
        self.assertIn("does not exist yet", text)
        self.assertNotIn("automatically finalizes every pull request", text.lower())

    def test_dev_extra_and_tests_support_the_declared_python_floor(self):
        pyproject = self.read("pyproject.toml")
        tests = self.read("tests/test_admissible_ready.py")
        self.assertIn('requires-python = ">=3.10"', pyproject)
        self.assertIn(
            '"tomli; python_version < \'3.11\'"', pyproject)
        self.assertNotIn("        import jsonschema", tests)
        self.assertNotIn("        import tomllib", tests)
        self.assertIn('require_module("jsonschema")', tests)
        self.assertIn('"tomllib" if sys.version_info >= (3, 11) else "tomli"',
                      tests)


class OneRepositoryFourCoordinatedDistributions(unittest.TestCase):
    """Statement 1: one repository, four 0.8.0 wheels, separate processes."""

    def test_the_readme_names_all_four_distributions_at_one_version(self):
        text = read("README.md")
        for project in PROJECTS:
            with self.subTest(distribution=project.distribution):
                self.assertIn(f"`{project.distribution}`", text)
        self.assertIn("four coordinated", text)
        self.assertIn(f"{VERSION}", text)

    def test_the_readme_says_one_repository_and_separate_processes(self):
        text = read("README.md")
        self.assertIn("one repository", text.lower())
        self.assertIn("separate processes", text.lower())

    def test_the_layout_table_names_each_split_project_directory(self):
        text = read("README.md")
        for project in PROJECTS:
            with self.subTest(directory=project.directory):
                self.assertIn(f"`{project.directory}/`", text)


class TheInstallLinesNameTheDistributionThatHasNoDependencies(
        unittest.TestCase):
    """The corrected install guidance: only Core has no dependencies."""

    #: The exact false sentences this change replaces.  Asserted absent
    #: because a document that gained the correction and kept the error would
    #: satisfy every positive assertion below.
    STALE = (
        ("README.md",
         "pip install admissible                         "
         "# zero required dependencies"),
        ("docs/DEVELOPER_WORKFLOW.md",
         "pip install admissible            "
         "# no runtime dependencies, Python 3.10+"),
    )

    def test_the_known_false_install_lines_are_gone(self):
        for relative, sentence in self.STALE:
            with self.subTest(document=relative):
                self.assertNotIn(sentence, read(relative))

    def test_only_core_is_ever_called_dependency_free(self):
        """Derived: every dependency claim beside a `pip install` names Core."""
        checked = 0
        for relative in OPERATOR_DOCS:
            for number, line in enumerate(read(relative).splitlines(), 1):
                install = _PIP_INSTALL.search(line)
                if not install or not _DEPENDENCY_CLAIM.search(line):
                    continue
                checked += 1
                with self.subTest(where=f"{relative}:{number}"):
                    self.assertEqual("admissible-core", install.group(1))
        self.assertGreater(checked, 0, "no install line makes the claim at all")

    def test_each_distribution_has_its_own_install_line(self):
        readme = read("README.md")
        workflow = read("docs/DEVELOPER_WORKFLOW.md")
        for project in PROJECTS:
            with self.subTest(distribution=project.distribution):
                line = f"pip install {project.distribution}"
                self.assertIn(line, readme)
                self.assertIn(line, workflow)


class DocumentedCommandsAreTheCommandsThePackagesInstall(unittest.TestCase):
    """Statement 2, as an equality against the parsers and entry points."""

    #: ``{document: {distribution: subcommand set}}`` -- the third column of
    #: the ownership table each document carries.
    DOCUMENTS = ("README.md", "docs/DEVELOPER_WORKFLOW.md")

    def documented(self, relative: str, distribution: str) -> set[str]:
        cell = table_cell(read(relative), f"`{distribution}`", 2)
        return set(_BACKTICKED.findall(cell))

    def test_the_parsers_are_read_at_all(self):
        """A silent parse failure would make every equality below vacuous."""
        self.assertIn("check", READY_COMMANDS)
        self.assertIn("finalize", TRUST_COMMANDS)
        self.assertEqual({"trust", "revoke", "list"}, TRUST_POLICY_COMMANDS)
        self.assertEqual({"run"}, SHARED_VERBS)

    def test_each_document_lists_readys_exact_subcommands(self):
        for relative in self.DOCUMENTS:
            with self.subTest(document=relative):
                self.assertEqual(
                    READY_COMMANDS, self.documented(relative,
                                                    "admissible-ready"))

    def test_each_document_lists_trusts_exact_subcommands(self):
        expected = TRUST_COMMANDS | TRUST_POLICY_COMMANDS
        for relative in self.DOCUMENTS:
            with self.subTest(document=relative):
                self.assertEqual(
                    expected, self.documented(relative, "admissible-trust"))

    def test_core_installs_no_command_and_the_table_says_so(self):
        self.assertIsNone(PROJECTS_BY_NAME["admissible-core"].console_script)
        for relative in self.DOCUMENTS:
            with self.subTest(document=relative):
                self.assertEqual(
                    "none", table_cell(read(relative), "`admissible-core`", 1))

    def test_the_umbrella_row_says_static_compatibility_dispatch(self):
        for relative in self.DOCUMENTS:
            with self.subTest(document=relative):
                cell = table_cell(read(relative), "`admissible`", 2)
                self.assertIn("static compatibility dispatch", cell)

    def test_the_console_command_column_is_the_entry_point_table(self):
        for relative in self.DOCUMENTS:
            for project in PROJECTS:
                if project.console_script is None:
                    continue
                with self.subTest(document=relative,
                                  distribution=project.distribution):
                    self.assertEqual(
                        f"`{project.console_script}`",
                        table_cell(read(relative), f"`{project.distribution}`",
                                   1))

    def test_the_split_packages_document_their_own_surface(self):
        """The per-wheel READMEs and the repository docs agree."""
        for command in sorted(READY_COMMANDS):
            with self.subTest(command=command):
                self.assertIn(command, read("packages/ready/README.md"))
        for command in sorted(TRUST_COMMANDS | TRUST_POLICY_COMMANDS):
            with self.subTest(command=command):
                self.assertIn(command, read("packages/trust/README.md"))


class TheReadyEnvironmentHoldsNoTrustAuthority(unittest.TestCase):
    """Statement 3: no Trust package, no trust credential, empty refuses."""

    def test_ready_guide_states_the_physical_distribution_boundary(self):
        text = read("docs/READY.md")
        self.assertIn("admissible-ready", text)
        self.assertIn("admissible-trust", text)
        self.assertIn("does not install `admissible-trust`", text)

    def test_ready_guide_names_the_credential_variables_it_refuses(self):
        text = read("docs/READY.md")
        for name in SIGNING_CREDENTIAL_NAMES:
            with self.subTest(variable=name):
                self.assertIn(name, text)

    def test_a_present_but_empty_credential_variable_refuses(self):
        for relative in ("docs/READY.md", "packages/ready/README.md"):
            with self.subTest(document=relative):
                self.assertIn("present but empty", read(relative))


class TheTrustEnvironmentRunsNoCandidateCommand(unittest.TestCase):
    """Statement 4: no Ready package, and nothing candidate-owned executes."""

    def test_ready_guide_states_the_trust_side_boundary(self):
        text = read("docs/READY.md")
        self.assertIn("does not install `admissible-ready`", text)
        self.assertIn("executes no candidate command", text)

    def test_the_trust_readme_says_the_same_thing(self):
        text = read("packages/trust/README.md")
        self.assertIn("no runner", text)
        self.assertIn("admissible-ready", text)


class TheUmbrellaIsConvenienceOnly(unittest.TestCase):
    """Statement 5: forbidden in every trusted deployment, by name."""

    FORBIDDEN_IN = ("reviewer", "observer", "finalizer", "policy signing",
                    "trusted")

    def test_the_operator_docs_forbid_it_in_each_named_deployment(self):
        for relative in ("README.md", "docs/DEVELOPER_WORKFLOW.md",
                         "packages/umbrella/README.md"):
            text = read(relative).lower()
            for role in self.FORBIDDEN_IN:
                with self.subTest(document=relative, role=role):
                    self.assertIn(role, text)
            with self.subTest(document=relative):
                self.assertIn("convenience", text)

    def test_the_readme_says_a_trusted_machine_installs_one_authority(self):
        self.assertIn("installs exactly one authority", read("README.md"))


class HmacIsASharedSecret(unittest.TestCase):
    """Statement 6: Ready cannot verify `ready` without becoming Trust."""

    def test_the_operator_docs_explain_why_ready_cannot_verify(self):
        for relative in ("README.md", "docs/READY.md"):
            text = read(relative)
            with self.subTest(document=relative):
                self.assertIn("shared secret", text)
                self.assertIn("verification and signing share", text)


class SeparationIsNotAnOperatingSystemSandbox(unittest.TestCase):
    """Statement 7: accidental capability adjacency, and nothing more."""

    def test_each_operator_doc_says_what_the_split_does_not_prove(self):
        for relative in ("README.md", "docs/READY.md",
                         "docs/DEVELOPER_WORKFLOW.md"):
            text = read(relative)
            with self.subTest(document=relative):
                self.assertIn("accidental capability adjacency", text)
                self.assertIn("not an operating-system sandbox", text)


class StoreCompatibilityAndLocalDenialOfServiceAreHonest(unittest.TestCase):
    """Statement 8: what the store still opens, and what still denies it."""

    LIMITS = (
        "-wal",
        "concurrent",
        "advisory",
        "same-user",
    )

    def test_the_ready_guide_keeps_v07_store_compatibility(self):
        text = read("docs/READY.md")
        self.assertIn("v0.7", text)
        self.assertIn("open and migrate in place", text)

    def test_both_operator_docs_name_every_local_denial_of_service_limit(self):
        """Case-folded: these are prose nouns, and a bullet capitalises them."""
        for relative in ("docs/READY.md", "docs/DEVELOPER_WORKFLOW.md"):
            text = read(relative).lower()
            for limit in self.LIMITS:
                with self.subTest(document=relative, limit=limit):
                    self.assertIn(limit, text)
            with self.subTest(document=relative):
                self.assertIn("denial of service", text)

    def test_the_docs_place_same_user_tampering_outside_the_claim(self):
        for relative in ("docs/READY.md", "docs/DEVELOPER_WORKFLOW.md"):
            with self.subTest(document=relative):
                self.assertIn("outside the claim", read(relative))


class TheLegacyMonolithIsLabelledMigrationOnly(unittest.TestCase):
    """Statement 11: 0.7.0 at the root is history with a window, not now."""

    def test_the_layout_row_labels_the_root_package_as_migration_only(self):
        cell = table_cell(read("README.md"), "`admissible/`", 1)
        self.assertIn("0.7.0", cell)
        self.assertIn("migration", cell.lower())

    def test_the_root_package_is_not_described_as_the_split_architecture(self):
        cell = table_cell(read("README.md"), "`admissible/`", 1)
        self.assertNotIn("zero required runtime dependencies", cell)
        self.assertIn("pre-split", cell.lower())

    def test_the_root_project_version_is_the_one_the_readme_states(self):
        pyproject = read("pyproject.toml")
        self.assertIn('version = "0.7.0"', pyproject)


class TheCoordinatedPinsAreExact(unittest.TestCase):
    """Statement 12: every sibling edge is `==0.8.0`, and the docs say so."""

    def test_the_declared_edges_are_all_exact(self):
        for distribution, requirements in EXPECTED_REQUIREMENTS.items():
            for sibling, specifier in requirements.items():
                with self.subTest(edge=f"{distribution} -> {sibling}"):
                    self.assertEqual(f"=={VERSION}", specifier)

    def test_the_readme_states_the_exact_pin(self):
        text = read("README.md")
        self.assertIn(f"=={VERSION}", text)
        self.assertIn("exact", text.lower())


class TheGithubDocsDescribeTheSplitCorrectly(unittest.TestCase):
    """The three corrections `docs/GITHUB_ACTIONS.md` needed."""

    STALE = "the same\nfiles ship inside the package under `admissible/templates/`"

    @property
    def shipped_templates(self) -> set[str]:
        directory = (ROOT / "packages" / "ready" / "src" / "admissible_ready"
                     / "templates")
        return {path.name for path in directory.iterdir() if path.is_file()}

    def test_the_ready_wheel_ships_exactly_one_template(self):
        self.assertEqual({"consumer-workflow.yml"}, self.shipped_templates)

    def test_the_document_no_longer_claims_the_wheel_ships_all_of_them(self):
        self.assertNotIn(self.STALE, read("docs/GITHUB_ACTIONS.md"))

    def test_the_document_names_the_one_file_the_wheel_ships(self):
        text = read("docs/GITHUB_ACTIONS.md")
        for name in sorted(self.shipped_templates):
            with self.subTest(template=name):
                self.assertIn(name, text)

    def test_the_document_says_where_the_other_two_come_from(self):
        text = read("docs/GITHUB_ACTIONS.md")
        self.assertIn("action.yml", text)
        self.assertIn("reusable-workflow.yml", text)
        self.assertIn("repository checkout", text)

    def test_the_document_explains_the_evaluate_job_is_ready_domain(self):
        text = read("docs/GITHUB_ACTIONS.md")
        self.assertIn("python3 -m admissible", text)
        self.assertIn("Ready domain", text)
        self.assertIn("migration window", text)

    def test_the_document_names_the_dotted_split_owners(self):
        text = read("docs/GITHUB_ACTIONS.md")
        self.assertIn("admissible_ready.github.evaluation_context", text)
        self.assertIn("admissible_trust.github.assert_trusted_tool", text)

    def test_the_legacy_facade_is_still_named_and_called_umbrella_only(self):
        """The census owes an owner for every documented facade symbol."""
        text = read("docs/GITHUB_ACTIONS.md")
        self.assertIn("admissible.github.evaluation_context()", text)
        self.assertIn("admissible.github.assert_trusted_tool()", text)
        self.assertIn("umbrella-only", text)
        self.assertIn("fail-closed", text)


class TrustOperationsUseTheExplicitCommand(unittest.TestCase):
    """Statement: an operator's copyable line names the signing distribution."""

    def test_no_runnable_line_hands_a_trust_verb_to_the_umbrella(self):
        offenders = []
        for relative in OPERATOR_DOCS:
            for line in code_lines(read(relative)):
                words = line.strip().split()
                if len(words) >= 2 and words[0] == "admissible":
                    if words[1] in TRUST_VERBS:
                        offenders.append(f"{relative}: {line.strip()}")
        self.assertEqual([], offenders)

    def test_the_explicit_trust_command_is_what_the_docs_run(self):
        for relative in ("README.md", "docs/DEVELOPER_WORKFLOW.md",
                         "docs/GITHUB_ACTIONS.md"):
            with self.subTest(document=relative):
                self.assertTrue(
                    any(line.strip().startswith("admissible-trust ")
                        for line in code_lines(read(relative))),
                    "no copyable admissible-trust line at all")

    def test_the_alias_is_documented_as_transitional(self):
        for relative in ("README.md", "docs/DEVELOPER_WORKFLOW.md"):
            with self.subTest(document=relative):
                text = read(relative)
                self.assertIn("transitional", text)
                self.assertIn("one release window", text)


class TheRunSurfaceIsDescribedAsItIs(unittest.TestCase):
    """`run --preview` stopped being the only `run` when Trust took an alias."""

    STALE = "`admissible run --preview` is the only form of `run` there is"

    def test_the_false_sentence_is_gone(self):
        self.assertNotIn(self.STALE, read("README.md"))

    def test_the_readme_says_who_owns_each_shape_of_run(self):
        text = read("README.md")
        self.assertIn("admissible-ready run --preview", text)
        self.assertIn("admissible-trust run", text)
        self.assertIn("finalize", text)

    def test_the_readme_says_dispatch_never_reads_a_credential(self):
        text = read("README.md")
        self.assertIn("never by ambient credentials", text)


class RunClaimsNameTheCommandTheyAreTrueOf(unittest.TestCase):
    """`run` is two commands in two wheels, so a bare claim about it is false.

    Ready's ``run --preview`` evaluates and never signs.  Trust installs a
    ``run`` of its own -- the bare-run alias for ``finalize`` -- which consumes
    a retained preview, signs it and anchors a receipt; the umbrella routes to
    whichever of the two the argument list names.  Every sentence that says
    "``run`` never signs" is therefore true of one command and false of the
    other, and this class is the rule that they must say which.
    """

    #: The exact unqualified spellings this correction removed.  Asserted
    #: absent as well as corrected, because the scanner below is satisfied by
    #: a block that carries a qualifier *somewhere*, and a document that says
    #: both things would pass it.
    STALE = (
        ("docs/DEVELOPER_WORKFLOW.md",
         "`run` is the explicit evaluator for advanced automation."),
        ("docs/DEVELOPER_WORKFLOW.md",
         "`admissible run` exits `0`, `1` or `2`, but its zero is never "
         "admission."),
        ("docs/DEVELOPER_WORKFLOW.md",
         "`run` is an evaluation and only an evaluation."),
        ("docs/DEVELOPER_WORKFLOW.md",
         "No run produces a receipt, ever:"),
        ("docs/DEVELOPER_WORKFLOW.md", "**`run` never holds one.**"),
        ("docs/DEVELOPER_WORKFLOW.md", "`run` produces an evaluation."),
        ("docs/DEVELOPER_WORKFLOW.md", "`run` reads none of them."),
        ("README.md", "`0` from `run` means only that the checks passed"),
        ("README.md", "`run` signs nothing, so its zero can never mean "
                      "admitted."),
    )

    def claiming_blocks(self, relative: str) -> list[str]:
        return [block for block in prose_blocks(read(relative))
                if _BARE_RUN.search(block)
                and any(claim in block.lower()
                        for claim in RUN_NEGATIVE_CLAIMS)]

    def test_run_is_the_one_verb_both_distributions_implement(self):
        """Without this the whole class is a rule about nothing."""
        self.assertEqual({"run"}, SHARED_VERBS)

    def test_the_signing_wheel_really_installs_a_run(self):
        self.assertIn("run", TRUST_INSTALLED_COMMANDS)

    def test_the_installed_trust_run_is_the_finalize_alias(self):
        docstring = function_docstring(
            "packages/trust/src/admissible_trust/cli.py", "_command_run")
        self.assertIn("alias for ``finalize``", docstring)

    def test_the_scan_finds_the_claims_it_is_meant_to_govern(self):
        found = sum(len(self.claiming_blocks(relative))
                    for relative in OPERATOR_DOCS)
        self.assertGreaterEqual(found, 8)

    def test_every_negative_run_claim_names_its_command(self):
        offenders = []
        for relative in OPERATOR_DOCS:
            for block in self.claiming_blocks(relative):
                if not any(mark in block for mark in RUN_QUALIFIERS):
                    offenders.append(f"{relative}: {block[:100]}")
        self.assertEqual([], offenders)

    def test_the_unqualified_spellings_are_gone(self):
        for relative, stale in self.STALE:
            with self.subTest(document=relative, stale=stale):
                self.assertFalse(says(relative, stale),
                                 f"{relative} still says: {stale}")

    def test_the_developer_guide_names_the_trust_side_run(self):
        for phrase in ("admissible-trust run", "admissible-ready run "
                       "--preview"):
            with self.subTest(phrase=phrase):
                self.assertTrue(says("docs/DEVELOPER_WORKFLOW.md", phrase),
                                f"the developer guide never says: {phrase}")

    def test_the_developer_guide_says_the_umbrella_run_reaches_trust(self):
        for phrase in ("`admissible run` without a bare `--preview`",
                       "one release window"):
            with self.subTest(phrase=phrase):
                self.assertTrue(says("docs/DEVELOPER_WORKFLOW.md", phrase),
                                f"the developer guide never says: {phrase}")


class TheTrustCommandListIsTheInstalledSurface(unittest.TestCase):
    """`packages/trust/README.md` calls its list "the whole surface"."""

    README = "packages/trust/README.md"

    def listed(self) -> set[str]:
        section = read(self.README).split("## Commands", 1)[1]
        block = section.split("```", 2)[1].split("\n", 1)[1]
        return {token for token in re.split(r"[\s|]+", block) if token}

    def test_the_list_is_exactly_what_the_wheel_installs(self):
        self.assertEqual(TRUST_INSTALLED_COMMANDS | TRUST_POLICY_COMMANDS,
                         self.listed())

    def test_the_transitional_run_is_listed_and_not_only_mentioned(self):
        self.assertIn("run", self.listed())

    def test_the_list_still_claims_to_be_the_whole_surface(self):
        self.assertTrue(says(self.README, "That is the whole surface."))

    def test_the_ownership_count_is_retained_and_is_the_real_count(self):
        self.assertEqual(12, len(TRUST_INSTALLED_COMMANDS))
        self.assertTrue(says(self.README, "twelve credentialed commands"))

    def test_the_migration_window_warning_is_retained(self):
        for phrase in ("one release window", "alias for `finalize`",
                       "never executes a check"):
            with self.subTest(phrase=phrase):
                self.assertTrue(says(self.README, phrase),
                                f"the trust README never says: {phrase}")


class TheHostedJobCommandIsSpelledAsTheWorkflowSpellsIt(unittest.TestCase):
    """The gate's command line is `python3 -m admissible`, and still is."""

    GATE = ".github/workflows/admissible-gate.yml"
    DOCUMENT = "docs/GITHUB_ACTIONS.md"
    STALE = "the same job runs `admissible-ready run --preview`"

    def test_the_workflow_source_still_invokes_the_umbrella_module(self):
        self.assertTrue(says(self.GATE, "python3 -m admissible "))
        self.assertFalse(says(self.GATE, "admissible-ready"),
                         "the gate workflow now spells admissible-ready; the "
                         "document below must be re-derived, not this test")

    def test_the_workflow_argv_is_a_ready_preview_evaluation(self):
        for phrase in ("args=(run --repo", "--preview --preview-out"):
            with self.subTest(phrase=phrase):
                self.assertTrue(says(self.GATE, phrase))

    def test_the_document_does_not_claim_the_workflow_source_changed(self):
        self.assertFalse(says(self.DOCUMENT, self.STALE),
                         f"{self.DOCUMENT} still says: {self.STALE}")

    def test_the_document_gives_the_exact_executable_spelling(self):
        for phrase in ("python3 -m admissible run --preview",
                       "command line is unchanged"):
            with self.subTest(phrase=phrase):
                self.assertTrue(says(self.DOCUMENT, phrase),
                                f"{self.DOCUMENT} never says: {phrase}")

    def test_the_document_still_explains_the_ready_domain_behaviour(self):
        for phrase in ("Ready-domain", "migration window"):
            with self.subTest(phrase=phrase):
                self.assertTrue(says(self.DOCUMENT, phrase),
                                f"{self.DOCUMENT} never says: {phrase}")


class TheHostedJobResolvesTheRootMonolithAndNotTheUmbrella(unittest.TestCase):
    """Which *program* the pinned command line reaches, derived not recalled.

    The sibling class above settles the spelling: the step still reads
    ``python3 -m admissible``.  This one settles the harder half, which the
    document got wrong -- what that module name resolves to.  The step runs
    with ``working-directory`` set to the checkout *root*, and ``-m`` puts the
    working directory first on ``sys.path``, so the name resolves to the
    ``admissible/`` package the repository root still carries: the retained
    0.7.0 monolith.  The umbrella's ``admissible/`` is not there -- it sits
    under ``packages/umbrella/compat/`` precisely so that it is *not* a second
    importable ``admissible`` -- and no step in the gate installs it.

    So no umbrella dispatcher is reached and no ``admissible-ready`` console
    script is handed the invocation.  What is true is the weaker, and separate,
    claim the document must now make: the *work* ``run --preview`` performs is
    Ready-domain work, while the *executable* performing it, for as long as the
    migration window lasts, is the legacy source-tree monolith.
    """

    GATE = ".github/workflows/admissible-gate.yml"
    DOCUMENT = "docs/GITHUB_ACTIONS.md"

    #: The checkout the step runs in, spelled as the workflow spells it.
    WORKING_DIRECTORY = "working-directory: ${{ github.workspace }}/admissible-tool"

    #: The claim that shipped.  Wrong in the one way that matters: it names the
    #: umbrella as the program the pinned command reaches, which reads as the
    #: gate already dispatching to `admissible-ready`.  Asserted absent by
    #: fragment, because the sentence it lived in wrapped across four lines.
    STALE = ("then the umbrella dispatcher",
             "hands the whole invocation to",
             "admissible-ready run --preview")

    def test_the_step_runs_the_module_from_the_checkout_root(self):
        """Not from `src/`, not from `packages/` -- the root itself."""
        self.assertTrue(says(self.GATE, self.WORKING_DIRECTORY),
                        f"{self.GATE} no longer runs the gate step from the "
                        f"checkout root; the resolution below is re-derived "
                        f"from that directory, so re-derive it, not this test")

    def test_the_checkout_root_carries_an_importable_admissible_package(self):
        """`-m admissible` from that root can only mean this directory."""
        package = ROOT / "admissible"
        for name in ("__init__.py", "__main__.py"):
            with self.subTest(name=name):
                self.assertTrue((package / name).is_file(),
                                f"admissible/{name} is gone from the "
                                f"repository root")

    def test_the_package_at_the_root_is_the_pre_split_monolith(self):
        """0.7.0 in both places the root declares it, and not the split 0.8.0."""
        self.assertIn('version = "0.7.0"', read("pyproject.toml"))
        self.assertIn('__version__ = "0.7.0"', read("admissible/__init__.py"))
        self.assertNotEqual(VERSION, "0.7.0",
                            "the split now versions at 0.7.0 too; the "
                            "distinction this class draws no longer holds")

    def test_the_umbrella_is_not_importable_from_that_root(self):
        """Its package lives under `packages/`, which is not on that path."""
        umbrella = PROJECTS_BY_NAME["admissible"]
        package = umbrella.path / "compat" / "admissible"
        self.assertTrue((package / "__main__.py").is_file(),
                        "the umbrella's module moved; re-derive where it is")
        self.assertNotEqual(package.parent, ROOT,
                            "the umbrella package now sits at the repository "
                            "root, which would make it the name `-m "
                            "admissible` resolves; re-derive this document")

    def test_the_gate_installs_no_distribution_before_running_the_module(self):
        """A `pip install` of the umbrella would change the answer above."""
        self.assertFalse(says(self.GATE, "pip install"),
                         f"{self.GATE} now installs something; which program "
                         f"the module name reaches must be re-derived")

    def test_the_document_does_not_claim_the_command_reaches_the_umbrella(self):
        text = read(self.DOCUMENT)
        for fragment in self.STALE:
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, text,
                                 f"{self.DOCUMENT} still says: {fragment}")

    def test_the_document_names_the_root_monolith_as_the_executable(self):
        for phrase in ("the retained 0.7.0 monolith",
                       "legacy source-tree monolith"):
            with self.subTest(phrase=phrase):
                self.assertTrue(says(self.DOCUMENT, phrase),
                                f"{self.DOCUMENT} never says: {phrase}")

    def test_the_document_keeps_the_work_and_the_executable_apart(self):
        """The behaviour is Ready-domain; the program running it is not Ready."""
        for phrase in ("Ready-domain work", "the executable performing it"):
            with self.subTest(phrase=phrase):
                self.assertTrue(says(self.DOCUMENT, phrase),
                                f"{self.DOCUMENT} never says: {phrase}")


class NoDocumentClaimsAnExternalRelease(unittest.TestCase):
    """Four distributions were versioned and built here. None was published."""

    def test_the_stale_release_claim_is_gone(self):
        self.assertFalse(says("README.md", "released together"),
                         "the README still says the four were released "
                         "together; nothing has been published")

    def test_no_operator_doc_claims_a_release_publication_or_deployment(self):
        offenders = []
        for relative in OPERATOR_DOCS:
            for block in prose_blocks(read(relative)):
                if _PUBLICATION_CLAIM.search(block):
                    offenders.append(f"{relative}: {block[:100]}")
        self.assertEqual([], offenders)

    def test_the_readme_states_the_coordination_that_is_true(self):
        for phrase in ("versioned and built together", f"**{VERSION}**"):
            with self.subTest(phrase=phrase):
                self.assertTrue(says("README.md", phrase),
                                f"the README never says: {phrase}")


class TheProcessLemmasRemainUnproved(unittest.TestCase):
    """Statement 9: P0-P3 are lemmas to implement, not theorems to cite."""

    def test_each_paper_file_still_says_unproved(self):
        for relative in ("paper/READY/INVARIANTS.md", "paper/READY/LEMMAS.md",
                         "docs/READY.md"):
            with self.subTest(document=relative):
                self.assertIn("unproved", read(relative))

    def test_the_lemmas_file_says_what_would_change_that(self):
        text = read("paper/READY/LEMMAS.md")
        self.assertIn("separate formal admission", text)

    def test_the_separation_does_not_promote_any_lemma(self):
        text = read("paper/READY/LEMMAS.md")
        self.assertNotIn("theorem P", text)
        self.assertIn("Not theorems", text)


class LemmaP1SaysWhatTheGuardActuallyDoes(unittest.TestCase):
    """Issue #13: the plain sentence for P1 described the opposite rule."""

    CORRECT = (
        "P1. An agent's check is admissible only under a work package issued "
        "for this connection and not yet spent; the first check — passing or "
        "refused — spends it. Issuance is refillable.")

    #: The sentence that shipped.  "Only under a spent work package" inverts
    #: the state the guard requires, and "may change code" names an activity
    #: the lemma does not govern at all.
    STALE = ("P1. An agent may change code only under a spent work package "
             "that is not the tree. Issuance is refillable.")

    def test_the_false_plain_sentence_is_gone(self):
        text = read("paper/READY/LEMMAS.md")
        self.assertNotIn(self.STALE, text)
        self.assertNotIn("only under a spent work package", text)

    def test_the_corrected_plain_sentence_is_present_verbatim(self):
        self.assertIn(self.CORRECT, read("paper/READY/LEMMAS.md"))

    def test_the_plain_sentence_agrees_with_the_lemma_body(self):
        """P1's body already says Issued-not-Spent; the plain line now too."""
        text = read("paper/READY/LEMMAS.md")
        self.assertIn("is still `Issued` (not `Spent`)", text)
        self.assertIn("marks the package `Spent`", text)

    def test_the_implementation_status_names_the_real_versions(self):
        text = read("paper/READY/LEMMAS.md")
        self.assertNotIn("v0.7.1", text)
        self.assertIn("v0.7.0", text)
        self.assertIn("v0.8.0", text)


class RedAdmissibleIsUnchanged(unittest.TestCase):
    """Statement 10: no new composition claim rides in on the split."""

    def test_the_premise_says_red_is_untouched(self):
        text = read("paper/READY/PREMISE.md")
        self.assertIn("Red Admissible is unchanged", text)
        self.assertIn("no new composition claim", text)

    def test_the_premise_carries_the_separation_contract_without_proof(self):
        text = read("paper/READY/PREMISE.md")
        self.assertIn("admissible-ready", text)
        self.assertIn("admissible-trust", text)
        self.assertIn("not a proof", text)


class TheCoreReadmeNamesEveryModuleItShips(unittest.TestCase):
    """`admissible_core.isolation` was shipped and undocumented."""

    @property
    def shipped(self) -> set[str]:
        directory = (ROOT / "packages" / "core" / "src" / "admissible_core")
        return {f"admissible_core.{path.stem}"
                for path in directory.glob("*.py")
                if path.stem != "__init__"}

    def test_the_module_table_is_exactly_the_shipped_modules(self):
        documented = {name for name
                      in _BACKTICKED.findall(read("packages/core/README.md"))
                      if name.startswith("admissible_core.")}
        self.assertEqual(self.shipped, documented)

    def test_isolation_is_among_them(self):
        self.assertIn("admissible_core.isolation", self.shipped)


class LocalMarkdownLinksResolve(unittest.TestCase):
    """Deterministic, offline: every relative link names a file that exists."""

    @staticmethod
    def markdown_files() -> list[Path]:
        files: list[Path] = []
        for name in LINKED_MARKDOWN_ROOTS:
            root = ROOT / name
            if root.is_file():
                files.append(root)
            elif root.is_dir():
                files += sorted(root.rglob("*.md"))
        return sorted(files)

    def test_the_scan_reads_more_than_a_handful_of_files(self):
        self.assertGreater(len(self.markdown_files()), 20)

    def test_every_relative_link_target_exists(self):
        broken = []
        for path in self.markdown_files():
            for number, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), 1):
                for target in _MARKDOWN_LINK.findall(line):
                    if re.match(r"^(https?:|mailto:|#)", target):
                        continue
                    relative = target.split("#", 1)[0]
                    if not relative or (path.parent / relative).exists():
                        continue
                    broken.append(
                        f"{path.relative_to(ROOT)}:{number} -> {target}")
        self.assertEqual([], broken)


class ReleaseChangelogIsExplicit(unittest.TestCase):
    """The public release adds a real changelog without rewriting history."""

    def test_unreleased_stays_above_the_first_public_release(self):
        text = read("CHANGELOG.md")
        self.assertLess(text.index("## [Unreleased]"), text.index("## [0.8.0]"))

    def test_the_release_entry_names_the_frozen_version_and_date(self):
        self.assertIn("## [0.8.0] - 30/08/2026", read("CHANGELOG.md"))


if __name__ == "__main__":
    unittest.main()
