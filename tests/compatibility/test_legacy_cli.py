"""Contract: ``admissible`` still works, and every command has one owner.

The umbrella is a dispatcher.  It parses far enough to know which distribution
owns an invocation, hands the whole argument list to that distribution's
``main``, and returns what it returns.  What it must never do is decide.

Three claims, and they are separate:

* **the table is static** -- command ownership is written down, matches what
  each distribution actually implements, and covers the legacy surface exactly;
* **the routing reads only the argument list** -- not the environment, not a
  credential, not a store; the same words dispatch the same way on every
  machine;
* **there is no fallthrough** -- a Ready command that refuses refuses in Ready,
  and the Trust distribution is not even imported; a Trust command never
  reaches Ready.

Everything runs in a child process with the umbrella on ``PYTHONPATH`` and the
checkout off it, because the repository root still holds the legacy package
under the same import name.  See :mod:`tests.compatibility` for why.
"""
from __future__ import annotations

import ast
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.architecture.test_import_census import load_manifest

from tests.compatibility import (CREDENTIAL_VARIABLES, IMPORT_PATH, READY_SRC,
                                 READY_TARGET, TRUST_SRC, TRUST_TARGET,
                                 UMBRELLA_PACKAGE, dispatch, loaded_domains,
                                 run_module, run_python, umbrella_env)

# The ownership the plan's command matrix records, retyped here on purpose:
# this file is where the decision is asserted, so it must say what the decision
# is rather than read it back out of the code under test.
READY_COMMANDS = frozenset({
    "profiles", "init", "check", "mcp", "connect", "ui",
})
TRUST_COMMANDS = frozenset({
    "ready-status", "attest-review", "attest-evaluation", "policy",
    "finalize", "verify", "impeach", "explain", "status", "export", "import",
})
# The one verb both distributions implement, and therefore the one verb that
# needs a rule rather than a row.
SHARED_COMMANDS = frozenset({"run"})

# The verbs the migration window keeps but does not recommend.  A human gets a
# line on stderr saying which explicit command replaces them; a ``--json`` or
# MCP caller gets nothing at all, because their stdout is a wire format.
TRANSITIONAL_COMMANDS = frozenset({"run", "explain", "status", "export",
                                   "import"})

#: Read the umbrella's own tables back as JSON, so the matrix below is checked
#: against the shipped decision rather than against a second copy of it.
_TABLES = """
import json, sys
from admissible import cli
sys.stdout.write(json.dumps({
    "ready": sorted(cli.READY_COMMANDS),
    "trust": sorted(cli.TRUST_COMMANDS),
    "shared": sorted(cli.SHARED_COMMANDS),
    "submodes": sorted(cli.SUBMODES),
    "transitional": sorted(cli.TRANSITIONAL_COMMANDS),
    "ready_target": cli.READY_TARGET,
    "trust_target": cli.TRUST_TARGET,
}))
"""

#: What each distribution actually implements, read from its own ``_COMMANDS``.
_IMPLEMENTED = """
import json, sys
from admissible_ready import cli as ready
from admissible_trust import cli as trust
sys.stdout.write(json.dumps({
    "ready": sorted(ready._COMMANDS),
    "trust": sorted(trust._COMMANDS),
}))
"""

#: Resolve a batch of invocations without running any of them.
_RESOLVE = """
import json, sys
from admissible import cli
sys.stdout.write(json.dumps(
    [cli.resolve(arguments) for arguments in json.loads(sys.argv[1])]))
"""


def _json_child(code: str, *args: str, env=None) -> object:
    completed = run_python(code, *args, env=env)
    if completed.returncode != 0:
        raise AssertionError(f"probe failed:\n{completed.stderr}")
    return json.loads(completed.stdout)


class TheFixtureImportsTheUmbrella(unittest.TestCase):
    """The control for everything below: which ``admissible`` is under test.

    The repository root is on the child's import path, because the kernel's
    source tree reaches ``fcd`` and ``protocol`` there, and the root also holds
    the legacy monolith under the name this suite is about.  Import order is
    what separates them, so it is asserted rather than assumed: without this
    test, a path regression would quietly re-point every assertion below at the
    package the split is replacing.
    """

    WHERE = """
import json, sys
import admissible, admissible.cli
sys.stdout.write(json.dumps({
    "package": admissible.__file__,
    "cli": admissible.cli.__file__,
    "version": admissible.__version__,
}))
"""

    def test_the_child_imports_the_umbrella_and_not_the_monolith(self):
        found = _json_child(self.WHERE)
        for key in ("package", "cli"):
            with self.subTest(module=key):
                self.assertTrue(
                    found[key].startswith(str(UMBRELLA_PACKAGE)),
                    f"{key} resolved to {found[key]}")
        self.assertEqual("0.8.1", found["version"])

    def test_the_monolith_is_reachable_from_the_root_but_not_first(self):
        """The leak this ordering could have: proved absent, not hoped for."""
        completed = run_python(
            "import admissible\n"
            "try:\n"
            "    import admissible.store\n"
            "except ModuleNotFoundError as error:\n"
            "    print('ModuleNotFoundError')\n")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("ModuleNotFoundError", completed.stdout.strip())


class DispatchTableIsExplicitAndTotal(unittest.TestCase):
    """Ownership is written down, and it is the ownership that exists."""

    @classmethod
    def setUpClass(cls):
        cls.tables = _json_child(_TABLES)

    def test_the_ready_half_of_the_table_is_the_agreed_one(self):
        self.assertEqual(sorted(READY_COMMANDS), self.tables["ready"])

    def test_the_trust_half_of_the_table_is_the_agreed_one(self):
        self.assertEqual(sorted(TRUST_COMMANDS), self.tables["trust"])

    def test_the_two_halves_are_disjoint_apart_from_the_shared_verbs(self):
        overlap = set(self.tables["ready"]) & set(self.tables["trust"])
        self.assertEqual(set(), overlap, "a command may have one owner only")

    def test_every_shared_verb_has_an_explicit_submode_rule(self):
        """A verb both distributions implement is ambiguous until a rule says
        which shape belongs to which, and an ambiguity is never resolved by
        looking at the machine."""
        self.assertEqual(sorted(SHARED_COMMANDS), self.tables["shared"])
        self.assertEqual(self.tables["shared"], self.tables["submodes"])

    def test_the_table_names_the_two_distribution_entry_modules(self):
        self.assertEqual(READY_TARGET, self.tables["ready_target"])
        self.assertEqual(TRUST_TARGET, self.tables["trust_target"])

    def test_each_half_is_exactly_what_that_distribution_implements(self):
        """The table is not allowed to promise a command nobody ships."""
        implemented = _json_child(_IMPLEMENTED)
        self.assertEqual(
            sorted(READY_COMMANDS | SHARED_COMMANDS), implemented["ready"],
            "the Ready rows plus the shared verbs are admissible-ready's map")
        self.assertEqual(
            sorted(TRUST_COMMANDS | SHARED_COMMANDS), implemented["trust"],
            "the Trust rows plus the shared verbs are admissible-trust's map")

    def test_the_table_covers_the_legacy_command_surface_exactly(self):
        """Every verb the monolith dispatched, and no verb it did not.

        The surface comes from the architecture manifest, which derives it from
        the parsed legacy CLI: a command that existed and is not routed here is
        a command the umbrella silently dropped.
        """
        legacy = load_manifest()["cli_surface"]["dispatched_commands"]
        self.assertEqual(
            sorted(legacy),
            sorted(READY_COMMANDS | TRUST_COMMANDS | SHARED_COMMANDS))

    def test_the_transitional_set_is_the_ambiguous_legacy_verbs(self):
        self.assertEqual(sorted(TRANSITIONAL_COMMANDS),
                         self.tables["transitional"])
        for command in TRANSITIONAL_COMMANDS:
            with self.subTest(command=command):
                self.assertIn(
                    command, READY_COMMANDS | TRUST_COMMANDS | SHARED_COMMANDS,
                    "a transitional verb must still be a routed verb")


class ResolutionMatrix(unittest.TestCase):
    """Where each invocation goes, asserted one invocation at a time."""

    def resolve(self, *invocations: list[str], env=None) -> list:
        return _json_child(_RESOLVE, json.dumps(list(invocations)), env=env)

    def test_every_ready_command_resolves_to_the_ready_distribution(self):
        commands = sorted(READY_COMMANDS)
        answers = self.resolve(*([command] for command in commands))
        self.assertEqual([READY_TARGET] * len(commands), answers,
                         dict(zip(commands, answers)))

    def test_every_trust_command_resolves_to_the_trust_distribution(self):
        commands = sorted(TRUST_COMMANDS)
        answers = self.resolve(*([command] for command in commands))
        self.assertEqual([TRUST_TARGET] * len(commands), answers,
                         dict(zip(commands, answers)))

    def test_the_policy_subcommands_all_stay_in_trust(self):
        """Including ``policy list``: reading the home is the home's business."""
        answers = self.resolve(["policy", "trust"], ["policy", "revoke"],
                               ["policy", "list"], ["policy", "list", "--all"])
        self.assertEqual([TRUST_TARGET] * 4, answers)

    def test_run_with_the_bare_preview_flag_is_the_ready_evaluation(self):
        answers = self.resolve(
            ["run", "--preview"],
            ["run", "--preview", "--repo", "."],
            ["run", "--repo", ".", "--preview", "--json"],
            ["run", "--preview", "--preview-out", "preview.json"])
        self.assertEqual([READY_TARGET] * 4, answers)

    def test_run_without_preview_is_the_transitional_trust_alias(self):
        answers = self.resolve(["run"], ["run", "--json"],
                               ["run", "--repo", "."])
        self.assertEqual([TRUST_TARGET] * 3, answers)

    def test_run_with_a_preview_file_is_the_trust_alias_for_finalize(self):
        """``--preview FILE`` is Trust's shape; ``--preview`` alone is Ready's.

        The two are told apart by the argument list and nothing else: Ready's
        ``run`` takes no positional argument at all, so a value after
        ``--preview`` cannot be a Ready invocation.
        """
        answers = self.resolve(
            ["run", "--preview", "preview.json"],
            ["run", "--preview=preview.json"],
            ["run", "--preview", "preview.json", "--sha", "0" * 40])
        self.assertEqual([TRUST_TARGET] * 3, answers)

    def test_the_preview_file_shape_reaches_trust_and_only_trust(self):
        """The rule above, followed all the way through to an import."""
        report = dispatch(["run", "--preview", "preview.json"])
        self.assertEqual({"admissible_trust"}, loaded_domains(report))

    def test_an_unknown_command_resolves_to_nothing(self):
        answers = self.resolve(["finalise"], ["sign"], ["ready"], ["polic"],
                               ["run-preview"], [""])
        self.assertEqual([None] * 6, answers)

    def test_an_option_where_a_command_belongs_resolves_to_nothing(self):
        """``admissible --json`` names no command, so it routes nowhere."""
        answers = self.resolve(["--json"], ["--repo", "."], ["-x"], [])
        self.assertEqual([None] * 4, answers)


class RoutingNeverReadsTheEnvironment(unittest.TestCase):
    """Ambient credentials are a fail-closed guard, never a router.

    Two proofs, because either alone is weak: the routing answers the same way
    under every credential this product knows about, and the dispatcher's
    source never reads the environment at all.
    """

    INVOCATIONS = (["check"], ["finalize"], ["run"], ["run", "--preview"],
                   ["status"], ["explain", "abc"])

    def resolve(self, env=None) -> list:
        return _json_child(_RESOLVE, json.dumps([list(invocation)
                                                 for invocation in
                                                 self.INVOCATIONS]), env=env)

    def test_the_answers_are_identical_under_every_credential(self):
        baseline = self.resolve()
        self.assertNotIn(None, baseline, "the fixture must route somewhere")
        for variable in CREDENTIAL_VARIABLES:
            with self.subTest(credential=variable):
                answers = self.resolve(
                    env=umbrella_env({variable: "not-a-real-key"}))
                self.assertEqual(baseline, answers)

    def test_the_answers_are_identical_with_every_credential_at_once(self):
        loaded = {variable: "not-a-real-key"
                  for variable in CREDENTIAL_VARIABLES}
        self.assertEqual(self.resolve(),
                         self.resolve(env=umbrella_env(loaded)))

    def test_the_dispatcher_source_reads_no_environment_variable(self):
        source = (UMBRELLA_PACKAGE / "cli.py").read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(UMBRELLA_PACKAGE / "cli.py"))
        readers = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in (
                    "environ", "getenv"):
                readers.append(node.attr)
            if isinstance(node, ast.Name) and node.id in ("environ", "getenv"):
                readers.append(node.id)
        self.assertEqual([], readers, "the router must read only its argv")
        self.assertNotIn("ADMISSIBLE_", source,
                         "a credential name in the router is a router that "
                         "could come to depend on one")


class NoFallthroughBetweenDomains(unittest.TestCase):
    """A refusal is final.  The other authority is not a second opinion."""

    def test_a_ready_command_beside_a_credential_refuses_inside_ready(self):
        for variable in CREDENTIAL_VARIABLES:
            with self.subTest(credential=variable):
                report = dispatch(
                    ["check", "--json"],
                    env=umbrella_env({variable: "not-a-real-key"}))
                self.assertEqual(2, report["exit_code"])
                self.assertEqual({"admissible_ready"}, loaded_domains(report),
                                 "the refusal must not fall through to Trust")
                self.assertIn(variable, report["stdout"],
                              "Ready must say which credential it refused for")

    def test_a_ready_command_never_imports_the_trust_distribution(self):
        for command in sorted(READY_COMMANDS - {"mcp", "ui", "connect"}):
            with self.subTest(command=command):
                report = dispatch([command, "--json"])
                self.assertNotIn("admissible_trust", loaded_domains(report))

    def test_a_trust_command_never_invokes_ready_as_a_helper(self):
        for command in sorted(TRUST_COMMANDS):
            with self.subTest(command=command):
                report = dispatch([command, "--json"])
                self.assertNotIn(
                    "admissible_ready", loaded_domains(report),
                    "a signing process must not be able to run a candidate")

    def test_the_transitional_run_alias_loads_trust_alone(self):
        report = dispatch(["run", "--json"])
        self.assertEqual({"admissible_trust"}, loaded_domains(report))
        self.assertEqual(2, report["exit_code"])

    def test_a_refused_ready_run_does_not_retry_as_a_trust_run(self):
        report = dispatch(["run", "--preview", "--repo", "/nonexistent",
                           "--json"])
        self.assertEqual({"admissible_ready"}, loaded_domains(report))
        self.assertNotEqual(0, report["exit_code"])


class UnknownAndAmbiguousInvocationsFailClosed(unittest.TestCase):
    """Refusing is the only safe answer to a command with no owner."""

    def test_an_unknown_command_refuses_and_loads_no_domain(self):
        report = dispatch(["finalise"])
        self.assertEqual(2, report["exit_code"])
        self.assertEqual(set(), loaded_domains(report),
                         "nothing may be imported on the way to a refusal")
        self.assertIn("finalise", report["stderr"])

    def test_an_unknown_command_answers_a_json_caller_on_stdout(self):
        report = dispatch(["finalise", "--json"])
        self.assertEqual(2, report["exit_code"])
        document = json.loads(report["stdout"])
        self.assertEqual("BLOCKED", document["state"])
        self.assertIn("finalise", document["message"])
        self.assertTrue(document["remediation"])

    def test_the_refusal_names_the_two_explicit_commands(self):
        report = dispatch(["finalise"])
        self.assertIn("admissible-ready", report["stderr"])
        self.assertIn("admissible-trust", report["stderr"])

    def test_an_option_without_a_command_refuses(self):
        report = dispatch(["--repo", "."])
        self.assertEqual(2, report["exit_code"])
        self.assertEqual(set(), loaded_domains(report))


class AMissingSiblingIsSaidRatherThanSubstituted(unittest.TestCase):
    """The other distribution is installed.  It is still the wrong one."""

    def without(self, *dropped: Path) -> dict[str, str]:
        keep = [entry for entry in IMPORT_PATH if entry not in dropped]
        return umbrella_env(
            {"PYTHONPATH": ":".join(str(entry) for entry in keep)})

    def test_a_trust_command_without_trust_installed_refuses(self):
        report = dispatch(["verify", "0" * 40, "--json"],
                          env=self.without(TRUST_SRC))
        self.assertEqual(2, report["exit_code"])
        document = json.loads(report["stdout"])
        self.assertIn("admissible-trust", document["message"])
        self.assertEqual(set(), loaded_domains(report),
                         "a missing owner is never replaced by the sibling")

    def test_a_ready_command_without_ready_installed_refuses(self):
        report = dispatch(["check", "--json"], env=self.without(READY_SRC))
        self.assertEqual(2, report["exit_code"])
        self.assertIn("admissible-ready",
                      json.loads(report["stdout"])["message"])
        self.assertEqual(set(), loaded_domains(report))

    def test_the_refusal_is_prose_on_stderr_without_json(self):
        report = dispatch(["verify", "0" * 40], env=self.without(TRUST_SRC))
        self.assertEqual(2, report["exit_code"])
        self.assertEqual("", report["stdout"])
        self.assertIn("admissible-trust", report["stderr"])


#: A module name nothing on any machine provides, used as the thing a broken
#: owner reaches for.  Spelled once so a message assertion can look for it.
ABSENT_MODULE = "a_module_that_is_definitely_not_installed_9c1f"

#: Five ways an *installed* owner can fail to import, and the name that appears
#: in the exception each raises.  None of them is an absent distribution: in
#: every one, ``admissible_ready`` is on the path and is found.
#:
#: The distinction matters because the two refusals send a reader to different
#: places.  "The distribution is not here" means install it; "the distribution
#: is here and its code raised" means the installed release has a defect, and
#: telling the second story with the first sentence sends somebody to reinstall
#: a package that is already installed while the real fault stays put.
BROKEN_OWNERS = {
    "a transitively absent import": (
        {"__init__.py": "", "cli.py": f"import {ABSENT_MODULE}\n"},
        ABSENT_MODULE, "ModuleNotFoundError"),
    "an absent import one level deeper": (
        {"__init__.py": "",
         "cli.py": "from admissible_ready import deep\n",
         "deep.py": f"import {ABSENT_MODULE}\n"},
        ABSENT_MODULE, "ModuleNotFoundError"),
    "a name the owner's own module does not define": (
        {"__init__.py": "",
         "cli.py": "from admissible_ready.helpers import missing_name\n",
         "helpers.py": "PRESENT = True\n"},
        "admissible_ready.helpers", "ImportError"),
    "an entry module the install never wrote": (
        {"__init__.py": ""},
        "admissible_ready.cli", "ModuleNotFoundError"),
    "a package whose __init__ itself raises": (
        {"__init__.py": f"import {ABSENT_MODULE}\n", "cli.py": ""},
        ABSENT_MODULE, "ModuleNotFoundError"),
}

#: The sentence the absent-owner refusal uses, and therefore the sentence a
#: present-but-broken owner must not be described with.
ABSENT_PHRASE = "not importable in this environment"


class AnOwnerThatFailsToImportIsNotCalledAbsent(unittest.TestCase):
    """An ``ImportError`` is two different facts, and they need two answers.

    The dispatcher imports one module and one only.  When that import raises,
    the question is whether the distribution that owns the command is *not
    here* -- ``pip install --no-deps admissible`` is a real thing people do --
    or is here and broken.  Catching every ``ImportError`` and reporting the
    first answer makes the second one unreportable: a genuine defect inside
    ``admissible_ready`` reads, to every user and every log, as a missing
    install.

    Each case below puts a broken ``admissible_ready`` ahead of the real one on
    the import path, so the top-level package is unambiguously present and only
    its contents are wrong.
    """

    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="admissible-broken-")
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.shadows = {}
        for index, (label, (files, _name, _kind)) in enumerate(
                sorted(BROKEN_OWNERS.items())):
            shadow = Path(cls.workspace.name) / f"case-{index}"
            package = shadow / "admissible_ready"
            package.mkdir(parents=True)
            for name, source in files.items():
                (package / name).write_text(source, encoding="utf-8")
            cls.shadows[label] = shadow

    def shadowed(self, label: str) -> dict[str, str]:
        """The umbrella's own import path with a broken owner ahead of Ready."""
        entries = [IMPORT_PATH[0], self.shadows[label], *IMPORT_PATH[1:]]
        return umbrella_env(
            {"PYTHONPATH": ":".join(str(entry) for entry in entries)})

    def refusal(self, label: str, *arguments: str) -> dict:
        return dispatch(list(arguments), env=self.shadowed(label))

    def test_the_fixture_really_shadows_an_installed_owner(self):
        """The control: the top-level package is present in every case."""
        for label in sorted(BROKEN_OWNERS):
            with self.subTest(case=label):
                completed = run_python(
                    "import importlib.util, sys\n"
                    "spec = importlib.util.find_spec('admissible_ready')\n"
                    "sys.stdout.write(spec.origin or '')\n",
                    env=self.shadowed(label))
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertTrue(
                    completed.stdout.startswith(str(self.shadows[label])),
                    f"the broken owner is not first: {completed.stdout}")

    def test_a_broken_owner_is_refused_rather_than_reported_absent(self):
        for label, (_files, _name, _kind) in sorted(BROKEN_OWNERS.items()):
            with self.subTest(case=label):
                report = self.refusal(label, "check", "--json")
                self.assertEqual(2, report["exit_code"])
                document = json.loads(report["stdout"])
                self.assertEqual("BLOCKED", document["state"])
                self.assertNotIn(ABSENT_PHRASE, document["message"])

    def test_the_refusal_names_the_import_that_actually_failed(self):
        """Not swallowed: the defect is quoted, so it can be acted on."""
        for label, (_files, name, kind) in sorted(BROKEN_OWNERS.items()):
            with self.subTest(case=label):
                report = self.refusal(label, "check", "--json")
                message = json.loads(report["stdout"])["message"]
                self.assertIn(name, message)
                self.assertIn(kind, message)

    def test_the_refusal_says_the_distribution_is_present(self):
        for label in sorted(BROKEN_OWNERS):
            with self.subTest(case=label):
                message = json.loads(
                    self.refusal(label, "check", "--json")["stdout"])["message"]
                self.assertIn("admissible-ready", message)
                self.assertIn("installed", message)

    def test_a_broken_owner_never_falls_through_to_the_other_domain(self):
        for label in sorted(BROKEN_OWNERS):
            with self.subTest(case=label):
                report = self.refusal(label, "check", "--json")
                self.assertNotIn("admissible_trust", loaded_domains(report))
                self.assertNotIn(
                    "admissible-trust",
                    json.loads(report["stdout"])["message"],
                    "a broken Ready is never answered by Trust")

    def test_the_machine_document_carries_the_whole_contract(self):
        for label in sorted(BROKEN_OWNERS):
            with self.subTest(case=label):
                report = self.refusal(label, "check", "--json")
                document = json.loads(report["stdout"])
                self.assertEqual(
                    ["exit_code", "message", "readiness", "remediation",
                     "scope", "state"], sorted(document))
                self.assertEqual(2, document["exit_code"])
                self.assertTrue(document["remediation"])
                self.assertEqual("", report["stderr"],
                                 "a --json caller reads one stream only")

    def test_the_human_refusal_is_prose_on_stderr_alone(self):
        for label, (_files, name, _kind) in sorted(BROKEN_OWNERS.items()):
            with self.subTest(case=label):
                report = self.refusal(label, "check")
                self.assertEqual(2, report["exit_code"])
                self.assertEqual("", report["stdout"])
                self.assertIn("BLOCKED", report["stderr"])
                self.assertIn(name, report["stderr"])
                self.assertNotIn(ABSENT_PHRASE, report["stderr"])

    def test_a_broken_trust_owner_is_classified_the_same_way(self):
        """The rule is about the relationship, not about which domain it is."""
        shadow = Path(self.workspace.name) / "broken-trust"
        package = shadow / "admissible_trust"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "cli.py").write_text(f"import {ABSENT_MODULE}\n",
                                        encoding="utf-8")
        entries = [IMPORT_PATH[0], shadow, *IMPORT_PATH[1:]]
        report = dispatch(["verify", "0" * 40, "--json"], env=umbrella_env(
            {"PYTHONPATH": ":".join(str(entry) for entry in entries)}))
        document = json.loads(report["stdout"])
        self.assertEqual(2, report["exit_code"])
        self.assertNotIn(ABSENT_PHRASE, document["message"])
        self.assertIn(ABSENT_MODULE, document["message"])
        self.assertIn("admissible-trust", document["message"])
        self.assertNotIn("admissible_ready", loaded_domains(report))

    def test_a_genuinely_absent_owner_still_gets_the_absent_refusal(self):
        """The other half of the distinction, asserted beside it.

        Without this, "never say absent" would be satisfiable by never saying
        it at all, and the bounded refusal the umbrella exists to give when a
        sibling is missing would quietly become a defect report.
        """
        keep = [entry for entry in IMPORT_PATH if entry != READY_SRC]
        report = dispatch(["check", "--json"], env=umbrella_env(
            {"PYTHONPATH": ":".join(str(entry) for entry in keep)}))
        document = json.loads(report["stdout"])
        self.assertEqual(2, report["exit_code"])
        self.assertIn(ABSENT_PHRASE, document["message"])
        self.assertIn("admissible-ready", document["message"])
        self.assertEqual(set(), loaded_domains(report))


#: The sentence a refusal may use only when it is true, and the sentence a
#: partial import must use instead.  Retyped here rather than imported: this
#: file is where the wording is decided, so it says what the wording is.
UNIMPORTED_PHRASE = "nothing was imported"
NO_FALLBACK_PHRASE = "no fallback to the opposite authority was attempted"

#: Three ways an *installed* owner fails to import after it has already run.
#: The value is the evidence each leaves behind: a module still in
#: ``sys.modules`` once the exception has propagated, or a file on disk.
#:
#: Python removes a module from ``sys.modules`` when its execution raises, but
#: it removes only that module: a package whose ``__init__`` finished and whose
#: entry module then raised is still there, and a submodule the ``__init__``
#: loaded before raising is still there even though the package itself is not.
#: Neither is a hypothetical -- the first is the shape of every broken entry
#: module, and it is the shape of four of the five cases in
#: :data:`BROKEN_OWNERS`.
PARTIAL_OWNERS = {
    "the package imports and its entry module raises": (
        {"__init__.py": "", "cli.py": f"import {ABSENT_MODULE}\n"},
        "admissible_ready", None),
    "the __init__ loads a submodule and then raises": (
        {"__init__.py": ("from admissible_ready import helper\n"
                         f"import {ABSENT_MODULE}\n"),
         "helper.py": "PRESENT = True\n",
         "cli.py": ""},
        "admissible_ready.helper", None),
    "the __init__ runs code with an effect and then raises": (
        {"__init__.py": ("import pathlib\n"
                         "pathlib.Path(__file__).with_name('ran.marker')"
                         ".write_text('the owner executed', encoding='utf-8')\n"
                         f"import {ABSENT_MODULE}\n"),
         "cli.py": ""},
        None, "ran.marker"),
}


class ABrokenOwnerIsNotReportedAsOneThatNeverRan(unittest.TestCase):
    """"Nothing was imported" is a claim, and for a broken owner it is false.

    The dispatcher's refusal has a "What is known" line, and its whole job is
    to tell a reader where to look.  For a command that was never routed, and
    for an owner that is genuinely not installed, nothing ran and the line is
    true.  For an owner that is installed and broken it is not: the import was
    attempted, so the package's ``__init__`` may have finished, a submodule may
    still be in ``sys.modules``, and whatever that code did on the way to
    raising has already happened.  Telling that reader nothing was imported
    sends them to look for a fault in a process they have been told did not
    start.

    What must survive unchanged is the property the line was there to state:
    the failure was not answered by reaching for the other distribution.  That
    is the claim the split depends on, it is true in every case here, and it is
    asserted as itself rather than as a side effect of "nothing was imported".
    """

    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="admissible-partial-")
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.shadows = {}
        for index, (label, (files, _module, _marker)) in enumerate(
                sorted(PARTIAL_OWNERS.items())):
            shadow = Path(cls.workspace.name) / f"partial-{index}"
            package = shadow / "admissible_ready"
            package.mkdir(parents=True)
            for name, source in files.items():
                (package / name).write_text(source, encoding="utf-8")
            cls.shadows[label] = shadow

    def refusal(self, label: str, *arguments: str) -> dict:
        """Dispatch with the partially-importable owner ahead of the real one."""
        shadow = self.shadows[label]
        marker = shadow / "admissible_ready" / "ran.marker"
        marker.unlink(missing_ok=True)
        entries = [IMPORT_PATH[0], shadow, *IMPORT_PATH[1:]]
        return dispatch(list(arguments), env=umbrella_env(
            {"PYTHONPATH": ":".join(str(entry) for entry in entries)}))

    def test_the_fixture_really_leaves_the_owner_partly_imported(self):
        """The control: each case proves something ran before the failure."""
        for label, (_files, module, marker) in sorted(PARTIAL_OWNERS.items()):
            with self.subTest(case=label):
                report = self.refusal(label, "check", "--json")
                self.assertEqual(2, report["exit_code"])
                if module is not None:
                    self.assertIn(module, report["modules"])
                if marker is not None:
                    self.assertTrue(
                        (self.shadows[label] / "admissible_ready"
                         / marker).is_file(),
                        "the owner's __init__ did not run")

    def test_the_refusal_does_not_claim_that_nothing_was_imported(self):
        for label in sorted(PARTIAL_OWNERS):
            with self.subTest(case=label):
                report = self.refusal(label, "check")
                self.assertNotIn(UNIMPORTED_PHRASE, report["stderr"])
                document = json.loads(
                    self.refusal(label, "check", "--json")["stdout"])
                self.assertNotIn(UNIMPORTED_PHRASE, document["message"])

    def test_the_refusal_says_no_other_authority_was_reached_for(self):
        """The claim that had been riding on the false one, said directly."""
        for label in sorted(PARTIAL_OWNERS):
            with self.subTest(case=label):
                report = self.refusal(label, "check")
                self.assertIn(NO_FALLBACK_PHRASE, report["stderr"])
                document = json.loads(
                    self.refusal(label, "check", "--json")["stdout"])
                self.assertIn(NO_FALLBACK_PHRASE, document["message"])

    def test_the_refusal_says_the_import_itself_was_attempted(self):
        for label in sorted(PARTIAL_OWNERS):
            with self.subTest(case=label):
                report = self.refusal(label, "check")
                self.assertIn("import", report["stderr"])
                self.assertIn("admissible-ready", report["stderr"])
                self.assertIn(ABSENT_MODULE, report["stderr"])

    def test_the_partial_import_never_reaches_the_other_domain(self):
        """The property the wording exists to report, asserted as a fact."""
        for label in sorted(PARTIAL_OWNERS):
            with self.subTest(case=label):
                report = self.refusal(label, "check", "--json")
                self.assertNotIn("admissible_trust", loaded_domains(report))
                self.assertNotIn(
                    "admissible-trust",
                    json.loads(report["stdout"])["message"])

    def test_the_machine_document_keeps_exactly_its_six_keys(self):
        """A --json caller's contract does not move because prose did."""
        for label in sorted(PARTIAL_OWNERS):
            with self.subTest(case=label):
                report = self.refusal(label, "check", "--json")
                document = json.loads(report["stdout"])
                self.assertEqual(
                    ["exit_code", "message", "readiness", "remediation",
                     "scope", "state"], sorted(document))
                self.assertEqual("BLOCKED", document["state"])
                self.assertEqual("", report["stderr"],
                                 "a --json caller reads one stream only")

    def test_a_genuinely_absent_owner_still_says_nothing_was_imported(self):
        """The wording is not deleted, it is confined to where it is true."""
        keep = [entry for entry in IMPORT_PATH if entry != READY_SRC]
        environment = umbrella_env(
            {"PYTHONPATH": ":".join(str(entry) for entry in keep)})
        report = dispatch(["check"], env=environment)
        self.assertEqual(2, report["exit_code"])
        self.assertIn(UNIMPORTED_PHRASE, report["stderr"])
        self.assertEqual(set(), loaded_domains(dispatch(
            ["check", "--json"], env=environment)))

    def test_a_command_that_was_never_routed_still_says_it_too(self):
        report = dispatch(["finalise"])
        self.assertEqual(2, report["exit_code"])
        self.assertIn(UNIMPORTED_PHRASE, report["stderr"])
        self.assertEqual(set(), loaded_domains(report))


class TheDispatcherTouchesNoStore(unittest.TestCase):
    """No migration, no reset, no read: the local home is not its business.

    An existing v0.7 home stays exactly as it was found -- the distributions
    that own the store are the ones that open it, and their compatibility with
    an older home is asserted in their own suites.  What is asserted here is
    that this layer adds nothing to that question.
    """

    def home_state(self, home: Path) -> list[tuple[str, int]]:
        return sorted((str(path.relative_to(home)), path.stat().st_size)
                      for path in home.rglob("*") if path.is_file())

    def test_an_undispatched_invocation_leaves_the_home_untouched(self):
        with tempfile.TemporaryDirectory(prefix="admissible-home-") as raw:
            home = Path(raw)
            (home / "store.sqlite3").write_bytes(b"a v0.7 home this is not")
            before = self.home_state(home)
            for arguments in ([], ["--help"], ["finalise"],
                              ["finalise", "--json"], ["--repo", "."]):
                with self.subTest(arguments=arguments):
                    dispatch(arguments,
                             env=umbrella_env({"ADMISSIBLE_HOME": str(home)}))
                    self.assertEqual(before, self.home_state(home))

    def test_no_umbrella_module_names_a_store_or_a_database_at_all(self):
        for path in sorted(UMBRELLA_PACKAGE.rglob("*.py")):
            with self.subTest(module=path.name):
                source = path.read_text(encoding="utf-8")
                for forbidden in ("sqlite3", "store_open", "store_base",
                                  "store_read", "store_candidate",
                                  "admissible_core.store", ".store"):
                    self.assertNotIn(forbidden, source)


class HelpStaysUsable(unittest.TestCase):
    """The first thing anybody types must still answer."""

    def test_help_exits_zero_and_lists_every_routed_command(self):
        report = dispatch(["--help"])
        self.assertEqual(0, report["exit_code"])
        for command in sorted(READY_COMMANDS | TRUST_COMMANDS
                              | SHARED_COMMANDS):
            with self.subTest(command=command):
                self.assertIn(command, report["stdout"])

    def test_help_says_which_distribution_owns_what(self):
        report = dispatch(["--help"])
        self.assertIn("admissible-ready", report["stdout"])
        self.assertIn("admissible-trust", report["stdout"])

    def test_help_loads_neither_distribution(self):
        self.assertEqual(set(), loaded_domains(dispatch(["--help"])))

    def test_no_arguments_prints_help_and_blocks(self):
        report = dispatch([])
        self.assertEqual(2, report["exit_code"])
        self.assertTrue(report["stdout"].strip())

    def test_the_module_entry_point_answers_identically(self):
        """``python -m admissible`` is the other way people start it."""
        completed = run_module("admissible", "--help")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(dispatch(["--help"])["stdout"], completed.stdout)

    def test_the_module_entry_point_returns_the_command_exit_code(self):
        completed = run_module("admissible", "finalise")
        self.assertEqual(2, completed.returncode)


class MachineOutputIsUncontaminated(unittest.TestCase):
    """A dispatcher that prints is a dispatcher that corrupts a wire format."""

    def direct(self, module: str, arguments: list[str], *,
               env=None, stdin: str | None = None):
        code = (
            "import json, sys\n"
            f"from {module} import main\n"
            "sys.exit(main(json.loads(sys.argv[1])))\n")
        return run_python(code, json.dumps(arguments), env=env, stdin=stdin)

    def umbrella(self, arguments: list[str], *, env=None,
                 stdin: str | None = None):
        code = ("import json, sys\n"
                "from admissible.cli import main\n"
                "sys.exit(main(json.loads(sys.argv[1])))\n")
        return run_python(code, json.dumps(arguments), env=env, stdin=stdin)

    def test_a_ready_json_command_is_byte_identical_to_the_direct_one(self):
        arguments = ["profiles", "--json"]
        through = self.umbrella(arguments)
        direct = self.direct(READY_TARGET, arguments)
        self.assertEqual(direct.returncode, through.returncode)
        self.assertEqual(direct.stdout, through.stdout)
        json.loads(through.stdout)

    def test_a_trust_json_command_is_byte_identical_to_the_direct_one(self):
        arguments = ["verify", "0" * 40, "--json"]
        through = self.umbrella(arguments)
        direct = self.direct(TRUST_TARGET, arguments)
        self.assertEqual(direct.returncode, through.returncode)
        self.assertEqual(direct.stdout, through.stdout)
        json.loads(through.stdout)

    def test_a_transitional_json_command_carries_no_warning_at_all(self):
        """Not on stdout, which is the document, and not on stderr either.

        A ``--json`` caller is a program.  It is reading one of the two
        streams and logging the other, and a deprecation line in either is a
        line it did not ask for.
        """
        arguments = ["explain", "0" * 40, "--json"]
        through = self.umbrella(arguments)
        direct = self.direct(TRUST_TARGET, arguments)
        self.assertEqual(direct.stdout, through.stdout)
        self.assertEqual(direct.stderr, through.stderr)
        self.assertNotIn("deprecat", through.stdout.lower())
        self.assertNotIn("deprecat", through.stderr.lower())

    def test_an_unknown_json_invocation_writes_only_a_document(self):
        report = dispatch(["finalise", "--json"])
        self.assertEqual("", report["stderr"])
        json.loads(report["stdout"])


class HumanWarningsGoToStderrOnly(unittest.TestCase):
    """The migration is said out loud, on the stream prose belongs on."""

    def test_the_transitional_verbs_warn_and_name_their_replacement(self):
        for command, arguments in (
                ("explain", ["explain", "0" * 40]),
                ("status", ["status"]),
                ("export", ["export", "--out", "journal.json"]),
                ("import", ["import", "--in", "journal.json"]),
                ("run", ["run"])):
            with self.subTest(command=command):
                report = dispatch(arguments)
                self.assertIn("admissible-", report["stderr"])
                self.assertNotIn("deprecat", report["stdout"].lower())

    def test_a_ready_command_that_is_not_transitional_says_nothing_extra(self):
        report = dispatch(["profiles"])
        direct = run_python(
            "import json, sys\n"
            f"from {READY_TARGET} import main\n"
            "sys.exit(main(json.loads(sys.argv[1])))\n",
            json.dumps(["profiles"]))
        self.assertEqual(direct.stdout, report["stdout"])
        self.assertEqual(direct.stderr, report["stderr"])

    def test_the_run_warning_names_both_halves_of_the_split(self):
        report = dispatch(["run"])
        self.assertIn("admissible-ready run --preview", report["stderr"])
        self.assertIn("admissible-trust finalize", report["stderr"])


class McpStdoutIsByteCompatible(unittest.TestCase):
    """MCP speaks JSON-RPC on stdout; one stray byte ends the session."""

    REQUESTS = (
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "canary"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )

    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="admissible-mcp-")
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.repo = Path(cls.workspace.name) / "candidate"
        cls.repo.mkdir(parents=True)
        cls.home = Path(cls.workspace.name) / "home"
        (cls.repo / "README.md").write_text("a commit to speak about\n",
                                            encoding="utf-8")
        for arguments in (("init", "--quiet"),
                          ("config", "user.email", "mcp@example.com"),
                          ("config", "user.name", "MCP"),
                          ("add", "-A"),
                          ("commit", "--quiet", "-m", "fixture")):
            subprocess.run(("git", "-C", str(cls.repo), *arguments),
                           check=True, timeout=60, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)

    def stdin(self) -> str:
        return "".join(json.dumps(item) + "\n" for item in self.REQUESTS)

    def mcp(self, code: str) -> object:
        return run_python(
            code, json.dumps([
                "mcp", "--repo", str(self.repo), "--agent-name", "canary",
                "--purpose", "prove the umbrella does not speak", "--runtime",
                "local"]),
            stdin=self.stdin(),
            env=umbrella_env({"ADMISSIBLE_HOME": str(self.home)}))

    def test_the_umbrella_and_ready_produce_the_same_stdout_bytes(self):
        through = self.mcp("import json, sys\n"
                           "from admissible.cli import main\n"
                           "sys.exit(main(json.loads(sys.argv[1])))\n")
        direct = self.mcp("import json, sys\n"
                          f"from {READY_TARGET} import main\n"
                          "sys.exit(main(json.loads(sys.argv[1])))\n")
        self.assertEqual(0, direct.returncode, direct.stderr)
        self.assertEqual(0, through.returncode, through.stderr)
        self.assertEqual(direct.stdout, through.stdout)

    def test_the_first_stdout_byte_is_the_first_json_rpc_frame(self):
        through = self.mcp("import json, sys\n"
                           "from admissible.cli import main\n"
                           "sys.exit(main(json.loads(sys.argv[1])))\n")
        first = through.stdout.splitlines()[0]
        self.assertEqual("2.0", json.loads(first)["jsonrpc"])


if __name__ == "__main__":
    unittest.main()
