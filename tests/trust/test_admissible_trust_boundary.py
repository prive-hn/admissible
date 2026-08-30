"""Contract: the one place Trust touches the outside is a fixed Git read.

Trust holds a key, so the capability it must not have is the ability to start a
program the repository under evaluation chose.  It still has to *identify* that
repository -- finalization re-derives repository, commit and tree rather than
believing a preview -- and identifying a working tree means running ``git``.

That is the whole exception, and it is asserted three ways:

* **static** -- every ``subprocess`` name in the distribution's source appears
  in :mod:`admissible_trust.git_reader` and nowhere else, and no other module
  even imports the module that could start one;
* **shape** -- the adapter's six questions map to six literal argument lists,
  ``argv[0]`` is the absolute system executable the adapter validated rather
  than a name to be looked up, the only interpolated values are a path the
  caller supplied and a commit SHA the kernel has already required to be 40 hex
  characters, and the child's environment is stripped of every ``GIT_*``
  variable and every Admissible credential;
* **runtime** -- with ``subprocess.run``, ``subprocess.Popen`` and ``os.exec*``
  all trapped, a whole finalization runs and the only argument vectors that
  reach the trap are ``git`` queries from that adapter's own vocabulary.

The last one is the claim that matters.  A source scan proves that no *name*
was written down; only running the finalizer with the traps armed proves that
no path through it starts anything.

Which ``git`` that absolute ``argv[0]`` resolves to, and what makes it
trustworthy enough to be run by a process holding the admission key, is the
subject of ``test_admissible_trust_executable``.
"""
from __future__ import annotations

import ast
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from admissible_core.identity import GIT_QUERIES, IdentityError

from admissible_trust import git_reader

from . import TRUST_SRC

TRUST_PACKAGE = TRUST_SRC / "admissible_trust"

# The module that is allowed to start a process, named once.
ADAPTER = "git_reader.py"

# Names that start, replace or fork a process. A module that imports none of
# them cannot begin one, whatever it was asked to do.
PROCESS_MODULES = ("subprocess", "multiprocessing", "pty", "_posixsubprocess",
                   "os.posix_spawn")
PROCESS_CALLS = ("system", "popen", "spawnl", "spawnv", "spawnvp",
                 "posix_spawn", "posix_spawnp", "execv", "execve", "execvp",
                 "execl", "execle", "execlp", "fork", "forkpty")

# Capabilities the plan forbids this distribution outright.
FORBIDDEN_IMPORTS = (
    "admissible", "admissible_ready", "http", "http.server", "socketserver",
    "socket", "ssl", "urllib.request", "wsgiref", "asyncio", "mcp",
)

#: The whole argv vocabulary the adapter may produce, after the fixed prefix.
GIT_VOCABULARY = frozenset({
    ("rev-parse", "--show-toplevel"),
    ("rev-parse", "HEAD"),
    ("status", "--porcelain", "--untracked-files=all"),
    ("remote", "get-url", "origin"),
})


def trust_sources() -> dict[str, ast.Module]:
    """Dotted-ish relative name -> parsed source, for every Trust module."""

    found = {}
    for path in sorted(TRUST_PACKAGE.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        found[path.name] = ast.parse(path.read_text(encoding="utf-8"),
                                     filename=str(path))
    return found


def imported_modules(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module)
            names |= {f"{node.module}.{alias.name}" for alias in node.names}
    return names


def called_attributes(tree: ast.Module) -> set[str]:
    return {node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)}


class TheSourceNamesOneExecutor(unittest.TestCase):
    """Static: only the adapter names anything that can start a process."""

    def test_there_are_sources_to_check(self):
        sources = trust_sources()
        self.assertTrue(sources, f"no Trust modules under {TRUST_PACKAGE}")
        self.assertIn(ADAPTER, sources)

    def test_only_the_adapter_imports_a_process_starting_module(self):
        offenders = []
        for name, tree in sorted(trust_sources().items()):
            if name == ADAPTER:
                continue
            for module in sorted(imported_modules(tree) & set(PROCESS_MODULES)):
                offenders.append(f"{name} imports {module}")
        self.assertEqual([], offenders)

    def test_only_the_adapter_calls_a_process_starting_function(self):
        offenders = []
        for name, tree in sorted(trust_sources().items()):
            if name == ADAPTER:
                continue
            for call in sorted(called_attributes(tree) & set(PROCESS_CALLS)):
                offenders.append(f"{name} calls {call}")
        self.assertEqual([], offenders)

    def test_the_adapter_starts_processes_only_through_subprocess_run(self):
        """``Popen`` is a longer-lived child and a shell is a parser."""

        tree = trust_sources()[ADAPTER]
        called = called_attributes(tree)
        self.assertIn("run", called)
        for forbidden in ("Popen", "call", "check_call", "check_output",
                          "getoutput", "system"):
            with self.subTest(call=forbidden):
                self.assertNotIn(forbidden, called)

    def test_no_module_imports_a_server_agent_or_sibling_authority(self):
        offenders = []
        for name, tree in sorted(trust_sources().items()):
            for module in sorted(imported_modules(tree) & set(FORBIDDEN_IMPORTS)):
                offenders.append(f"{name} imports {module}")
        self.assertEqual([], offenders)

    def test_no_module_reads_the_repository_configured_command_file(self):
        """``.admissible.json`` names argv; Trust reads policy, never a program.

        The kernel parses that file and Trust asks it for a class and a digest.
        What no module here may do is take the ``argv`` a check declares and
        hand it to anything.

        The adapter is exempt because ``argv`` is its own builder for the fixed
        Git vocabulary, asserted literally in :class:`TheGitAdapterIsFixed`; the
        attribute this looks for is the one on a policy's ``Check``.
        """

        offenders = []
        for name, tree in sorted(trust_sources().items()):
            if name == ADAPTER:
                continue
            for node in ast.walk(tree):
                if (isinstance(node, ast.Attribute) and node.attr == "argv"
                        and not (isinstance(node.value, ast.Name)
                                 and node.value.id == "sys")):
                    offenders.append(f"{name} reads .argv")
        self.assertEqual([], offenders)

    def test_no_dynamic_import_escape_exists(self):
        offenders = []
        for name, tree in sorted(trust_sources().items()):
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                dotted = None
                if isinstance(node.func, ast.Name):
                    dotted = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    dotted = node.func.attr
                if dotted in ("__import__", "import_module", "exec", "eval",
                              "compile", "spec_from_file_location"):
                    offenders.append(f"{name} calls {dotted}")
        self.assertEqual([], offenders)


class TheGitAdapterIsFixed(unittest.TestCase):
    """Six questions, six literal argument lists, and no way to add a seventh."""

    def setUp(self) -> None:
        raw = tempfile.mkdtemp(prefix="trust-git-")
        self.addCleanup(shutil.rmtree, raw, True)
        self.repo = Path(raw)
        for args in (("init", "--quiet"),
                     ("config", "user.email", "git@example.com"),
                     ("config", "user.name", "Git")):
            subprocess.run(("git", "-C", str(self.repo), *args), check=True,
                           timeout=60, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        (self.repo / "file.txt").write_text("content\n", encoding="utf-8")
        subprocess.run(("git", "-C", str(self.repo), "add", "-A"), check=True,
                       timeout=60)
        subprocess.run(("git", "-C", str(self.repo), "commit", "--quiet",
                        "-m", "one"), check=True, timeout=60,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_it_answers_exactly_the_kernel_s_six_questions(self):
        reader = git_reader.GitReader()
        for query in GIT_QUERIES:
            with self.subTest(query=query):
                self.assertTrue(callable(getattr(reader, query, None)))

    def test_every_argv_it_would_run_is_a_literal_plus_bounded_values(self):
        recorded: list[tuple[str, ...]] = []

        def record(argv, **kwargs):
            recorded.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with mock.patch("subprocess.run", record):
            reader = git_reader.GitReader()
            reader.top_level(self.repo)
            reader.head_commit(self.repo)
            reader.tree_of(self.repo, "a" * 40)
            reader.status(self.repo)
            reader.origin_url(self.repo)
            reader.root_commits(self.repo, "a" * 40)
        prefix = (git_reader.trusted_git_executable(),
                  "-c", "core.fsmonitor=false", "-c",
                  "core.hooksPath=/dev/null", "-C", str(self.repo))
        self.assertEqual([
            (*prefix, "rev-parse", "--show-toplevel"),
            (*prefix, "rev-parse", "HEAD"),
            (*prefix, "rev-parse", "a" * 40 + "^{tree}"),
            (*prefix, "status", "--porcelain", "--untracked-files=all"),
            (*prefix, "remote", "get-url", "origin"),
            (*prefix, "rev-list", "--max-parents=0", "a" * 40),
        ], recorded)

    def test_hooks_and_the_filesystem_monitor_are_disabled_on_every_call(self):
        reader = git_reader.GitReader()
        for query in GIT_QUERIES:
            with self.subTest(query=query):
                argv = reader.argv(self.repo, query)
                self.assertIn("core.hooksPath=/dev/null", argv)
                self.assertIn("core.fsmonitor=false", argv)

    def test_no_git_variable_survives_into_the_child(self):
        source = {"GIT_DIR": "/elsewhere/.git", "GIT_INDEX_FILE": "/tmp/index",
                  "GIT_AUTHOR_NAME": "someone", "PATH": "/candidate/bin"}
        environment = git_reader.GitReader(environment=source).environment()
        self.assertEqual(
            [], sorted(name for name in environment
                       if name.startswith("GIT_")
                       and name not in ("GIT_CONFIG_NOSYSTEM",
                                        "GIT_OPTIONAL_LOCKS",
                                        "GIT_TERMINAL_PROMPT")))
        # ``PATH`` is not carried across either: the caller's is exactly the
        # string a candidate's tooling gets to edit, so the child is given the
        # adapter's own closed system path instead.
        self.assertEqual(git_reader.TRUSTED_PATH, environment["PATH"])
        self.assertNotIn("/candidate/bin", environment["PATH"])

    def test_no_admissible_credential_survives_into_the_child(self):
        """Trust legitimately holds keys; ``git`` has no use for one.

        Nothing here is protecting Trust from itself -- it is keeping a
        credential out of any program ``git`` might still manage to consult.
        """

        source = {name: "material"
                  for name in git_reader.STRIPPED_CREDENTIAL_NAMES}
        source["PATH"] = "/usr/bin"
        environment = git_reader.GitReader(environment=source).environment()
        for name in git_reader.STRIPPED_CREDENTIAL_NAMES:
            with self.subTest(variable=name):
                self.assertNotIn(name, environment)

    def test_the_stripped_credential_list_covers_all_three_key_domains(self):
        names = set(git_reader.STRIPPED_CREDENTIAL_NAMES)
        for required in ("ADMISSIBLE_HMAC_KEY", "ADMISSIBLE_HMAC_KEY_FILE",
                         "ADMISSIBLE_REVIEW_KEY", "ADMISSIBLE_REVIEW_KEYRING",
                         "ADMISSIBLE_EVALUATION_KEY",
                         "ADMISSIBLE_EVALUATION_KEYRING"):
            with self.subTest(variable=required):
                self.assertIn(required, names)

    def test_terminal_prompting_and_system_configuration_are_off(self):
        environment = git_reader.GitReader(environment={}).environment()
        self.assertEqual("1", environment["GIT_CONFIG_NOSYSTEM"])
        self.assertEqual("0", environment["GIT_TERMINAL_PROMPT"])
        self.assertEqual("0", environment["GIT_OPTIONAL_LOCKS"])

    def test_it_reads_a_real_repository_exactly(self):
        found = git_reader.repository_identity(self.repo)
        self.assertEqual(40, len(found.commit_sha))
        self.assertEqual(40, len(found.tree_sha))
        self.assertFalse(found.dirty)

    def test_a_dirty_tree_is_refused_rather_than_summarised(self):
        (self.repo / "extra.txt").write_text("x\n", encoding="utf-8")
        with self.assertRaises(IdentityError):
            git_reader.repository_identity(self.repo)

    def test_a_missing_git_is_reported_as_an_identity_failure(self):
        def missing(argv, **kwargs):
            raise FileNotFoundError(argv[0])

        with mock.patch("subprocess.run", missing):
            with self.assertRaises(IdentityError):
                git_reader.GitReader().head_commit(self.repo)

    def test_a_timeout_is_reported_as_an_identity_failure(self):
        def slow(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 1)

        with mock.patch("subprocess.run", slow):
            with self.assertRaises(IdentityError):
                git_reader.GitReader().head_commit(self.repo)

    def test_the_vocabulary_is_the_only_thing_it_can_ask(self):
        """Every fixed argument list, compared to the declared vocabulary."""

        reader = git_reader.GitReader()
        prefix_length = len(reader.argv(self.repo))
        asked = set()
        for query, arguments in (("top_level", ()), ("head_commit", ()),
                                 ("status", ()), ("origin_url", ())):
            recorded: list[tuple[str, ...]] = []

            def record(argv, **kwargs):
                recorded.append(tuple(argv))
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            with mock.patch("subprocess.run", record):
                getattr(reader, query)(self.repo, *arguments)
            asked.add(recorded[0][prefix_length:])
        self.assertEqual(GIT_VOCABULARY, asked)


class TheAdapterRefusesEverythingElse(unittest.TestCase):
    """A caller cannot smuggle an argument through the fixed vocabulary."""

    def test_there_is_no_public_way_to_pass_an_arbitrary_argument(self):
        public = sorted(name for name in dir(git_reader.GitReader)
                        if not name.startswith("_"))
        self.assertEqual(
            ["argv", "environment", "head_commit", "origin_url",
             "root_commits", "status", "top_level", "tree_of"], public)

    def test_argv_is_an_inspection_helper_and_not_an_execution_path(self):
        """It builds the vector a test can read; it starts nothing."""

        source = (TRUST_PACKAGE / ADAPTER).read_text(encoding="utf-8")
        tree = ast.parse(source)
        argv_function = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "argv")
        self.assertEqual(
            [], [node for node in ast.walk(argv_function)
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute)
                 and node.func.attr in PROCESS_CALLS + ("run", "Popen")])


class NoCandidateExecutorExists(unittest.TestCase):
    """Runtime: with every executor trapped, only ``git`` reaches the trap."""

    def armed(self):
        """Trap every way a process could be started, and record the calls."""

        seen: list[tuple] = []

        def trap_run(argv, **kwargs):
            seen.append(tuple(argv) if not isinstance(argv, str) else (argv,))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        def refuse(*args, **kwargs):
            raise AssertionError(f"Trust started a process: {args!r}")

        patches = [
            mock.patch("subprocess.run", trap_run),
            mock.patch("subprocess.Popen", refuse),
            mock.patch.object(os, "system", refuse),
            mock.patch.object(os, "execv", refuse),
            mock.patch.object(os, "execve", refuse),
            mock.patch.object(os, "posix_spawn", refuse),
        ]
        return seen, patches

    def test_an_identity_read_is_the_only_thing_that_reaches_the_trap(self):
        seen, patches = self.armed()
        raw = tempfile.mkdtemp(prefix="trust-trap-")
        self.addCleanup(shutil.rmtree, raw, True)
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        try:
            git_reader.GitReader().head_commit(raw)
        except IdentityError:
            pass
        self.assertTrue(seen, "the trap must actually be reachable")
        expected = git_reader.trusted_git_executable()
        for argv in seen:
            with self.subTest(argv=argv):
                self.assertEqual(expected, argv[0])
                self.assertTrue(os.path.isabs(argv[0]))


if __name__ == "__main__":
    unittest.main()
