"""Contract: the extracted kernel answers exactly as the monolith does.

``admissible_core`` is a copy of the authority-neutral half of ``admissible``,
made so the two halves can ship as separate distributions.  A copy that drifts
is worse than no copy: two implementations of the same policy digest, decision
document or evidence record can disagree, and whichever one a process happens
to import decides what it admits.

So the parity asserted here is *observational*, not textual.  Comparing the two
files byte for byte would prove they are the same text today and would have to
be deleted the moment the root module becomes a facade; comparing what the two
modules compute from identical inputs stays true through that change and is the
claim that actually matters.  The digests are the sharpest form of it: a digest
is the identity of a decision, so equal digests mean the two kernels produce
records that are interchangeable everywhere the product uses them.

Refusals are compared too.  A kernel that accepts a document the other rejects
is not a parity failure that shows up in a digest -- it shows up as an artefact
admitted by the wrong build.

One deliberate difference is asserted rather than smoothed over.  The monolith
identifies a repository by running git itself; Core cannot start a process at
all, so it is handed a reader and asks it six named questions.  The comparison
is kept honest by giving Core an adapter that runs *the monolith's* git -- same
argv, same stripped environment -- so any remaining difference between the two
identities is a difference in the kernel rather than in how git was called.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from admissible import config as legacy_config
from admissible import decision as legacy_decision
from admissible import evidence as legacy_evidence
from admissible import fsutil as legacy_fsutil
from admissible import identity as legacy_identity
from admissible import profiles as legacy_profiles
from admissible import schema as legacy_schema

from admissible_core import config as core_config
from admissible_core import decision as core_decision
from admissible_core import evidence as core_evidence
from admissible_core import fsutil as core_fsutil
from admissible_core import identity as core_identity
from admissible_core import profiles as core_profiles
from admissible_core import schema as core_schema

from . import REPO_ROOT
from .legacy_git import LegacyGitReader, SIGNING_ENVIRONMENT

# Every module the extraction claims to have carried over, paired with the
# root module it must agree with.  Named once, so a module added to Core
# without a parity pair is a missing row here rather than an untested module.
PAIRS = {
    "fsutil": (legacy_fsutil, core_fsutil),
    "identity": (legacy_identity, core_identity),
    "profiles": (legacy_profiles, core_profiles),
    "schema": (legacy_schema, core_schema),
    "evidence": (legacy_evidence, core_evidence),
    "config": (legacy_config, core_config),
    "decision": (legacy_decision, core_decision),
}

# Names Core exports and the monolith does not, per module, with the reason.
# The monolith runs git itself; Core is handed a reader and therefore has to
# say what a reader is.  Stated as an exact set so a name that appears in Core
# for any *other* reason still fails the surface comparison below.
EXTRA_CORE_EXPORTS = {"identity": {"GIT_QUERIES", "GitReader"}}

SHA = "a" * 40
TREE = "b" * 40
REPOSITORY = "github.com/acme/widget"
ATTEMPT = "attempt-one"

POLICY_DOCUMENT = {
    "version": 1,
    "profile": "python-library",
    "title": "Widget",
    "summary": "A parity fixture, not a real policy.",
    "classes": [{
        "id": "default",
        "description": "one required check, no independent review",
        "checks": [
            {"id": "unit", "argv": ["true"], "timeout_seconds": 60,
             "cost_units": 1, "required": True, "version": "1"},
            {"id": "lint", "argv": ["true", "--lint"], "timeout_seconds": 30,
             "cost_units": 1, "required": False, "version": "1"},
        ],
        "required_independent_reviews": 0,
        "review_max_age_seconds": 86400,
        "max_cost_units": 10,
        "max_wall_seconds": 600,
    }],
}


def command_document(argv_digest: str, policy_digest: str, **overrides) -> dict:
    document = {
        "kind": "command",
        "check_id": "unit",
        "check_version": "1",
        "repository": REPOSITORY,
        "commit_sha": SHA,
        "tree_sha": TREE,
        "policy_digest": policy_digest,
        "argv_digest": argv_digest,
        "exit_code": 0,
        "timed_out": False,
        "launch_failed": False,
        "duration_ms": 1200,
        "stdout_sha256": "e" * 64,
        "stderr_sha256": "f" * 64,
        "stdout_bytes": 6,
        "stderr_bytes": 0,
        "output_truncated": False,
        "started_at": 1000,
        "finished_at": 1002,
        "attempt_id": ATTEMPT,
        "reused_from_attempt": "",
    }
    document.update(overrides)
    return document


class PublicSurfaceParity(unittest.TestCase):
    """The two kernels export the same names and the same record shapes."""

    def test_every_pair_declares_the_same_public_names(self):
        """Same names, except the injection point Core needs and has declared."""
        for name, (legacy, core) in sorted(PAIRS.items()):
            expected = EXTRA_CORE_EXPORTS.get(name, set())
            with self.subTest(module=name):
                self.assertEqual(
                    set(), set(legacy.__all__) - set(core.__all__),
                    "Core dropped a name the monolith exports",
                )
                self.assertEqual(
                    expected, set(core.__all__) - set(legacy.__all__),
                    "Core exports a name the monolith does not, unexplained",
                )

    def test_every_exported_name_actually_exists_in_core(self):
        """``__all__`` is a promise; an entry naming nothing is a broken one."""
        for name, (_legacy, core) in sorted(PAIRS.items()):
            missing = [entry for entry in core.__all__ if not hasattr(core, entry)]
            with self.subTest(module=name):
                self.assertEqual([], missing)

    def test_exported_dataclasses_have_identical_fields(self):
        """Field name, order and default: the record shape, not just the name.

        Evidence and decision records are serialised by field, so a reordered
        or re-defaulted field is a different data format wearing the same
        class name.
        """
        compared = 0
        for name, (legacy, core) in sorted(PAIRS.items()):
            shared = set(core.__all__) & set(legacy.__all__)
            for exported in sorted(shared):
                legacy_type = getattr(legacy, exported)
                core_type = getattr(core, exported)
                if not dataclasses.is_dataclass(core_type):
                    continue
                compared += 1
                with self.subTest(module=name, dataclass=exported):
                    self.assertEqual(
                        [(f.name, f.default) for f in dataclasses.fields(legacy_type)],
                        [(f.name, f.default) for f in dataclasses.fields(core_type)],
                    )
        self.assertGreater(compared, 0, "no dataclass was compared at all")

    def test_the_two_kernels_are_not_the_same_module_object(self):
        """The control: parity above must be between two real imports.

        If ``admissible_core.evidence`` resolved to ``admissible.evidence`` --
        an aliasing shim, a stray ``sys.modules`` entry -- every assertion in
        this file would pass while proving nothing at all.
        """
        for name, (legacy, core) in sorted(PAIRS.items()):
            with self.subTest(module=name):
                self.assertIsNot(legacy, core)
                self.assertNotEqual(legacy.__name__, core.__name__)
                self.assertTrue(core.__name__.startswith("admissible_core."))


class RepositoryCase(unittest.TestCase):
    """A throwaway git repository, and the adapter that reads it."""

    def reader(self) -> LegacyGitReader:
        return LegacyGitReader()

    def repository(self, *, remote: str | None = None) -> Path:
        raw = tempfile.mkdtemp(prefix="admissible-core-identity-")
        self.addCleanup(shutil.rmtree, raw, True)
        root = Path(raw)
        self.git(root, "init", "--quiet")
        self.git(root, "config", "user.email", "parity@example.com")
        self.git(root, "config", "user.name", "Parity")
        if remote:
            self.git(root, "remote", "add", "origin", remote)
        (root / "file.txt").write_text("content\n", encoding="utf-8")
        self.git(root, "add", "file.txt")
        self.git(root, "commit", "--quiet", "-m", "one")
        return root

    @staticmethod
    def git(root: Path, *args: str) -> None:
        subprocess.run(("git", "-C", str(root), *args), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=60)


class IdentityParity(RepositoryCase):
    """Repository identity is the binding every artefact hangs from.

    The monolith runs git itself; Core is handed a reader that runs the same
    git.  Every answer below therefore has to be identical -- the point of the
    injection is *where* the process is started, not what is computed from it.
    """

    REMOTES = (
        "",
        "https://github.com/acme/widget.git",
        "git@github.com:acme/widget.git",
        "ssh://git@example.com:2222/acme/widget",
        "git://example.com/acme/widget.git",
        "https://USER@Example.COM/Acme/Widget/",
        "/srv/git/widget",
        "example.com",
    )

    def test_normalize_remote_agrees_on_every_shape(self):
        for url in self.REMOTES:
            with self.subTest(url=url):
                self.assertEqual(
                    legacy_identity.normalize_remote(url),
                    core_identity.normalize_remote(url),
                )

    def test_a_real_repository_is_identified_identically(self):
        root = self.repository(remote="https://github.com/acme/widget.git")
        legacy = legacy_identity.repository_identity(root)
        core = core_identity.repository_identity(root, git=self.reader())
        self.assertEqual(legacy.to_dict(), core.to_dict())
        self.assertEqual(dataclasses.asdict(legacy), dataclasses.asdict(core))
        self.assertEqual("github.com/acme/widget", core.repository)

    def test_a_repository_with_no_remote_falls_back_identically(self):
        """The ``local/<root commit>`` namespace is a whole separate branch."""
        root = self.repository()
        legacy = legacy_identity.repository_identity(root)
        core = core_identity.repository_identity(root, git=self.reader())
        self.assertEqual(dataclasses.asdict(legacy), dataclasses.asdict(core))
        self.assertTrue(core.repository.startswith("local/"), core.repository)

    def test_a_dirty_tree_is_refused_and_described_identically(self):
        root = self.repository(remote="https://github.com/acme/widget.git")
        (root / "untracked.txt").write_text("late\n", encoding="utf-8")
        for module, extra in ((legacy_identity, {}),
                              (core_identity, {"git": self.reader()})):
            with self.subTest(module=module.__name__):
                with self.assertRaises(module.IdentityError) as caught:
                    module.repository_identity(root, **extra)
                self.assertIn("uncommitted or untracked changes",
                              str(caught.exception))
        legacy = legacy_identity.repository_identity(root, allow_dirty=True)
        core = core_identity.repository_identity(
            root, git=self.reader(), allow_dirty=True)
        self.assertEqual(dataclasses.asdict(legacy), dataclasses.asdict(core))
        self.assertTrue(core.dirty)
        self.assertTrue(core.status)

    def test_the_expected_sha_is_checked_identically(self):
        root = self.repository(remote="https://github.com/acme/widget.git")
        head = legacy_identity.repository_identity(root).commit_sha
        self.assertEqual(
            head,
            core_identity.repository_identity(
                root, git=self.reader(), expected_sha=head).commit_sha)
        for bad in ("abcdef", head.upper(), "z" * 40, b"x" * 40, 7,
                    "b" * 40):
            with self.subTest(expected_sha=bad):
                with self.assertRaises(legacy_identity.IdentityError) as legacy:
                    legacy_identity.repository_identity(root, expected_sha=bad)
                with self.assertRaises(core_identity.IdentityError) as core:
                    core_identity.repository_identity(
                        root, git=self.reader(), expected_sha=bad)
                self.assertEqual(str(legacy.exception), str(core.exception))

    def test_both_refuse_a_directory_that_is_not_a_repository(self):
        with tempfile.TemporaryDirectory(prefix="admissible-core-plain-") as raw:
            for module, extra in ((legacy_identity, {}),
                                  (core_identity, {"git": self.reader()})):
                with self.subTest(module=module.__name__):
                    with self.assertRaises(module.IdentityError):
                        module.repository_identity(raw, **extra)

    def test_both_refuse_a_path_that_is_not_a_directory_at_all(self):
        root = self.repository()
        target = root / "file.txt"
        for module, extra in ((legacy_identity, {}),
                              (core_identity, {"git": self.reader()})):
            with self.subTest(module=module.__name__):
                with self.assertRaises(module.IdentityError) as caught:
                    module.repository_identity(target, **extra)
                self.assertIn("is not a directory", str(caught.exception))


class CoreIdentityRequiresAnInjectedReader(RepositoryCase):
    """Core computes an identity; it never starts the process that reads one.

    The reader is a required argument rather than a defaulted one on purpose.
    A default would be a runner living in the kernel -- imported lazily or
    not, it would be the capability Core is defined by not having, and every
    caller would silently get it.
    """

    def test_the_reader_has_no_default_and_cannot_be_omitted(self):
        root = self.repository()
        with self.assertRaises(TypeError):
            core_identity.repository_identity(root)

    def test_the_queries_core_asks_are_a_fixed_named_set(self):
        """Named questions, not an argv: Core cannot ask git for anything else."""
        self.assertEqual(
            ("head_commit", "origin_url", "root_commits", "status", "top_level",
             "tree_of"),
            tuple(sorted(core_identity.GIT_QUERIES)),
        )
        self.assertEqual(len(core_identity.GIT_QUERIES),
                         len(set(core_identity.GIT_QUERIES)))
        missing = [name for name in core_identity.GIT_QUERIES
                   if not hasattr(LegacyGitReader, name)]
        self.assertEqual([], missing, "the adapter must answer every query")

    def test_a_reader_missing_a_query_is_refused_before_anything_is_read(self):
        class Partial:
            def top_level(self, root):  # pragma: no cover - never reached
                raise AssertionError("must be refused before any query runs")

        root = self.repository()
        with self.assertRaises(core_identity.IdentityError) as caught:
            core_identity.repository_identity(root, git=Partial())
        message = str(caught.exception)
        for query in core_identity.GIT_QUERIES:
            if query != "top_level":
                self.assertIn(query, message)

    def test_a_reader_answering_with_something_other_than_text_is_refused(self):
        class Numeric:
            def top_level(self, root):
                return 17

            def __getattr__(self, name):
                if name in core_identity.GIT_QUERIES:
                    return lambda *args: ""
                raise AttributeError(name)

        root = self.repository()
        with self.assertRaises(core_identity.IdentityError) as caught:
            core_identity.repository_identity(root, git=Numeric())
        self.assertIn("top_level", str(caught.exception))

    def test_the_adapter_reads_the_tree_it_is_pointed_at_and_nothing_else(self):
        """The reader is the only thing that touches git, and it is injectable."""
        asked: list[tuple[str, tuple]] = []
        real = self.reader()

        class Recording:
            def __getattr__(self, name):
                attribute = getattr(real, name)

                def record(*args):
                    asked.append((name, args))
                    return attribute(*args)

                return record

        root = self.repository(remote="https://github.com/acme/widget.git")
        identity = core_identity.repository_identity(root, git=Recording())
        self.assertEqual(
            ["top_level", "head_commit", "tree_of", "status", "origin_url",
             "head_commit"],
            [name for name, _ in asked],
        )
        self.assertEqual(identity.commit_sha,
                         legacy_identity.repository_identity(root).commit_sha)

    def test_a_head_that_moves_mid_capture_is_caught(self):
        """The closing read is what makes the identity a snapshot."""
        root = self.repository(remote="https://github.com/acme/widget.git")
        real = self.reader()
        answers = iter((real.head_commit(root), "c" * 40))

        class Moving:
            def __getattr__(self, name):
                if name == "head_commit":
                    return lambda *args: next(answers)
                return getattr(real, name)

        with self.assertRaises(core_identity.IdentityError) as caught:
            core_identity.repository_identity(root, git=Moving())
        self.assertIn("HEAD changed while identity was captured",
                      str(caught.exception))


class TheTestAdapterInvokesGitAsTheMonolithDoes(RepositoryCase):
    """The adapter is the parity control: same argv, same stripped environment.

    If it called git differently, the identity comparison above would be
    comparing two different questions and would prove nothing about the kernel.
    """

    def test_the_argv_is_the_monolith_argv(self):
        self.assertEqual(
            ("git", "-c", "core.fsmonitor=false", "-c",
             "core.hooksPath=/dev/null", "-C", "/tmp/x", "rev-parse", "HEAD"),
            self.reader().argv("/tmp/x", "rev-parse", "HEAD"),
        )

    def test_no_signing_credential_reaches_the_git_process(self):
        ambient = {name: "leak" for name in SIGNING_ENVIRONMENT}
        ambient.update({"GIT_DIR": "/elsewhere/.git", "PATH": "/usr/bin",
                        "HOME": "/home/parity"})
        environment = LegacyGitReader(environment=ambient).environment()
        for name in SIGNING_ENVIRONMENT:
            with self.subTest(variable=name):
                self.assertNotIn(name, environment)
        self.assertNotIn("GIT_DIR", environment)
        self.assertEqual("/usr/bin", environment["PATH"])
        self.assertEqual("1", environment["GIT_CONFIG_NOSYSTEM"])
        self.assertEqual("0", environment["GIT_TERMINAL_PROMPT"])

    def test_the_signing_variables_are_the_ones_the_monolith_strips(self):
        """A list that drifted from the monolith's would strip the wrong names."""
        source = (REPO_ROOT / "admissible" / "identity.py").read_text(
            encoding="utf-8")
        for name in SIGNING_ENVIRONMENT:
            with self.subTest(variable=name):
                self.assertIn(name, source)

    def test_an_absent_origin_is_an_empty_answer_rather_than_a_refusal(self):
        root = self.repository()
        self.assertEqual("", self.reader().origin_url(root))

    def test_a_failing_required_query_is_refused_with_gits_own_detail(self):
        with tempfile.TemporaryDirectory(prefix="admissible-core-plain-") as raw:
            with self.assertRaises(core_identity.IdentityError) as caught:
                self.reader().head_commit(raw)
            self.assertIn("git rev-parse HEAD failed", str(caught.exception))


class SchemaParity(unittest.TestCase):
    """Schema documents are the wire contract, so they are compared as bytes."""

    def known_files(self) -> tuple[str, ...]:
        return (
            core_schema.EVIDENCE_SCHEMA_FILE,
            core_schema.RECEIPT_SCHEMA_FILE,
            core_schema.DEFECT_SCHEMA_FILE,
            core_schema.EVALUATION_SCHEMA_FILE,
            core_schema.READY_SCHEMA_FILE,
            core_schema.WORK_PACKAGE_SCHEMA_FILE,
            core_schema.REMEDIATION_SCHEMA_FILE,
        )

    def test_the_named_schema_files_are_the_same(self):
        for attribute in ("EVIDENCE_SCHEMA_FILE", "RECEIPT_SCHEMA_FILE",
                          "DEFECT_SCHEMA_FILE", "EVALUATION_SCHEMA_FILE",
                          "READY_SCHEMA_FILE", "WORK_PACKAGE_SCHEMA_FILE",
                          "REMEDIATION_SCHEMA_FILE"):
            with self.subTest(constant=attribute):
                self.assertEqual(getattr(legacy_schema, attribute),
                                 getattr(core_schema, attribute))

    def test_every_known_document_loads_identically(self):
        for name in self.known_files():
            with self.subTest(schema=name):
                self.assertEqual(legacy_schema.load_schema(name),
                                 core_schema.load_schema(name))

    def test_the_schema_ids_are_preserved(self):
        """``$id`` is what a consumer pins; a changed id is a changed contract."""
        identifiers = {}
        for name in self.known_files():
            document = core_schema.load_schema(name)
            identifiers[name] = document.get("$id")
            with self.subTest(schema=name):
                self.assertEqual(legacy_schema.load_schema(name).get("$id"),
                                 identifiers[name])
                self.assertTrue(identifiers[name], f"{name} declares no $id")
        self.assertEqual(len(identifiers), len(set(identifiers.values())),
                         "two schema documents share one $id")

    def test_the_loaded_document_is_the_canonical_protocol_resource(self):
        """Core reads ``protocol/``; it does not carry a schema copy of its own.

        Compared through the file's own bytes rather than through the loader,
        so a Core that vendored a second, drifting copy of a schema would fail
        here even though both copies parse.
        """
        for name in self.known_files():
            source = REPO_ROOT / "protocol" / name
            with self.subTest(schema=name):
                self.assertTrue(source.is_file(), f"{source} is missing")
                self.assertEqual(
                    json.loads(source.read_text(encoding="utf-8")),
                    core_schema.load_schema(name),
                )

    def test_the_protocol_resources_have_exactly_one_source_of_bytes(self):
        """No second file in the tree carries a known schema's basename."""
        for name in self.known_files():
            copies = sorted(
                path for path in REPO_ROOT.rglob(name)
                if ".venv" not in path.parts and "build" not in path.parts
            )
            with self.subTest(schema=name):
                self.assertEqual([REPO_ROOT / "protocol" / name], copies)
                self.assertTrue(
                    hashlib.sha256(copies[0].read_bytes()).hexdigest(),
                    "a schema resource must have readable bytes",
                )

    def test_an_unknown_document_is_refused_by_both(self):
        for module in (legacy_schema, core_schema):
            with self.subTest(module=module.__name__):
                with self.assertRaises(KeyError):
                    module.load_schema("not-a-schema.json")


class ProfileParity(unittest.TestCase):
    """Shipped profiles are policy defaults; they must be the same defaults."""

    def test_the_profile_names_are_the_same(self):
        self.assertEqual(legacy_profiles.PROFILE_NAMES,
                         core_profiles.PROFILE_NAMES)
        self.assertEqual(legacy_profiles.HIGH_RISK_PROFILES,
                         core_profiles.HIGH_RISK_PROFILES)

    def test_every_profile_document_is_identical(self):
        for name in core_profiles.PROFILE_NAMES:
            with self.subTest(profile=name):
                self.assertEqual(legacy_profiles.profile_document(name),
                                 core_profiles.profile_document(name))
                self.assertEqual(legacy_profiles.profile_floor(name),
                                 core_profiles.profile_floor(name))

    def test_an_unknown_profile_is_refused_by_both(self):
        for module in (legacy_profiles, core_profiles):
            with self.subTest(module=module.__name__):
                with self.assertRaises(module.UnknownProfile):
                    module.profile_document("no-such-profile")


class ConfigParity(unittest.TestCase):
    """The policy digest is the identity of a policy; it cannot fork."""

    def test_the_shipped_profiles_parse_to_the_same_policy_digest(self):
        for name in core_profiles.PROFILE_NAMES:
            document = core_profiles.profile_document(name)
            with self.subTest(profile=name):
                legacy = legacy_config.parse_config(document,
                                                    allow_placeholders=True)
                core = core_config.parse_config(document,
                                                allow_placeholders=True)
                self.assertEqual(legacy.policy_digest, core.policy_digest)
                self.assertEqual(
                    [item.id for item in legacy.classes],
                    [item.id for item in core.classes],
                )

    def test_the_fixture_policy_agrees_digest_for_digest(self):
        legacy = legacy_config.parse_config(POLICY_DOCUMENT)
        core = core_config.parse_config(POLICY_DOCUMENT)
        self.assertEqual(legacy.policy_digest, core.policy_digest)
        legacy_class = legacy.select_class("default")
        core_class = core.select_class("default")
        self.assertEqual(legacy_class.policy_digest, core_class.policy_digest)
        self.assertEqual(legacy_config.enforcement_digest(legacy_class),
                         core_config.enforcement_digest(core_class))
        self.assertEqual(legacy_class.core(), core_class.core())
        self.assertEqual(legacy_class.check("unit").argv_digest,
                         core_class.check("unit").argv_digest)

    def test_the_policy_domain_and_file_name_are_unchanged(self):
        self.assertEqual(legacy_config.POLICY_DOMAIN, core_config.POLICY_DOMAIN)
        self.assertEqual(legacy_config.CONFIG_FILENAME,
                         core_config.CONFIG_FILENAME)
        self.assertEqual(".admissible.json", core_config.CONFIG_FILENAME)

    def test_both_refuse_the_same_malformed_documents(self):
        broken = (
            {"version": 1, "profile": "python-library"},
            {"version": 2, "profile": "python-library", "classes": []},
            dict(POLICY_DOCUMENT, unexpected="key"),
            dict(POLICY_DOCUMENT, classes=[]),
        )
        for index, document in enumerate(broken):
            with self.subTest(document=index):
                with self.assertRaises(legacy_config.ConfigError):
                    legacy_config.parse_config(document)
                with self.assertRaises(core_config.ConfigError):
                    core_config.parse_config(document)


class FsutilParity(unittest.TestCase):
    """Path containment is a refusal surface, so both must refuse alike."""

    def test_resolve_within_agrees_on_accepted_and_refused_paths(self):
        with tempfile.TemporaryDirectory(prefix="admissible-core-paths-") as raw:
            root = Path(raw)
            (root / "nested").mkdir()
            (root / "nested" / "file.txt").write_text("x", encoding="utf-8")
            for relative in ("nested/file.txt", "nested"):
                with self.subTest(relative=relative, accepted=True):
                    self.assertEqual(
                        legacy_fsutil.resolve_within(root, relative),
                        core_fsutil.resolve_within(root, relative),
                    )
            for relative in ("../escape", "/etc/passwd", "nested/../../out"):
                with self.subTest(relative=relative, accepted=False):
                    with self.assertRaises(legacy_fsutil.PathError):
                        legacy_fsutil.resolve_within(root, relative)
                    with self.assertRaises(core_fsutil.PathError):
                        core_fsutil.resolve_within(root, relative)


class EvidenceParity(unittest.TestCase):
    """Evidence records are exchanged between processes; both must read both."""

    def setUp(self):
        self.policy = core_config.parse_config(POLICY_DOCUMENT)
        self.artifact_class = self.policy.select_class("default")
        self.argv_digest = self.artifact_class.check("unit").argv_digest
        self.policy_digest = self.artifact_class.policy_digest
        self.document = command_document(self.argv_digest, self.policy_digest)

    def test_command_evidence_round_trips_to_the_same_document(self):
        legacy = legacy_evidence.command_evidence_from_dict(self.document)
        core = core_evidence.command_evidence_from_dict(self.document)
        self.assertEqual(legacy_evidence.command_evidence_to_dict(legacy),
                         core_evidence.command_evidence_to_dict(core))
        self.assertEqual(self.document,
                         core_evidence.command_evidence_to_dict(core))

    def test_the_evidence_digest_is_the_same_in_both_kernels(self):
        legacy = legacy_evidence.command_evidence_from_dict(self.document)
        core = core_evidence.command_evidence_from_dict(self.document)
        self.assertEqual(legacy_evidence.evidence_digest(legacy),
                         core_evidence.evidence_digest(core))

    def test_a_record_produced_by_one_kernel_is_read_by_the_other(self):
        """The claim that matters on the wire: neither side is special."""
        core = core_evidence.command_evidence_from_dict(self.document)
        written = core_evidence.command_evidence_to_dict(core)
        reread = legacy_evidence.command_evidence_from_dict(written)
        self.assertEqual(legacy_evidence.evidence_digest(reread),
                         core_evidence.evidence_digest(core))

    def test_reuse_in_attempt_derives_the_same_record(self):
        legacy = legacy_evidence.reuse_in_attempt(
            legacy_evidence.command_evidence_from_dict(self.document),
            attempt_id="attempt-two")
        core = core_evidence.reuse_in_attempt(
            core_evidence.command_evidence_from_dict(self.document),
            attempt_id="attempt-two")
        self.assertEqual(legacy_evidence.command_evidence_to_dict(legacy),
                         core_evidence.command_evidence_to_dict(core))
        self.assertEqual(ATTEMPT,
                         core_evidence.command_evidence_to_dict(core)
                         ["reused_from_attempt"])

    def test_a_bundle_round_trips_across_the_two_kernels(self):
        bundle_document = {
            "schema": core_evidence.EVIDENCE_SCHEMA,
            "commands": [self.document],
            "reviews": [],
            "defects": [],
            "attestations": [],
        }
        legacy = legacy_evidence.parse_bundle(bundle_document)
        core = core_evidence.parse_bundle(bundle_document)
        self.assertEqual(legacy_evidence.bundle_to_dict(legacy),
                         core_evidence.bundle_to_dict(core))

    def test_both_refuse_the_same_malformed_records(self):
        broken = (
            dict(self.document, kind="not-a-command"),
            dict(self.document, exit_code="0"),
            {key: value for key, value in self.document.items()
             if key != "check_id"},
            dict(self.document, surprise=1),
        )
        for index, document in enumerate(broken):
            with self.subTest(document=index):
                with self.assertRaises(legacy_evidence.EvidenceError):
                    legacy_evidence.command_evidence_from_dict(document)
                with self.assertRaises(core_evidence.EvidenceError):
                    core_evidence.command_evidence_from_dict(document)


class DecisionParity(unittest.TestCase):
    """The decision document and its digest are what a receipt attests to."""

    def decide(self, config_module, decision_module, evidence_module, *,
               exit_code: int = 0):
        artifact_class = config_module.parse_config(
            POLICY_DOCUMENT).select_class("default")
        document = command_document(
            artifact_class.check("unit").argv_digest,
            artifact_class.policy_digest,
            exit_code=exit_code,
        )
        record = evidence_module.command_evidence_from_dict(document)
        return decision_module.evaluate(
            artifact_class=artifact_class,
            repository=REPOSITORY,
            commit_sha=SHA,
            tree_sha=TREE,
            policy_digest=artifact_class.policy_digest,
            commands=(record,),
            reviews=(),
            now=2000,
            attempt_id=ATTEMPT,
        )

    def both(self, *, exit_code: int = 0):
        return (
            self.decide(legacy_config, legacy_decision, legacy_evidence,
                        exit_code=exit_code),
            self.decide(core_config, core_decision, core_evidence,
                        exit_code=exit_code),
        )

    def test_a_passing_evaluation_produces_the_same_document(self):
        legacy, core = self.both()
        self.assertEqual(legacy_decision.decision_to_dict(legacy),
                         core_decision.decision_to_dict(core))

    def test_a_passing_evaluation_produces_the_same_digest(self):
        legacy, core = self.both()
        self.assertEqual(legacy_decision.decision_digest(legacy),
                         core_decision.decision_digest(core))
        self.assertEqual(legacy_decision.digest_of_document(
            legacy_decision.decision_to_dict(legacy)),
            core_decision.digest_of_document(
                core_decision.decision_to_dict(core)))

    def test_a_failing_evaluation_produces_the_same_document_and_digest(self):
        legacy, core = self.both(exit_code=1)
        self.assertEqual(legacy_decision.decision_to_dict(legacy),
                         core_decision.decision_to_dict(core))
        self.assertEqual(legacy_decision.decision_digest(legacy),
                         core_decision.decision_digest(core))
        self.assertNotEqual(core_decision.CHECKS_PASSED,
                            core_decision.decision_to_dict(core)["state"])

    def test_the_plain_explanation_is_word_for_word_the_same(self):
        """The refusal a developer reads is part of the product, not decoration."""
        for exit_code in (0, 1):
            legacy, core = self.both(exit_code=exit_code)
            with self.subTest(exit_code=exit_code):
                self.assertEqual(legacy_decision.render_plain(legacy),
                                 core_decision.render_plain(core))
                self.assertEqual(legacy_decision.preview_readiness(legacy),
                                 core_decision.preview_readiness(core))

    def test_the_decision_scope_and_states_are_unchanged(self):
        for constant in ("DECISION_SCOPE", "CHECKS_PASSED", "REFUSED",
                         "BLOCKED", "ADMITTED", "READINESS",
                         "READINESS_READY_FOR_ATTESTATION",
                         "READINESS_AWAITING_REVIEW", "READINESS_NOT_READY",
                         "MAX_CLOCK_SKEW_SECONDS"):
            with self.subTest(constant=constant):
                self.assertEqual(getattr(legacy_decision, constant),
                                 getattr(core_decision, constant))

    def test_the_budget_plan_agrees(self):
        legacy_class = legacy_config.parse_config(
            POLICY_DOCUMENT).select_class("default")
        core_class = core_config.parse_config(
            POLICY_DOCUMENT).select_class("default")
        self.assertEqual(legacy_decision.plan_budget(legacy_class),
                         core_decision.plan_budget(core_class))

    def test_both_refuse_an_evaluation_with_no_attempt(self):
        artifact_class = core_config.parse_config(
            POLICY_DOCUMENT).select_class("default")
        for module in (legacy_decision, core_decision):
            with self.subTest(module=module.__name__):
                with self.assertRaises(ValueError):
                    module.evaluate(
                        artifact_class=artifact_class,
                        repository=REPOSITORY, commit_sha=SHA, tree_sha=TREE,
                        policy_digest=artifact_class.policy_digest,
                        commands=(), reviews=(), now=2000, attempt_id="")


if __name__ == "__main__":
    unittest.main()
