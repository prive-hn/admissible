"""Shared helpers for the developer admission product contract tests.

The helpers here deliberately keep failures loud: a module that does not exist
yet raises a plain ``AssertionError`` naming the missing behaviour, so a RED run
reads as "behaviour absent" rather than "collection error".
"""
from __future__ import annotations

import contextlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class _MissingModule:
    """Stands in for an unimplemented module and fails on first use."""

    def __init__(self, name: str, error: BaseException) -> None:
        self._name = name
        self._error = error

    def __getattr__(self, attribute: str):
        raise AssertionError(
            f"{self._name}.{attribute} is not implemented yet "
            f"({type(self._error).__name__}: {self._error})")

    def __bool__(self) -> bool:
        return False


def require_module(name: str):
    try:
        return importlib.import_module(name)
    except Exception as error:  # noqa: BLE001 - RED must name the gap
        return _MissingModule(name, error)


GIT_ENV = {
    "GIT_AUTHOR_NAME": "Admissible Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Admissible Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def git(root: Path, *args: str) -> str:
    env = dict(os.environ)
    env.update(GIT_ENV)
    result = subprocess.run(
        ("git", *args), cwd=str(root), env=env, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode("utf-8").strip()


def make_repo(root: Path, *, remote: str | None = "https://github.com/acme/widget.git",
              files: dict[str, str] | None = None) -> str:
    """Create a real one-commit git repository and return its full SHA."""
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-q", "-b", "main")
    for name, text in (files or {"README.md": "widget\n"}).items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")
    if remote is not None:
        git(root, "remote", "add", "origin", remote)
    return git(root, "rev-parse", "HEAD")


@contextlib.contextmanager
def evaluating_domain():
    """The environment an evaluate job actually runs in.

    ``run`` starts commands the repository under evaluation controls, and it
    refuses to do that while this process holds a signing credential -- the
    boundary would already be gone. In a real deployment that is free: the
    evaluate job and the finalizer are different jobs on different machines.
    In a test everything shares one process, so the credentials a later step
    needs are lifted out for the duration of the evaluation and put back.
    """

    from admissible import runner as runner_module

    saved = {name: os.environ.pop(name)
             for name in runner_module.SIGNING_CREDENTIAL_NAMES
             if name in os.environ}
    try:
        yield
    finally:
        os.environ.update(saved)


class TempCase(unittest.TestCase):
    """Test case with a private temporary directory and clean environment."""

    def setUp(self) -> None:
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory(prefix="admissible-test-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / "home"
        self.home.mkdir()
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        for name in list(os.environ):
            if name.startswith("ADMISSIBLE_") or name.startswith("GITHUB_"):
                del os.environ[name]
        os.environ.update(GIT_ENV)
        os.environ["ADMISSIBLE_HOME"] = str(self.home)
        # These fixtures stand in for an operator who runs the checks inside a
        # boundary something outside the evaluation destroys before the handoff
        # is read. Declared here rather than left absent, because absent is
        # ISOLATION_NONE, and a preview that declares none is never finalisable
        # -- which is the point of the field and would otherwise turn every
        # test that admits anything into a test of that one refusal. Tests that
        # are about the boundary set it themselves.
        os.environ["ADMISSIBLE_ISOLATION"] = "pid-namespace"

    def write_json(self, path: Path, document: object) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document), encoding="utf-8")
        return path


# The external observer's identity in tests. It is deliberately not the
# admission key and not a reviewer key: three separate trust domains, three
# separate secrets, and a test that blurred them would be testing nothing.
OBSERVER_KEY_ID = "observer-1"
OBSERVER_SECRET = b"test-external-observer-secret-not-real"


def source_receipt_document(commit_sha, *, provider="github-actions",
                            run_id="17825349901", conclusion="success",
                            receipt_digest=None, skip_commit_check=False,
                            **overrides):
    """The closed external receipt an observer says it read, for tests.

    Real ones come from a provider's API. What matters here is the shape: a
    provider, an immutable run id, the exact commit, the conclusion that
    provider reported, and the digest of the document that was read.
    """

    document = {
        "schema": "admissible/v0.6/external-source-receipt",
        "provider": provider,
        "run_id": run_id,
        "commit_sha": commit_sha,
        "conclusion": conclusion,
        "receipt_digest": receipt_digest or ("a1" * 32),
    }
    document.update(overrides)
    return document


def admit(case, root, sha, *, home=None, class_id=None, evidence=None,
          config_path=None, now=None, trust=True, run_args=(),
          reviewer_keyring=None):
    """Take one commit all the way to an anchored receipt, honestly.

    There is no shortcut left, and that is the point: ``run`` evaluates and
    never signs, so a receipt takes four steps in three trust domains --
    evaluate, observe, trust the policy once, finalize. Tests that need a
    receipt go through the same path a real operator does, so a change that
    breaks the path breaks them.

    Returns the issued :class:`admissible.receipt.WorkflowReceipt`.
    """

    import io
    import json
    import time

    from admissible import attestation as attestation_module
    from admissible import cli as cli_module
    from admissible import config as config_module
    from admissible import github as github_module
    from admissible import receipt as receipt_module
    from admissible import store as store_module

    home = case.home if home is None else home
    moment = int(time.time()) if now is None else now
    preview = Path(case.tmp) / f"preview-{sha[:12]}.json"
    argv = ["run", "--preview", "--repo", str(root), "--sha", sha,
            "--preview-out", str(preview), "--json", *run_args]
    if class_id is not None:
        argv += ["--class", class_id]
    if evidence is not None:
        argv += ["--evidence", str(evidence)]
    if config_path is not None:
        argv += ["--config", config_path]
    out, err = io.StringIO(), io.StringIO()
    with evaluating_domain():
        cli_module.main(argv, stdout=out, stderr=err)

    document = json.loads(preview.read_text(encoding="utf-8"))
    attestation_path = Path(case.tmp) / f"evaluation-{sha[:12]}.json"
    attestation_path.write_text(json.dumps(attestation_module.attest_preview(
        document, key_id=OBSERVER_KEY_ID, secret=OBSERVER_SECRET,
        isolation="pid-namespace",
        source_receipt=source_receipt_document(sha),
        observed_at=max(moment, document["issued_at"]))),
        encoding="utf-8")

    opened = store_module.open_store(home)
    case.addCleanup(opened.close)
    if trust:
        parsed = config_module.load_config(root, config_path)
        identity = json.loads(preview.read_text(encoding="utf-8"))
        for artifact_class in parsed.classes:
            opened.trust_policy(
                repository=identity["repository"],
                class_id=artifact_class.id,
                policy_digest=artifact_class.policy_digest,
                enforcement_digest=config_module.enforcement_digest(
                    artifact_class),
                trusted_at=moment)
    return github_module.finalize(
        opened, preview, signer=receipt_module.load_signer(),
        expected_sha=sha, now=max(moment, document["issued_at"]),
        policy_root=root,
        evaluation_attestation=attestation_path,
        evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
        keyring=dict(reviewer_keyring or {}), environment={})
