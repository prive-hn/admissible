"""The shipped git adapter: the one place this product runs ``git``.

:mod:`admissible_core.identity` asks six fixed questions about a working tree
and computes an identity from the answers.  Something has to *answer* them, and
answering them means starting a process -- which is exactly the capability the
kernel is defined by not having.  This is where that capability lives, in the
distribution that already has it because it runs the candidate's checks.

Two restrictions make it narrower than "Ready can run git":

* **The argv is fixed.**  :data:`GIT_QUERIES` is the whole vocabulary and each
  question maps to one literal argument list built here.  No policy, no
  configuration file and no MCP argument reaches an argument vector, so there
  is no path from a repository-controlled string to a command this adapter
  runs.  ``tree_of`` and ``root_commits`` interpolate a commit, and the caller
  has already required it to be a 40-character lowercase hex SHA before asking.
* **The environment is sanitized.**  Every ``GIT_*`` variable is dropped so an
  ambient ``GIT_DIR``/``GIT_INDEX_FILE`` cannot redirect the read, system and
  hook configuration is disabled, terminal prompting is off, and every signing
  credential this distribution refuses to hold is removed as well.  The last
  one is belt and braces -- a Ready entry point refuses to start at all while
  one is present -- because a library caller can reach this adapter directly.

The body is a transcription of ``admissible.identity._git`` at the tree the
split was taken from: same argv, same stripped environment, same timeout, same
refusals.  Any difference between an identity computed here and one computed by
the monolith is therefore a difference in the kernel rather than in how git was
called.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from admissible_core.identity import IdentityError

__all__ = ["GIT_TIMEOUT_SECONDS", "GitReader", "repository_identity"]

GIT_TIMEOUT_SECONDS = 60

# Configuration this adapter forces on every invocation. ``core.fsmonitor`` and
# ``core.hooksPath`` are repository-controlled otherwise: a candidate could
# point either at a program of its own and have ``git rev-parse`` run it.
_FIXED_CONFIGURATION = ("-c", "core.fsmonitor=false",
                        "-c", "core.hooksPath=/dev/null")
_FIXED_ENVIRONMENT = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}


class GitReader:
    """Answers Core's six questions by running a fixed set of git commands."""

    def __init__(self, *, timeout_seconds: int = GIT_TIMEOUT_SECONDS,
                 environment: dict[str, str] | None = None) -> None:
        self._timeout_seconds = timeout_seconds
        self._source = os.environ if environment is None else environment

    # -- the environment a git invocation may see ----------------------------
    def environment(self) -> dict[str, str]:
        """Ambient environment minus every ``GIT_*`` and every credential."""

        # Imported here rather than at module scope: the credential list lives
        # with the runner, which imports nothing from this module, and a
        # top-level import in both directions would be a cycle.
        from .runner import SIGNING_CREDENTIAL_NAMES

        environment = {
            name: value for name, value in self._source.items()
            if not name.startswith("GIT_")
        }
        for name in SIGNING_CREDENTIAL_NAMES:
            environment.pop(name, None)
        environment.update(_FIXED_ENVIRONMENT)
        return environment

    def argv(self, root: Path | str, *args: str) -> tuple[str, ...]:
        """The exact argv this adapter would run, exposed so a test can read it."""

        return ("git", *_FIXED_CONFIGURATION, "-C", str(root), *args)

    # -- the six questions ---------------------------------------------------
    def top_level(self, root: Path | str) -> str:
        return self._run(root, "rev-parse", "--show-toplevel")

    def head_commit(self, root: Path | str) -> str:
        return self._run(root, "rev-parse", "HEAD")

    def tree_of(self, root: Path | str, commit: str) -> str:
        return self._run(root, "rev-parse", f"{commit}^{{tree}}")

    def status(self, root: Path | str) -> str:
        return self._run(root, "status", "--porcelain", "--untracked-files=all")

    def origin_url(self, root: Path | str) -> str:
        return self._run(root, "remote", "get-url", "origin", required=False)

    def root_commits(self, root: Path | str, commit: str) -> str:
        return self._run(root, "rev-list", "--max-parents=0", commit)

    # -- how they are answered -----------------------------------------------
    def _run(self, root: Path | str, *args: str, required: bool = True) -> str:
        try:
            completed = subprocess.run(
                self.argv(root, *args),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self._timeout_seconds, check=False,
                env=self.environment())
        except FileNotFoundError:
            raise IdentityError("git is not installed or not on PATH") from None
        except subprocess.TimeoutExpired:
            raise IdentityError(f"git {args[0]} timed out in {root}") from None
        if completed.returncode != 0:
            if not required:
                return ""
            detail = completed.stderr.decode("utf-8", "replace").strip()
            raise IdentityError(
                f"git {' '.join(args)} failed in {root}: {detail or 'no detail'}")
        return completed.stdout.decode("utf-8", "replace").strip()


def repository_identity(root: Path | str, *, expected_sha: object = None,
                        allow_dirty: bool = False):
    """Identify ``root`` exactly, through this distribution's git adapter.

    The kernel's function takes a reader and this one supplies the shipped one.
    Keeping the two apart is what makes "the kernel cannot start a process" a
    property of the installed wheel; keeping this wrapper is what stops every
    caller in Ready from constructing its own adapter and drifting.
    """

    from admissible_core import identity as identity_module

    return identity_module.repository_identity(
        root, git=GitReader(), expected_sha=expected_sha,
        allow_dirty=allow_dirty)
