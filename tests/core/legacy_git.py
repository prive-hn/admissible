"""The concrete git adapter, kept in the tests and shipped by no wheel.

:mod:`admissible_core.identity` asks a reader six fixed questions about a
working tree and computes an identity from the answers.  Something has to
*answer* them, and answering them means running ``git`` -- which is exactly the
capability the kernel is defined by not having.  The Ready distribution will own
the shipped adapter; until it exists, this one stands in.

It lives here on purpose.  A copy of it under ``packages/core`` would be an
executor inside the Core wheel no matter which module imported it, and "Core
cannot start a process" would become a statement about import graphs rather
than about what is installed.  Nothing under ``packages/`` imports this file,
and no distribution ships ``tests/``.

The body is a transcription of ``admissible.identity._git`` at the tree this
adapter was written against: same argv, same stripped environment, same
timeout, same refusals.  That is what makes the parity comparison in
``test_admissible_core_parity`` meaningful -- the two identities are computed by
the same git invocations, so any difference between them is a difference in the
kernel rather than in how git was called.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from admissible_core.identity import IdentityError

__all__ = ["GIT_TIMEOUT_SECONDS", "SIGNING_ENVIRONMENT", "LegacyGitReader"]

GIT_TIMEOUT_SECONDS = 60

# Signing material never reaches a subprocess started to identify a tree. The
# kernel no longer names these because it no longer starts the process; the
# adapter that does inherits the obligation.
SIGNING_ENVIRONMENT = (
    "ADMISSIBLE_HMAC_KEY", "ADMISSIBLE_HMAC_KEY_FILE",
    "ADMISSIBLE_REVIEW_KEY", "ADMISSIBLE_REVIEW_KEY_FILE",
    "ADMISSIBLE_REVIEW_KEYRING",
    "ADMISSIBLE_EVALUATION_KEY", "ADMISSIBLE_EVALUATION_KEY_FILE",
    "ADMISSIBLE_EVALUATION_KEYRING",
)


class LegacyGitReader:
    """Answers Core's six questions by running the git the monolith runs."""

    def __init__(self, *, timeout_seconds: int = GIT_TIMEOUT_SECONDS,
                 environment: dict[str, str] | None = None) -> None:
        self._timeout_seconds = timeout_seconds
        self._source = os.environ if environment is None else environment

    # -- the environment a git invocation may see ----------------------------
    def environment(self) -> dict[str, str]:
        """Ambient environment minus every ``GIT_*`` and every credential."""

        environment = {
            name: value for name, value in self._source.items()
            if not name.startswith("GIT_")
        }
        for name in SIGNING_ENVIRONMENT:
            environment.pop(name, None)
        environment.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        })
        return environment

    def argv(self, root: Path | str, *args: str) -> tuple[str, ...]:
        """The exact argv this adapter would run, exposed so a test can read it."""

        return ("git", "-c", "core.fsmonitor=false",
                "-c", "core.hooksPath=/dev/null", "-C", str(root), *args)

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
