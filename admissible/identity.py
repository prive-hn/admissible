"""Exact repository identity: remote namespace, full SHA, tree, cleanliness.

Every downstream artefact is bound to *this* repository at *this* exact commit
and tree. Abbreviated SHAs, uppercase SHAs, dirty worktrees, and non-repository
directories are refused rather than normalised.
"""
from __future__ import annotations

import re
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

__all__ = ["Identity", "IdentityError", "normalize_remote", "repository_identity"]

_FULL_SHA = re.compile(r"[0-9a-f]{40}")
_GIT_TIMEOUT_SECONDS = 60
_MAX_STATUS_LINES = 20
_SIGNING_ENVIRONMENT = (
    "ADMISSIBLE_HMAC_KEY", "ADMISSIBLE_HMAC_KEY_FILE",
    "ADMISSIBLE_REVIEW_KEY", "ADMISSIBLE_REVIEW_KEY_FILE",
    "ADMISSIBLE_REVIEW_KEYRING",
    "ADMISSIBLE_EVALUATION_KEY", "ADMISSIBLE_EVALUATION_KEY_FILE",
    "ADMISSIBLE_EVALUATION_KEYRING",
)


class IdentityError(ValueError):
    """The working tree cannot be identified exactly enough to admit."""


@dataclass(frozen=True)
class Identity:
    """The exact artefact under evaluation."""

    repository: str
    commit_sha: str
    tree_sha: str
    root: str
    dirty: bool
    remote_url: str = ""
    status: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "tree_sha": self.tree_sha,
            "dirty": self.dirty,
        }

    def same_artifact(self, other: "Identity") -> bool:
        """Same repository, same commit, same tree, and still clean."""

        return (self.repository == other.repository
                and self.commit_sha == other.commit_sha
                and self.tree_sha == other.tree_sha
                and self.dirty == other.dirty)


def _git(root: Path, *args: str, required: bool = True) -> str:
    environment = {
        name: value for name, value in os.environ.items()
        if not name.startswith("GIT_")
    }
    for name in _SIGNING_ENVIRONMENT:
        environment.pop(name, None)
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    })
    safe_args = (
        "git", "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null", "-C", str(root), *args)
    try:
        completed = subprocess.run(
            safe_args,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=_GIT_TIMEOUT_SECONDS, check=False, env=environment)
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


def normalize_remote(url: str) -> str:
    """Normalise a git remote URL to a stable ``host/path`` namespace."""

    text = url.strip()
    if not text:
        return ""
    if text.endswith(".git"):
        text = text[:-4]
    for scheme in ("https://", "http://", "ssh://", "git://", "git+ssh://"):
        if text.startswith(scheme):
            text = text[len(scheme):]
            break
    else:
        if "://" not in text and ":" in text and not text.startswith("/"):
            host, _, path = text.partition(":")
            text = f"{host}/{path.lstrip('/')}"
    if "@" in text.split("/", 1)[0]:
        text = text.split("@", 1)[1]
    host, _, path = text.partition("/")
    if ":" in host:  # strip an explicit port
        host = host.split(":", 1)[0]
    return f"{host.lower()}/{path.strip('/')}" if path else host.lower()


def repository_identity(root: Path | str, *, expected_sha: object = None,
                        allow_dirty: bool = False) -> Identity:
    """Identify the repository at ``root`` exactly, or refuse."""

    root = Path(root)
    if not root.is_dir():
        raise IdentityError(f"{root} is not a directory")
    top = _git(root, "rev-parse", "--show-toplevel")
    if not top:
        raise IdentityError(f"{root} is not inside a git repository")
    top_path = Path(top)
    if expected_sha is not None:
        if type(expected_sha) is not str:
            raise IdentityError("--sha must be a string")
        if _FULL_SHA.fullmatch(expected_sha) is None:
            raise IdentityError(
                f"--sha must be a full 40-character lowercase commit SHA, "
                f"got {expected_sha!r}")
    commit_sha = _git(top_path, "rev-parse", "HEAD")
    if _FULL_SHA.fullmatch(commit_sha) is None:
        raise IdentityError(
            f"{top} has no resolvable commit at HEAD (got {commit_sha!r})")
    if expected_sha is not None and expected_sha != commit_sha:
        raise IdentityError(
            f"requested commit {expected_sha} is not the checked-out HEAD; "
            f"{top} is at {commit_sha}. Check out that commit, or re-run with "
            f"--sha {commit_sha}.")
    tree_sha = _git(top_path, "rev-parse", f"{commit_sha}^{{tree}}")
    if _FULL_SHA.fullmatch(tree_sha) is None:
        raise IdentityError(
            f"{top} has no resolvable tree at captured commit {commit_sha}")
    status = _git(top_path, "status", "--porcelain", "--untracked-files=all")
    dirty = bool(status.strip())
    # Bounded: enough to name what changed, never a whole tree listing.
    status_lines = tuple(
        line.strip() for line in status.splitlines()[:_MAX_STATUS_LINES]
        if line.strip())
    if dirty and not allow_dirty:
        raise IdentityError(
            f"{top} has uncommitted or untracked changes, so evidence would "
            "not describe commit "
            f"{commit_sha}. Commit or remove them, then re-run.")
    remote_url = _git(top_path, "remote", "get-url", "origin", required=False)
    repository = normalize_remote(remote_url)
    if not repository:
        roots = _git(top_path, "rev-list", "--max-parents=0", commit_sha)
        first = sorted(line.strip() for line in roots.splitlines() if line.strip())
        if not first:
            raise IdentityError(f"{top} has no root commit to identify")
        repository = f"local/{first[0]}"
    closing_head = _git(top_path, "rev-parse", "HEAD")
    if closing_head != commit_sha:
        raise IdentityError(
            f"{top} HEAD changed while identity was captured: "
            f"{commit_sha} -> {closing_head}")
    return Identity(repository=repository, commit_sha=commit_sha,
                    tree_sha=tree_sha, root=str(top_path), dirty=dirty,
                    remote_url=remote_url, status=status_lines)
