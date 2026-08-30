"""Exact repository identity: remote namespace, full SHA, tree, cleanliness.

Every downstream artefact is bound to *this* repository at *this* exact commit
and tree. Abbreviated SHAs, uppercase SHAs, dirty worktrees, and non-repository
directories are refused rather than normalised.

Finding out what a tree is at means running ``git``, and running anything is
the capability this kernel is defined by not having.  So the two halves are
separated: an injected reader answers six named questions, and everything here
is arithmetic on its answers -- the shape of a SHA, which mismatch is a
refusal, which remote URL normalises to which namespace, and the closing read
that makes the result a snapshot rather than a summary of a moving tree.

The reader is *required*.  A default would be a runner living in the floor --
lazily imported or not, present in every process that touches the kernel, and
silently handed to every caller who did not think to pass one.  The Ready
distribution owns the shipped adapter; a test may supply its own.

The questions are named rather than spelled as an argv, which is the other half
of the same restriction: :data:`GIT_QUERIES` is the whole vocabulary, so this
module cannot ask a reader to run a command that a policy chose.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

__all__ = [
    "GIT_QUERIES",
    "GitReader",
    "Identity",
    "IdentityError",
    "normalize_remote",
    "repository_identity",
]

_FULL_SHA = re.compile(r"[0-9a-f]{40}")
_MAX_STATUS_LINES = 20

#: Every question this module asks about a working tree, in no particular
#: order.  A reader offering these six answers everything the kernel can ask.
GIT_QUERIES = (
    "top_level",
    "head_commit",
    "tree_of",
    "status",
    "origin_url",
    "root_commits",
)


class IdentityError(ValueError):
    """The working tree cannot be identified exactly enough to admit."""


class GitReader(Protocol):
    """Answers the fixed questions :func:`repository_identity` asks.

    Every answer is the text git printed, stripped.  A query that git could not
    answer raises :class:`IdentityError` -- except :meth:`origin_url`, where
    "there is no origin" is a fact about the repository rather than a failure,
    and is reported as the empty string.

    Deliberately not ``runtime_checkable``.  An ``isinstance`` against a
    protocol checks that six names exist and reads as though it had checked
    more; :func:`_require_reader` does the check that is actually made, once,
    before the first question is asked, and says which answers are missing.
    """

    def top_level(self, root: Path | str) -> str:
        """Absolute path of the working tree containing ``root``, or ``""``."""

    def head_commit(self, root: Path | str) -> str:
        """Full SHA the checked-out ``HEAD`` resolves to."""

    def tree_of(self, root: Path | str, commit: str) -> str:
        """Full SHA of the tree ``commit`` names."""

    def status(self, root: Path | str) -> str:
        """Porcelain status including untracked files; ``""`` when clean."""

    def origin_url(self, root: Path | str) -> str:
        """Configured ``origin`` URL, or ``""`` when there is no origin."""

    def root_commits(self, root: Path | str, commit: str) -> str:
        """Parentless commits reachable from ``commit``, one per line."""


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


def _require_reader(git: object) -> object:
    """The reader, or a refusal naming every question it cannot answer.

    Checked once, before anything is read, so a reader that would fail on the
    fifth query fails before the first -- an identity captured halfway is a
    partial read of a tree that may move in between.
    """

    missing = [name for name in GIT_QUERIES
               if not callable(getattr(git, name, None))]
    if missing:
        raise IdentityError(
            f"a git reader must answer {', '.join(GIT_QUERIES)}; this "
            f"{type(git).__name__} cannot answer {', '.join(missing)}")
    return git


def _ask(git: object, query: str, *arguments: object) -> str:
    """One answer, normalised to stripped text or refused outright."""

    answer = getattr(git, query)(*arguments)
    if not isinstance(answer, str):
        raise IdentityError(
            f"the git reader answered {query} with "
            f"{type(answer).__name__}, not text; an identity is computed from "
            "what git printed")
    return answer.strip()


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


def repository_identity(root: Path | str, *, git: GitReader,
                        expected_sha: object = None,
                        allow_dirty: bool = False) -> Identity:
    """Identify the repository at ``root`` exactly, or refuse."""

    git = _require_reader(git)
    root = Path(root)
    if not root.is_dir():
        raise IdentityError(f"{root} is not a directory")
    top = _ask(git, "top_level", root)
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
    commit_sha = _ask(git, "head_commit", top_path)
    if _FULL_SHA.fullmatch(commit_sha) is None:
        raise IdentityError(
            f"{top} has no resolvable commit at HEAD (got {commit_sha!r})")
    if expected_sha is not None and expected_sha != commit_sha:
        raise IdentityError(
            f"requested commit {expected_sha} is not the checked-out HEAD; "
            f"{top} is at {commit_sha}. Check out that commit, or re-run with "
            f"--sha {commit_sha}.")
    tree_sha = _ask(git, "tree_of", top_path, commit_sha)
    if _FULL_SHA.fullmatch(tree_sha) is None:
        raise IdentityError(
            f"{top} has no resolvable tree at captured commit {commit_sha}")
    status = _ask(git, "status", top_path)
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
    remote_url = _ask(git, "origin_url", top_path)
    repository = normalize_remote(remote_url)
    if not repository:
        roots = _ask(git, "root_commits", top_path, commit_sha)
        first = sorted(line.strip() for line in roots.splitlines() if line.strip())
        if not first:
            raise IdentityError(f"{top} has no root commit to identify")
        repository = f"local/{first[0]}"
    closing_head = _ask(git, "head_commit", top_path)
    if closing_head != commit_sha:
        raise IdentityError(
            f"{top} HEAD changed while identity was captured: "
            f"{commit_sha} -> {closing_head}")
    return Identity(repository=repository, commit_sha=commit_sha,
                    tree_sha=tree_sha, root=str(top_path), dirty=dirty,
                    remote_url=remote_url, status=status_lines)
