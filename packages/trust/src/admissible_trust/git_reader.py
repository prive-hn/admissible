"""The one place this distribution starts a process, and it is ``git``.

:mod:`admissible_core.identity` asks six fixed questions about a working tree
and computes an identity from the answers.  Something has to *answer* them, and
answering them means starting a process -- which is exactly the capability the
kernel is defined by not having.

Trust needs those answers for one reason: finalization does not believe a
preview.  It re-derives repository, commit and tree from a trusted checkout it
was pointed at, and compares.  A distribution that could not read a working
tree would have to take the candidate's word for what it was signing.

Four restrictions make this narrower than "Trust can run git", and narrower
than the Ready adapter it is a transcription of:

* **The executable is the system's.**  ``git`` as a bare word is not a program,
  it is a *search*, and the search is ``PATH`` -- a string the ambient
  environment supplies and, in the one workflow this distribution exists for,
  a string the candidate's own tooling has usually just edited.  A repository
  that ships ``./bin/git`` and prepends its directory would otherwise have
  Trust execute it, in the process holding the admission key, and every other
  guarantee here would still hold: the argv would be one of six fixed queries,
  the environment would be stripped, the receipt would be issued -- by a
  program the candidate wrote.  So an absolute executable is resolved from
  :data:`TRUSTED_SEARCH_DIRECTORIES`, a closed list that no environment
  variable, configuration file, preview field or command line can change, it
  is validated before anything is started, and that absolute path is
  ``argv[0]``.  There is no fallback to an ambient ``git``: a distribution that
  cannot find a Git it trusts refuses rather than running one it does not.
* **The argv is fixed.**  :data:`admissible_core.identity.GIT_QUERIES` is the
  whole vocabulary and each question maps to one literal argument list built
  here.  No policy, no configuration file, no preview field and no CLI argument
  reaches an argument vector, so there is no path from a repository-controlled
  string to a command this adapter runs.  ``tree_of`` and ``root_commits``
  interpolate a commit, and the caller has already required it to be a
  40-character lowercase hex SHA before asking.
* **The environment is built, not inherited.**  The child gets
  :data:`TRUSTED_PATH` -- the same closed system directories, never the
  caller's ``PATH`` -- plus whichever of :data:`PRESERVED_ENVIRONMENT_NAMES`
  the caller had and are plausible enough to pass on.  Every ``GIT_*`` variable
  is dropped so an ambient ``GIT_DIR``/``GIT_INDEX_FILE`` cannot redirect the
  read, system and hook configuration is disabled, the filesystem monitor is
  off, and terminal prompting is off.  Every Admissible credential is removed
  as well -- :data:`STRIPPED_CREDENTIAL_NAMES` -- not to protect Trust from
  itself, since Trust legitimately holds those keys, but because ``git`` has no
  use for one and a child process that cannot see a secret cannot leak it.
* **There is nothing else here.**  ``argv`` builds the vector so a test can read
  it and starts nothing; the whole public surface is the six questions, that
  builder, and the environment it would hand a child.  A seventh question would
  have to be written into this file.

The body is a transcription of ``admissible.identity._git`` at the tree the
split was taken from: same argv shape, same stripped environment, same timeout,
same refusals.  Any difference between an identity computed here and one
computed by the monolith is therefore a difference in the kernel rather than in
how git was called -- and the same holds against the Ready adapter, which is
the property that makes a cross-process handoff comparable at all.  The one
deliberate divergence is ``argv[0]``: the candidate distribution resolves the
command a candidate is entitled to influence, and this one does not.
"""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from admissible_core.identity import IdentityError

__all__ = [
    "GIT_TIMEOUT_SECONDS",
    "GitReader",
    "PRESERVED_ENVIRONMENT_NAMES",
    "STRIPPED_CREDENTIAL_NAMES",
    "TRUSTED_PATH",
    "TRUSTED_SEARCH_DIRECTORIES",
    "TrustedExecutableError",
    "repository_identity",
    "trusted_git_executable",
]

GIT_TIMEOUT_SECONDS = 60

# Configuration this adapter forces on every invocation. ``core.fsmonitor`` and
# ``core.hooksPath`` are repository-controlled otherwise: a candidate could
# point either at a program of its own and have ``git rev-parse`` run it. That
# would be a candidate-chosen program running inside the process that holds the
# admission key, which is precisely the adjacency this distribution exists to
# remove.
_FIXED_CONFIGURATION = ("-c", "core.fsmonitor=false",
                        "-c", "core.hooksPath=/dev/null")
_FIXED_ENVIRONMENT = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}

#: Every Admissible credential removed from the child's environment.
#:
#: The list is closed and covers all three key domains, key ids included: an id
#: names *which* identity a nearby secret speaks for, and neither belongs in a
#: process whose only job is to print a SHA. It is spelled here rather than
#: imported because the module that owns it in the candidate distribution is
#: the runner, and this distribution does not have one.
STRIPPED_CREDENTIAL_NAMES = (
    "ADMISSIBLE_HMAC_KEY",
    "ADMISSIBLE_HMAC_KEY_FILE",
    "ADMISSIBLE_HMAC_KEY_ID",
    "ADMISSIBLE_REVIEW_KEY",
    "ADMISSIBLE_REVIEW_KEY_FILE",
    "ADMISSIBLE_REVIEW_KEY_ID",
    "ADMISSIBLE_REVIEW_KEYRING",
    "ADMISSIBLE_EVALUATION_KEY",
    "ADMISSIBLE_EVALUATION_KEY_FILE",
    "ADMISSIBLE_EVALUATION_KEY_ID",
    "ADMISSIBLE_EVALUATION_KEYRING",
)

#: Variables the child keeps if the caller had them, and the whole of the list.
#:
#: An allowlist rather than a filtered copy of the ambient environment. The
#: filtered copy answers "what did the caller happen to have, minus the things
#: we thought of", which is a question whose answer changes whenever somebody
#: exports something new; this answers "what does a program that prints a SHA
#: need", which does not. ``HOME`` is here because ``git`` looks for the
#: operator's configuration through it and a process with no home behaves
#: differently on different platforms; the locale variables are here because
#: their absence changes how ``git`` renders paths.
PRESERVED_ENVIRONMENT_NAMES = (
    "HOME", "LANG", "LC_ALL", "LC_CTYPE", "LOGNAME", "TMPDIR", "TZ", "USER",
    # Windows cannot start a process at all without these, and they name
    # locations the operating system owns rather than anything a candidate
    # writes. This distribution is POSIX-shaped -- ``core.hooksPath=/dev/null``
    # says so -- but a value dropped here would be an obscure failure rather
    # than a refusal, so they are carried.
    "APPDATA", "COMSPEC", "LOCALAPPDATA", "NUMBER_OF_PROCESSORS", "OS",
    "PATHEXT", "PROGRAMDATA", "PROGRAMFILES", "SYSTEMDRIVE", "SYSTEMROOT",
    "TEMP", "TMP", "USERPROFILE", "WINDIR",
)

#: A preserved value longer than this is not a platform variable any more.
_MAX_ENVIRONMENT_VALUE_BYTES = 4096

#: The executable's basename, per platform. One name, spelled once.
_EXECUTABLE_NAMES = ("git.exe",) if os.name == "nt" else ("git",)


class TrustedExecutableError(IdentityError):
    """No ``git`` this distribution is willing to run could be found.

    An :class:`~admissible_core.identity.IdentityError` on purpose: every
    caller in this distribution already treats a failure to identify a working
    tree as a refusal to sign, and "there is no Git I trust" is exactly that
    failure. Naming it separately is what lets a test say which refusal it
    meant.
    """


def _absolute_entries(raw: str) -> tuple[str, ...]:
    """The absolute directories in a ``PATH``-shaped string, in order.

    Empty entries are dropped rather than resolved. An empty entry means the
    current directory, and the current directory during a finalization is
    wherever the operator's shell happened to be -- frequently the candidate
    checkout itself, which is the one place this module must never look.
    """

    found: list[str] = []
    for entry in raw.split(os.pathsep):
        if entry and os.path.isabs(entry) and entry not in found:
            found.append(entry)
    return tuple(found)


def _system_search_directories() -> tuple[str, ...]:
    """The closed list of directories a trusted ``git`` may be found in.

    ``os.defpath`` is the standard library's own answer to "where do system
    programs live when nobody has said otherwise" -- ``/bin:/usr/bin`` on
    POSIX -- and it is not derived from ``os.environ``, which is the property
    that matters. ``/usr/bin`` is put first because that is where a
    distribution-managed ``git`` is, and preferring it makes the resolution
    deterministic on systems where both entries exist.
    """

    preferred = ("/usr/bin", "/bin") if os.name == "posix" else ()
    found = [entry for entry in preferred if os.path.isdir(entry)]
    for entry in _absolute_entries(os.defpath):
        if entry not in found:
            found.append(entry)
    return tuple(found)


#: Where a trusted ``git`` is looked for, in order, and the whole of it.
TRUSTED_SEARCH_DIRECTORIES = _system_search_directories()

#: The ``PATH`` the child is given, which is those same directories and no more.
TRUSTED_PATH = os.pathsep.join(TRUSTED_SEARCH_DIRECTORIES)


def _trusted_owners() -> frozenset[int]:
    """Whose files this process is willing to execute: root, or its own.

    Anything else is a file some third account can rewrite, and a program a
    third account can rewrite is that account's program rather than the
    system's.
    """

    return frozenset({0, os.geteuid()}) if os.name == "posix" else frozenset()


def _directory_problem(path: str) -> str:
    """Why the directories above ``path`` are not safe to trust, or ``""``.

    Validating the file alone would be validating a name: whoever can write a
    directory on the way to it can replace what the name refers to, whatever
    the file's own mode says. So every ancestor is walked to the root.

    A group- or world-writable directory is refused *unless* it carries the
    sticky bit, which is the one case where the permission is not the whole
    story: with ``S_ISVTX`` set only the owner of an entry may rename or
    unlink it, so an already-validated file cannot be swapped out from under
    this process. ``/tmp`` is the reason the exception exists and the reason it
    is safe to make.
    """

    current = os.path.dirname(path)
    while current:
        try:
            info = os.lstat(current)
        except OSError:
            return f"sits under {current}, which cannot be examined"
        if stat.S_ISLNK(info.st_mode):
            return f"sits under {current}, which is a symbolic link"
        if not stat.S_ISDIR(info.st_mode):
            return f"sits under {current}, which is not a directory"
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022 and not mode & stat.S_ISVTX:
            return (f"sits under {current}, which is writable by group or "
                    "others")
        owners = _trusted_owners()
        if owners and info.st_uid not in owners:
            return f"sits under {current}, which is owned by uid {info.st_uid}"
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return ""


def _executable_problem(path: str) -> str:
    """Why ``path`` is not an executable Trust will run, or ``""`` if it is.

    Stated as a reason rather than a boolean so the refusal can say which rule
    the candidate broke; an operator who is told "no trusted git" and nothing
    else has to guess.
    """

    if not os.path.isabs(path):
        return "is not an absolute path"
    real = os.path.realpath(path)
    if real != path:
        return (f"resolves to {real}; a trusted executable is named by its "
                "real path, never reached through a link or a redirection")
    try:
        info = os.lstat(path)
    except OSError:
        return "cannot be examined"
    if stat.S_ISLNK(info.st_mode):
        return "is a symbolic link"
    if not stat.S_ISREG(info.st_mode):
        return "is not a regular file"
    mode = stat.S_IMODE(info.st_mode)
    if not mode & 0o111 or not os.access(path, os.X_OK):
        return "is not executable"
    if mode & 0o022:
        return "is writable by group or others"
    owners = _trusted_owners()
    if owners and info.st_uid not in owners:
        return f"is owned by uid {info.st_uid}"
    return _directory_problem(path)


def trusted_git_executable() -> str:
    """The absolute ``git`` this distribution runs, or a refusal.

    Called when a reader is constructed rather than resolved once at import:
    the answer is a statement about the filesystem now, and a value cached at
    import time would be a statement about the filesystem when the interpreter
    started. It costs a handful of ``lstat`` calls per identity read.
    """

    problems: list[str] = []
    for directory in TRUSTED_SEARCH_DIRECTORIES:
        for name in _EXECUTABLE_NAMES:
            candidate = os.path.join(directory, name)
            if not os.path.lexists(candidate):
                continue
            problem = _executable_problem(candidate)
            if not problem:
                return candidate
            problems.append(f"{candidate} {problem}")
    looked = ", ".join(TRUSTED_SEARCH_DIRECTORIES) or "nowhere"
    detail = "; ".join(problems) or "no such file in any of them"
    raise TrustedExecutableError(
        "Trust found no git it is willing to run. It looks only in "
        f"{looked}, never on PATH and never at a path a repository, a "
        "configuration file or a command line named, because the process "
        f"asking holds the admission key. What it found: {detail}.")


def _preserved(source, name: str) -> str | None:
    """The caller's value for ``name`` if it is plausibly a platform value."""

    value = source.get(name)
    if not isinstance(value, str) or not value:
        return None
    if "\x00" in value or len(value.encode("utf-8", "replace")) > \
            _MAX_ENVIRONMENT_VALUE_BYTES:
        return None
    return value


class GitReader:
    """Answers Core's six questions by running a fixed set of git commands."""

    def __init__(self, *, timeout_seconds: int = GIT_TIMEOUT_SECONDS,
                 environment: dict[str, str] | None = None) -> None:
        self._timeout_seconds = timeout_seconds
        self._source = os.environ if environment is None else environment
        # Resolved here, before any query: constructing a reader is the last
        # moment at which "there is no Git I trust" can be a refusal instead
        # of a fallback, and the callers that build one are the finalizer and
        # the authenticated projection, both of which must fail closed.
        # There is deliberately no parameter to override it.
        self._executable = trusted_git_executable()

    # -- the environment a git invocation may see ----------------------------
    def environment(self) -> dict[str, str]:
        """The child's whole environment, built rather than inherited.

        An allowlist and then the strips, in that order. The strips are
        redundant against the allowlist -- no ``GIT_*`` name and no credential
        name is in it -- and they stay because the allowlist is a list somebody
        will one day add a name to, and this is where that mistake stops.
        """

        environment: dict[str, str] = {}
        for name in PRESERVED_ENVIRONMENT_NAMES:
            value = _preserved(self._source, name)
            if value is not None:
                environment[name] = value
        for name in list(environment):
            if name.startswith("GIT_") or name in STRIPPED_CREDENTIAL_NAMES:
                del environment[name]
        environment["PATH"] = TRUSTED_PATH
        environment.update(_FIXED_ENVIRONMENT)
        return environment

    def argv(self, root: Path | str, *args: str) -> tuple[str, ...]:
        """The exact argv this adapter would run, exposed so a test can read it.

        It builds a tuple and returns it. Nothing here starts anything, which
        is what makes it safe to be the one public way to see what would run.
        ``argv[0]`` is the absolute executable validated when this reader was
        constructed, so what a test reads here is what a child would be.
        """

        return (self._executable, *_FIXED_CONFIGURATION, "-C", str(root),
                *args)

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
            raise IdentityError(
                f"{self._executable} could not be started; it was a valid "
                "executable a moment ago and is not one now") from None
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
    caller in Trust from constructing its own adapter and drifting.
    """

    from admissible_core import identity as identity_module

    return identity_module.repository_identity(
        root, git=GitReader(), expected_sha=expected_sha,
        allow_dirty=allow_dirty)
