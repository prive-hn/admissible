"""argv-only command execution with hashed, private, bounded output.

The runner never sees a shell. It captures the child's exact bytes once, hashes
those same bytes, and writes them to an owner-only private log. Results carry
digests and sizes, never raw output, so a receipt can quote evidence without
quoting logs or secrets.

This module also owns :data:`SIGNING_CREDENTIAL_NAMES`, the closed list of
credentials no process that starts a candidate-owned command may hold. It lives
here, beside the code that starts those commands, because the reason is the
same fact: a check runs as this user, and a descendant that escapes the process
group runs as this user after the evaluation believes it is over. Every Ready
entry point consults this list before its first side effect, and so does
:func:`run_check` itself: it is public, so being reached only through a guarded
caller is an arrangement rather than a property.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from fcd.journal import canonical_json

from admissible_core.config import Check
from admissible_core.fsutil import PathError, resolve_within

__all__ = [
    "CommandResult",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "ISOLATION_MODES",
    "ISOLATION_NONE",
    "LOCKFILE_NAMES",
    "RunnerError",
    "SIGNING_CREDENTIAL_NAMES",
    "ambient_signing_credentials",
    "argv_digest",
    "child_environment",
    "declared_isolation",
    "environment_fingerprint",
    "order_checks",
    "present_signing_credentials",
    "read_stdout_bytes",
    "run_check",
    "tool_tree_digest",
]

DEFAULT_MAX_OUTPUT_BYTES = 1 << 20
_KILL_GRACE_SECONDS = 5
_STDOUT_MARKER = b"--- stdout ("
_STDERR_MARKER = b"--- stderr ("
_FRAME_END = b") ---\n"
_READ_BLOCK_BYTES = 65536

# The whole runner namespace a candidate command must never reach. Naming
# individual variables was the earlier design and it was the wrong shape: the
# list has to be complete to be worth anything, and GitHub adds variables to it
# faster than any list here can be kept correct.
#
# So the rule is the namespace, not the enumeration. GITHUB_OUTPUT, GITHUB_ENV,
# GITHUB_PATH and GITHUB_STEP_SUMMARY are *writable files* that steer the
# trusted evaluator job; RUNNER_TEMP and GITHUB_WORKSPACE tell a check exactly
# where the preview, the decision document and the other job's files are going
# to be, which is everything a surviving descendant needs to rewrite one; and
# ACTIONS_* carry the runner's own credentials. A check runs against a checkout,
# not against a job, so none of it is any of its business.
#
# Everything named ADMISSIBLE_* is removed too, including ADMISSIBLE_HOME: a
# check has no business finding, let alone editing, the store that will record
# what it did.
_CONTROL_NAMESPACES = ("GITHUB_", "RUNNER_", "ACTIONS_", "ADMISSIBLE_")
_SECRET_ENVIRONMENT = re.compile(
    r"(?i)secret|token|password|passwd|credential|api[_-]?key"
    r"|_KEY$|^GH_TOKEN$")


# What confines a candidate command beyond this runner's own process group.
#
# The process group is real and it is not enough. ``start_new_session=True``
# makes the check a session leader so one ``killpg`` reaches every descendant it
# forked -- but a descendant that calls ``setsid()`` leaves that group, and no
# portable call finds it again. It then runs as this user, after the evaluation
# believes the check is over, and can rewrite whatever the handoff is about to
# be read from: the preview, the decision document, the CI output file.
#
# There is no way to close that from inside this process, so it is not claimed
# shut. An evaluation instead records *which* boundary confined the commands,
# the observer signs that field with everything else, and finalization refuses a
# preview that declares none. The declaration is the operator's, exactly like
# the external source receipt is: Admissible cannot verify it and says so.
#
# A mode means: every process the checks started is destroyed, by something
# outside this process, before anything reads the artefacts this evaluation
# produced.
#
#   none          only the process-group kill above. Honest default, and never
#                 finalisable.
#   pid-namespace the checks ran inside a PID namespace (a container) that is
#                 torn down before the handoff is read.
#   single-use-vm the whole evaluation ran on a machine created for it and
#                 destroyed before the handoff is read.
#   separate-uid  the checks ran as a different unprivileged user that cannot
#                 write any file the evaluator, the observer or the finalizer
#                 reads.
#
# The names themselves live in :mod:`admissible_core.isolation` and are
# re-exported here, unchanged, because this field is compared across the split:
# Ready refuses a mode it does not know when it writes a preview, and Trust
# refuses one it does not know -- and ``none`` outright -- when it reads the
# observer's assertion. Two spellings of that set would be two gates, so there
# is one definition and both authorities import it.
from admissible_core.isolation import ISOLATION_MODES, ISOLATION_NONE  # noqa: E402

# Credentials that must never be in the environment of a process that starts
# candidate-owned commands. Stripping them from the *child* is not enough: a
# check that escapes its process group inherits nothing, but it can read
# ``/proc/<pid>/environ`` of the parent on Linux, and on any platform it runs as
# the same user and can read whatever file those variables point at. So the
# evaluating process refuses to start at all while it holds one.
#
# This is the whole list, for all three key domains, and it is closed on
# purpose: the key ids are here beside the key material because an id is what
# names *which* identity a nearby secret speaks for, and a process that has been
# handed one is a process somebody intended to sign in. The Ready distribution
# ships no code that can read any of them; refusing on their presence is what
# turns "Ready has no loader" into "Ready will not run beside a credential".
SIGNING_CREDENTIAL_NAMES = (
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


class RunnerError(ValueError):
    """A check could not be executed at all."""


def declared_isolation(source: dict[str, str] | None = None) -> str:
    """The boundary an operator declares confined this evaluation's commands.

    Absent means :data:`ISOLATION_NONE`, which is the truth about a bare
    process group and is refused by finalization. An unrecognised value is a
    refusal rather than a pass-through: a field a finalizer compares must mean
    the same thing to everyone who writes it, and "whatever the operator typed"
    is not a boundary.
    """

    environment = os.environ if source is None else source
    declared = (environment.get("ADMISSIBLE_ISOLATION") or "").strip()
    if not declared:
        return ISOLATION_NONE
    if declared not in ISOLATION_MODES:
        raise RunnerError(
            f"ADMISSIBLE_ISOLATION is {declared!r}, which names no boundary "
            "this product knows. Use one of: "
            + ", ".join(ISOLATION_MODES)
            + ". Each means every process the checks started is destroyed, by "
            "something outside this process, before anything reads what this "
            "evaluation produced. Declaring one you have not built is the "
            "same as not having it.")
    return declared


def ambient_signing_credentials(source: dict[str, str] | None = None
                                ) -> tuple[str, ...]:
    """Every signing credential with usable material here, in declared order."""

    environment = os.environ if source is None else source
    return tuple(
        name for name in SIGNING_CREDENTIAL_NAMES
        if (environment.get(name) or "").strip())


def present_signing_credentials(source: dict[str, str] | None = None
                                ) -> tuple[str, ...]:
    """Every signing credential *named* here, empty or not, in declared order.

    This is what the Ready entry points refuse on, and it is deliberately
    wider than :func:`ambient_signing_credentials`.

    An empty ``ADMISSIBLE_HMAC_KEY`` is not a credential, so refusing on it
    looks pedantic. It is not: the variable being set at all means this process
    was launched by something that intended a signing identity to be here --
    an exported shell variable whose file was not readable, a CI step that
    populated it from a secret that resolved to nothing, a wrapper that will
    fill it in a moment. The value can change under a long-lived MCP or UI
    process; the intent that put the name there does not. Refusing on presence
    also removes an entire class of near-miss, where a credential arrives
    quoted, whitespace-only, or one variable away from the one that is set, and
    the run proceeds because the guard was reading the value rather than the
    arrangement.

    The cost of being wrong in this direction is one unset variable. The cost
    of being wrong in the other is a candidate's command running in a process
    that a key was meant to be in.
    """

    environment = os.environ if source is None else source
    return tuple(name for name in SIGNING_CREDENTIAL_NAMES
                 if name in environment)


@dataclass(frozen=True)
class CommandResult:
    """What a single check did, described only by digests and counters."""

    check_id: str
    check_version: str
    argv_digest: str
    exit_code: int
    timed_out: bool
    launch_failed: bool
    duration_ms: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    output_truncated: bool
    started_at: int
    finished_at: int
    log_name: str = ""


def argv_digest(argv: tuple[str, ...]) -> str:
    return hashlib.sha256(
        canonical_json(list(argv)).encode("utf-8")).hexdigest()


def order_checks(checks: tuple[Check, ...]) -> tuple[Check, ...]:
    """Cheapest first, then by id: a cheap refusal should not wait on a slow one."""

    return tuple(sorted(checks, key=lambda check: (check.cost_units, check.id)))


def child_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    """The filtered environment a candidate command is allowed to see.

    ``ADMISSIBLE_IN_CHECK`` is put back afterwards so a repository's own tooling
    can tell it is running inside the gate. It is the only ``ADMISSIBLE_``
    variable a check ever sees, and it carries no path and no secret.
    """

    items = (os.environ if source is None else source).items()
    environment = {
        name: value for name, value in items
        if not name.startswith(_CONTROL_NAMESPACES)
        and _SECRET_ENVIRONMENT.search(name) is None}
    environment["ADMISSIBLE_IN_CHECK"] = "1"
    return environment


# The dependency manifests a repository commits, in the order they are read.
# A cache key already carries the tree, so a *committed* lockfile change moves
# it anyway; these are read because a lockfile is the thing an operator points
# at when asking "did the dependencies change?", and reading it costs a hash.
LOCKFILE_NAMES = (
    "Cargo.lock",
    "Gemfile.lock",
    "Pipfile.lock",
    "composer.lock",
    "go.sum",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "requirements-dev.txt",
    "requirements.txt",
    "uv.lock",
    "yarn.lock",
)
# Above this, an executable is identified by its path and stat rather than by
# its content. A 512 MiB binary hashed once per check is a cost nobody asked
# for; the stat tuple still changes when the file is replaced.
_MAX_EXECUTABLE_HASH_BYTES = 64 * 1024 * 1024


def _executable_identity(name: str, environment: dict[str, str]) -> dict:
    """What the child would actually execute for ``name``, as data.

    Resolution uses the *child's* PATH, not this process's: the child is the
    one that runs the command, and a fingerprint taken against a different
    search path answers a question nobody asked.
    """

    import shutil

    try:
        resolved = shutil.which(name, path=environment.get("PATH"))
    except (OSError, ValueError):
        resolved = None
    if resolved is None:
        return {"name": name, "resolved": False, "path": "", "digest": "",
                "stat": ""}
    path = Path(resolved)
    try:
        info = path.stat()
    except OSError:
        return {"name": name, "resolved": False, "path": str(path),
                "digest": "", "stat": ""}
    digest = ""
    if info.st_size <= _MAX_EXECUTABLE_HASH_BYTES:
        try:
            hasher = hashlib.sha256()
            with open(path, "rb") as handle:
                for block in iter(lambda: handle.read(_READ_BLOCK_BYTES), b""):
                    hasher.update(block)
            digest = hasher.hexdigest()
        except OSError:
            digest = ""
    return {
        "name": name,
        "resolved": True,
        "path": str(path),
        "digest": digest,
        # Only consulted when the content could not be hashed, and carried
        # always so the two cases are never confusable.
        "stat": "" if digest else
                f"{info.st_dev}:{info.st_ino}:{info.st_size}:{info.st_mtime_ns}",
    }


def _lockfile_digests(root: Path | str | None) -> list[dict]:
    if root is None:
        return []
    base = Path(root)
    found = []
    for name in LOCKFILE_NAMES:
        path = base / name
        try:
            if not path.is_file():
                continue
            hasher = hashlib.sha256()
            with open(path, "rb") as handle:
                for block in iter(lambda: handle.read(_READ_BLOCK_BYTES), b""):
                    hasher.update(block)
        except OSError:
            continue
        found.append({"name": name, "digest": hasher.hexdigest()})
    return found


def environment_fingerprint(source: dict[str, str] | None = None, *,
                            executables: tuple[str, ...] = (),
                            root: Path | str | None = None) -> str:
    """What about this machine could change what a command observes.

    A cached pass is a claim that running the command again would produce the
    same answer. That claim is about the machine as well as the tree, so this
    binds the things that make it true or false:

    * **the exact environment the child would see** -- every name and every
      value, after filtering. ``PATH`` decides which program runs; ``LANG``,
      ``TZ``, ``CFLAGS`` and their kind decide what it does. Hashing the
      platform alone let a pass recorded under one of these stand in for a run
      under another;
    * **the executables that would run**, resolved through that same ``PATH``
      and identified by content where the file is small enough to hash and by
      device/inode/size/mtime where it is not;
    * **the dependency manifests the repository commits**;
    * the interpreter, implementation, architecture and platform.

    Cheap over-invalidation is the right error here -- a needless re-run costs
    seconds, a wrong reuse costs the guarantee -- so a change to any executable
    any check names invalidates every cached result for the attempt.
    """

    environment = child_environment(source)
    return hashlib.sha256(canonical_json({
        "domain": "admissible/v0.6/environment-fingerprint",
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "environment": dict(sorted(environment.items())),
        "executables": sorted(
            (_executable_identity(name, environment)
             for name in sorted(set(executables))),
            key=lambda item: item["name"]),
        "lockfiles": _lockfile_digests(root),
    }).encode("utf-8")).hexdigest()


def tool_tree_digest(package_root: Path | str | None = None) -> str:
    """A digest of the Admissible source tree that is executing right now.

    Taken before the candidate's commands run and again after they finish. The
    gate's own code is on the same filesystem, under the same user, as every
    check it starts; a check that edits it would be rewriting the program that
    is about to judge it, and every later verification would then be the
    candidate checking itself.

    The default root is this distribution's package directory. That is a
    narrower measurement than the monolith's, and it is the correct one here:
    the kernel is a separate installed distribution, so what a candidate would
    have to edit to change what runs next is these files.
    """

    root = Path(__file__).resolve().parent if package_root is None \
        else Path(package_root).resolve()
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.parts or not path.is_file():
            continue
        digest.update(str(path.relative_to(root)).encode("utf-8"))
        digest.update(b"\0")
        try:
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        except OSError as error:
            raise RunnerError(
                f"cannot read the Admissible source at {path}: "
                f"{error.strerror}") from None
    return digest.hexdigest()


class _BoundedDrain(threading.Thread):
    """Read one pipe to exhaustion, keeping at most ``limit`` bytes.

    The child is never allowed to stall on a full pipe, and never allowed to
    turn its own verbosity into disk or memory pressure: bytes past the limit
    are counted as truncation and dropped on the floor as they arrive.
    """

    def __init__(self, stream, limit: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._limit = limit
        self._lock = threading.Lock()
        self._kept = bytearray()
        self._truncated = False

    def run(self) -> None:  # pragma: no cover - exercised through run_check
        try:
            while True:
                block = self._stream.read(_READ_BLOCK_BYTES)
                if not block:
                    return
                with self._lock:
                    room = self._limit - len(self._kept)
                    if room > 0:
                        self._kept += block[:room]
                    if len(block) > max(room, 0):
                        self._truncated = True
        except (OSError, ValueError):
            return
        finally:
            try:
                self._stream.close()
            except OSError:
                pass

    def result(self) -> tuple[bytes, bool]:
        with self._lock:
            return bytes(self._kept), self._truncated


def _write_private_log(log_dir: Path, name: str, check: Check,
                       digest: str, stdout: bytes, stderr: bytes) -> None:
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(log_dir, 0o700)
    except OSError as error:
        raise RunnerError(
            f"cannot use the private log directory {log_dir}: "
            f"{error.strerror}") from None
    try:
        # The log name is derived from a repository-controlled check id, so it
        # is resolved and contained before anything is written.
        path = resolve_within(log_dir, name)
    except PathError as error:
        raise RunnerError(
            f"refusing to write a check log outside {log_dir}: {error}") from None
    try:
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                             0o600)
    except OSError as error:
        raise RunnerError(
            f"cannot write the check log {path}: {error.strerror}") from None
    with os.fdopen(descriptor, "wb") as handle:
        header = (
            f"# admissible check log\n"
            f"# check: {check.id}\n"
            f"# check-version: {check.version}\n"
            f"# argv-digest: {digest}\n"
            f"# argv: {canonical_json(list(check.argv))}\n").encode("utf-8")
        handle.write(header)
        handle.write(_STDOUT_MARKER + str(len(stdout)).encode("ascii") + _FRAME_END)
        handle.write(stdout)
        handle.write(b"\n" + _STDERR_MARKER + str(len(stderr)).encode("ascii")
                     + _FRAME_END)
        handle.write(stderr)
        handle.write(b"\n")
    os.chmod(path, 0o600)


def _framed_section(blob: bytes, marker: bytes) -> bytes:
    start = blob.find(marker)
    if start < 0:
        raise RunnerError("log file is not an admissible check log")
    head = blob.index(_FRAME_END, start) + len(_FRAME_END)
    count = int(blob[start + len(marker):blob.index(b")", start)])
    return blob[head:head + count]


def read_stdout_bytes(path: Path | str) -> bytes:
    """Recover the exact stdout bytes that were hashed into the evidence."""

    return _framed_section(Path(path).read_bytes(), _STDOUT_MARKER)


def read_stderr_bytes(path: Path | str) -> bytes:
    return _framed_section(Path(path).read_bytes(), _STDERR_MARKER)


def _kill_process_group(group: int, process: subprocess.Popen) -> None:
    """Kill everything the check started, not only the process it started.

    A check runs in its own session, so one ``killpg`` reaches every descendant
    it forked -- including the ones that closed their pipes to look finished. A
    survivor is not a tidiness problem: it runs as the same user, after the
    trusted evaluation believes the check is over, and can rewrite whatever the
    gate is about to read.

    ``group`` is passed in rather than looked up, and that is the whole point.
    ``os.getpgid(process.pid)`` fails once the leader has been reaped, which is
    exactly when the group still has surviving members -- so looking it up here
    would fall back to killing a process that has already exited and leave the
    descendants running. ``start_new_session=True`` makes the child a group
    leader, so its pid *is* the group id, and the kernel keeps that id reserved
    while any member of the group is alive.
    """

    try:
        os.killpg(group, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except OSError:
            pass

def run_check(check: Check, *, cwd: Path | str, log_dir: Path | str | None = None,
              max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES) -> CommandResult:
    """Execute one check with argv only and return digest-shaped evidence."""

    # First, before the arguments are judged, before a clock is read, before a
    # log is named and long before a child exists. This function is public and
    # exported: a caller reaches it without passing the CLI, the library entry
    # point, the MCP server or the UI, so every guard those install is a guard
    # this call has not been through. The refusal has to belong to the callable
    # that starts the process, because that is the fact the credential rule is
    # about -- not "Ready declined", but "no command was started by a process
    # holding a key".
    #
    # Presence, not material, exactly as everywhere else: see
    # :func:`present_signing_credentials` for why the name being set is the
    # arrangement that matters and the value is not.
    present = present_signing_credentials()
    if present:
        raise RunnerError(
            "this process holds a signing credential ("
            + ", ".join(present)
            + "), so it will not start a candidate's command. A check runs as "
            "this user and a descendant that escapes the process group keeps "
            "running as this user after the evaluation believes it is over. "
            "Unset "
            + ", ".join(present)
            + " and keep every signing credential in its separate trusted "
            "domain.")

    if type(check) is not Check:
        raise RunnerError("run_check needs a parsed Check")
    if type(max_output_bytes) is not int or max_output_bytes <= 0:
        raise RunnerError("max_output_bytes must be a positive integer")
    digest = argv_digest(check.argv)
    started_at = int(time.time())
    started = time.monotonic()
    log_name = f"{check.id}-{started_at}-{digest[:12]}.log"

    timed_out = False
    launch_failed = False
    stdout, stderr = b"", b""
    stdout_cut = stderr_cut = False
    try:
        process = subprocess.Popen(
            list(check.argv), cwd=str(cwd), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            env=child_environment(), start_new_session=True, close_fds=True,
            bufsize=0)
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
        launch_failed = True
        exit_code = 127
    else:
        # The child is a session and group leader, so its pid is the group id.
        # Captured now, while it is certainly valid.
        group = process.pid
        out_drain = _BoundedDrain(process.stdout, max_output_bytes)
        err_drain = _BoundedDrain(process.stderr, max_output_bytes)
        out_drain.start()
        err_drain.start()
        try:
            try:
                exit_code = process.wait(timeout=check.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_process_group(group, process)
                try:
                    exit_code = process.wait(timeout=_KILL_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    exit_code = -signal.SIGKILL
                if exit_code == 0:
                    exit_code = -signal.SIGKILL
            out_drain.join(_KILL_GRACE_SECONDS)
            err_drain.join(_KILL_GRACE_SECONDS)
            if out_drain.is_alive() or err_drain.is_alive():
                # A grandchild is still holding the pipe open. Kill the group so
                # the readers finish; the retained bytes are capped either way.
                _kill_process_group(group, process)
                out_drain.join(_KILL_GRACE_SECONDS)
                err_drain.join(_KILL_GRACE_SECONDS)
        finally:
            # Unconditional, and last. Normal completion is not evidence that
            # nothing was left behind: a check that exits zero can still have
            # forked a process that closed its pipes and kept running. This also
            # covers the interrupt path -- Ctrl-C in a terminal used to leave the
            # child alive while the CLI printed that nothing had been recorded.
            _kill_process_group(group, process)
            # Killing is not reaping.  Without this wait the Popen object keeps
            # returncode=None and Python warns (and briefly retains a zombie) on
            # an interrupt path.  Cleanup is best-effort and must not replace the
            # original exception that brought us here.
            try:
                process.wait(timeout=_KILL_GRACE_SECONDS)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                pass
        stdout, stdout_cut = out_drain.result()
        stderr, stderr_cut = err_drain.result()

    finished_at = int(time.time())
    duration_ms = int((time.monotonic() - started) * 1000)
    if log_dir is not None:
        _write_private_log(Path(log_dir), log_name, check, digest, stdout, stderr)
    else:
        log_name = ""
    return CommandResult(
        check_id=check.id,
        check_version=check.version,
        argv_digest=digest,
        exit_code=int(exit_code),
        timed_out=timed_out,
        launch_failed=launch_failed,
        duration_ms=duration_ms,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        stdout_bytes=len(stdout),
        stderr_bytes=len(stderr),
        output_truncated=stdout_cut or stderr_cut,
        started_at=started_at,
        finished_at=finished_at,
        log_name=log_name,
    )
