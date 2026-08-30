"""Path containment, and the one place a secret file is read from disk."""
from __future__ import annotations

import errno
import os
import stat
from pathlib import Path, PurePosixPath

__all__ = ["PathError", "SecretFileError", "read_secret_file",
           "resolve_within", "resolve_write_target"]


class PathError(ValueError):
    """A path escaped, or could not be contained by, its base directory."""


def resolve_within(base: Path | str, relative: object) -> Path:
    """Resolve ``relative`` strictly inside ``base``.

    Absolute paths, ``..`` segments, and symlink escapes are refused. The
    containment check runs *after* resolution so a symlinked directory cannot
    smuggle the final path outside ``base``.
    """

    if type(relative) is not str or not relative.strip():
        raise PathError("path must be a non-empty plain string")
    if os.path.isabs(relative) or (os.name == "nt" and os.path.splitdrive(relative)[0]):
        raise PathError("path must be relative to the repository root")
    parts = PurePosixPath(relative.replace(os.sep, "/")).parts
    if any(part == ".." for part in parts):
        raise PathError("path must not traverse above the repository root")
    root = Path(base).resolve()
    resolved = (root / relative).resolve()
    if resolved == root or root not in resolved.parents:
        raise PathError("path must resolve strictly inside the repository root")
    return resolved


def resolve_write_target(base: Path | str, relative: object) -> Path:
    """The path ``relative`` names inside ``base``, or a refusal.

    Reading through a symlink is a question about content. *Writing* through
    one is a question about authority: the link says where the bytes land, and
    the link is a file in the tree under evaluation. A candidate that commits
    ``.gitignore -> /etc/cron.d/anything``, or ``.github -> ../..``, would
    otherwise turn ``init`` into a write primitive aimed wherever it liked.

    So every existing component of the path is checked, not only the last one,
    and a symlink anywhere along it is refused rather than followed. The path
    is returned unresolved: it is where the write must go, and resolving it
    would reintroduce exactly what was just refused.
    """

    if type(relative) is not str or not relative.strip():
        raise PathError("path must be a non-empty plain string")
    if os.path.isabs(relative) or (os.name == "nt"
                                   and os.path.splitdrive(relative)[0]):
        raise PathError("path must be relative to the repository root")
    parts = PurePosixPath(relative.replace(os.sep, "/")).parts
    if not parts or any(part in ("..", ".") for part in parts):
        raise PathError("path must not traverse above the repository root")
    root = Path(base)
    if root.is_symlink():
        raise PathError(f"the repository root {root} is a symbolic link")
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise PathError(
                f"{current} is a symbolic link; writing through it would put "
                "these bytes wherever the link points, which is a file the "
                "repository under evaluation controls")
    return current


class SecretFileError(ValueError):
    """A key file is missing, world-readable, or implausibly large."""


def read_secret_file(path_text: str, variable: str, *,
                     max_bytes: int = 256 * 1024) -> bytes:
    """Read key material from a regular file only its owner can read.

    Every secret this product accepts from disk arrives through here, so the
    permission rule is stated once. A key file group- or world-readable is not
    a key: it is a key plus everyone who shares the machine.

    The file is opened **once**, and every question is asked of that open
    descriptor rather than of the path. The earlier shape -- ``stat`` the path,
    then reopen it to read -- checked one filesystem object and read another:
    anybody who could write the containing directory could swap the checked
    file for a symlink between the two calls and be read a file that passed
    none of these rules. ``O_NOFOLLOW`` refuses a symlink at the final
    component in the same syscall that opens it, and ``fstat`` then describes
    the object actually opened, which is the one about to be read.
    """

    path = Path(path_text)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NOCTTY", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as error:
        if getattr(error, "errno", None) in (errno.ELOOP, errno.EMLINK):
            raise SecretFileError(
                f"{variable} {path} is a symbolic link. A key is read from the "
                "file it names, never through a link: the link is one rename "
                "away from naming something else, and this process would "
                "follow it. Point the variable at the file itself.") from None
        raise SecretFileError(f"{variable} {path} cannot be read") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SecretFileError(f"{variable} {path} must be a regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise SecretFileError(
                f"{variable} {path} is readable by group or others; run "
                "'chmod 600' on it first")
        if info.st_size > max_bytes:
            raise SecretFileError(f"{variable} {path} is implausibly large")
        # Read to EOF, one byte past the ceiling, so a file that grew between
        # the fstat and the read is refused rather than silently truncated
        # into a shorter key -- and so a short read never becomes one either.
        body = bytearray()
        while len(body) <= max_bytes:
            try:
                block = os.read(descriptor, max_bytes + 1 - len(body))
            except OSError:
                raise SecretFileError(
                    f"{variable} {path} cannot be read") from None
            if not block:
                break
            body.extend(block)
        if len(body) > max_bytes:
            raise SecretFileError(f"{variable} {path} is implausibly large")
        return bytes(body)
    finally:
        os.close(descriptor)
