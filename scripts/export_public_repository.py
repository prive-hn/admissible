#!/usr/bin/env python3
"""Create a one-commit, tree-identical Git repository from an accepted commit."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

DEFAULT_AUTHOR_NAME = "Roque Briceño"
DEFAULT_AUTHOR_EMAIL = "roque@priveperfumeshn.com"
DEFAULT_MESSAGE = "Admissible 0.8.0 public release"


class ExportError(RuntimeError):
    """The source cannot be exported without ambiguity or history leakage."""


def _git(repo: Path, *args: str, text: bool = True) -> str | bytes:
    completed = subprocess.run(
        ["git", "--no-replace-objects", *args], cwd=repo,
        text=text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr if text else completed.stderr.decode("utf-8", "replace")
        raise ExportError(stderr.strip() or f"git {' '.join(args)} failed")
    return completed.stdout


def _inside(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _entries(source: Path, revision: str) -> list[tuple[str, str, str, bytes]]:
    raw = _git(source, "ls-tree", "-rz", "--full-tree", revision, text=False)
    assert isinstance(raw, bytes)
    entries: list[tuple[str, str, str, bytes]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        header, separator, raw_path = record.partition(b"\t")
        if not separator:
            raise ExportError("malformed git ls-tree record")
        try:
            mode, object_type, object_id = header.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise ExportError("public paths must be valid UTF-8 Git entries") from error
        if object_type != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ExportError(
                f"unsupported tracked entry {path!r}: {mode} {object_type}")
        payload = _git(source, "cat-file", "blob", object_id, text=False)
        assert isinstance(payload, bytes)
        entries.append((mode, object_type, path, payload))
    if not entries:
        raise ExportError("source commit has no tracked files")
    return entries


def export(
        source: Path,
        output: Path,
        *,
        author_name: str = DEFAULT_AUTHOR_NAME,
        author_email: str = DEFAULT_AUTHOR_EMAIL,
        message: str = DEFAULT_MESSAGE) -> dict[str, object]:
    source = source.resolve()
    output = output.resolve()
    if not (source / ".git").exists():
        raise ExportError(f"source is not a Git checkout: {source}")
    if _inside(output, source):
        raise ExportError("output must be outside the source checkout")
    if output.exists():
        raise ExportError(f"output already exists: {output}")

    status = _git(source, "status", "--porcelain", "--untracked-files=all")
    assert isinstance(status, str)
    if status:
        raise ExportError("source Git tree must be clean before public export")

    source_commit = str(_git(source, "rev-parse", "HEAD^{commit}")).strip()
    source_tree = str(_git(source, "rev-parse", f"{source_commit}^{{tree}}")).strip()
    source_date = str(
        _git(source, "show", "-s", "--format=%aI", source_commit)
    ).strip()
    entries = _entries(source, source_commit)

    output.mkdir(parents=True)
    for mode, _, relative, payload in entries:
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if mode == "120000":
            os.symlink(payload.decode("utf-8"), destination)
        else:
            destination.write_bytes(payload)
            destination.chmod(0o755 if mode == "100755" else 0o644)

    _git(output, "init", "--initial-branch=main")
    _git(output, "add", "-A")
    public_tree = str(_git(output, "write-tree")).strip()
    if public_tree != source_tree:
        raise ExportError(
            f"public tree differs from source: {public_tree} != {source_tree}")

    env = os.environ.copy()
    env.update({
        "GIT_AUTHOR_NAME": author_name,
        "GIT_AUTHOR_EMAIL": author_email,
        "GIT_AUTHOR_DATE": source_date,
        "GIT_COMMITTER_NAME": author_name,
        "GIT_COMMITTER_EMAIL": author_email,
        "GIT_COMMITTER_DATE": source_date,
    })
    completed = subprocess.run(
        [
            "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
            "commit", "-m", message,
        ],
        cwd=output,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise ExportError(completed.stderr.strip() or "public root commit failed")

    public_commit = str(_git(output, "rev-parse", "HEAD")).strip()
    final_tree = str(_git(output, "rev-parse", "HEAD^{tree}")).strip()
    commit_count = str(_git(output, "rev-list", "--count", "HEAD")).strip()
    if final_tree != source_tree or commit_count != "1":
        raise ExportError("public repository identity changed after root commit")
    return {
        "source_commit": source_commit,
        "source_tree": source_tree,
        "public_commit": public_commit,
        "public_tree": final_tree,
        "commit_count": 1,
        "branch": "main",
        "output": str(output),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--author-name", default=DEFAULT_AUTHOR_NAME)
    parser.add_argument("--author-email", default=DEFAULT_AUTHOR_EMAIL)
    parser.add_argument("--message", default=DEFAULT_MESSAGE)
    args = parser.parse_args()
    try:
        receipt = export(
            args.source,
            args.output,
            author_name=args.author_name,
            author_email=args.author_email,
            message=args.message,
        )
    except ExportError as error:
        print(f"public export refused: {error}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
