#!/usr/bin/env python3
"""Build and inspect the coordinated Admissible release artifacts."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.metadata
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.8.0"
PROJECTS = (
    ("admissible-core", ROOT / "packages" / "core"),
    ("admissible-ready", ROOT / "packages" / "ready"),
    ("admissible-trust", ROOT / "packages" / "trust"),
    ("admissible", ROOT / "packages" / "umbrella"),
)
SCHEMA = "admissible/v0.8/release-artifacts"
DETERMINISTIC_ENVIRONMENT = {
    "PYTHONHASHSEED": "0",
    "SOURCE_DATE_EPOCH": "315532800",  # ZIP's minimum: 1980-01-01 UTC.
    "TZ": "UTC",
}


class ReleaseBuildError(RuntimeError):
    """The release artifact set is incomplete, ambiguous, or unbound."""


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", "--no-replace-objects", *args], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode != 0:
        raise ReleaseBuildError(completed.stderr.strip() or "git command failed")
    return completed.stdout.strip()


def _snapshot_working_tree(destination: Path | None = None) -> str:
    """Hash release inputs and optionally materialize those exact indexed bytes."""
    with tempfile.TemporaryDirectory(prefix="admissible-release-index-") as td:
        environment = os.environ.copy()
        environment["GIT_INDEX_FILE"] = str(Path(td) / "index")
        for command in (("read-tree", "HEAD"), ("add", "-A", "--", ".")):
            completed = subprocess.run(
                ["git", "--no-replace-objects", *command], cwd=ROOT,
                env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if completed.returncode != 0:
                raise ReleaseBuildError(
                    completed.stderr.strip() or "cannot hash the working tree")
        completed = subprocess.run(
            ["git", "--no-replace-objects", "ls-files", "--stage", "-z"],
            cwd=ROOT, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if completed.returncode != 0:
            raise ReleaseBuildError(
                completed.stderr.decode("utf-8", "replace").strip()
                or "cannot inspect release inputs")
        for record in completed.stdout.split(b"\0"):
            if not record:
                continue
            metadata, separator, raw_path = record.partition(b"\t")
            if not separator:
                raise ReleaseBuildError("malformed Git index entry in release inputs")
            mode = metadata.split(b" ", 1)[0]
            if mode == b"120000":
                path = raw_path.decode("utf-8", "replace")
                raise ReleaseBuildError(f"release inputs contain symlink: {path}")
        completed = subprocess.run(
            ["git", "--no-replace-objects", "write-tree"], cwd=ROOT,
            env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if completed.returncode != 0:
            raise ReleaseBuildError(
                completed.stderr.strip() or "cannot write the working-tree identity")
        tree_oid = completed.stdout.strip()
        if destination is not None:
            destination.mkdir(parents=True, exist_ok=False)
            prefix = str(destination.resolve()) + os.sep
            completed = subprocess.run(
                [
                    "git", "--no-replace-objects", "checkout-index", "--all",
                    "--force", f"--prefix={prefix}",
                ],
                cwd=ROOT, env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if completed.returncode != 0:
                raise ReleaseBuildError(
                    completed.stderr.strip() or "cannot materialize release inputs")
        return tree_oid


def _working_tree_oid() -> str:
    """Hash tracked and untracked non-ignored release inputs without staging."""
    return _snapshot_working_tree()


def _initialize_frozen_repository(root: Path, expected_tree: str) -> None:
    """Give a materialized snapshot real Git identity without changing its tree."""
    identity_environment = os.environ.copy()
    identity_environment.update({
        "GIT_AUTHOR_NAME": "Admissible release builder",
        "GIT_AUTHOR_EMAIL": "release-builder@invalid",
        "GIT_AUTHOR_DATE": "@0 +0000",
        "GIT_COMMITTER_NAME": "Admissible release builder",
        "GIT_COMMITTER_EMAIL": "release-builder@invalid",
        "GIT_COMMITTER_DATE": "@0 +0000",
    })

    def run(*arguments: str, input_text: str | None = None) -> str:
        completed = subprocess.run(
            ["git", *arguments], cwd=root, env=identity_environment, text=True,
            input=input_text, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False)
        if completed.returncode != 0:
            raise ReleaseBuildError(
                completed.stderr.strip() or
                f"cannot initialize frozen release repository: git {' '.join(arguments)}")
        return completed.stdout.strip()

    run("init", "--quiet")
    run("symbolic-ref", "HEAD", "refs/heads/frozen-release-source")
    run("add", "--force", "--all", "--", ".")
    frozen_tree = run("write-tree")
    if frozen_tree != expected_tree:
        raise ReleaseBuildError(
            "materialized release repository does not match its source tree")
    frozen_commit = run("commit-tree", frozen_tree, input_text="frozen release source\n")
    run("update-ref", "refs/heads/frozen-release-source", frozen_commit)


def _source_identity() -> dict[str, object]:
    """Capture the exact repository inputs that a release build may consume."""
    status = _git("status", "--porcelain", "--untracked-files=all")
    return {
        "commit": _git("rev-parse", "HEAD"),
        "tree": _git("rev-parse", "HEAD^{tree}"),
        "working_tree": _working_tree_oid(),
        "dirty": bool(status),
    }


def _installed_setuptools_version() -> str:
    import setuptools.build_meta as build_meta

    site_packages = Path(build_meta.__file__).resolve().parent.parent
    versions = {
        distribution.version
        for distribution in importlib.metadata.distributions(path=[str(site_packages)])
        if (distribution.metadata["Name"] or "").lower() == "setuptools"
    }
    if len(versions) != 1:
        raise ReleaseBuildError(
            f"cannot identify one setuptools distribution at {site_packages}: "
            f"{sorted(versions)!r}")
    return versions.pop()


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts


def _headers(text: str) -> dict[str, str]:
    parsed = Parser().parsestr(text)
    return {key: str(value) for key, value in parsed.items()}


def _wheel_record(path: Path, expected_generator: str) -> dict[str, object]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if not names or any(not _safe_member(name) for name in names):
            raise ReleaseBuildError(f"unsafe wheel member in {path.name}")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
        if len(metadata_names) != 1 or len(wheel_names) != 1:
            raise ReleaseBuildError(f"ambiguous wheel metadata in {path.name}")
        headers = _headers(archive.read(metadata_names[0]).decode("utf-8"))
        wheel_headers = _headers(archive.read(wheel_names[0]).decode("utf-8"))
        generator = wheel_headers.get("Generator", "")
        if generator != expected_generator:
            raise ReleaseBuildError(
                f"{path.name}: generator {generator!r}, expected {expected_generator!r}")
        contains_license = any(name.endswith("/licenses/LICENSE") for name in names)
        contains_notice = any(name.endswith("/licenses/NOTICE") for name in names)
    return _record(path, headers, generator, contains_license, contains_notice, "wheel")


def _normalize_sdist(path: Path) -> None:
    """Rewrite an sdist with stable ownership, timestamp, PAX, and gzip metadata."""
    epoch = int(DETERMINISTIC_ENVIRONMENT["SOURCE_DATE_EPOCH"])
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            payload: bytes | None = None
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ReleaseBuildError(
                        f"cannot read {member.name} while normalizing {path.name}")
                payload = extracted.read()
            normalized = tarfile.TarInfo(member.name)
            normalized.mode = member.mode
            normalized.type = member.type
            normalized.linkname = member.linkname
            normalized.size = len(payload) if payload is not None else member.size
            normalized.mtime = epoch
            normalized.uid = 0
            normalized.gid = 0
            normalized.uname = ""
            normalized.gname = ""
            normalized.devmajor = member.devmajor
            normalized.devminor = member.devminor
            normalized.pax_headers = {}
            entries.append((normalized, payload))

    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for member, payload in entries:
            archive.addfile(
                member,
                io.BytesIO(payload) if payload is not None else None,
            )

    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=compressed,
        mtime=epoch,
    ) as archive:
        archive.write(tar_bytes.getvalue())
    temporary = path.with_name(f".{path.name}.normalized")
    try:
        temporary.write_bytes(compressed.getvalue())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _sdist_record(path: Path, expected_generator: str) -> dict[str, object]:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if not members or any(not _safe_member(member.name) for member in members):
            raise ReleaseBuildError(f"unsafe sdist member in {path.name}")
        if any(member.issym() or member.islnk() or member.isdev() for member in members):
            raise ReleaseBuildError(f"link or device member in {path.name}")
        metadata_members = [
            member for member in members
            if member.name.endswith("/PKG-INFO")
            and len(PurePosixPath(member.name).parts) == 2
        ]
        if len(metadata_members) != 1:
            raise ReleaseBuildError(f"ambiguous sdist metadata in {path.name}")
        extracted = archive.extractfile(metadata_members[0])
        if extracted is None:
            raise ReleaseBuildError(f"unreadable PKG-INFO in {path.name}")
        headers = _headers(extracted.read().decode("utf-8"))
        names = [member.name for member in members]
        contains_license = any(name.endswith("/LICENSE") for name in names)
        contains_notice = any(name.endswith("/NOTICE") for name in names)
    return _record(path, headers, expected_generator, contains_license,
                   contains_notice, "sdist")


def _record(
        path: Path,
        headers: dict[str, str],
        generator: str,
        contains_license: bool,
        contains_notice: bool,
        artifact_type: str) -> dict[str, object]:
    if headers.get("Version") != VERSION:
        raise ReleaseBuildError(
            f"{path.name}: version {headers.get('Version')!r}, expected {VERSION!r}")
    if headers.get("License-Expression") != "Apache-2.0":
        raise ReleaseBuildError(
            f"{path.name}: missing Apache-2.0 License-Expression")
    if not contains_license or not contains_notice:
        raise ReleaseBuildError(f"{path.name}: LICENSE or NOTICE is missing")
    payload = path.read_bytes()
    return {
        "name": path.name,
        "distribution": headers.get("Name", ""),
        "version": headers.get("Version", ""),
        "type": artifact_type,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "license_expression": headers.get("License-Expression", ""),
        "generator": generator,
        "contains_license": contains_license,
        "contains_notice": contains_notice,
    }


def _expected_names() -> set[str]:
    names: set[str] = set()
    for distribution, _ in PROJECTS:
        stem = distribution.replace("-", "_")
        names.add(f"{stem}-{VERSION}-py3-none-any.whl")
        names.add(f"{stem}-{VERSION}.tar.gz")
    return names


def build(output: Path, *, allow_dirty: bool = False) -> dict[str, object]:
    if output.exists() and any(output.iterdir()):
        raise ReleaseBuildError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    source_identity = _source_identity()
    if source_identity["dirty"] and not allow_dirty:
        raise ReleaseBuildError("release builds require a clean Git tree")

    setuptools_version = _installed_setuptools_version()
    if setuptools_version != "83.0.0":
        raise ReleaseBuildError(
            f"setuptools {setuptools_version} is loaded; expected pinned 83.0.0")
    generator = f"setuptools ({setuptools_version})"
    build_environment = os.environ.copy()
    build_environment.update(DETERMINISTIC_ENVIRONMENT)

    with tempfile.TemporaryDirectory(prefix="admissible-release-source-") as td:
        frozen_root = Path(td) / "source"
        materialized_tree = _snapshot_working_tree(frozen_root)
        if materialized_tree != source_identity["working_tree"]:
            raise ReleaseBuildError("source identity changed before materialization")
        _initialize_frozen_repository(frozen_root, materialized_tree)

        for _, project in PROJECTS:
            try:
                relative_project = project.relative_to(ROOT)
            except ValueError as error:
                raise ReleaseBuildError(
                    f"release project is outside the source tree: {project}"
                ) from error
            frozen_project = frozen_root / relative_project
            completed = subprocess.run(
                [sys.executable, "-m", "build", "--no-isolation", "--outdir",
                 str(output), str(frozen_project)],
                cwd=frozen_root,
                env=build_environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            if completed.returncode != 0:
                raise ReleaseBuildError(
                    f"build failed for {relative_project}:\n{completed.stdout}")

    artifacts = sorted(
        path for path in output.iterdir()
        if path.suffix == ".whl" or path.name.endswith(".tar.gz"))
    actual = {path.name for path in artifacts}
    expected = _expected_names()
    if actual != expected:
        raise ReleaseBuildError(
            f"artifact set mismatch: missing={sorted(expected - actual)!r}, "
            f"extra={sorted(actual - expected)!r}")

    for path in artifacts:
        if path.name.endswith(".tar.gz"):
            _normalize_sdist(path)

    records = []
    for path in artifacts:
        if path.suffix == ".whl":
            records.append(_wheel_record(path, generator))
        else:
            records.append(_sdist_record(path, generator))
    final_source_identity = _source_identity()
    if final_source_identity != source_identity:
        raise ReleaseBuildError("source identity changed during release build")

    manifest: dict[str, object] = {
        "schema": SCHEMA,
        "source": source_identity,
        "build": {
            "python": sys.version.split()[0],
            "setuptools": setuptools_version,
            "command": "python -m build --no-isolation",
            "environment": dict(DETERMINISTIC_ENVIRONMENT),
        },
        "artifacts": records,
    }
    manifest_path = output / "artifact-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    parser.add_argument(
        "--allow-dirty", action="store_true",
        help="development-only: permit dirty inputs and record their synthetic tree")
    args = parser.parse_args()
    try:
        manifest = build(args.output_dir.resolve(), allow_dirty=args.allow_dirty)
    except ReleaseBuildError as error:
        print(f"release build refused: {error}", file=sys.stderr)
        return 2
    artifacts = manifest["artifacts"]
    source = manifest["source"]
    if not isinstance(artifacts, list) or not isinstance(source, dict):
        print("release build refused: invalid internal manifest", file=sys.stderr)
        return 2
    print(json.dumps({
        "manifest": str((args.output_dir.resolve() / "artifact-manifest.json")),
        "artifacts": len(artifacts),
        "dirty": bool(source.get("dirty")),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
