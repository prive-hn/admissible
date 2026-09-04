"""Release-builder contract for the coordinated Admissible 0.8.1 artifacts."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_release_artifacts.py"
EXPECTED = {
    "admissible_core-0.8.1-py3-none-any.whl",
    "admissible_core-0.8.1.tar.gz",
    "admissible_ready-0.8.1-py3-none-any.whl",
    "admissible_ready-0.8.1.tar.gz",
    "admissible_trust-0.8.1-py3-none-any.whl",
    "admissible_trust-0.8.1.tar.gz",
    "admissible-0.8.1-py3-none-any.whl",
    "admissible-0.8.1.tar.gz",
}


class ReleaseBuilderProducesBoundArtifacts(unittest.TestCase):
    def test_builds_exact_set_and_content_manifest(self):
        expected_dirty = bool(
            _git("status", "--porcelain", "--untracked-files=all")
        )
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "dist"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(BUILDER),
                    "--allow-dirty",
                    "--output-dir",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)

            second_output = Path(td) / "dist-second"
            second = subprocess.run(
                [
                    sys.executable,
                    str(BUILDER),
                    "--allow-dirty",
                    "--output-dir",
                    str(second_output),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(second.returncode, 0, second.stdout)
            first_files = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in output.iterdir()
            }
            second_files = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in second_output.iterdir()
            }
            self.assertEqual(first_files, second_files)

            artifacts = {path.name for path in output.iterdir()
                         if path.suffix == ".whl" or path.name.endswith(".tar.gz")}
            self.assertEqual(artifacts, EXPECTED)

            manifest = json.loads((output / "artifact-manifest.json").read_text())
            self.assertEqual(manifest["schema"], "admissible/v0.8/release-artifacts")
            self.assertEqual(
                manifest["build"]["environment"],
                {
                    "PYTHONHASHSEED": "0",
                    "SOURCE_DATE_EPOCH": "315532800",
                    "TZ": "UTC",
                },
            )
            self.assertEqual(manifest["source"]["commit"], _git("rev-parse", "HEAD"))
            self.assertEqual(manifest["source"]["tree"], _git("rev-parse", "HEAD^{tree}"))
            self.assertEqual(manifest["source"]["dirty"], expected_dirty)
            self.assertRegex(manifest["source"]["working_tree"], r"^[0-9a-f]{40}$")
            if not expected_dirty:
                self.assertEqual(
                    manifest["source"]["working_tree"],
                    manifest["source"]["tree"],
                )
            self.assertEqual(
                {item["name"] for item in manifest["artifacts"]}, EXPECTED)

            for item in manifest["artifacts"]:
                path = output / item["name"]
                self.assertEqual(item["size"], path.stat().st_size)
                self.assertEqual(item["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(item["version"], "0.8.1")
                self.assertEqual(item["license_expression"], "Apache-2.0")
                self.assertEqual(item["generator"], "setuptools (83.0.0)")
                self.assertTrue(item["contains_license"])
                self.assertTrue(item["contains_notice"])

                if path.suffix == ".whl":
                    with zipfile.ZipFile(path) as archive:
                        names = archive.namelist()
                else:
                    with tarfile.open(path, "r:gz") as archive:
                        names = archive.getnames()
                self.assertTrue(any(name.endswith("/LICENSE") for name in names))
                self.assertTrue(any(name.endswith("/NOTICE") for name in names))

    def test_default_output_directory_does_not_change_source_identity(self):
        spec = importlib.util.spec_from_file_location("release_builder_default", BUILDER)
        if spec is None or spec.loader is None:
            self.fail("cannot load release builder module")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        output = ROOT / "dist"
        probe = output / ".release-source-identity-probe"
        output_existed = output.exists()
        self.assertFalse(probe.exists())
        before = module._source_identity()
        try:
            output.mkdir(exist_ok=True)
            probe.write_text("generated output\n", encoding="utf-8")
            after = module._source_identity()
        finally:
            probe.unlink(missing_ok=True)
            if not output_existed:
                output.rmdir()

        self.assertEqual(after, before)

    def test_release_inputs_refuse_tracked_symlinks(self):
        spec = importlib.util.spec_from_file_location("release_builder_symlink", BUILDER)
        if spec is None or spec.loader is None:
            self.fail("cannot load release builder module")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repository = root / "repository"
            repository.mkdir()
            outside = root / "outside.py"
            outside.write_text("VALUE = 'external'\n", encoding="utf-8")
            (repository / "README.md").write_text("# fixture\n", encoding="utf-8")
            (repository / "payload.py").symlink_to(outside)
            subprocess.check_call(["git", "init", "-q"], cwd=repository)
            subprocess.check_call(
                ["git", "config", "user.email", "fixture@example.invalid"],
                cwd=repository,
            )
            subprocess.check_call(
                ["git", "config", "user.name", "Release Fixture"], cwd=repository
            )
            subprocess.check_call(["git", "add", "-A"], cwd=repository)
            subprocess.check_call(
                ["git", "commit", "-q", "-m", "fixture"], cwd=repository
            )

            with (
                mock.patch.object(module, "ROOT", repository),
                mock.patch.object(module, "PROJECTS", ()),
            ):
                with self.assertRaisesRegex(module.ReleaseBuildError, "symlink"):
                    module.build(root / "dist")

    def test_ignored_package_source_cannot_enter_a_clean_release(self):
        spec = importlib.util.spec_from_file_location("release_builder_race", BUILDER)
        if spec is None or spec.loader is None:
            self.fail("cannot load release builder module")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as td:
            repository = Path(td) / "repository"
            project = repository / "packages" / "ready"
            package = project / "src" / "admissible_ready"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text("VALUE = 'tracked'\n")
            (project / "README.md").write_text("# fixture\n")
            (project / "LICENSE").write_text("fixture license\n")
            (project / "NOTICE").write_text("fixture notice\n")
            (repository / ".gitignore").write_text("*.egg-info/\n")
            (project / "pyproject.toml").write_text(
                """[build-system]
requires = ["setuptools==83.0.0"]
build-backend = "setuptools.build_meta"

[project]
name = "admissible-ready"
version = "0.8.1"
readme = "README.md"
license = "Apache-2.0"
license-files = ["LICENSE", "NOTICE"]

[tool.setuptools]
package-dir = {"" = "src"}
packages = ["admissible_ready"]
"""
            )
            subprocess.check_call(["git", "init", "-q"], cwd=repository)
            subprocess.check_call(
                ["git", "config", "user.email", "fixture@example.invalid"],
                cwd=repository,
            )
            subprocess.check_call(
                ["git", "config", "user.name", "Release Fixture"], cwd=repository
            )
            subprocess.check_call(["git", "add", "."], cwd=repository)
            subprocess.check_call(
                ["git", "commit", "-q", "-m", "fixture"], cwd=repository
            )

            ignored = package / "race_ignored_payload.py"
            ignored.write_text("RACE_SUBSTITUTION = True\n")
            (repository / ".git" / "info" / "exclude").write_text(
                "packages/ready/src/admissible_ready/race_ignored_payload.py\n"
            )
            self.assertEqual(
                subprocess.check_output(
                    ["git", "status", "--porcelain", "--untracked-files=all"],
                    cwd=repository,
                    text=True,
                ),
                "",
            )

            output = Path(td) / "dist"
            with (
                mock.patch.object(module, "ROOT", repository),
                mock.patch.object(
                    module,
                    "PROJECTS",
                    (("admissible-ready", project),),
                ),
            ):
                manifest = module.build(output)

            self.assertFalse(manifest["source"]["dirty"])
            self.assertEqual(
                manifest["source"]["tree"], manifest["source"]["working_tree"]
            )
            wheel = output / "admissible_ready-0.8.1-py3-none-any.whl"
            with zipfile.ZipFile(wheel) as archive:
                self.assertNotIn(
                    "admissible_ready/race_ignored_payload.py", archive.namelist()
                )

    def test_refuses_replacement_object_substitution(self):
        spec = importlib.util.spec_from_file_location("release_builder_replace", BUILDER)
        if spec is None or spec.loader is None:
            self.fail("cannot load release builder module")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repository = root / "repository"
            repository.mkdir()
            subject = repository / "subject.txt"
            subject.write_text("accepted-public-bytes\n", encoding="utf-8")
            subprocess.check_call(["git", "init", "-q", "-b", "main"], cwd=repository)
            subprocess.check_call(
                ["git", "config", "user.email", "fixture@example.invalid"],
                cwd=repository,
            )
            subprocess.check_call(
                ["git", "config", "user.name", "Release Fixture"], cwd=repository
            )
            subprocess.check_call(["git", "add", "subject.txt"], cwd=repository)
            subprocess.check_call(
                ["git", "commit", "-q", "-m", "accepted"], cwd=repository
            )
            accepted = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repository, text=True
            ).strip()
            subject.write_text("substituted-private-bytes\n", encoding="utf-8")
            subprocess.check_call(["git", "add", "subject.txt"], cwd=repository)
            subprocess.check_call(
                ["git", "commit", "-q", "-m", "substitute"], cwd=repository
            )
            substitute = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repository, text=True
            ).strip()
            subprocess.check_call(
                ["git", "replace", accepted, substitute], cwd=repository
            )
            subprocess.check_call(
                ["git", "reset", "--hard", "-q", accepted], cwd=repository
            )
            self.assertEqual(
                subprocess.check_output(
                    ["git", "status", "--porcelain", "--untracked-files=all"],
                    cwd=repository,
                    text=True,
                ),
                "",
            )

            with (
                mock.patch.object(module, "ROOT", repository),
                mock.patch.object(module, "PROJECTS", ()),
            ):
                with self.assertRaises(module.ReleaseBuildError):
                    module.build(root / "dist")

    def test_refuses_to_mix_with_an_existing_output_directory(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "dist"
            output.mkdir()
            (output / "stale.whl").write_bytes(b"stale")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(BUILDER),
                    "--allow-dirty",
                    "--output-dir",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("not empty", completed.stdout.lower())
            self.assertEqual((output / "stale.whl").read_bytes(), b"stale")


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


if __name__ == "__main__":
    unittest.main()
