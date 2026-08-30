"""Clean-history export contract for the public Admissible repository."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
EXPORTER = ROOT / "scripts" / "export_public_repository.py"


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


class PublicExportStartsOneTreeIdenticalHistory(unittest.TestCase):
    def test_exports_one_root_commit_with_the_same_tree_and_modes(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source"
            output = Path(td) / "public"
            source.mkdir()
            subprocess.run(["git", "init", "--initial-branch=main"], cwd=source,
                           check=True, stdout=subprocess.DEVNULL)
            (source / "README.md").write_text("# public\n", encoding="utf-8")
            tool = source / "tool.sh"
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o755)
            os.symlink("README.md", source / "README-link")
            subprocess.run(["git", "add", "-A"], cwd=source, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Source Author",
                    "-c", "user.email=source@example.invalid",
                    "commit", "-m", "accepted private history tip",
                ],
                cwd=source,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            accepted_commit = _git(source, "rev-parse", "HEAD")
            accepted_tree = _git(source, "rev-parse", "HEAD^{tree}")

            (source / "README.md").write_text("# moved head\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=source, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Source Author",
                    "-c", "user.email=source@example.invalid",
                    "commit", "-m", "later private head",
                ],
                cwd=source,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            later_commit = _git(source, "rev-parse", "HEAD")
            subprocess.run(
                ["git", "reset", "--hard", accepted_commit],
                cwd=source,
                check=True,
                stdout=subprocess.DEVNULL,
            )

            spec = importlib.util.spec_from_file_location("public_export_race", EXPORTER)
            if spec is None or spec.loader is None:
                self.fail("cannot load public exporter module")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            original_git = module._git
            moved = False

            def move_head_after_capture(repo, *args, text=True):
                nonlocal moved
                result = original_git(repo, *args, text=text)
                if (
                    not moved
                    and Path(repo).resolve() == source.resolve()
                    and args in {("rev-parse", "HEAD"), ("rev-parse", "HEAD^{commit}")}
                ):
                    subprocess.run(
                        ["git", "reset", "--hard", later_commit],
                        cwd=source,
                        check=True,
                        stdout=subprocess.DEVNULL,
                    )
                    moved = True
                return result

            with mock.patch.object(module, "_git", side_effect=move_head_after_capture):
                receipt = module.export(source, output)

            self.assertTrue(moved)
            self.assertEqual(receipt["source_commit"], accepted_commit)
            self.assertEqual(receipt["source_tree"], accepted_tree)
            self.assertEqual(receipt["public_tree"], accepted_tree)
            self.assertEqual(_git(output, "rev-list", "--count", "HEAD"), "1")
            self.assertEqual(_git(output, "rev-parse", "HEAD^{tree}"), accepted_tree)
            self.assertEqual(_git(output, "branch", "--show-current"), "main")
            self.assertEqual(_git(output, "remote"), "")
            self.assertEqual((output / "README.md").read_text(), "# public\n")
            self.assertTrue((output / "README-link").is_symlink())
            self.assertEqual(os.readlink(output / "README-link"), "README.md")
            self.assertTrue((output / "tool.sh").stat().st_mode & 0o111)

    def test_refuses_replacement_object_substitution(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source"
            output = Path(td) / "public"
            source.mkdir()
            subprocess.run(
                ["git", "init", "--initial-branch=main"],
                cwd=source,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            payload = source / "payload.txt"
            payload.write_text("accepted-public-bytes\n", encoding="utf-8")
            subprocess.run(["git", "add", "payload.txt"], cwd=source, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Source Author",
                    "-c", "user.email=source@example.invalid",
                    "commit", "-m", "accepted",
                ],
                cwd=source,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            accepted_commit = _git(source, "rev-parse", "HEAD")

            payload.write_text("substituted-private-bytes\n", encoding="utf-8")
            subprocess.run(["git", "add", "payload.txt"], cwd=source, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Source Author",
                    "-c", "user.email=source@example.invalid",
                    "commit", "-m", "substitute",
                ],
                cwd=source,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            substitute_commit = _git(source, "rev-parse", "HEAD")
            subprocess.run(
                ["git", "replace", accepted_commit, substitute_commit],
                cwd=source,
                check=True,
            )
            subprocess.run(
                ["git", "reset", "--hard", accepted_commit],
                cwd=source,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            self.assertEqual(_git(source, "status", "--porcelain"), "")

            spec = importlib.util.spec_from_file_location("public_export_replace", EXPORTER)
            if spec is None or spec.loader is None:
                self.fail("cannot load public exporter module")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            with self.assertRaises(module.ExportError):
                module.export(source, output)

    def test_refuses_a_dirty_source(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source"
            output = Path(td) / "public"
            source.mkdir()
            subprocess.run(["git", "init", "--initial-branch=main"], cwd=source,
                           check=True, stdout=subprocess.DEVNULL)
            (source / "tracked.txt").write_text("accepted\n")
            subprocess.run(["git", "add", "tracked.txt"], cwd=source, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Source Author",
                    "-c", "user.email=source@example.invalid",
                    "commit", "-m", "accepted",
                ],
                cwd=source,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            (source / "tracked.txt").write_text("dirty\n")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(EXPORTER),
                    "--source",
                    str(source),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("clean", completed.stdout.lower())
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
