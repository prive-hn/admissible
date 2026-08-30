"""Project/agent/model/gate registry — TDD RED first."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from server.project import (
    AgentDefinition,
    GateDefinition,
    ModelDefinition,
    ProjectDefinition,
    ProjectRegistry,
)


class ProjectRegistryTests(unittest.TestCase):
    def repo(self, root: Path, name: str, remote: str) -> Path:
        p = root / name
        p.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=p, check=True, capture_output=True)
        subprocess.run(["git", "remote", "add", "origin", f"https://github.com/{remote}.git"], cwd=p, check=True)
        return p

    def definition(self, repo: Path, pid="p", github="org/repo") -> ProjectDefinition:
        models = (
            ModelDefinition("builder-model", 1, "openai", "gpt-builder", "Builder", "128k", "high"),
            ModelDefinition("review-model", 1, "anthropic", "claude-review", "Reviewer", "1m", "high"),
        )
        agents = (
            AgentDefinition("builder", 1, "Builder", "Implement", "builder-model", ("read", "write", "test"), ("implement",)),
            AgentDefinition("reviewer", 1, "Reviewer", "Review independently", "review-model", ("read", "test"), ("review",)),
        )
        gates = (
            GateDefinition("implement", 1, "Implement", "builder", "demo", "builder-model", "project_shared", "fresh"),
            GateDefinition("review", 1, "Review", "reviewer", "demo", "review-model", "fresh_blind", "fresh"),
        )
        return ProjectDefinition(pid, "Project", 1, str(repo), github, "main", 1, 1, "policy-1", True, "instrument", models, agents, gates)

    def test_project_must_verify_local_git_remote_before_loading(self):
        with tempfile.TemporaryDirectory() as td:
            repo = self.repo(Path(td), "repo", "org/repo")
            reg = ProjectRegistry()
            loaded = reg.load(self.definition(repo))
            self.assertTrue(loaded.verified)
            self.assertEqual(reg.current.definition.id, "p")

    def test_wrong_github_remote_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            repo = self.repo(Path(td), "repo", "wrong/repo")
            reg = ProjectRegistry()
            with self.assertRaises(ValueError):
                reg.load(self.definition(repo))
            self.assertIsNone(reg.current)

    def test_agent_model_gate_references_are_separate_and_validated(self):
        with tempfile.TemporaryDirectory() as td:
            repo = self.repo(Path(td), "repo", "org/repo")
            reg = ProjectRegistry()
            loaded = reg.load(self.definition(repo))
            review = loaded.gate("review")
            self.assertEqual(review.agent_id, "reviewer")
            self.assertEqual(review.model_id, "review-model")
            self.assertEqual(loaded.model(review.model_id).api_id, "claude-review")

    def test_project_switch_keeps_runtime_state_isolated(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            r1 = self.repo(root, "r1", "org/one")
            r2 = self.repo(root, "r2", "org/two")
            reg = ProjectRegistry()
            p1 = self.definition(r1, "one", "org/one")
            p2 = self.definition(r2, "two", "org/two")
            reg.load(p1).runtime_data["work"] = ["W1"]
            reg.load(p2).runtime_data["work"] = []
            self.assertEqual(reg.current.definition.id, "two")
            reg.select("one")
            self.assertEqual(reg.current.runtime_data["work"], ["W1"])
            reg.select("two")
            self.assertEqual(reg.current.runtime_data["work"], [])


if __name__ == "__main__":
    unittest.main()
