"""Contract: packaging, entry points, schemas, and dependency-free install."""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SCHEMAS = (
    "protocol/workflow-evidence.schema.json",
    "protocol/workflow-receipt.schema.json",
    "protocol/defect-record.schema.json",
    "protocol/evaluation-attestation.schema.json",
)


class PyprojectTest(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    def test_admissible_package_is_distributed(self):
        self.assertIn('"admissible*"', self.text)

    def test_console_entry_point_is_declared(self):
        self.assertIn("[project.scripts]", self.text)
        self.assertIn('admissible = "admissible.cli:main"', self.text)

    def test_no_mandatory_runtime_dependencies(self):
        for line in self.text.splitlines():
            self.assertFalse(re.match(r"^dependencies\s*=\s*\[[^\]]", line.strip()),
                             line)

    def test_python_floor_stays_at_3_10(self):
        self.assertIn('requires-python = ">=3.10"', self.text)

    def test_package_data_ships_templates(self):
        self.assertIn("admissible", self.text.split("[tool.setuptools.package-data]")[1])


class SchemaTest(unittest.TestCase):
    def test_workflow_schemas_exist_and_are_closed_json(self):
        for relative in SCHEMAS:
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("$schema", document)
            self.assertEqual(document.get("type"), "object")
            self.assertIs(document.get("additionalProperties"), False)
            self.assertTrue(document.get("required"))

    def test_receipt_schema_is_not_the_composed_receipt_schema(self):
        path = ROOT / "protocol/workflow-receipt.schema.json"
        self.assertTrue(path.is_file(), path.name)
        document = json.loads(path.read_text(encoding="utf-8"))
        text = json.dumps(document)
        self.assertIn("developer-workflow-admission", text)
        self.assertNotIn("admissibility-receipt", text)

    def test_receipt_documents_validate_against_their_schema(self):
        sys.path.insert(0, str(ROOT))
        path = ROOT / "protocol/workflow-receipt.schema.json"
        self.assertTrue(path.is_file(), path.name)
        self.assertTrue((ROOT / "admissible" / "schema.py").is_file())
        from admissible import schema as schema_module
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(schema_module.receipt_schema(), document)

    def test_evaluation_attestation_schema_is_public_package_data(self):
        sys.path.insert(0, str(ROOT))
        path = ROOT / "protocol/evaluation-attestation.schema.json"
        self.assertTrue(path.is_file(), path.name)
        from admissible import schema as schema_module
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(schema_module.evaluation_schema(), document)
        self.assertEqual(
            document["properties"]["schema"]["const"],
            "admissible/v0.6/evaluation-attestation")
        statement = document["$defs"]["statement"]
        self.assertIn("preview_schema", statement["required"])
        self.assertIn("issued_at", statement["required"])
        self.assertNotIn("attestation_digests", statement["properties"])
        self.assertNotIn("author_attestation_digests",
                         statement["properties"])
        self.assertEqual(len(statement["oneOf"]), 4)


class TemplateTest(unittest.TestCase):
    def test_shipped_templates_match_the_repository_workflow(self):
        pairs = (
            ("admissible/templates/workflow.yml",
             ".github/workflows/admissible.yml"),
            ("admissible/templates/action.yml",
             ".github/actions/admissible/action.yml"),
        )
        for shipped, canonical in pairs:
            shipped_path = ROOT / shipped
            self.assertTrue(shipped_path.is_file(), shipped)
            self.assertEqual(shipped_path.read_text(encoding="utf-8"),
                             (ROOT / canonical).read_text(encoding="utf-8"),
                             f"{shipped} has drifted from {canonical}")


class SourceHygieneTest(unittest.TestCase):
    def sources(self):
        return sorted((ROOT / "admissible").rglob("*.py"))

    def test_package_has_sources(self):
        self.assertTrue(self.sources())

    def test_no_third_party_imports(self):
        import ast

        allowed = {"admissible", "fcd", "rga", "protocol"}
        stdlib = set(sys.stdlib_module_names)
        for path in self.sources():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [(node.module or "").split(".")[0]]
                for name in names:
                    self.assertTrue(name in stdlib or name in allowed,
                                    f"{path.name}: imports {name!r}")

    def test_no_dynamic_import_hatch(self):
        for path in self.sources():
            self.assertNotIn("__import__", path.read_text(encoding="utf-8"),
                             path.name)

    def test_no_shell_true_anywhere(self):
        for path in self.sources():
            self.assertNotIn("shell=True", path.read_text(encoding="utf-8"))

    def test_no_hardcoded_secret_material(self):
        pattern = re.compile(
            r"(?i)(api[_-]?key|secret|token|password)\s*=\s*['\"][A-Za-z0-9/+_-]{12,}")
        for path in self.sources():
            for line in path.read_text(encoding="utf-8").splitlines():
                self.assertIsNone(pattern.search(line), f"{path.name}: {line.strip()}")


class DocumentationTest(unittest.TestCase):
    def test_developer_documents_exist(self):
        for relative in ("docs/DEVELOPER_WORKFLOW.md", "docs/GITHUB_ACTIONS.md",
                         "docs/COST_AND_LATENCY.md", "docs/IMPEACHMENT.md"):
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            self.assertGreater(len(path.read_text(encoding="utf-8")), 400, relative)

    def test_exit_codes_are_documented(self):
        path = ROOT / "docs/DEVELOPER_WORKFLOW.md"
        self.assertTrue(path.is_file(), path.name)
        text = path.read_text(encoding="utf-8")
        # The explicit spellings, because the exit-code contract belongs to a
        # command and `run` is now one verb in two distributions: Ready's
        # zero means the checks passed, Trust's `run` is `finalize` and its
        # zero is an admission.
        for token in ("0", "1", "2", "admissible-ready run --preview",
                      "admissible-trust run", "admissible-trust verify"):
            self.assertIn(token, text)

    def test_example_demo_exists(self):
        self.assertTrue((ROOT / "examples/developer-workflow/demo.sh").is_file())


if __name__ == "__main__":
    unittest.main()
