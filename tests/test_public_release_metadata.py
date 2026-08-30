"""Public-release metadata and export-surface contract for Admissible 0.8.0."""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

from pypdf import PdfReader  # type: ignore[import-not-found]

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_PROJECTS = (
    ROOT / "packages" / "core",
    ROOT / "packages" / "ready",
    ROOT / "packages" / "trust",
    ROOT / "packages" / "umbrella",
)
REQUIRED_COMMUNITY_FILES = (
    "CHANGELOG.md",
    "CITATION.cff",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE.md",
    "RELEASING.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "TRADEMARKS.md",
    ".github/CODEOWNERS",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
)
REQUIRED_URLS = {"Documentation", "Issues", "Repository"}


class PublicLicenseContract(unittest.TestCase):
    def test_root_carries_both_approved_license_texts(self):
        apache = (ROOT / "LICENSE").read_text(encoding="utf-8")
        papers = (ROOT / "LICENSES" / "CC-BY-4.0.txt").read_text(
            encoding="utf-8")
        self.assertIn("Apache License", apache)
        self.assertIn("Version 2.0, January 2004", apache)
        self.assertIn(
            "Creative Commons Attribution 4.0 International Public License",
            papers,
        )

    def test_each_distribution_ships_the_canonical_apache_text(self):
        canonical = (ROOT / "LICENSE").read_bytes()
        notice = (ROOT / "NOTICE").read_bytes()
        for project in PACKAGE_PROJECTS:
            with self.subTest(project=project.name):
                self.assertEqual(canonical, (project / "LICENSE").read_bytes())
                self.assertEqual(notice, (project / "NOTICE").read_bytes())

    def test_every_distribution_declares_apache_and_public_project_urls(self):
        for project in (ROOT, *PACKAGE_PROJECTS):
            with self.subTest(project=project.name):
                document = tomllib.loads(
                    (project / "pyproject.toml").read_text(encoding="utf-8"))
                metadata = document["project"]
                self.assertEqual("Apache-2.0", metadata["license"])
                self.assertEqual(
                    ["LICENSE", "NOTICE"], metadata["license-files"])
                self.assertTrue(metadata["keywords"])
                self.assertTrue(metadata["classifiers"])
                self.assertFalse(any(
                    item.startswith("License ::")
                    for item in metadata["classifiers"]
                ))
                self.assertTrue(
                    REQUIRED_URLS.issubset(metadata["urls"]), metadata["urls"])
                self.assertEqual(
                    "https://github.com/prive-hn/admissible",
                    metadata["urls"]["Repository"],
                )
                self.assertEqual(
                    ["setuptools==83.0.0"],
                    document["build-system"]["requires"],
                )


class PublicRepositorySurface(unittest.TestCase):
    def test_e8_reproducer_environment_is_pinned_and_documented(self):
        document = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        dev = document["project"]["optional-dependencies"]["dev"]
        self.assertIn("hypothesis==6.165.10", dev)
        self.assertIn("lxml==6.0.2", dev)
        instructions = (ROOT / "eval" / "README.md").read_text(encoding="utf-8")
        self.assertIn("hypothesis==6.165.10", instructions)
        self.assertIn("lxml==6.0.2", instructions)
        self.assertIn(
            "/tmp/admissible-e8-v080/bin/python eval/realdefects/e8_handcheck.py",
            instructions,
        )

    def test_bibtex_inventory_matches_every_arxiv_citation(self):
        draft_ids: set[str] = set()
        for relative in ("paper/DRAFT.md", "paper/RGA/DRAFT.md",
                         "paper/admissible/DRAFT.md"):
            draft_ids.update(re.findall(
                r"arXiv:(\d{4}\.\d{5})",
                (ROOT / relative).read_text(encoding="utf-8")))
        bib_ids = set(re.findall(
            r"eprint\s*=\s*\{(\d{4}\.\d{5})\}",
            (ROOT / "paper/REFERENCES.bib").read_text(encoding="utf-8")))
        self.assertEqual(draft_ids, bib_ids)

    def test_generated_papers_carry_release_and_license_headers(self):
        for relative in (
                "paper/fail-closed-class-dispatch.pdf",
                "paper/RGA/refutation-gated-admission.pdf",
                "paper/admissible/admissible.pdf",
                "paper/admissible-volume.pdf"):
            reader = PdfReader(ROOT / relative)
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            front_page_count = 3 if relative.endswith("admissible-volume.pdf") else 1
            front = "\n".join(
                page.extract_text() or ""
                for page in reader.pages[:front_page_count])
            with self.subTest(pdf=relative):
                self.assertIn("Version 0.8.0", front)
                self.assertIn("CC BY 4.0", front)
                self.assertNotIn("release candidate", front.lower())
                self.assertNotIn("Working draft", front)
                self.assertNotIn("[CC BY", text)
                self.assertNotIn("](../../LICENSES", text)
                self.assertNotIn("../DRAFT.md", front)
                self.assertNotIn("../RGA/DRAFT.md", front)
                if relative.endswith("admissible-volume.pdf"):
                    self.assertEqual(
                        "Admissible — complete technical report volume",
                        reader.metadata.title)
                    self.assertNotIn("Part VII", text)
                    self.assertNotIn("Exact-head review of PR", text)
                    self.assertNotIn("Working voice", text)

    def test_public_ci_is_a_pinned_admissible_gate_evaluate(self):
        pin = "bf928dadd057934bfe8c2406f98734804b193290"
        self.assertFalse((ROOT / ".github/workflows/public-ci.yml").exists())
        workflow = (ROOT / ".github/workflows/admissible.yml").read_text(
            encoding="utf-8")
        self.assertIn("pull_request:", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("${{ secrets.", workflow)
        self.assertNotIn("publish", workflow.lower())
        self.assertNotRegex(workflow, r"(?m)^  finalize:")
        uses = (
            "prive-hn/admissible/.github/workflows/admissible-gate.yml@"
            + pin)
        self.assertIn("uses: " + uses, workflow)
        self.assertIn("tool-sha: " + pin, workflow)
        self.assertEqual(workflow.count(pin), 2)
        self.assertNotIn("REPLACE-WITH-FULL-40-HEX", workflow)
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from admissible.config import parse_config
        policy = json.loads(
            (ROOT / ".admissible.json").read_text(encoding="utf-8"))
        parsed = parse_config(policy)
        self.assertEqual(1, parsed.version)
        self.assertEqual(0, parsed.classes[0].required_independent_reviews)
        argv = [check.argv for check in parsed.classes[0].checks]
        self.assertIn(("make", "test"), argv)
        artifact = parsed.classes[0]
        self.assertLessEqual(
            artifact.planned_wall_seconds, artifact.max_wall_seconds)
        self.assertLessEqual(
            artifact.planned_cost_units, artifact.max_cost_units)

    def test_every_arxiv_reference_has_a_canonical_link(self):
        for relative in (
                "paper/DRAFT.md",
                "paper/RGA/DRAFT.md",
                "paper/admissible/DRAFT.md"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            ids = re.findall(r"arXiv:(\d{4}\.\d{5})", text)
            self.assertTrue(ids, relative)
            with self.subTest(paper=relative):
                self.assertNotRegex(text, r"(?<!\[)arXiv:\d{4}\.\d{5}")
                for identifier in ids:
                    self.assertIn(
                        f"[arXiv:{identifier}](https://arxiv.org/abs/{identifier})",
                        text,
                    )

    def test_paper_renderer_is_tracked_inside_the_repository(self):
        renderer = ROOT / "paper" / "tools" / "pdf_create.py"
        self.assertTrue(renderer.is_file(), renderer)
        for relative in ("paper/build_pdf.py", "paper/admissible/build_pdf.py"):
            source = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(builder=relative):
                self.assertNotIn(".hermes", source)
                self.assertIn("tools", source)
                self.assertIn("pdf_create.py", source)

    def test_community_health_files_are_present_and_nonempty(self):
        for relative in REQUIRED_COMMUNITY_FILES:
            with self.subTest(path=relative):
                path = ROOT / relative
                self.assertTrue(path.is_file(), relative)
                self.assertGreater(len(path.read_bytes()), 40, relative)

    def test_private_evaluation_material_is_not_in_the_release_tree(self):
        self.assertFalse((ROOT / "eval" / "private").exists())

    def test_citation_names_the_release_and_approved_copyright_holders(self):
        citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
        self.assertRegex(citation, r"(?m)^version:\s*[\"']?0\.8\.0")
        self.assertRegex(citation, r'(?m)^date-released: "2026-08-30"$')
        self.assertIn("Roque", citation)
        self.assertIn("Briceño", citation)
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("Roque Briceño", notice)
        self.assertIn("PRIVÉ, S. DE R.L.", notice)
        self.assertIn("contributors", notice)
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [0.8.0] - 30/08/2026", changelog)
        self.assertNotIn("Unreleased release candidate", changelog)

    def test_package_lock_names_the_cockpit_consistently(self):
        package = json.loads(
            (ROOT / "apps" / "cockpit" / "package.json").read_text(
                encoding="utf-8"))
        lock = json.loads(
            (ROOT / "apps" / "cockpit" / "package-lock.json").read_text(
                encoding="utf-8"))
        self.assertEqual(package["name"], lock["name"])
        self.assertEqual(package["name"], lock["packages"][""]["name"])


if __name__ == "__main__":
    unittest.main()
