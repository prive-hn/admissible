"""The papers' typesetter may not silently lose or mangle what it converts.

The PDFs are built from the canonical markdown so the two cannot drift, which
only holds if conversion is total: every heading and every table cell reaches
the page. Two defects found by review are pinned here — a glyph the renderer's
font lacks (rendered as a black box, verified empirically against the
renderer) and a table wider than the frame (reportlab does not wrap raw cell
strings, so the row is clipped at both edges and nothing says so).

These test the converter's contract, not the third-party renderer: they need
no PDF toolchain, only the converter module.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 dev extra
    import tomli as tomllib  # type: ignore[import-not-found]

ROOT = Path(__file__).resolve().parents[1]
PDF_CREATE = ROOT / "paper" / "tools" / "pdf_create.py"

warnings.filterwarnings(
    "ignore",
    message=r"builtin type (SwigPyPacked|SwigPyObject|swigvarlink) has no __module__ attribute",
    category=DeprecationWarning,
)
try:
    import pymupdf as fitz  # renders pages, so a notdef box is visible
    _HAVE_FITZ = True
except ImportError:  # pragma: no cover
    _HAVE_FITZ = False

# Every document the volume typesets, so a construct any one of them uses is
# covered here — READMEs bring fenced code that the papers do not have.
PAPERS = [
    ROOT / "paper" / "admissible" / "DRAFT.md",
    ROOT / "paper" / "DRAFT.md",
    ROOT / "paper" / "INVARIANTS.md",
    ROOT / "paper" / "PROOFS.md",
    ROOT / "paper" / "RGA" / "DRAFT.md",
    ROOT / "paper" / "RGA" / "INVARIANTS.md",
    ROOT / "paper" / "RGA" / "PROOFS.md",
    ROOT / "paper" / "RGA" / "PREMISE.md",
    ROOT / "paper" / "SECTIONS.md",
    ROOT / "docs" / "PROOFS_PLAIN.md",
    ROOT / "docs" / "UI_GLOSSARY.md",
    ROOT / "metrics" / "SCHEMA.md",
    ROOT / "eval" / "bench" / "RESULTS.md",
    ROOT / "README.md",
    ROOT / "eval" / "README.md",
    ROOT / "data" / "README.md",
]
BUILDERS = (
    "paper/build_pdf.py",
    "paper/admissible/build_pdf.py",
    "paper/build_volume_pdf.py",
)
PDF_ARTIFACTS = (
    "paper/fail-closed-class-dispatch.pdf",
    "paper/RGA/refutation-gated-admission.pdf",
    "paper/admissible/admissible.pdf",
    "paper/admissible-volume.pdf",
)
FIGURE_ARTIFACTS = (
    "paper/figures/fig1_automaton.png",
    "paper/figures/fig2_writers.png",
    "paper/figures/fig3_theorems.png",
    "paper/figures/fig4_rates.png",
    "paper/figures/fig5_objectives.png",
    "paper/figures/fig6_layers.png",
    "paper/figures/fig7_seal.png",
    "paper/figures/fig8_bench.png",
    "paper/figures/fig9_realdefects.png",
)
ARTIFACTS = PDF_ARTIFACTS + FIGURE_ARTIFACTS


def _ignore_copy(_directory: str, names: list[str]) -> set[str]:
    ignored = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"}
    return {name for name in names if name in ignored}


def _cells(line: str) -> list[str]:
    """Split a table row into cells — deliberately a DIFFERENT algorithm from
    the converter's character scan: split on every pipe, then re-join the
    fragments until the backticks balance and no fragment ends in a backslash.
    Oracle and subject agree only when both are right; a shared implementation
    would have hidden the bug this exists to catch (a `|` inside a code span
    is content, `\\|` is a literal)."""
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    out: list[str] = []
    held: list[str] = []
    for part in body.split("|"):
        held.append(part)
        merged = "|".join(held)
        if merged.count("`") % 2 == 0 and not merged.endswith("\\"):
            out.append(merged.strip())
            held = []
    if held:
        out.append("|".join(held).strip())
    return [c.replace("\\|", "|") for c in out]


def _is_separator(line: str) -> bool:
    return all(re.fullmatch(r":?-{3,}:?", c.strip()) for c in line.strip().strip("|").split("|"))


def _outside_fences(text: str) -> list[str]:
    """Markdown lines with fenced blocks removed. A '#' comment inside a code
    block is not a heading, and a '|' inside one is not a table row."""
    out, inside = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            inside = not inside
            continue
        if not inside:
            out.append(line)
    return out

try:
    import matplotlib  # noqa: F401
    _HAVE_MPL = True
except ImportError:  # pragma: no cover
    _HAVE_MPL = False


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(_HAVE_MPL, "matplotlib not installed (converter import)")
class ConversionIsTotal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conv = _load("admissible_build_pdf", ROOT / "paper" / "admissible" / "build_pdf.py")
        cls.elements = {p: cls.conv.md_to_elements(p.read_text()) for p in PAPERS}

    def _rendered_text(self, elements) -> str:
        out = []
        for el in elements:
            if "text" in el:
                out.append(el["text"])
            if el["type"] == "table":
                for row in el["rows"]:
                    out.extend(row)
        return "\n".join(out)

    def test_every_heading_reaches_the_page(self):
        for path, elements in self.elements.items():
            blob = self._rendered_text(elements)
            for line in _outside_fences(path.read_text()):
                m = re.match(r"^(#{1,3})\s+(.*)$", line)
                if m:
                    self.assertIn(self.conv._inline(m.group(2)), blob,
                                  f"{path.name}: heading dropped")

    def test_every_table_body_cell_reaches_the_page(self):
        """Wide tables fold into definition paragraphs; folded or not, no
        body cell may vanish. Header cells are column labels, not content:
        folding keeps them as inline labels only where they disambiguate
        (three columns or more), so their disappearance is by design and
        this test does not demand them."""
        for path, elements in self.elements.items():
            blob = self._rendered_text(elements)
            for block in re.split(r"\n\s*\n", "\n".join(_outside_fences(path.read_text()))):
                lines = [l for l in block.strip().splitlines() if l.lstrip().startswith("|")]
                if len(lines) < 2:
                    continue
                rows = [_cells(l) for l in lines if not _is_separator(l)]
                for cell in (c for row in rows[1:] for c in row if c):
                    # A cell reaches the page one of two ways: inside a real
                    # table, where the renderer parses nothing so the text is
                    # unescaped and stripped of markup; or folded into a
                    # definition paragraph, which the renderer does parse and
                    # which therefore keeps its escaping.
                    marked = self.conv._inline(cell)
                    self.assertTrue(marked in blob or self.conv._plain(marked) in blob,
                                    f"{path.name}: table body cell dropped: {cell[:40]!r}")

    def test_fenced_code_survives_verbatim(self):
        """A runnable snippet reflowed into prose is no longer runnable, so
        fences keep their line structure and indentation."""
        elements = self.conv.md_to_elements(
            "Before.\n\n```bash\nmake test\n\n  indented\n```\n\nAfter.\n")
        code = [e for e in elements if "Courier" in e.get("text", "")]
        self.assertEqual(len(code), 1)
        self.assertIn("make&nbsp;test", code[0]["text"])
        self.assertIn("&nbsp;&nbsp;indented", code[0]["text"])
        self.assertEqual(code[0]["text"].count("<br/>"), 2)   # the blank line is kept
        self.assertEqual([e["text"] for e in elements if e["type"] == "paragraph"][0], "Before.")

    def test_no_glyph_the_font_lacks_survives_conversion(self):
        for path, elements in self.elements.items():
            blob = self._rendered_text(elements)
            for bad in self.conv.UNSUPPORTED:
                self.assertNotIn(bad, blob, f"{path.name}: {bad!r} renders as a black box")

    def test_unified_figure_and_volume_sources_use_current_kernel_claims(self):
        figure_text = inspect.getsource(self.conv.fig_layers)
        seal_text = inspect.getsource(self.conv.fig_seal)
        sections = (ROOT / "paper" / "SECTIONS.md").read_text()
        draft = (ROOT / "paper" / "admissible" / "DRAFT.md").read_text()
        readme = (ROOT / "README.md").read_text()
        metrics = (ROOT / "metrics" / "SCHEMA.md").read_text()

        self.assertIn("mediated", figure_text)
        self.assertIn("E1–E9", figure_text)
        self.assertNotIn("E1–E8", figure_text)
        self.assertIn("authenticated", seal_text)
        self.assertNotIn("forgetting is impossible", seal_text)
        self.assertIn("sealed ∧ mediated ∧ ¬tainted ∧ ¬impeached", sections)
        self.assertIn("597", sections)
        # The paper counts the research kernel, and that is the number this
        # test owns: it belongs beside the figures and the sections that cite
        # it. The README's other two figures -- the developer-product count and
        # the repository total -- are *derived* from collection and compared in
        # tests/test_admissible_bounded_repair.py, because a test that searches
        # the README for a number somebody typed only proves somebody typed it.
        self.assertIn("597", readme)
        self.assertIn(
            "| Research kernel — the number the paper cites | 597 |", readme)
        self.assertNotIn("597 tests", readme)
        self.assertIn("fault codes are E1–E9", metrics)
        self.assertIn("B0–B14", draft)

    @unittest.skipUnless(PDF_CREATE.exists() and _HAVE_FITZ, "renderer or pymupdf missing")
    def test_every_glyph_is_probed_against_the_real_renderer(self):
        """The list of unsupported characters is measured, not asserted. Two
        subscripts shipped as black boxes because the notdef box EXTRACTS as
        the letter 'I' — no text scan of the output can find them, so this
        renders a probe page and compares each character to itself."""
        chars = sorted({c for path, els in self.elements.items()
                        for t in self._rendered_text(els) for c in t if ord(c) > 127})
        self.assertTrue(chars, "no non-ASCII characters to probe")
        probe = {"title": "glyph probe", "author": "x", "page_size": "letter",
                 "page_numbers": False,
                 "elements": [{"type": "paragraph", "text": f"{i:03d} {c} {c}"}
                              for i, c in enumerate(chars)]}
        with tempfile.TemporaryDirectory() as td:
            spec, out = Path(td) / "s.json", Path(td) / "o.pdf"
            spec.write_text(json.dumps(probe, ensure_ascii=False))
            subprocess.run([sys.executable, str(PDF_CREATE), str(spec), "-o", str(out)],
                           capture_output=True, check=True)
            text = "\n".join(page.get_text("text") for page in fitz.open(out))
        missing = []
        for line in (l.strip() for l in text.splitlines()):
            if len(line) > 4 and line[:3].isdigit():
                c = chars[int(line[:3])]
                if line[4:].strip() != f"{c} {c}":
                    missing.append((c, hex(ord(c))))
        self.assertFalse(missing, f"glyphs the renderer cannot draw: {missing} "
                                  "— add them to build_pdf.UNSUPPORTED")

    def test_no_emitted_table_can_overflow_the_frame(self):
        """Measured independently of the converter's own decision: the width
        is recomputed here from the renderer's font metrics against the real
        frame, so this fails if the emitting rule is ever wrong — the earlier
        version recomputed the converter's own expression against the
        converter's own constant and could not fail for any input."""
        from reportlab.pdfbase.pdfmetrics import stringWidth
        for path, elements in self.elements.items():
            for el in elements:
                if el["type"] != "table":
                    continue
                rows = el["rows"]
                cols = max(len(r) for r in rows)
                width = sum(
                    max(stringWidth(r[i] if i < len(r) else "", "Helvetica", 10) for r in rows) + 12.0
                    for i in range(cols))
                self.assertLessEqual(width, 468.0,
                                     f"{path.name}: table renders past the frame edge")

    def test_no_table_cell_carries_markup_the_renderer_will_not_parse(self):
        """Cells reach reportlab as raw strings; a tag or entity in one is
        printed literally. <b>0.8182</b> shipped in the bench tables."""
        for path, elements in self.elements.items():
            for el in elements:
                if el["type"] != "table":
                    continue
                for cell in (c for row in el["rows"] for c in row):
                    self.assertNotRegex(cell, r"</?[a-z]+[^>]*>", f"{path.name}: markup in a cell")
                    self.assertNotIn("&gt;", cell)
                    self.assertNotIn("&lt;", cell)


class PaperArtifactsMatchSources(unittest.TestCase):
    def test_no_orphaned_pages(self):
        try:
            import pymupdf
        except ImportError as exc:  # pragma: no cover - pinned paper toolchain owns this
            self.fail(f"pymupdf is required to inspect committed paper layout: {exc}")
        for rel in PDF_ARTIFACTS:
            document = pymupdf.open(ROOT / rel)
            for number, page in enumerate(document, start=1):
                text = page.get_text("text")
                text = "\n".join(
                    line for line in text.splitlines()
                    if line.strip() != f"Page {number}"
                ).strip()
                self.assertGreaterEqual(
                    len(text),
                    200,
                    f"{rel} page {number} is an orphaned or near-empty page ({len(text)} text characters)",
                )

    def test_renderer_is_repository_local(self):
        self.assertTrue(PDF_CREATE.is_file(), f"missing repository renderer: {PDF_CREATE}")
        for rel in BUILDERS:
            source = (ROOT / rel).read_text(encoding="utf-8")
            self.assertNotIn(".hermes/skills", source, f"{rel} depends on one user's home directory")

        paper_requirements = {
            line.strip()
            for line in (ROOT / "paper" / "requirements.txt").read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip() and not line.startswith("#")
        }
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        dev_requirements = set(project["project"]["optional-dependencies"]["dev"])
        self.assertLessEqual(paper_requirements, dev_requirements)

    def test_committed_artifacts_match_a_clean_rebuild(self):
        self.assertTrue(PDF_CREATE.is_file(), f"missing repository renderer: {PDF_CREATE}")
        with tempfile.TemporaryDirectory(prefix="admissible-paper-rebuild-") as td:
            checkout = Path(td) / "repo"
            shutil.copytree(ROOT, checkout, ignore=_ignore_copy)
            for rel in BUILDERS:
                completed = subprocess.run(
                    [sys.executable, rel],
                    cwd=checkout,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    f"{rel} failed\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
                )
            for rel in ARTIFACTS:
                committed = (ROOT / rel).read_bytes()
                rebuilt = (checkout / rel).read_bytes()
                self.assertEqual(
                    rebuilt,
                    committed,
                    f"{rel} is stale; run `make paper` and commit the rebuilt artifact",
                )


@unittest.skipUnless(_HAVE_MPL, "matplotlib not installed (converter import)")
class VolumeAnchorsAreChecked(unittest.TestCase):
    def test_a_figure_whose_anchor_matches_nothing_raises(self):
        """A figure quietly dropped from a hundred-page volume is invisible;
        the assembler refuses instead."""
        volume = _load("volume_build_pdf", ROOT / "paper" / "build_volume_pdf.py")
        with tempfile.TemporaryDirectory() as td:
            doc = Path(td) / "doc.md"
            doc.write_text("# Title\n\n## 1. Real section\n\nBody.\n")
            volume.anchored(doc, {"1. Real section": [volume.para("here")]})  # matches
            with self.assertRaises(ValueError):
                volume.anchored(doc, {"9. Missing section": [volume.para("x")]})


if __name__ == "__main__":
    unittest.main()
