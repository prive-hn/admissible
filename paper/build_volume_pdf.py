#!/usr/bin/env python3
"""Typeset the complete Admissible technical-report volume.

The volume is assembled from canonical Markdown block by block with the same
converter used by the standalone reports. Figures are regenerated at build
time from source. The volume contains the three papers, their premises,
invariants and proofs, plain-language companions, and machine-readable contract
documentation. Repository READMEs and internal review logs stay in the source
tree rather than being presented as paper content.

    python3 paper/build_volume_pdf.py
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT_PDF = HERE / "admissible-volume.pdf"


def _load(name: str, path: Path):
    """Load a module by path. Both figure/converter modules are named
    `build_pdf`; importing them by name would collide on sys.modules."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CONV = _load("admissible_build_pdf", HERE / "admissible" / "build_pdf.py")
FCD = _load("fcd_build_pdf", HERE / "build_pdf.py")

md_to_elements = CONV.md_to_elements
para, h, img = CONV.para, CONV.h, CONV.img
PDF_CREATE = CONV.PDF_CREATE
FIGDIR = HERE / "figures"


def pagebreak() -> dict:
    return {"type": "pagebreak"}


def anchored(md_path: Path, figures: dict[str, list[dict]]) -> list[dict]:
    """Convert one document, inserting each anchor's figures immediately
    before the heading whose text starts with that anchor's prefix. An
    anchor that matches nothing raises: a figure silently dropped from a
    volume is exactly the kind of quiet omission this project refuses."""
    elements = md_to_elements(md_path.read_text())
    used: set[str] = set()
    out: list[dict] = []
    for el in elements:
        if el["type"] == "heading":
            for prefix, figs in figures.items():
                if el["text"].startswith(prefix):
                    out.extend(figs)
                    used.add(prefix)
        out.append(el)
    missing = set(figures) - used
    if missing:
        raise ValueError(f"{md_path.name}: no heading matched {sorted(missing)}")
    return out


def part(title: str, blurb: str) -> list[dict]:
    return [pagebreak(), h(title, 1), para(blurb)]


def doc(path: Path) -> list[dict]:
    return md_to_elements(path.read_text())


def build_spec() -> dict:
    # Regenerated every build: the figures are code, not artifacts on disk.
    figs = {"layers": CONV.fig_layers(), "seal": CONV.fig_seal(), "bench": CONV.fig_bench(),
            "realdefects": CONV.fig_realdefects(),
            "automaton": FCD.fig_automaton(), "writers": FCD.fig_writers()}

    elements: list[dict] = [
        h("Admissible", 1),
        para("<b>A fail-closed admissibility kernel for agents that do not repeat.</b>"),
        para("Roque Briceño. Version 0.8.1, 4 September 2026. CC BY 4.0."),
        para("Reference implementation: <b>fcd/core.py</b> (identity), <b>rga/core.py</b> "
             "(scrutiny), <b>rga/calibration.py</b> (standing)."),
        h("What this volume is", 2),
        para("The complete 0.8.1 technical-report set in one document: the composition paper, "
             "the scrutiny and standing paper, the identity paper, the custody-theory paper, "
             "each layer's premises, invariants and proofs, plain-language companions, and the "
             "machine-readable contracts and deterministic bench record."),
        para("The predicate the whole stack computes is admissible(id) := id ∈ S_R ∧ mediated(id) "
             "∧ ¬tainted(id) ∧ ¬impeached(id): sealed under scrutiny, counter-signed by the "
             "calibration authority, no instrument it relied on later caught unreliable, and no "
             "escape standing against it. Each conjunct is the top of one theorem family."),
        para("Every guarantee names the transition that enforces it. The R and C proofs cite "
             "file:line:symbol, bound by a move-detecting test; every R and C guard is a named "
             "method with a delete-the-guard proof. Each report states what is not proved as the "
             "theorems' complement."),
        h("Contents", 2),
        para("<b>Part I — The composition.</b> The predicate, threat model, three layers, "
             "composition theorems, methodology, evaluation, related work and limitations."),
        para("<b>Part II — Scrutiny and standing.</b> Refutation-gated admission and the escape "
             "ledger, including the premise, invariants R1–R13 and C1–C7, and proofs."),
        para("<b>Part III — Identity.</b> Fail-closed class dispatch, its invariants I1–I17, "
             "and proofs."),
        para("<b>Part IV — In plain words.</b> The theorem set without notation and the "
             "vocabulary exposed by the reference interface."),
        para("<b>Part V — Contracts and records.</b> The journal event contract, deterministic "
             "kernel bench, and section map."),
        para("<b>Part VI — Custody theory.</b> The mathematics the three machines are instances "
             "of: custodial semantics and the Asymmetry theorem, the Fréchet algebra of carried "
             "power, the record under rewriting, and stacked custody, read back into the kernel "
             "as capabilities and findings."),
        para("The standalone PDFs are generated from the same Markdown and figure sources as "
             "this volume. Repository READMEs and review logs are intentionally not reprinted as "
             "paper content."),
    ]

    elements += part(
        "Part I — The composition",
        "One machine, three layers, one predicate. This part states what the composition buys "
        "over its parts and proves the two composition theorems; the layers' own invariants are "
        "inherited by citation, never re-derived.")
    elements += anchored(HERE / "admissible" / "DRAFT.md", {
        "3. Layer I": [img(figs["layers"])],
        "5. Layer C": [img(figs["seal"])],
        # Both land at the end of §9 (the anchor inserts before the heading
        # that follows it): the bench, and the real-defect study that is the
        # only thing here bearing on §11's coupling assumption.
        "10. Related work": [img(figs["bench"]), img(figs["realdefects"])],
    })

    elements += part(
        "Part II — Scrutiny and standing",
        "Layer I verifies the die, not the roll. Layer R moves the gate to the claim: an artifact "
        "seals only when pinned, deterministic, replayable refuters were given a fair chance to "
        "kill it and failed, with measured power carried on the seal. Layer C keeps the seal "
        "honest afterwards: a defect found later, demonstrated as a counterfactual trial of the "
        "very instrument the seal trusted, impeaches it — and no successor policy can quietly "
        "forget it.")
    elements += doc(HERE / "RGA" / "DRAFT.md")
    elements += [pagebreak(), h("Appendix A — Premise, attacked before the kernel", 1)]
    elements += doc(HERE / "RGA" / "PREMISE.md")
    elements += [pagebreak(), h("Appendix B — Invariants: R1–R13, C1–C7", 1)]
    elements += doc(HERE / "RGA" / "INVARIANTS.md")
    elements += [pagebreak(), h("Appendix C — Proofs", 1)]
    elements += doc(HERE / "RGA" / "PROOFS.md")

    elements += part(
        "Part III — Identity",
        "Fail-closed class dispatch binds each class to an allowed specialist, records declared and "
        "executed identity independently, and refuses fallback edges. The report, invariants and "
        "proofs below define the identity layer inherited by Parts I and II.")
    elements += doc(HERE / "DRAFT.md")
    elements += [pagebreak(), img(figs["automaton"]), img(figs["writers"])]
    elements += doc(HERE / "INVARIANTS.md")
    elements += [pagebreak()]
    elements += doc(HERE / "PROOFS.md")

    elements += part(
        "Part IV — In plain words",
        "The same guarantees without the notation. Nothing here may weaken a claim the proofs "
        "make, and every sentence restates something a proof or a transition already says.")
    elements += doc(ROOT / "docs" / "PROOFS_PLAIN.md")
    elements += [pagebreak()]
    elements += doc(ROOT / "docs" / "UI_GLOSSARY.md")

    elements += part(
        "Part V — Contracts and records",
        "What the machines emit, and what the machines measured. The event contract is "
        "language-neutral and conformance-tested against live emissions; the bench numbers are "
        "kernel queries over the journals, under simulated generators the record labels as "
        "simulated.")
    elements += doc(ROOT / "metrics" / "SCHEMA.md")
    elements += [pagebreak()]
    elements += doc(ROOT / "eval" / "bench" / "RESULTS.md")
    elements += [pagebreak()]
    elements += doc(HERE / "SECTIONS.md")

    elements += part(
        "Part VI — Custody theory",
        "The mathematics the three machines are instances of. A custody is an append-only record "
        "held by parties who may lie, certified by replay under a declared trust base; identity, "
        "scrutiny and standing are shown to be theorems of that one structure. Custodial "
        "semantics and the Asymmetry theorem, the Fréchet algebra of carried power, the record "
        "under rewriting and stacked custody — read back into the kernel as twenty-eight "
        "capabilities and fourteen executable findings. It states no new mechanism; it says what "
        "the layers already are.")
    elements += doc(HERE / "custody" / "DRAFT.md")

    return {"title": "Admissible — complete technical report volume",
            "author": "Roque Briceño", "page_size": "letter", "page_numbers": True,
            "elements": elements}


def main() -> int:
    spec = build_spec()
    with tempfile.TemporaryDirectory(prefix="admissible-volume-spec-") as td:
        spec_path = Path(td) / "spec.json"
        spec_path.write_text(json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(PDF_CREATE), str(spec_path), "-o", str(OUT_PDF)],
            check=False,
        )
    if result.returncode != 0:
        return result.returncode
    print(json.dumps({"pdf": str(OUT_PDF), "elements": len(spec["elements"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
