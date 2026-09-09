# The arXiv preprint

`admissible.tex` is one self-contained article: every theorem statement it
relies on, both assumption tables, both fault tables and all the proofs are
inside the single PDF. It sends the reader to this repository for the code, the
journal event contract and the evaluation artifacts, and nowhere else.

That is the difference between this document and the technical-report volume in
`paper/`. The volume is the lab notebook — four connected reports, their
premises, invariants, proofs, plain-language companions, machine-readable
contracts and bench records, about 130 pages, with each paper pointing at the
others and at repository files for its assumptions and proofs. An arXiv
submission has to stand alone, so this is a rewrite rather than an export, and
the two are expected to diverge in coverage: the volume carries everything, the
preprint carries what one refereeable article can defend.

## Build

```bash
cd paper/arxiv && make          # figures, admissible.bbl, admissible.pdf
make figures                    # regenerate the five PNGs only
make check                      # pages, unresolved refs, overfull boxes, bibtex warnings
```

LaTeX runs in a scratch directory and only the two products that ship — the PDF
and the `.bbl` — are copied back. Leaving `.aux`, `.log` and `.blg` beside the
source would put files in the working tree that Git ignores but a directory
walk still sees, and `tests/architecture/test_separation_sabotage.py` asserts
those two answers agree — "the clone is complete" means nothing once they
diverge. That check caught exactly this when the preprint was first added.

The five figures are **derived, not copied**. `figures.py` drives the same
generators the technical reports use, so a figure cannot silently disagree with
the kernel or the evaluation artifacts it draws — `fig4-bench` reads the bench
record and `fig5-realdefects` the real-defect study. It also strips the
`Figure N.` prefix those generators bake into their titles, because the reports
number their own figures in the image and LaTeX numbers them again in the
caption; left alone, one figure would print two different numbers.

Requires `pdflatex` with `amsmath`, `booktabs`, `longtable`, `microtype`,
`hyperref` and `cleveref` — on Debian and Ubuntu, `texlive-latex-base`,
`texlive-latex-recommended`, `texlive-latex-extra` and
`texlive-fonts-recommended`. Two passes are needed for `cleveref` to resolve.

`make check` must report zero unresolved references and zero unresolved
citations. An unresolved `\cite` is a returned submission, which is why the
bibliography is a `thebibliography` environment inside the `.tex` rather than a
separate `.bib` compiled with BibTeX: arXiv runs the toolchain itself, and a
missing `.bbl` fails there rather than here.

## Submitting

arXiv prefers TeX source and will typically reject a PDF produced from TeX
source, so upload the source as one archive:

```
admissible.tex  admissible.bbl  references.bib
fig1-composition.png  fig2-writers.png  fig3-seal.png
fig4-bench.png  fig5-realdefects.png
```

The `.bbl` is not optional. arXiv runs the TeX toolchain but does **not** run
BibTeX, so a submission carrying only `references.bib` fails there with
unresolved citations rather than failing here. `references.bib` is included
anyway, because it is the source of the `.bbl` and costs nothing.

There is no `\input`, no local style file and no hidden directory, so nothing
else is needed. The figures are PNG, which is what PDFLaTeX wants; do not mix
in `.eps`.

Before uploading, check the things arXiv checks:

- **Endorsement.** Since 21 January 2026 a first-time submitter needs *both* an
  academic or research email address *and* previous authorship on a paper in the
  target endorsement domain, or else a personal endorsement from an established
  author in that domain. An institutional address alone no longer qualifies, and
  arXiv staff cannot waive this. Plan on seeking a personal endorsement.
- **Category.** `cs.SE` primary, with `cs.CR` as a cross-list. This is a
  software-integrity mechanism with a threat model, not a mathematics paper; the
  custody-theory material in `paper/custody/` is deliberately *not* part of this
  submission, because its own novelty ledger records the literature verdict as
  derivative and its theorems do not yet carry tests.
- **Generative-tool disclosure.** arXiv requires significant use of text-to-text
  tools to be reported. The paper reports it in the closing section, and the
  author remains responsible for every citation and every theorem statement.
- **Scholarly form.** Single-spaced, 11pt, 1-inch margins, no line numbers, no
  watermarks, no referee remarks, complete references, machine-readable text.
  The repository link resolves publicly, which arXiv requires of links to code.

## Keeping it honest

The counts and the results in the paper are measured, not remembered. When the
kernel changes, re-measure before editing the prose: the per-guard deletion
proof count comes from the two mutation registries, and the evaluation figures
come from the artifacts under `eval/`. The claim that a kernel guard enforces a
theorem is bound to a live source line by `tests/test_rga_citations.py` for the
reports in `paper/`; this document paraphrases those bindings in prose instead,
so it is the one place in the repository where a stale enforcement claim would
not be caught by a test. Re-read Sections 3 and 5 against the kernel after any
change to a guard.
