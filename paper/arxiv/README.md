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
cd paper/arxiv && make          # admissible.pdf
make check                      # page count, unresolved refs, overfull boxes
```

LaTeX runs in a scratch directory and only the PDF is copied back. Leaving
`.aux`, `.log` and `.out` beside the source would put files in the working tree
that Git ignores but a directory walk still sees, and
`tests/architecture/test_separation_sabotage.py` asserts those two answers
agree — "the clone is complete" means nothing once they diverge. That check
caught exactly this when the preprint was first added.

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
source, so upload `admissible.tex` alone. It has no `\input`, no figures and no
local style files, so it needs no archive.

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
