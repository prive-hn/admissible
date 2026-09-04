# Admissible research papers

This directory contains four connected technical reports:

1. [`DRAFT.md`](DRAFT.md) — *Fail-closed class dispatch* (identity layer).
2. [`RGA/DRAFT.md`](RGA/DRAFT.md) — *Refutation-gated admission* (scrutiny and
   standing layers).
3. [`admissible/DRAFT.md`](admissible/DRAFT.md) — the composed Admissible
   kernel and its non-interference results.
4. [`custody/DRAFT.md`](custody/DRAFT.md) — *Custody theory*: the mathematics
   the three machines are instances of (custodial semantics, the Asymmetry
   theorem, the Fréchet algebra of carried power, the rewrite groupoid of
   journals, stacked custody), read back into the kernel as twenty-eight
   capabilities and fourteen executable findings about the kernel as it is. Its executable companion is [`custody/custody.py`](custody/custody.py)
   with `tests/test_custody.py`, and the theorems' functional content is asserted
   against the live kernel by a property harness (`tests/test_custody_theorems.py`)
   with a conjecture-attack lane (`tests/test_custody_conjectures.py`); the catalogue of capabilities with their
   verification status is [`custody/IMPROVEMENTS.md`](custody/IMPROVEMENTS.md), and
   the record of its nine review rounds (three adversarial referee rounds, the pull request's automated review, two seven-referee re-reviews of the pull request head, and three internal six-reviewer adversarial re-reviews) is [`custody/REVIEWS.md`](custody/REVIEWS.md).
   Adopted for the 0.8.0 release: its standalone PDF is `custody/custody.pdf`, and
   it is Part VI of the combined volume.

They are versioned technical reports, not peer-reviewed publications. The
implementation and tests are the source of truth when prose and executable
behavior disagree. Each paper states assumptions, guarantees, and explicit
non-claims; none claims that an admitted artifact is true or high quality.

## Build and verification

```bash
python3 paper/build_pdf.py
python3 paper/admissible/build_pdf.py
python3 paper/build_volume_pdf.py
python3 -m unittest tests.test_paper_build -v
```

`paper/admissible-volume.pdf` is the current combined volume. Standalone PDFs
are retained for their named papers. Generated PDFs must be rebuilt after any
manuscript change and verified for parseability, page count, required title,
author, version, references, and license text before release.

## Citation

Use the repository [`CITATION.cff`](../CITATION.cff) for the software and
composed report. [`REFERENCES.bib`](REFERENCES.bib) contains the machine-readable
arXiv entries used across the manuscripts; non-arXiv works remain identified in
each report's bibliography. Cite a layer paper by its title and the author name
printed in that manuscript. No DOI, journal acceptance, or peer-review status
is claimed for version 0.8.0.

## License

The authored manuscripts and generated research PDFs are licensed under
[CC BY 4.0](../LICENSES/CC-BY-4.0.txt). Paper build scripts and tests are
Apache-2.0 except for the vendored MIT-licensed renderer identified in
[`LICENSE.md`](../LICENSE.md) and [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
Third-party publications in the bibliographies are cited, not incorporated or
relicensed.
