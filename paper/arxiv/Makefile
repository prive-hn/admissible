# Build the self-contained arXiv preprint.
#
# arXiv runs the TeX toolchain itself but does NOT run BibTeX, so the .bbl is
# part of the submission: `make` generates it here and leaves it beside the
# .tex. Everything else builds in a scratch directory and only the products
# that ship are copied back. Leaving .aux/.log/.blg in the working tree would
# put files there that Git ignores but a directory walk still sees, and
# tests/architecture/test_separation_sabotage.py asserts those two answers
# agree -- "the clone is complete" means nothing once they diverge.
#
#   make          figures, admissible.bbl, admissible.pdf
#   make figures  regenerate the five PNGs from the kernel and eval artifacts
#   make check    build, then report pages, unresolved refs and overfull boxes
#   make clean    remove the PDF and the .bbl
#
# Upload to arXiv: admissible.tex, admissible.bbl, references.bib and the five
# PNGs, as one archive. See README.md.

TEX      := pdflatex
BIB      := bibtex
TEXFLAGS := -interaction=nonstopmode -halt-on-error -file-line-error
MAIN     := admissible
FIGURES  := fig1-composition.png fig2-writers.png fig3-seal.png \
            fig4-bench.png fig5-realdefects.png
SCRATCH  := $(shell mktemp -d -t admissible-tex-XXXXXX)

.PHONY: all figures check clean

all: $(MAIN).pdf

figures:
	python3 figures.py

$(FIGURES): figures.py
	python3 figures.py

# BibTeX needs the .aux from a first pass; the two passes after it resolve
# \cite, \label and cleveref. The .bbl is copied back because it ships.
$(MAIN).pdf: $(MAIN).tex references.bib $(FIGURES)
	@trap 'rm -rf "$(SCRATCH)"' EXIT; \
	  cp $(MAIN).tex references.bib $(FIGURES) "$(SCRATCH)/" && \
	  cd "$(SCRATCH)" && \
	  $(TEX) $(TEXFLAGS) $(MAIN).tex >/dev/null && \
	  $(BIB) $(MAIN) >/dev/null && \
	  $(TEX) $(TEXFLAGS) $(MAIN).tex >/dev/null && \
	  $(TEX) $(TEXFLAGS) $(MAIN).tex >/dev/null && \
	  cd - >/dev/null && \
	  cp "$(SCRATCH)/$(MAIN).pdf" $(MAIN).pdf && \
	  cp "$(SCRATCH)/$(MAIN).bbl" $(MAIN).bbl && \
	  echo "wrote $(MAIN).pdf and $(MAIN).bbl"

check: $(MAIN).tex references.bib $(FIGURES)
	@trap 'rm -rf "$(SCRATCH)"' EXIT; \
	  cp $(MAIN).tex references.bib $(FIGURES) "$(SCRATCH)/" && \
	  cd "$(SCRATCH)" && \
	  $(TEX) $(TEXFLAGS) $(MAIN).tex >/dev/null && \
	  $(BIB) $(MAIN) >/dev/null && \
	  $(TEX) $(TEXFLAGS) $(MAIN).tex >/dev/null && \
	  $(TEX) $(TEXFLAGS) $(MAIN).tex >/dev/null && \
	  cd - >/dev/null && \
	  cp "$(SCRATCH)/$(MAIN).pdf" $(MAIN).pdf && \
	  cp "$(SCRATCH)/$(MAIN).bbl" $(MAIN).bbl && \
	  grep -oE 'Output written on .* \([0-9]+ pages' "$(SCRATCH)/$(MAIN).log" && \
	  echo "overfull boxes: $$(grep -c Overfull "$(SCRATCH)/$(MAIN).log")" && \
	  if grep -qE 'LaTeX Warning: (Reference|Citation)' "$(SCRATCH)/$(MAIN).log"; then \
	    echo "unresolved cross-references or citations:"; \
	    grep -E 'LaTeX Warning: (Reference|Citation)' "$(SCRATCH)/$(MAIN).log"; \
	    exit 1; \
	  else echo "no unresolved references or citations"; fi && \
	  if grep -qE 'Warning.*empty|didn.t find a database entry' "$(SCRATCH)/$(MAIN).blg"; then \
	    echo "bibtex warnings:"; grep -E 'Warning|error' "$(SCRATCH)/$(MAIN).blg"; exit 1; \
	  else echo "no bibtex warnings"; fi

clean:
	rm -f $(MAIN).pdf $(MAIN).bbl
