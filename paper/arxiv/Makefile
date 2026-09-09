# Build the self-contained arXiv preprint.
#
# arXiv prefers TeX source over PDF, so `admissible.tex` is the submission and
# this Makefile only exists to check locally that it compiles clean. Bibliography
# entries are in a thebibliography environment inside the .tex rather than a
# separate .bib, because arXiv processes the source itself and an unresolved
# \cite is a returned submission.
#
#   make          build admissible.pdf
#   make check    build and report page count and unresolved references
#   make clean    remove build products (never the .tex)

TEX      := pdflatex
TEXFLAGS := -interaction=nonstopmode -halt-on-error -file-line-error
MAIN     := admissible

.PHONY: all check clean

all: $(MAIN).pdf

# Twice: \label/\ref and cleveref need the second pass to resolve.
$(MAIN).pdf: $(MAIN).tex
	$(TEX) $(TEXFLAGS) $(MAIN).tex
	$(TEX) $(TEXFLAGS) $(MAIN).tex

check: $(MAIN).pdf
	@echo "--- pages ---"
	@pdfinfo $(MAIN).pdf 2>/dev/null | grep -i '^Pages' || \
	  $(TEX) --version >/dev/null && grep -c '^' /dev/null
	@echo "--- unresolved references and citations ---"
	@! grep -E 'LaTeX Warning: (Reference|Citation)' $(MAIN).log || \
	  (echo "unresolved cross-references above"; exit 1)
	@echo "--- overfull boxes ---"
	@grep -c 'Overfull' $(MAIN).log || true

clean:
	rm -f $(MAIN).aux $(MAIN).log $(MAIN).out $(MAIN).toc $(MAIN).pdf
