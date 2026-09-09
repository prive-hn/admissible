# Build the self-contained arXiv preprint.
#
# arXiv prefers TeX source over PDF, so `admissible.tex` is the submission and
# this Makefile only exists to check locally that it compiles clean. Bibliography
# entries live in a thebibliography environment inside the .tex rather than in a
# separate .bib, because arXiv processes the source itself and an unresolved
# \cite is a returned submission.
#
# LaTeX is built OUT OF TREE, into a scratch directory, and only the PDF is
# copied back. Leaving .aux/.log/.out beside the source would put files in the
# working tree that Git ignores but a directory walk still sees, and
# tests/architecture/test_separation_sabotage.py asserts those two answers
# agree -- "the clone is complete" means nothing if they diverge.
#
#   make          build admissible.pdf
#   make check    build, then report pages, unresolved refs and overfull boxes
#   make clean    remove the PDF

TEX      := pdflatex
TEXFLAGS := -interaction=nonstopmode -halt-on-error -file-line-error
MAIN     := admissible
SCRATCH  := $(shell mktemp -d -t admissible-tex-XXXXXX)

.PHONY: all check clean

all: $(MAIN).pdf

# Twice: \label/\ref and cleveref need the second pass to resolve.
$(MAIN).pdf: $(MAIN).tex
	@trap 'rm -rf "$(SCRATCH)"' EXIT; \
	  $(TEX) $(TEXFLAGS) -output-directory="$(SCRATCH)" $(MAIN).tex >/dev/null && \
	  $(TEX) $(TEXFLAGS) -output-directory="$(SCRATCH)" $(MAIN).tex >/dev/null && \
	  cp "$(SCRATCH)/$(MAIN).pdf" $@ && \
	  echo "wrote $@"

check: $(MAIN).tex
	@trap 'rm -rf "$(SCRATCH)"' EXIT; \
	  $(TEX) $(TEXFLAGS) -output-directory="$(SCRATCH)" $(MAIN).tex >/dev/null && \
	  $(TEX) $(TEXFLAGS) -output-directory="$(SCRATCH)" $(MAIN).tex >/dev/null && \
	  cp "$(SCRATCH)/$(MAIN).pdf" $(MAIN).pdf && \
	  grep -oE 'Output written on .* \([0-9]+ pages' "$(SCRATCH)/$(MAIN).log" && \
	  echo "overfull boxes: $$(grep -c Overfull "$(SCRATCH)/$(MAIN).log")" && \
	  if grep -qE 'LaTeX Warning: (Reference|Citation)' "$(SCRATCH)/$(MAIN).log"; then \
	    echo "unresolved cross-references or citations:"; \
	    grep -E 'LaTeX Warning: (Reference|Citation)' "$(SCRATCH)/$(MAIN).log"; \
	    exit 1; \
	  else echo "no unresolved references or citations"; fi

clean:
	rm -f $(MAIN).pdf
