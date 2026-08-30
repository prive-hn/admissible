PYTHON ?= $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)
COCKPIT := apps/cockpit

.PHONY: test test-python test-cockpit audit build cockpit paper paper-check

test: test-python test-cockpit

test-python:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -q
	$(PYTHON) -m unittest discover -s atlas/tests -p 'test_*.py' -q

test-cockpit:
	npm --prefix $(COCKPIT) test -- --run

# Committed PDFs are deterministic artifacts. Install the pinned toolchain with
# `$(PYTHON) -m pip install -r paper/requirements.txt` before rebuilding.
paper:
	$(PYTHON) paper/build_pdf.py
	$(PYTHON) paper/admissible/build_pdf.py
	$(PYTHON) paper/build_volume_pdf.py

paper-check:
	$(PYTHON) -m unittest tests.test_paper_build -v

# Full audit: dev-server packages are part of the threat surface.
audit:
	npm --prefix $(COCKPIT) audit

build:
	npm --prefix $(COCKPIT) run build
	rm -rf server/static
	mkdir -p server/static
	cp -R $(COCKPIT)/dist/. server/static/

# HOST/ALLOW_HOST match scripts/cockpit.sh. Binding every interface refuses a
# Host that is a name, so ALLOW_HOST declares the one name an operator reaches
# it by -- see README, "Reaching it from another machine".
HOST ?= 127.0.0.1
PORT ?= 8791
ALLOW_HOST ?=
cockpit: build
	$(PYTHON) -m server.app --port $(PORT) --host $(HOST) \
	  $(foreach name,$(ALLOW_HOST),--allow-host $(name))
