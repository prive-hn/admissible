PYTHON ?= $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)
COCKPIT := apps/cockpit

# The pinned isolated-build backend that
# tests/compatibility/test_umbrella_build_backend.py proves an offline build
# against. That suite only ever takes the backend from a local wheelhouse
# (never an index), so `make test` stages the pinned wheel once and points
# ADMISSIBLE_WHEELHOUSE at it -- otherwise the suite fails closed with "no local
# wheel ... the isolated build could not be proved offline", as it does on a
# runner that sets no wheelhouse. An operator who already exported
# ADMISSIBLE_WHEELHOUSE (an offline mirror, say) keeps it: `?=` defers to the
# environment and the download is skipped whenever the wheel is already present.
ADMISSIBLE_WHEELHOUSE ?= $(CURDIR)/.wheelhouse
BUILD_BACKEND_PIN := setuptools==83.0.0
BUILD_BACKEND_WHEEL := setuptools-83.0.0-py3-none-any.whl
export ADMISSIBLE_WHEELHOUSE

.PHONY: test test-python test-cockpit wheelhouse audit build cockpit paper paper-check

test: test-python test-cockpit

# Stage the pinned build backend into the wheelhouse. Needs a network once
# (exactly the fix the suite's own message prescribes); thereafter the wheel is
# cached in the tree. A no-op when the wheel is already present, so an offline
# operator wheelhouse is never re-fetched.
wheelhouse:
	@test -f "$(ADMISSIBLE_WHEELHOUSE)/$(BUILD_BACKEND_WHEEL)" || \
	  $(PYTHON) -m pip download $(BUILD_BACKEND_PIN) \
	    --only-binary=:all: --no-deps -d "$(ADMISSIBLE_WHEELHOUSE)"

test-python: wheelhouse
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
