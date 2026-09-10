#!/usr/bin/env python3
"""Generate the preprint's figures beside admissible.tex.

Derived, never copied. The generators live with the technical reports and read
live kernel and evaluation state -- `fig_bench` imports the bench record and
`fig_realdefects` the real-defect study -- so driving them here keeps the
preprint's figures and the repository's from telling different stories. A
stale figure in a paper is exactly the quiet drift the citation binder exists
to catch for proofs, and figures have no binder.

    python3 paper/arxiv/figures.py

Writes four PNGs into this directory. arXiv processes the source itself, so the
figures ship in the upload archive beside the .tex; see README.md.
"""
from __future__ import annotations

import importlib.util
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAPER = HERE.parent
ROOT = PAPER.parent

# The figure the composition paper numbers 6, 7, 8 and 9. Renamed here to the
# preprint's own numbering, which differs because the preprint drops the layer
# papers' figures.
WANTED = {
    "fig_layers": "fig1-composition.png",
    "fig_writers": "fig2-writers.png",
    "fig_seal": "fig3-seal.png",
    "fig_bench": "fig4-bench.png",
    "fig_realdefects": "fig5-realdefects.png",
}


def _load(name: str, path: Path):
    """Load a build module by path. Both are named `build_pdf`, so importing
    by name would collide in sys.modules."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_FIGURE_PREFIX = re.compile(r"^Figure\s+\d+[.:]\s*")


def _strip_embedded_numbers():
    """Drop the ``Figure N.`` prefix the generators bake into their titles.

    The technical reports number their own figures in the image, because their
    renderer has no float environment to do it. LaTeX does, so leaving the
    baked-in number in place would print two different numbers for one figure
    -- the report's and the preprint's. The descriptive half of each title is
    kept: it says something the caption does not repeat."""
    from matplotlib.axes import Axes

    original = Axes.set_title

    def set_title(self, label, *args, **kwargs):
        return original(self, _FIGURE_PREFIX.sub("", label or ""), *args, **kwargs)

    Axes.set_title = set_title


def main() -> int:
    sys.path.insert(0, str(ROOT))
    composed = _load("arxiv_admissible_build", PAPER / "admissible" / "build_pdf.py")
    identity = _load("arxiv_fcd_build", PAPER / "build_pdf.py")
    _strip_embedded_numbers()

    sources = {}
    for attribute in ("fig_layers", "fig_seal", "fig_bench", "fig_realdefects"):
        sources[attribute] = getattr(composed, attribute)
    sources["fig_writers"] = identity.fig_writers

    written = []
    for attribute, filename in WANTED.items():
        produced = sources[attribute]()
        destination = HERE / filename
        shutil.copyfile(produced, destination)
        written.append(filename)
    print("wrote " + ", ".join(sorted(written)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
