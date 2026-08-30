"""Focused tests for the candidate-executing ``admissible-ready`` distribution.

``admissible_ready`` is its own project under ``packages/ready`` and is not
installed into this checkout's interpreter, so importing it from the source
tree needs that project's ``src`` directory on ``sys.path`` -- and Core's too,
because Ready is written against ``admissible_core`` and nothing else.

Both entries are *appended*, for the same reason ``tests/core`` appends its
one: a real installation alongside this checkout is what the rest of the
interpreter would import, and these tests must agree with it rather than
quietly shadow it.

Nothing here imports ``admissible_ready``.  The isolation suite measures what
importing it drags in -- whether a Trust module, a credential loader or a
process-starting one arrives as a side effect -- and a package initialiser
that had already imported it would make every one of those measurements a
measurement of this file.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_PROJECT = REPO_ROOT / "packages" / "core"
CORE_SRC = CORE_PROJECT / "src"
READY_PROJECT = REPO_ROOT / "packages" / "ready"
READY_SRC = READY_PROJECT / "src"

for entry in (CORE_SRC, READY_SRC):
    if str(entry) not in sys.path:
        sys.path.append(str(entry))
