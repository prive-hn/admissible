"""Focused tests for the credentialed ``admissible-trust`` distribution.

``admissible_trust`` is its own project under ``packages/trust`` and is not
installed into this checkout's interpreter, so importing it from the source
tree needs that project's ``src`` directory on ``sys.path`` -- and Core's too,
because Trust is written against ``admissible_core`` and nothing else.

Both entries are *appended*, for the same reason ``tests/core`` and
``tests/ready`` append theirs: a real installation alongside this checkout is
what the rest of the interpreter would import, and these tests must agree with
it rather than quietly shadow it.

``packages/ready/src`` is deliberately **not** appended.  A Trust test that
could import ``admissible_ready`` is a Trust test that cannot tell an absent
module from a present one, and the isolation suite below exists to measure
exactly that.

Nothing here imports ``admissible_trust``.  The isolation suite measures what
importing it drags in -- whether a runner, an MCP server, an HTTP server or a
candidate executor arrives as a side effect -- and a package initialiser that
had already imported it would make every one of those measurements a
measurement of this file.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_PROJECT = REPO_ROOT / "packages" / "core"
CORE_SRC = CORE_PROJECT / "src"
TRUST_PROJECT = REPO_ROOT / "packages" / "trust"
TRUST_SRC = TRUST_PROJECT / "src"
READY_PROJECT = REPO_ROOT / "packages" / "ready"

for entry in (CORE_SRC, TRUST_SRC):
    if str(entry) not in sys.path:
        sys.path.append(str(entry))
