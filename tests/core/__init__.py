"""Focused tests for the authority-neutral ``admissible-core`` distribution.

``admissible_core`` is its own project under ``packages/core`` and is not
installed into this checkout's interpreter, so importing it from the source
tree needs that project's ``src`` directory on ``sys.path``.  Doing it once,
here, keeps every module below to a plain ``import admissible_core``; the
alternative is the same three lines in four files, one of which will
eventually be forgotten and silently test whatever ``admissible_core`` the
ambient environment happens to provide.

The entry is *appended*.  A real ``admissible-core`` installed alongside this
checkout is what the rest of the interpreter would import, and these tests
must agree with that installation rather than quietly shadow it.

Nothing here imports ``admissible_core`` itself: the isolation tests below
measure what importing it drags in, and a package initialiser that had
already imported it would make every one of those measurements a measurement
of this file.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_PROJECT = REPO_ROOT / "packages" / "core"
CORE_SRC = CORE_PROJECT / "src"

if str(CORE_SRC) not in sys.path:
    sys.path.append(str(CORE_SRC))
