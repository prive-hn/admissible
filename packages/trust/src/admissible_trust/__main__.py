"""``python -m admissible_trust`` runs the same command the console script does."""
from __future__ import annotations

from .cli import main

if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
