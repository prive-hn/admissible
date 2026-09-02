#!/usr/bin/env python3
"""Run the canonical suite without inherited CI control-plane identity."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping

_CONTROL_PREFIXES = ("ADMISSIBLE_", "ACTIONS_", "GITHUB_", "RUNNER_")
_CONTROL_NAMES = frozenset({"CI"})


def sanitized_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Preserve ordinary process inputs while removing host control-plane state."""
    return {
        name: value
        for name, value in environment.items()
        if name not in _CONTROL_NAMES
        and not name.startswith(_CONTROL_PREFIXES)
    }


def main() -> None:
    environment = sanitized_environment(os.environ)
    if sys.argv[1:] == ["--print-sanitized-keys"]:
        print(json.dumps(sorted(environment)))
        return
    if sys.argv[1:]:
        raise SystemExit("usage: run-tests-clean-env.py [--print-sanitized-keys]")
    os.execvpe("make", ["make", "test"], environment)


if __name__ == "__main__":
    main()
