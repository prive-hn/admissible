"""Compatibility facade: ``admissible.ready`` is ``admissible_ready.ready``.

``from admissible.ready import ReadyError, from_evaluation, from_problem`` is
printed by ``admissible/templates/reusable-workflow.yml`` -- a file this tool
copies verbatim into a consumer's repository -- and runs in the job the shipped
``.github/workflows/admissible-gate.yml`` builds from it.  A line a user's CI
executes is as documented as a line in the README, so it keeps resolving for
one release window and then stops.

What it resolves to is the candidate-side distribution's module.  A Ready
document describes what an evaluation found and what a person should do next;
producing one needs no key and asserts no admission, which is why the split
gave it to ``admissible-ready``.  ``UNSIGNED_STATUSES`` there is the proof:
``ready`` is deliberately not among the statuses this half can write.

This module holds no implementation.  Every name it exports is fetched from the
owner at attribute access, so the ``ReadyError`` a workflow catches is the one
``from_evaluation`` raises.  Two classes would be an ``except`` clause that
silently stopped catching.

Importing it loads ``admissible-ready`` and never ``admissible-trust``.  That
is the direction that matters here: the job running this line is the job that
runs the candidate's own checks, and nothing that holds a key belongs in it.

The deprecation notice is a warning rather than a print, for the same reason as
in :mod:`admissible.evidence`: the step importing it writes a job summary to
stdout.
"""
from __future__ import annotations

import warnings

from admissible_ready import ready as _owner

_OWNER_NAME = "admissible_ready.ready"

#: Exactly the owner's public surface, read from the owner rather than retyped.
__all__ = list(_owner.__all__)

warnings.warn(
    f"admissible.ready is a compatibility facade for {_OWNER_NAME} and is "
    "removed after this migration window; import from admissible_ready.ready "
    "instead.",
    DeprecationWarning, stacklevel=2)


def __getattr__(name: str):
    """Re-export one of the owner's public names, and nothing else."""
    if name in __all__:
        return getattr(_owner, name)
    raise AttributeError(
        f"module 'admissible.ready' has no attribute {name!r}; it re-exports "
        f"the public surface of {_OWNER_NAME}, which is: {', '.join(__all__)}")


def __dir__() -> list[str]:
    return sorted(__all__)
