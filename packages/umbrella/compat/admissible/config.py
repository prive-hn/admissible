"""Compatibility facade: ``admissible.config`` is ``admissible_core.config``.

``from admissible.config import load_config`` is the line the worked example in
``examples/developer-workflow/show.py`` runs, so it keeps resolving for one
release window and then stops.  What it resolves to is the kernel's own module:
a policy is a document both halves read and neither owns -- the evaluating side
must know which checks to run, the signing side must know which policy it is
being asked to stand behind -- so the split gave it to ``admissible-core``.

This module holds no implementation.  Every name it exports is fetched from the
owner at attribute access, so ``admissible.config.Config`` and
``admissible_core.config.Config`` are one class.  Two classes would be two
policy parsers, and a policy digest computed by one and checked by the other
would disagree exactly when it mattered.

Importing it loads the kernel and neither authority: reading a config file must
not bring a runner or a receipt signer into the process that reads it.

The deprecation notice is a warning rather than a print, for the same reason as
in :mod:`admissible.evidence`: the importing process may already be writing a
decision document to stdout.
"""
from __future__ import annotations

import warnings

from admissible_core import config as _owner

_OWNER_NAME = "admissible_core.config"

#: Exactly the owner's public surface, read from the owner rather than retyped:
#: a facade with its own list is a facade that drifts.
__all__ = list(_owner.__all__)

warnings.warn(
    f"admissible.config is a compatibility facade for {_OWNER_NAME} and is "
    "removed after this migration window; import from admissible_core.config "
    "instead.",
    DeprecationWarning, stacklevel=2)


def __getattr__(name: str):
    """Re-export one of the owner's public names, and nothing else."""
    if name in __all__:
        return getattr(_owner, name)
    raise AttributeError(
        f"module 'admissible.config' has no attribute {name!r}; it re-exports "
        f"the public surface of {_OWNER_NAME}, which is: {', '.join(__all__)}")


def __dir__() -> list[str]:
    return sorted(__all__)
