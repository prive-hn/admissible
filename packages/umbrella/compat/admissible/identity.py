"""Compatibility facade: ``admissible.identity`` is ``admissible_core.identity``.

``from admissible.identity import repository_identity`` is the second line the
worked example in ``examples/developer-workflow/show.py`` runs, so it keeps
resolving for one release window and then stops.  What it resolves to is the
kernel's own module: which repository this is, and which commit, is a fact
about a working tree rather than a judgement about it, and both halves must
read that fact the same way or they are talking about different commits.

This module holds no implementation.  Every name it exports is fetched from the
owner at attribute access, so ``admissible.identity.Identity`` and
``admissible_core.identity.Identity`` are one class.  Two classes would be two
answers to "which commit is this?", and evidence bound by one would not verify
against the other.

Importing it loads the kernel and neither authority.

The deprecation notice is a warning rather than a print, for the same reason as
in :mod:`admissible.evidence`.
"""
from __future__ import annotations

import warnings

from admissible_core import identity as _owner

_OWNER_NAME = "admissible_core.identity"

#: Exactly the owner's public surface, read from the owner rather than retyped.
__all__ = list(_owner.__all__)

warnings.warn(
    f"admissible.identity is a compatibility facade for {_OWNER_NAME} and is "
    "removed after this migration window; import from admissible_core.identity "
    "instead.",
    DeprecationWarning, stacklevel=2)


def __getattr__(name: str):
    """Re-export one of the owner's public names, and nothing else."""
    if name in __all__:
        return getattr(_owner, name)
    raise AttributeError(
        f"module 'admissible.identity' has no attribute {name!r}; it "
        f"re-exports the public surface of {_OWNER_NAME}, which is: "
        f"{', '.join(__all__)}")


def __dir__() -> list[str]:
    return sorted(__all__)
