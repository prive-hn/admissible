"""Compatibility facade: ``admissible.receipt`` is ``admissible_trust.receipt``.

``from admissible.receipt import WorkflowReceipt`` is the second documented
import of the migration window.  It resolves to the signing distribution's
module, because a receipt is the one artefact only an authority can produce:
issuing one needs the admission key, and authenticating one needs it too.

This module holds no implementation.  Every name it exports is fetched from the
owner at attribute access, so a receipt body built here and a receipt body
built by ``admissible-trust`` hash identically -- a second copy of this code
would be a second receipt format, and the one a verifier disagreed with would
be the one that mattered.

Importing it loads ``admissible-trust`` and never ``admissible-ready``.  That
is the direction that matters: a consumer reading receipts must not pull a
candidate runner into its process, and no import here can.

The deprecation notice is a warning rather than a print, for the same reason as
in :mod:`admissible.evidence`: stdout may already be carrying a receipt.
"""
from __future__ import annotations

import warnings

from admissible_trust import receipt as _owner

_OWNER_NAME = "admissible_trust.receipt"

#: Exactly the owner's public surface, read from the owner rather than retyped.
__all__ = list(_owner.__all__)

warnings.warn(
    f"admissible.receipt is a compatibility facade for {_OWNER_NAME} and is "
    "removed after this migration window; import from admissible_trust.receipt "
    "instead.",
    DeprecationWarning, stacklevel=2)


def __getattr__(name: str):
    """Re-export one of the owner's public names, and nothing else."""
    if name in __all__:
        return getattr(_owner, name)
    raise AttributeError(
        f"module 'admissible.receipt' has no attribute {name!r}; it re-exports "
        f"the public surface of {_OWNER_NAME}, which is: {', '.join(__all__)}")


def __dir__() -> list[str]:
    return sorted(__all__)
