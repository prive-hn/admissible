"""Compatibility facade: ``admissible.evidence`` is ``admissible_core.evidence``.

``from admissible.evidence import ReviewEvidence`` is one of the two imports
the migration window documents, so it keeps resolving for one release window
and then stops.  What it resolves to is the kernel's own module: evidence
records are authority-neutral -- a command's exact output, a review's parsed
body, the digest either hashes to -- so the split gave them to
``admissible-core``, and both distributions read the same definitions from
there.

This module holds no implementation.  Every name it exports is fetched from the
owner at attribute access, so ``admissible.evidence.ReviewEvidence`` and
``admissible_core.evidence.ReviewEvidence`` are one class.  Two classes would
be two evidence formats with import order deciding which one a consumer
hashed, which is the whole failure a facade exists to avoid.

Importing it loads the kernel and neither authority: a consumer that wanted an
evidence record must not find a runner or a receipt signer arriving behind it.

The deprecation notice is a warning rather than a print, because a facade that
wrote to stdout would corrupt every JSON document and every MCP frame a process
importing it went on to emit.
"""
from __future__ import annotations

import warnings

from admissible_core import evidence as _owner

_OWNER_NAME = "admissible_core.evidence"

#: Exactly the owner's public surface, read from the owner rather than retyped:
#: a facade with its own list is a facade that drifts.
__all__ = list(_owner.__all__)

warnings.warn(
    f"admissible.evidence is a compatibility facade for {_OWNER_NAME} and is "
    "removed after this migration window; import from admissible_core.evidence "
    "instead.",
    DeprecationWarning, stacklevel=2)


def __getattr__(name: str):
    """Re-export one of the owner's public names, and nothing else."""
    if name in __all__:
        return getattr(_owner, name)
    raise AttributeError(
        f"module 'admissible.evidence' has no attribute {name!r}; it re-exports "
        f"the public surface of {_OWNER_NAME}, which is: {', '.join(__all__)}")


def __dir__() -> list[str]:
    return sorted(__all__)
