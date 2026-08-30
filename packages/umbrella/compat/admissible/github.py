"""Compatibility facade: ``admissible.github``, whose surface the split cut.

``docs/GITHUB_ACTIONS.md`` names two functions from this module as the code
that applies two of the rules it describes::

    admissible.github.evaluation_context()
    admissible.github.assert_trusted_tool()

They are documented together and they no longer live together.
``evaluation_context`` derives what a workflow may do from named environment
inputs -- it refuses anything that is not a full 40-character SHA and refuses
``pull_request_target`` outright -- which is candidate-side work that holds no
key, so it went to ``admissible-ready``.  ``assert_trusted_tool`` refuses a
``--policy-root`` that ships its own ``admissible`` package, which is a check
that only matters once a key is in the process, so it went to
``admissible-trust``.

So this facade cannot be what the other five are: a module that re-exports one
owner.  A module-level ``from admissible_ready.github import *`` beside a
``from admissible_trust.github import *`` would put a runner and a receipt
signer in every process that so much as touched this name, which is the exact
adjacency the split exists to remove.

What it is instead is a table.  ``_OWNERS`` names, per symbol, the half that
implements it.  Importing this module imports neither half.  Reading a
Ready-owned name imports ``admissible_ready.github`` and nothing else; reading
a Trust-owned name imports ``admissible_trust.github`` and nothing else.  The
two module names are written as literals at the call site, in ``_LOADERS``, so
the complete set of modules this file can reach is readable in the file itself
-- by a person and by the import census.  There is no computed target and no
delegation to an arbitrary module; a name outside the table is not looked up
anywhere.

**Two names are refused on purpose.**  ``GitHubError`` and ``PREVIEW_SCHEMA``
exist in *both* halves, as different objects: an ``except GitHubError`` bound
to Ready's class does not catch Trust's, and each half's ``PREVIEW_SCHEMA``
labels its own artefact.  Nothing documents either name, so nothing here
promises it -- and answering it would mean picking an authority on the caller's
behalf, silently, in the one place where guessing is least affordable.  They
fail closed, naming both replacements, so the caller decides which half they
meant.  Fixing that by importing both and merging them is not available: it is
the same reconnection, spelled as a convenience.

Nothing here reads the environment.  This module imports no ``os``, so no
credential, keyring path or home directory can influence which half a name
comes from; the answer is the table and the table is static.

The deprecation notice is a warning rather than a print, for the same reason as
in :mod:`admissible.evidence`: a workflow step importing this is a step whose
stdout is a job output.
"""
from __future__ import annotations

import importlib
import warnings

#: The two modules the legacy surface was divided between.
READY_OWNER = "admissible_ready.github"
TRUST_OWNER = "admissible_trust.github"

#: ``symbol -> the half that implements it``.  This is the whole promise: a
#: name absent from here is not re-exported, whichever half happens to define
#: one like it.
_OWNERS = {
    "assert_trusted_tool": TRUST_OWNER,
    "evaluation_context": READY_OWNER,
}

#: Explicit, and exactly the documented names.
__all__ = sorted(_OWNERS)

#: Names both halves define as separate objects.  Listed rather than merely
#: omitted, so that asking for one gets an answer that says why, and names the
#: two modules the caller must choose between.
_AMBIGUOUS = ("GitHubError", "PREVIEW_SCHEMA")

#: One loader per half, each naming its module as a literal.  A single loader
#: taking the owner as an argument would read the same and census as a facade
#: that can import anything.
_LOADERS = {
    READY_OWNER: lambda: importlib.import_module("admissible_ready.github"),
    TRUST_OWNER: lambda: importlib.import_module("admissible_trust.github"),
}

warnings.warn(
    "admissible.github is a compatibility facade and is removed after this "
    f"migration window; its surface was divided between {READY_OWNER} "
    f"(evaluation_context) and {TRUST_OWNER} (assert_trusted_tool). Import "
    "from the half you mean instead.",
    DeprecationWarning, stacklevel=2)


def __getattr__(name: str):
    """Resolve one documented name to its own half, importing only that half."""
    owner = _OWNERS.get(name)
    if owner is not None:
        return getattr(_LOADERS[owner](), name)
    if name in _AMBIGUOUS:
        raise AttributeError(
            f"module 'admissible.github' refuses {name!r}: the split gave that "
            f"name to both {READY_OWNER} and {TRUST_OWNER}, as two different "
            "objects, and this facade will not choose an authority for you. "
            f"Import it from {READY_OWNER} or from {TRUST_OWNER}, whichever "
            "half you mean.")
    raise AttributeError(
        f"module 'admissible.github' has no attribute {name!r}; it re-exports "
        f"only the documented names {', '.join(__all__)}. Everything else "
        f"moved to {READY_OWNER} or {TRUST_OWNER} and is imported from there.")


def __dir__() -> list[str]:
    return sorted(__all__)
