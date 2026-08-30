"""The ``admissible`` compatibility namespace: a dispatcher and its facades.

This distribution exists so that the command a developer already types keeps
working after the split, and so that the ``admissible.*`` imports this project
documents -- in its docs, its worked example, and the CI template it copies
into a consumer's repository -- keep resolving for one migration window.  It
holds no authority of its own.  Every command is handed, unchanged, to the
distribution that owns it -- ``admissible-ready`` where candidate code runs,
``admissible-trust`` where a key is held -- and that distribution's answer is
the answer.

Ownership is static.  It is read off the command line and nothing else: no
credential, environment variable or installed key selects a domain here, and a
command with no owner is refused rather than routed somewhere plausible.  An
ambient credential remains a fail-closed guard inside each distribution; it is
never a router.

Importing this package imports neither authority.  ``admissible.cli`` resolves
one target and imports that one; each single-owner facade imports its own owner
only; and ``admissible.github`` -- the one surface the split divided -- imports
neither half until a name is read, and then only the half that owns that name.
No process ever loads both halves as a side effect of loading this.

Installing it, however, *does* put both halves on the machine.  That is what it
is for and it is why it is forbidden in trusted infrastructure: a finalizer,
reviewer, observer or policy-signing environment installs exactly one authority,
and this package is not that package.
"""
from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.8.0"
