"""The credentialed Admissible distribution.

This is the half of the product that holds a key.  It authenticates reviewer
and observer attestations, records which policy an operator made enforceable,
consumes a retained preview, recomputes the decision that preview describes
against a trusted checkout, issues and anchors the authenticated receipt, and
answers what is current now.

Everything here is *authority*.  What is deliberately absent is the capability
that would make that authority dangerous: there is no runner, no MCP server, no
HTTP server, no packaged browser asset and no candidate workflow invocation --
not withheld behind a flag, but missing from the wheel -- so no code path in
this distribution can start a program the repository under evaluation chose.

One process is started, in one module.  :mod:`admissible_trust.git_reader`
answers the six fixed questions ``admissible_core.identity`` asks about a
working tree, with a literal argument vector, hooks and fsmonitor and system
configuration disabled, and every ``GIT_*`` variable and every Admissible
credential removed from the child's environment.  Finalization uses it to
re-derive the artefact it is about to sign for, and once identity has been
captured it is not consulted again except where the contract requires the exact
identity to be read a second time.

Importing this package imports nothing else.  The submodules are reached by
name, so a consumer that only wants to verify a receipt does not load the
finalizer, and no signing credential is read as an import side effect.

The honest limits, stated once: HMAC-SHA256 is shared-secret authenticity and
never public non-repudiation, and separate distributions are not a sandbox.
Code running under the same Unix account can still read this process's
environment and delete this home's files; what the split removes is
*accidental capability adjacency*, so a signing key is not one import away from
a process that runs whatever ``.admissible.json`` says.
"""
from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.8.0"
