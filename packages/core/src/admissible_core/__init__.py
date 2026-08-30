"""The authority-neutral Admissible kernel.

Everything here is arithmetic on documents: repository identity, policy
parsing and its digest, evidence records, the deterministic decision, and the
shipped JSON Schemas those documents are written against.  Two processes that
disagree about any of it disagree about what was admitted, which is why it is
one distribution rather than a copy inside each of the others.

What is deliberately *not* here is authority.  Core starts no process -- not a
candidate's command, and not ``git`` either -- does not serve HTTP, does not
speak an agent protocol, does not load a signing credential, does not issue or
finalise a receipt, and does not make a policy enforceable.  Those are
capabilities, and a capability that lives in the floor is a capability every
consumer of the floor has.  They belong to the executing (Ready) and signing
(Trust) distributions, which depend on this one.

Identifying a repository does need git run somewhere, so
:func:`admissible_core.identity.repository_identity` takes a reader and asks it
six named questions.  Keeping the process on the caller's side of that line is
what makes "Core cannot run a command" a property of the installed wheel rather
than a promise about how carefully its one exception was written.

Importing this package imports nothing else: the submodules are reached by
name, so a consumer that only needs the schemas does not load the decision
engine, and no module here loads a process-starting one at all.
"""
from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.8.0"
