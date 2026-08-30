"""The closed vocabulary of isolation boundaries, owned by neither authority.

An evaluation records *what confined the commands it started*, an external
observer signs that field with everything else, and a finalizer refuses a
preview whose observer asserted no boundary at all.  Three distributions
therefore compare on one set of strings: Ready writes one into a preview and
refuses a value it does not know, the observer signs one, and Trust refuses a
value it does not know and refuses :data:`ISOLATION_NONE` outright.

Two spellings of that set would be two gates.  A mode one side accepts and the
other rejects is a preview that evaluates and cannot be finalized; the same
disagreement in the other direction is a boundary one side would have refused
and the other admitted.  So the names live here, in the kernel both sides
already agree with about digests and decisions, and each distribution imports
them.

What is deliberately *not* here is ``declared_isolation``.  Reading
``ADMISSIBLE_ISOLATION`` to decide what an evaluating process should record is
a question only a process that starts commands has, and it stays in the Ready
runner beside the code those commands are started by.  The kernel owns the
names and nothing else.

None of these strings is verified by Admissible.  ``pid-namespace``,
``single-use-vm`` and ``separate-uid`` name boundaries an operator arranged and
an observer says it independently validated; this module makes the claim
sayable and comparable, and never checks it.
"""
from __future__ import annotations

__all__ = ["ISOLATION_MODES", "ISOLATION_NONE"]

#: The truth about a bare process group, and the one value a finalizer refuses.
#:
#: It is a member of the set rather than an absence, because "no boundary" is a
#: fact an observer can honestly assert; refusing it is a separate decision made
#: where a receipt would otherwise be issued.
ISOLATION_NONE = "none"

#: Every boundary this product knows how to be told about, ``none`` first.
ISOLATION_MODES = (ISOLATION_NONE, "pid-namespace", "single-use-vm",
                   "separate-uid")
