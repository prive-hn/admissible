"""The candidate-executing Admissible distribution.

This is the half of the product that runs on a developer's machine and inside a
hosted evaluate job: it identifies the repository, executes the deterministic
checks the repository configured, records what it observed, presents that as
Ready state, and serves the same state to an agent over MCP and to a browser
over loopback HTTP.

Everything here is *description*.  A check that passes is an observation about
one exact commit; it is not an admission, and nothing in this distribution can
turn it into one.  There is no receipt issuer, no reviewer keyring, no observer
key, no policy-trust write and no verifier -- not withheld behind a flag, but
absent from the wheel -- so the strongest thing a Ready process can say is that
the checks are complete and secure confirmation is next.  Saying anything
stronger needs the signing distribution, in a different process, holding a key
this one refuses to hold.

That refusal is enforced rather than promised.  Every entry point that could
start a candidate-owned command, touch the store or bind a socket first checks
the environment for admission, review and observer credentials and refuses
before the first side effect: a check runs as this user, so a process that
holds a key while starting one has already lost the boundary the key was
protecting.

Importing this package imports nothing else.  The submodules are reached by
name, so a consumer that only wants the Ready document does not start an HTTP
server, and nothing here is loaded as an import side effect.

The honest limits, stated once: separate distributions are not a sandbox.  Code
running under the same Unix account can still read this process's environment,
edit the store, and delete the private logs; what the split removes is
*accidental capability adjacency*, so a signing key is not one import away from
a process that runs whatever ``.admissible.json`` says.
"""
from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.8.0"
