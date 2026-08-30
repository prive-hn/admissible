"""Admissible developer admission product.

A deterministic developer gate: it consumes exact-artifact evidence, explains
refusal in plain words, authenticates decisions with signed workflow receipts,
and updates current standing when later defects impeach earlier approvals.

This package is a *developer workflow* boundary. It never claims the composed
identity/scrutiny/standing predicate of the research kernel in ``fcd``/``rga``;
see :mod:`admissible.receipt` for the distinct receipt domain.
"""
from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.7.0"
