"""Stage-scoped prefix cache.

Rule: a cache hit may make a stage cheaper, never different. The key
binds (specialist, norm(phi(a)), prefix_hash) together, so:

- a different specialist  -> different key -> miss (no F2 collapse)
- a different bound model -> different key -> miss (no silent rebind)
- a mutated prompt prefix -> different key -> miss (no stale tools)

The cache is cleared at stage boundaries (Admit/Close). A hit NEVER
skips Observe: Pass still compares the executed model, and a mismatch
still closes with F1. This module stores bytes and counts; it holds no
policy and cannot pass or accept anything.
"""
from __future__ import annotations

from collections import OrderedDict
from typing import Optional

from .core import norm


class StageCache:
    """Tiny LRU keyed by (specialist, model, prefix). Zero threads,
    zero locks: one cache per stage-runner, not shared across items."""

    def __init__(self, maxsize: int = 32) -> None:
        self._data: OrderedDict[tuple, bytes] = OrderedDict()
        self.maxsize = maxsize
        self.stats = {"hit": 0, "miss": 0, "evict": 0}

    @staticmethod
    def key(specialist: str, bound_model: str, prefix_hash: str) -> tuple:
        # norm(bound_model) pins the identity the cache is valid for.
        return (specialist, norm(bound_model), prefix_hash)

    def get(self, key: tuple) -> Optional[bytes]:
        if key in self._data:
            self._data.move_to_end(key)
            self.stats["hit"] += 1
            return self._data[key]
        self.stats["miss"] += 1
        return None

    def put(self, key: tuple, payload: bytes) -> None:
        self._data[key] = payload
        self._data.move_to_end(key)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)
            self.stats["evict"] += 1

    def clear(self) -> None:
        """Stage boundary: drop everything. Cross-stage reuse is how a
        cache turns into a binding lie."""
        self._data.clear()
