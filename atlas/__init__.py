"""atlas — canonical cockpit state reduced from the fcd journal.

Pure, deterministic, stdlib-only. The reducer in `atlas.model` turns an
append-only fcd journal plus evidence/artifact/plan records into an
immutable `AtlasSnapshot`. Skins are read-only projections of that
snapshot; they never mutate canonical state.
"""
from .model import (
    AtlasSnapshot,
    Node,
    Question,
    Impact,
    Artifact,
    build_snapshot,
    capabilities_from_policy,
)

__all__ = [
    "AtlasSnapshot",
    "Node",
    "Question",
    "Impact",
    "Artifact",
    "build_snapshot",
    "capabilities_from_policy",
]
