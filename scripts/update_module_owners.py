"""Regenerate the derived halves of ``tests/architecture/expected_module_owners.json``.

The manifest has two kinds of field.  ``current_edges``, ``dynamic_imports``,
``resource_packages`` and ``metadata.module_count`` are *derived*: they are what
``census()`` and ``module_edges()`` observe at the current tree, and a human
retyping them is a human introducing a typo the census will then blame on the
source.  ``module_owners`` and ``target_policy`` are *judgement*: this script
never invents one, and refuses when it meets a module nobody has classified.

Deterministic by construction -- every collection is sorted, and the file is
written with the same indent and key order it already has -- so running it twice
produces the same bytes and running it on an unchanged tree produces no diff.

    .venv/bin/python scripts/update_module_owners.py [--check]

``--check`` writes nothing and exits non-zero if the file would change, which is
what a gate wants; the default rewrites it in place.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tests.architecture.test_import_census import (  # noqa: E402
    MANIFEST_PATH, census, module_edges)

# How a newly scanned module is classified, longest prefix first. A module that
# matches nothing here is an error rather than a default: "Ready, probably" is
# exactly the guess this manifest exists to prevent.
OWNER_PREFIXES = (
    ("admissible_core", "Core"),
    ("admissible_ready", "Ready"),
    ("admissible_trust", "Trust"),
    ("tests", "Test Surface"),
    ("atlas", "Existing Research Surface"),
    ("fcd", "Existing Research Surface"),
    ("rga", "Existing Research Surface"),
    ("server", "Existing Research Surface"),
)

# Owners whose modules must also appear in ``target_policy.target_owners``.
NAMESPACE_OWNERS = ("Core", "Ready", "Trust", "Umbrella")


def owner_for(name: str) -> str:
    root = name.split(".")[0]
    for prefix, owner in OWNER_PREFIXES:
        if root == prefix:
            return owner
    raise SystemExit(
        f"{name} matches no owner prefix; classify it in the manifest by hand "
        "before re-running this script")


def rebuild(manifest: dict) -> dict:
    modules = census()
    edges = module_edges(modules)

    owners = dict(manifest["module_owners"])
    for name in modules:
        if name not in owners:
            owners[name] = owner_for(name)
    for stale in set(owners) - set(modules):
        del owners[stale]
    manifest["module_owners"] = {name: owners[name] for name in sorted(owners)}

    target = dict(manifest["target_policy"]["target_owners"])
    for name, owner in manifest["module_owners"].items():
        if owner in NAMESPACE_OWNERS and owner != "Umbrella":
            target.setdefault(name, owner)
    # An authority-owned module needs a target owner; anything else must not
    # have one, or the forbidden-edge check would silently cover a research or
    # test module under a namespace label.
    for stale in set(target) - {
            name for name, owner in manifest["module_owners"].items()
            if owner in NAMESPACE_OWNERS}:
        del target[stale]
    manifest["target_policy"]["target_owners"] = {
        name: target[name] for name in sorted(target)}

    manifest["current_edges"] = {
        importer: sorted(targets) for importer, targets in sorted(edges.items())}
    manifest["dynamic_imports"] = {
        name: sorted(entry["dynamic"],
                     key=lambda item: (item["what"], item["target"] or ""))
        for name, entry in sorted(modules.items()) if entry["dynamic"]}
    manifest["resource_packages"] = {
        name: sorted(entry["resource_packages"])
        for name, entry in sorted(modules.items()) if entry["resource_packages"]}
    manifest["metadata"]["module_count"] = len(modules)
    return manifest


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    rebuilt = rebuild(manifest)
    body = json.dumps(rebuilt, indent=2, ensure_ascii=False) + "\n"
    if "--check" in arguments:
        current = MANIFEST_PATH.read_text(encoding="utf-8")
        if current != body:
            print(f"{MANIFEST_PATH} is stale; re-run without --check",
                  file=sys.stderr)
            return 1
        return 0
    MANIFEST_PATH.write_text(body, encoding="utf-8")
    print(f"{MANIFEST_PATH}: {rebuilt['metadata']['module_count']} modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
