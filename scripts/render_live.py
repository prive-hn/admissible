#!/usr/bin/env python3
"""Run a real project through the machine and draw the journal.

Scenario (three lines, one time-layer):
  A  write+check, accepted
  B  depends on A, first Observe mismatches (F1), then retries and accepts
  C  depends on A — refused because we never open it until A is stored
  v1 → v2 install: in-flight B keeps v1
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fcd.core import Enforcer, Policy
from fcd.visual import render


def policy(version: str, allow: set[str]) -> Policy:
    return Policy(
        allow={"impl": set(allow)},
        deny={"impl": set()},
        phi={"alice": "model-a", "carol": "model-c", "bob": "model-b"},
        required={"impl": [("write", "w1"), ("check", "c1")]},
        version=version,
    )


def pass_stage(e: Enforcer, iid: str, who: str) -> None:
    e.admit(iid, who)
    e.bind(iid, True)
    e.observe(iid, e.policy_for(iid).phi[who])
    e.decide_pass(iid)


def main() -> None:
    out_dir = Path(__file__).resolve().parents[1] / "paper" / "figures"
    e = Enforcer(policy("v1", {"alice", "carol"}))

    e.open("A", "impl", "hash-A")
    pass_stage(e, "A", "alice")
    pass_stage(e, "A", "carol")
    render(e, out_dir / "live-1-A-accepted.png", "1. Line A accepted — store has A")

    e.open("B", "impl", "hash-B", depends_on=("A",))  # still v1
    e.install(policy("v2", {"carol"}))  # alice gone for NEW items; B stays v1
    e.admit("B", "alice")
    e.bind("B", True)
    e.observe("B", "model-other")
    e.decide_pass("B")
    render(e, out_dir / "live-2-B-shears.png", "2. Line B shears (F1) — A stays in the store")

    e.admit("B", "carol")  # retry same class, unused specialist
    e.bind("B", True)
    e.observe("B", "model-c")
    e.decide_pass("B")
    # write passed with carol → authors={carol}; check excludes carol
    e.admit("B", "alice")
    e.bind("B", True)
    e.observe("B", "model-a")
    e.decide_pass("B")
    render(e, out_dir / "live-3-stack.png", "3. B accepted on A — two lines in the store")

    print("events", len(e.events), "store", sorted(e.store))
    print("B version", e.items["B"].policy_version, "live policy", e.policy.version)


if __name__ == "__main__":
    main()
