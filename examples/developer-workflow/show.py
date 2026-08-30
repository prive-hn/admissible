"""The small pieces of Python the developer-workflow demo needs.

They live in a file rather than in shell heredocs for two reasons. Heredocs
inside a script that is itself full of heredocs are a delimiter hazard -- one
collision and the shell silently swallows the rest of the script -- and a file
can be read, linted and reviewed like the rest of the product. Every handle
here is opened in a ``with`` block, so a demo run under ``-W error`` reports no
``ResourceWarning``.

Nothing here is part of the shipped package: it is demo scaffolding, and it
imports Admissible only to read the policy it just wrote.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def _read(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _write(path: str | Path, document: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(document, indent=2) + "\n")


def retarget_checks(path: str) -> None:
    """Point the starter policy at commands this demo repository really has."""

    document = _read(path)
    document["classes"][0]["checks"] = [
        # `cacheable` is written out rather than left to a default. A policy
        # that says nothing about reuse authorises none, so step 4 of the demo
        # -- which is entirely about an exact-identity cache hit -- has to ask
        # for reuse in the file, exactly as a real policy would.
        {"id": "compile", "argv": [sys.executable, "-m", "compileall", "-q", "."],
         "timeout_seconds": 120, "cost_units": 1, "required": True,
         "version": "1", "cacheable": True, "cache_max_age_seconds": 86400,
         "description": "every module byte-compiles"},
        {"id": "unit", "argv": [sys.executable, "test_runner.py"],
         "timeout_seconds": 120, "cost_units": 2, "required": True,
         "version": "1", "cacheable": True, "cache_max_age_seconds": 86400,
         "description": "the project's own tests pass"},
    ]
    _write(path, document)


def adopt_payment_profile(path: str) -> None:
    """Keep the payment-change profile's gate; stand in for its commands only.

    The demo used to reach a two-review class by editing the python-library
    policy, and then call the result money-touching. It was not: none of the
    payment profile's own floors were in play, so the step demonstrated a
    review count and advertised a risk class.

    So the file this reads is what `admissible init --profile payment-change`
    actually wrote, and everything that decides admission is left exactly as
    that profile wrote it -- two required independent reviews, the two-day
    review freshness bound, the 18-unit cost and 5400-second wall ceilings, and
    the rule that a reviewer key may never be an author key. What is replaced
    is the three check *argv*: the profile names `make test`, `make
    test-payments` and `make test-ledger`, and a throwaway repository with one
    function has no such targets. The ids, costs, timeouts and required flags
    stay, so the budget the ceilings bound is the profile's budget.

    The placeholders are replaced too. The profile ships `REPLACE-WITH-...` in
    both key lists on purpose: a high-risk class nobody has configured is
    BLOCKED rather than lenient. Here the demo is the operator doing the
    configuring, with keys that are worth nothing.
    """

    document = _read(path)
    artifact_class = document["classes"][0]
    stand_ins = {
        "unit": [sys.executable, "test_runner.py"],
        "payment-tests": [sys.executable, "test_runner.py"],
        "ledger-invariants": [sys.executable, "test_runner.py"],
    }
    for check in artifact_class["checks"]:
        original = " ".join(check["argv"])
        check["argv"] = stand_ins[check["id"]]
        print(f"  check {check['id']}: '{original}' -> a command this "
              f"throwaway repository has (cost {check['cost_units']}, "
              f"required {str(check['required']).lower()})")
    artifact_class["reviewer_key_ids"] = ["reviewer-a", "reviewer-b"]
    artifact_class["author_key_ids"] = ["author-key"]
    print(f"  kept from the profile: {artifact_class['required_independent_reviews']}"
          f" independent reviews, review_max_age_seconds "
          f"{artifact_class['review_max_age_seconds']}, max_cost_units "
          f"{artifact_class['max_cost_units']}, max_wall_seconds "
          f"{artifact_class['max_wall_seconds']}")
    print("  the check commands are stand-ins; this demo runs no real payment tests "
          "and does not claim to")
    _write(path, document)


def first_run(path: str) -> None:
    document = _read(path)
    print("state:     ", document["state"])
    print("readiness: ", document["readiness"])
    print("attempt:   ", document["attempt_id"])
    print("receipt:   ", document["receipt"], "<- a run never issues one")
    print("policy:    ", document["policy_anchor"], "<- no baseline yet")
    for check in document["checks"]:
        print(f"  check {check['check_id']}: {check['status']} "
              f"[{check['provenance']}]")


def reused_run(path: str) -> None:
    document = _read(path)
    print("attempt:   ", document["attempt_id"],
          "(a new attempt, the same observations)")
    for check in document["checks"]:
        source = check["reused_from_attempt"] or check["attempt_id"]
        print(f"  check {check['check_id']}: {check['status']} "
              f"[{check['provenance']}, first observed in attempt "
              f"{source[:12]}]")
    assert all(check["provenance"] == "reused"
               for check in document["checks"]), document["checks"]
    assert all(check["attempt_id"] == document["attempt_id"]
               for check in document["checks"])
    print("every check served from the exact-identity cache, and every reuse "
          "says so")


def pending(path: str) -> None:
    document = _read(path)
    print("state:     ", document["state"])
    print("readiness: ", document["readiness"],
          "<- a handoff, never an admission")
    for reason in document["reasons"]:
        print(f"  - [{reason['code']}] {reason['detail']}")


def verify(path: str) -> None:
    document = _read(path)
    print("state:", document["state"],
          " signature_valid:", document["signature_valid"])


def write_reviews(repo: str, work: str) -> None:
    """Two approving reviews bound to this exact repository, commit and tree."""

    from admissible.config import load_config
    from admissible.identity import repository_identity

    found = repository_identity(repo)
    artifact_class = load_config(repo).select_class("default")
    now = int(time.time())
    for index, (review_id, reviewer) in enumerate(
            (("REV-1", "alice"), ("REV-2", "carol"))):
        _write(Path(work) / f"review-{index}.json", {
            "kind": "review", "review_id": review_id,
            "reviewer_id": reviewer, "reviewer_version": "1",
            "author_id": "dave", "verdict": "approve",
            "repository": found.repository, "commit_sha": found.commit_sha,
            "tree_sha": found.tree_sha,
            "policy_digest": artifact_class.policy_digest,
            "findings_digest": "0" * 64, "issued_at": now, "attempt_id": "",
        })
    # And who wrote it, as a record the author's own key can sign. Two
    # independent reviews only mean something if something other than a string
    # in the submitted document says who the author is.
    _write(Path(work) / "authorship.json", {
        "kind": "authorship", "author_id": "dave",
        "repository": found.repository, "commit_sha": found.commit_sha,
        "tree_sha": found.tree_sha,
        "policy_digest": artifact_class.policy_digest, "issued_at": now,
    })


def bundle_reviews(work: str) -> None:
    attestations = [_read(Path(work) / f"attested-{index}.json")
                    for index in (0, 1)]
    _write(Path(work) / "reviews.json", {
        "schema": "admissible/v0.6/workflow-evidence",
        "commands": [], "reviews": [], "defects": [],
        "attestations": attestations,
        "author_attestations": [_read(Path(work) / "attested-author.json")]})


def write_keyring(work: str) -> None:
    _write(Path(work) / "keyring.json", {
        "reviewer-a": "demo-reviewer-a-secret",
        "reviewer-b": "demo-reviewer-b-secret",
        "author-key": "demo-author-secret"})


_ACTIONS = {
    "retarget-checks": retarget_checks,
    "adopt-payment-profile": adopt_payment_profile,
    "first-run": first_run,
    "reused-run": reused_run,
    "pending": pending,
    "verify": verify,
    "write-reviews": write_reviews,
    "bundle-reviews": bundle_reviews,
    "write-keyring": write_keyring,
}


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in _ACTIONS:
        print(f"usage: show.py {{{'|'.join(sorted(_ACTIONS))}}} [ARGS]",
              file=sys.stderr)
        return 2
    _ACTIONS[argv[0]](*argv[1:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
