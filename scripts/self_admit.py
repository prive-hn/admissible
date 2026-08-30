#!/usr/bin/env python3
"""Run the composed kernel over this repository's own change, and issue a receipt.

Everything else in this repository evaluates the kernel against something else:
stdlib reference implementations (`eval/bench/`), generated code
(`eval/generators/`), historical defects (`eval/realdefects/`). This drives it
over the only artifact it can be fully honest about -- itself.

    subject    the tracked tree at HEAD, as a content-addressed manifest
    claim      every guard in the defect model is individually load-bearing
    D          the 298 sabotage cases in `scripts/sabotage_admissible.py`,
               each a source mutation paired with the test that must catch it
    refuter    the sabotage harness: apply each mutation, run its named test,
               and require the test to go red
    power      kills / |D|, counted from real runs, not asserted

The refuter's verdict has the kernel's meaning, which is the opposite of the
harness's console output: "refuted" means the refuter FOUND something -- a
mutation no test caught, so a guard is not load-bearing. "survived" means it
looked and found nothing.

This is a self-application and its weaknesses are stated on the receipt rather
than around it. k=1: there is one repository, so the concordance layer is
trivial here and the seal records `(agreeing, 1)` to say so. The defect model
is authored by the same people as the code, which is exactly the coupling
assumption the paper declines to prove. What the run does establish is that the
guards D names are load-bearing, measured rather than claimed.

    python3 scripts/self_admit.py  # run D freshly against the current clean HEAD

Previously this command accepted a free-form sabotage log through ``--reuse``.
That path is retained only as an explicit refusal so an old automation cannot
silently downgrade to unauthenticated evidence: a text log cannot prove which
source tree it evaluated or that any mutation actually ran.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fcd.core import Enforcer, Policy                                # noqa: E402
from fcd.head import HMACSHA256Signer, MonotoneHeadRegistry          # noqa: E402
from rga.attestation import (issue_admissibility_receipt,            # noqa: E402
                             admissibility_receipt_to_dict,
                             verify_admissibility_receipt)
from rga.calibration import (CalibrationAuthority, CalibrationClass,  # noqa: E402
                             CalibrationPolicy)
from rga.core import (Admission, AdmissionPolicy, ClaimSpec,          # noqa: E402
                      ClassAdmission, DefectModel, LedgerEntry, Refuter, sha256)

CLASS = "admissible-repo-change"
CLAIM = "guards_are_load_bearing"
REFUTER = ("sabotage", "v1")
NAMESPACE = "admissible-self"
OUT = ROOT / "eval" / "self" / "receipt.json"


# ------------------------------------------------------------- the subject ----

def tree_manifest() -> bytes:
    """Every tracked file and its blob hash, sorted. Content-addressed by git,
    so the artifact hash on the seal is reproducible from a checkout alone."""
    out = subprocess.run(
        ["git", "--no-replace-objects", "ls-tree", "-r", "HEAD"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    lines = sorted(line for line in out.splitlines() if line)
    return "\n".join(lines).encode()


def head_commit() -> str:
    return subprocess.run(
        ["git", "--no-replace-objects", "rev-parse", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True, check=True).stdout.strip()


def require_clean_head() -> dict[str, str]:
    """Return the exact commit/tree only when non-ignored bytes equal ``HEAD``.

    The sabotage harness edits tracked source in place and promises to restore
    it. Measuring a dirty checkout would bind the committed tree to different
    executed bytes, so both the pre-run and post-run boundaries use this check.
    Ignored build environments and the overwritten raw harness log stay outside
    the measured subject. Any other untracked file is refused because it can
    shadow an import or otherwise change the run.
    """
    status = subprocess.run(
        [
            "git", "--no-replace-objects", "status", "--porcelain",
            "--untracked-files=all",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if status:
        raise ValueError("self-measurement requires a clean HEAD source tree")
    return {
        "commit": head_commit(),
        "tree": subprocess.run(
            ["git", "--no-replace-objects", "rev-parse", "HEAD^{tree}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip(),
    }


def assert_same_clean_head(expected: dict[str, str]) -> dict[str, str]:
    observed = require_clean_head()
    if observed != expected:
        raise ValueError(
            "repository identity changed during measurement: "
            f"expected {expected}, observed {observed}"
        )
    return observed


# ------------------------------------------------- the defect model, from D ----

def case_labels() -> list[str]:
    """The mutations D contains, read out of the harness rather than counted
    by hand, so |D| cannot drift from what actually runs."""
    src = (ROOT / "scripts" / "sabotage_admissible.py").read_text()
    body = src[src.index("CASES = ["):]
    return re.findall(r'^    \("([^"]+)"', body, re.M)


def run_defect_model(log: pathlib.Path | None) -> tuple[list[LedgerEntry], dict]:
    """Apply every mutation and record whether its test caught it.

    RED is a kill: the mutation was applied and the named test went red, so the
    guard it deletes is load-bearing. GREEN is a survivor: the mutation is
    invisible to the suite.
    """
    if log is None:
        log = ROOT / "_sabotage.log"
        print(f"running the defect model ({len(case_labels())} cases)...",
              file=sys.stderr)
        with log.open("w") as fh:
            subprocess.run([sys.executable, "scripts/sabotage_admissible.py",
                            "--legacy-only"], cwd=ROOT, stdout=fh,
                           stderr=subprocess.STDOUT, check=False)
    text = log.read_text(errors="replace")

    ledger, killed, survived = [], [], []
    for line in text.splitlines():
        m = re.match(r"^(RED|GREEN)\s+\(\w+\)\s+(.+?)\s+->", line)
        if not m:
            continue
        verdict, label = m.group(1), m.group(2).strip()
        (killed if verdict == "RED" else survived).append(label)
        ledger.append(LedgerEntry(label, "killed" if verdict == "RED" else "survived"))
    undetected = re.search(r"^undetected sabotage: (.+)$", text, re.M)
    integrity = re.search(r"^source integrity: (.+)$", text, re.M)
    declared = case_labels()
    return ledger, {
        "cases_declared": len(declared),
        "cases_run": len(ledger),
        "killed": len(killed), "survived_the_mutation": len(survived),
        "undetected_line": undetected.group(1) if undetected else "(absent)",
        "integrity_line": integrity.group(1) if integrity else "(absent)",
        "unrun": sorted(set(declared) - {e.defect_id for e in ledger}),
        "survivors": survived,
    }


def refuse_partial(stats: dict) -> str | None:
    """Why this log cannot support a measurement, or None.

    A truncated log -- an aborted subprocess, a `--reuse` file cut short -- used
    to pass, because the only check was for zero verdicts. It would then report
    a ratio over whatever it happened to parse, which for one surviving line is
    a perfect 1/1, and overwrite the receipt with it. A partial defect model is
    not a small defect model; it is a different one.
    """
    if stats["cases_run"] == 0:
        return "the defect model produced no verdicts"
    if stats["cases_run"] != stats["cases_declared"]:
        missing = len(stats["unrun"])
        return (f"the log carries {stats['cases_run']} verdicts for "
                f"{stats['cases_declared']} declared cases "
                f"({missing} never ran, e.g. {stats['unrun'][:3]})")
    if stats["undetected_line"] == "(absent)":
        return "the harness did not print its completion line, so the run did not finish"
    if not stats["integrity_line"].startswith("every target byte-identical"):
        return (f"the harness's source-integrity check did not pass: "
                f"{stats['integrity_line']}")
    return None


# ----------------------------------------------------------------- the run ----

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--reuse", type=pathlib.Path, default=None, metavar="LOG",
        help="refused: unauthenticated logs are not current-source evidence",
    )
    args = ap.parse_args()
    if args.reuse is not None:
        print(
            "refusing --reuse: an unauthenticated log cannot establish the "
            "source identity it evaluated; run the defect model fresh",
            file=sys.stderr,
        )
        return 2

    try:
        source_identity = require_clean_head()
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"refusing to measure: {exc}", file=sys.stderr)
        return 2

    artifact = tree_manifest()
    commit = source_identity["commit"]
    ledger, stats = run_defect_model(None)
    try:
        post_identity = assert_same_clean_head(source_identity)
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"refusing to measure: {exc}", file=sys.stderr)
        return 2
    bad = refuse_partial(stats)
    if bad is not None:
        print(f"refusing to measure: {bad}", file=sys.stderr)
        return 2

    # D is content-addressed by its own entries, so a changed defect model is a
    # different D and the ratchet can see it.
    d_hash = "D-self-" + sha256(json.dumps(sorted(
        (e.defect_id for e in ledger))).encode())[:16]

    tick = {"t": 0}
    def clock() -> float:
        tick["t"] += 1
        return float(tick["t"])
    count = {"n": 0}
    def nonce() -> str:
        count["n"] += 1
        return f"self-n{count['n']}"

    fcd = Enforcer(Policy(
        allow={CLASS: {"author", "reviewer"}}, deny={CLASS: set()},
        phi={"author": "repo:branch", "reviewer": "repo:adversarial-review"},
        required={CLASS: [("write", "s0"), ("check", "c1")]},
        version="self-v1"), clock=clock)

    adm = Admission(fcd, AdmissionPolicy({CLASS: ClassAdmission(
        claims=(ClaimSpec(CLAIM, sha256(b"every guard in D is load-bearing"),
                          frozenset({REFUTER}), d_hash),),
        # k=1 by necessity: there is one repository. The seal carries
        # (agreeing, k) precisely so this is visible rather than implied.
        k=1, theta=1.0, p_min=0.9,
        excluded=frozenset({"refuter_source"}),
        residual=(("the defect model is authored by the same people as the code",
                   "unreviewed"),
                  ("environmental failures in this container are not modelled",
                   "unreviewed")),
    )}, version="self-r1"), clock=clock, nonce=nonce)

    cal = CalibrationAuthority(adm, CalibrationPolicy(
        {CLASS: CalibrationClass(e_max=1, demotion_gate="seal")}), clock=clock)

    # Both are authored by this project, and they are declared that way. Giving
    # them different labels would get past V14 and would be exactly the
    # claim-shaping the threat model names.
    AUTHOR = "repo:admissible"
    adm.declare(Refuter(REFUTER[0], REFUTER[1], author=AUTHOR, mode="ledger"))
    measured = {"kills": sum(1 for e in ledger if e.verdict == "killed"),
                "size": len(ledger)}
    measured["ratio"] = round(measured["kills"] / max(1, measured["size"]), 4)
    print(f"\nmeasured detection: {measured['kills']}/{measured['size']} "
          f"= {measured['ratio']:.4f}")

    outcome: dict = {
        "commit": commit,
        "source": {"pre": source_identity, "post": post_identity},
        "artifact_hash": sha256(artifact),
        "defect_model": {"hash": d_hash, "author": AUTHOR, **stats},
        "refuter": {"id": REFUTER[0], "version": REFUTER[1], "author": AUTHOR},
        "measured_detection": measured,
    }
    try:
        power = adm.measure(REFUTER[0], REFUTER[1],
                            DefectModel(d_hash, AUTHOR), ledger)
    except ValueError as exc:
        # The interesting outcome, and the honest one. V14 forbids a refuter
        # carrying power against a defect model its own author wrote. In this
        # repository that is simply true: the same project wrote the guards,
        # the tests that catch their deletion, and the mutation set. The
        # measurement above is real; what the kernel refuses is letting the
        # artifact *carry* it as certified power.
        outcome["sealed"] = False
        outcome["refused_at"] = "measure"
        outcome["fault"] = "V14"
        outcome["refusal"] = str(exc)
        outcome["reading"] = (
            "The system refuses to certify its own power. The defect model and "
            "the refuter have one author, so the power record would be "
            "self-certified. This is the coupling assumption the paper declines "
            "to prove, enforced rather than noted: "
            f"{measured['kills']}/{measured['size']} detection is a fact about "
            "this repository and is not admissible evidence about it.")
        print(f"\nREFUSED at measure — fault V14: {exc}")
        print("  " + outcome["reading"].replace(". ", ".\n  "))
        _write(outcome)
        return 0
    print(f"carried power: {power.kills}/{power.size} = {power.power:.4f}")

    iid = f"self-{commit[:12]}"
    fcd.open(iid, CLASS, sha256(artifact))
    cal.open(iid, "repo:branch", "single-artifact")
    fcd.admit(iid, "author"); fcd.bind(iid, True)
    fcd.observe(iid, "repo:branch"); fcd.decide_pass(iid)
    adm.sample(iid, artifact, {"contract"}, "single-artifact")

    # The refuter looked at every mutation in D and found no guard that was not
    # load-bearing, so it did not refute. A survivor in D would make this
    # "refuted" and close the line loudly instead.
    verdict = "refuted" if stats["survived_the_mutation"] else "survived"
    seed = adm.seed_for(iid, 0, REFUTER[0], REFUTER[1], CLAIM)
    witness = sha256(json.dumps(stats["survivors"], sort_keys=True).encode())
    adm.trial(iid, REFUTER[0], REFUTER[1], CLAIM, 0, seed, sha256(artifact),
              verdict, witness)
    if verdict == "survived":
        adm.replay(iid, len(adm.lines[iid].trials) - 1, verdict, witness)

    fcd.admit(iid, "reviewer"); fcd.bind(iid, True)
    fcd.observe(iid, "repo:adversarial-review"); fcd.decide_pass(iid)
    fcd.check(iid, "c1", True)

    outcome["power"] = {"kills": power.kills, "size": power.size,
                        "power": round(power.power, 4)}
    outcome["refuter_verdict"] = verdict
    try:
        seal = cal.seal(iid)
    except ValueError as exc:
        outcome["sealed"] = False
        outcome["refusal"] = str(exc)
        print(f"\nREFUSED: {exc}")
        _write(outcome)
        return 1

    outcome["sealed"] = True
    outcome["seal"] = {"artifact_hash": seal.artifact_hash, "k": seal.k,
                       "theta": seal.theta, "p_min": seal.p_min,
                       "power_min": seal.power_min,
                       "residual": [list(r) for r in seal.residual],
                       "policy_version": seal.policy_version,
                       "fcd_policy_version": seal.fcd_policy_version}

    signer = HMACSHA256Signer("admissible-self", b"self-application-demo-key-32byt")
    registry = MonotoneHeadRegistry()
    receipt = issue_admissibility_receipt(
        iid, fcd, adm, cal, registry, signer,
        journal_namespace=NAMESPACE, issued_at=int(time.time()))
    ok = verify_admissibility_receipt(receipt, fcd, adm, cal, registry, signer)

    outcome["receipt"] = admissibility_receipt_to_dict(receipt)
    outcome["verified"] = bool(ok)
    outcome["predicate"] = {"sealed": receipt.sealed, "mediated": receipt.mediated,
                            "tainted": receipt.tainted,
                            "impeached": receipt.impeached,
                            "admissible": cal.admissible(iid)}
    outcome["journal_events"] = {"fcd": len(fcd.events), "rga": len(adm.events),
                                 "calibration": len(cal.events)}
    _write(outcome)

    print(f"\n  artifact   {outcome['artifact_hash'][:32]}…  ({commit[:12]})")
    print(f"  power      {power.kills}/{power.size} = {power.power:.4f}")
    print(f"  admissible {outcome['predicate']['admissible']}   "
          f"(sealed {receipt.sealed}, mediated {receipt.mediated}, "
          f"tainted {receipt.tainted}, impeached {receipt.impeached})")
    print(f"  receipt    verified={ok}  events "
          f"fcd={len(fcd.events)} rga={len(adm.events)} cal={len(cal.events)}")
    print(f"  written    {OUT.relative_to(ROOT)}")
    return 0 if ok else 1


def _write(outcome: dict) -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(outcome, indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
