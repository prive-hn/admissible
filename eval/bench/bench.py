"""The admissibility bench: the three-layer kernel evaluated end to end.

WHAT THIS IS: a deterministic, journal-complete evaluation of the kernels in
fcd/, rga/ — identity, scrutiny, standing — on reference implementations of
four well-established stdlib specifications (statistics.median,
textwrap.wrap, posixpath.normpath, statistics.quantiles),
with the stdlib itself as the strong refuter's differential oracle and a
seeded AST mutator building the defect models. Every number in RESULTS.md is
computed by the kernels from their own write-ahead journals on the named cut
[0, end-of-run]; nothing is declared.

WHAT THIS IS NOT: an LLM deployment study. The "generators" are simulated —
honest (correct code under cosmetic variation), sloppy (a latent mutant in
all k samples), unstable (behavior flips between samples). They exist to
exercise every gate; no claim about any model's defect rate follows.

Determinism: the clock is a counter and all randomness flows from seeds the
kernels issue or the bench derives. Two runs must agree on every number AND
on the hash of every serialized journal — the results record carries those
hashes, and tests/test_bench.py asserts full equality across two fresh runs.
"""
from __future__ import annotations

import ast
import copy
import functools
import hashlib
import json
import random
import statistics
import sys
import posixpath
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fcd.core import Enforcer, Policy
from fcd.journal import to_plain_json
from rga.calibration import CalibrationAuthority, CalibrationClass, CalibrationPolicy
from rga.core import (
    Admission, AdmissionPolicy, ClaimSpec, ClassAdmission, DefectModel,
    LedgerEntry, Refuter, derive_seed, sha256,
)

MASTER_SEED = 20260821


# ---------------------------------------------------------------- targets ----

MEDIAN_SRC = '''\
def median(data):
    xs = sorted(data)
    n = len(xs)
    if n == 0:
        raise ValueError("no data")
    mid = n // 2
    if n % 2 == 1:
        return xs[mid]
    return (xs[mid - 1] + xs[mid]) / 2
'''

WRAP_SRC = '''\
def wrap(text, width):
    words = text.split()
    lines = []
    line = ""
    for word in words:
        if not line:
            candidate = word
        else:
            candidate = line + " " + word
        if len(candidate) <= width:
            line = candidate
        else:
            if line:
                lines.append(line)
            line = word
    if line:
        lines.append(line)
    return lines
'''


NORMPATH_SRC = '''\
def normpath(path):
    if path == "":
        return "."
    initial_slashes = 1 if path.startswith("/") else 0
    if initial_slashes and path.startswith("//") and not path.startswith("///"):
        initial_slashes = 2
    comps = path.split("/")
    new_comps = []
    for comp in comps:
        if comp in ("", "."):
            continue
        if (comp != ".." or (not initial_slashes and not new_comps)
                or (new_comps and new_comps[-1] == "..")):
            new_comps.append(comp)
        elif new_comps:
            new_comps.pop()
    path = "/".join(new_comps)
    if initial_slashes:
        path = "/" * initial_slashes + path
    return path or "."
'''

QUANTILES_SRC = '''\
def quantiles(data):
    xs = sorted(data)
    n = len(xs)
    if n < 2:
        raise ValueError("need at least two data points")
    m = n - 1
    out = []
    for i in range(1, 4):
        j = i * m // 4
        delta = i * m - 4 * j
        out.append((xs[j] * (4 - delta) + xs[j + 1] * delta) / 4)
    return out
'''


def _compile(src: str, name: str):
    ns: dict = {}
    exec(compile(src, f"<{name}>", "exec"), ns)  # bench-local, bench-authored source only
    return ns[name]


def _median_inputs(rng: random.Random):
    n = rng.randint(1, 9)
    return [rng.randint(-50, 50) for _ in range(n)]


def _wrap_inputs(rng: random.Random):
    words = ["a" * rng.randint(1, 9) for _ in range(rng.randint(1, 10))]
    longest = max(len(w) for w in words)
    return (" ".join(words), rng.randint(longest, 25))  # spec domain: words fit


def median_properties(fn, args) -> list[str]:
    data = args
    r = fn(list(data))
    out = [f"value:{r!r}"]
    xs = sorted(data)
    if not (min(xs) <= r <= max(xs)):
        out.append("violated:range")
    if sum(1 for x in xs if x <= r) < len(xs) / 2 or sum(1 for x in xs if x >= r) < len(xs) / 2:
        out.append("violated:half-split")
    if fn(list(reversed(data))) != r:
        out.append("violated:permutation")
    return out


def median_differential(fn, args) -> list[str]:
    expected = statistics.median(list(args))
    got = fn(list(args))
    return [f"diff:{got!r}"] + ([] if got == expected else [f"violated:oracle:{expected!r}"])


def wrap_properties(fn, args) -> list[str]:
    text, width = args
    lines = fn(text, width)
    out = [f"value:{lines!r}"]
    if any(len(line) > width for line in lines):
        out.append("violated:width")
    if [w for line in lines for w in line.split()] != text.split():
        out.append("violated:content")
    if any(not line for line in lines):
        out.append("violated:empty-line")
    return out


def wrap_differential(fn, args) -> list[str]:
    text, width = args
    expected = textwrap.wrap(text, width)
    got = fn(text, width)
    return [f"diff:{got!r}"] + ([] if got == expected else [f"violated:oracle:{expected!r}"])


def _normpath_inputs(rng: random.Random):
    segments = ["a", "b", "cc", ".", "..", ""]
    body = "/".join(rng.choice(segments) for _ in range(rng.randint(0, 5)))
    return "/" * rng.choice([0, 0, 1, 1, 2, 3]) + body


def _quantiles_inputs(rng: random.Random):
    return [rng.randint(-60, 60) for _ in range(rng.randint(2, 12))]


def normpath_properties(fn, args) -> list[str]:
    path = args
    r = fn(path)
    out = [f"value:{r!r}"]
    if r == "":
        out.append("violated:empty")
    if fn(r) != r:
        out.append("violated:idempotent")
    parts = [c for c in r.split("/") if c]
    if r != "." and any(c == "." for c in parts):
        out.append("violated:dot-component")
    # `//` is a correct answer, not a trailing slash: POSIX leaves exactly two
    # leading slashes implementation-defined and normpath preserves them. An
    # all-slash result is therefore exempt -- without this the property refutes
    # the reference implementation itself.
    if len(r) > 1 and r.endswith("/") and set(r) != {"/"}:
        out.append("violated:trailing-slash")
    return out


def normpath_differential(fn, args) -> list[str]:
    expected = posixpath.normpath(args)
    got = fn(args)
    return [f"diff:{got!r}"] + ([] if got == expected else [f"violated:oracle:{expected!r}"])


def quantiles_properties(fn, args) -> list[str]:
    data = args
    r = fn(list(data))
    out = [f"value:{r!r}"]
    if len(r) != 3:
        out.append("violated:cutpoint-count")
    if any(b < a for a, b in zip(r, r[1:])):
        out.append("violated:monotone")
    if r and not (min(data) <= min(r) and max(r) <= max(data)):
        out.append("violated:range")
    if fn(list(reversed(data))) != r:
        out.append("violated:permutation")
    return out


def quantiles_differential(fn, args) -> list[str]:
    expected = statistics.quantiles(list(args), n=4, method="inclusive")
    got = fn(list(args))
    return [f"diff:{got!r}"] + ([] if got == expected else [f"violated:oracle:{expected!r}"])


TARGETS = {
    "median": {
        "src": MEDIAN_SRC, "fn": "median", "inputs": _median_inputs,
        "weak": (median_properties, 2), "strong": (median_properties, 4, median_differential),
    },
    "wrap": {
        "src": WRAP_SRC, "fn": "wrap", "inputs": _wrap_inputs,
        "weak": (wrap_properties, 2), "strong": (wrap_properties, 4, wrap_differential),
    },
    # Added as a harder tier. `median` and `wrap` are textbook exercises whose
    # reference implementations are near-certainly in any generator's training
    # data, which flatters every model and compresses the differences between
    # them. These two carry more behaviour per line -- path normalisation's
    # `..` and leading-slash rules, and quantile index arithmetic -- so a
    # defect has somewhere to hide.
    "normpath": {
        "src": NORMPATH_SRC, "fn": "normpath", "inputs": _normpath_inputs,
        "weak": (normpath_properties, 2),
        "strong": (normpath_properties, 4, normpath_differential),
    },
    "quantiles": {
        "src": QUANTILES_SRC, "fn": "quantiles", "inputs": _quantiles_inputs,
        "weak": (quantiles_properties, 2),
        "strong": (quantiles_properties, 4, quantiles_differential),
    },
}


# ---------------------------------------------------------------- refuters ----

def run_refuter(target: str, kind: str, artifact_src: bytes, seed: str) -> tuple[str, str]:
    """A pure function of (target spec, artifact bytes, seed): compile the
    candidate, draw N seeded inputs, evaluate the properties (and, for the
    strong refuter, the stdlib differential oracle). The witness is computed
    separately on a fixed probe set (B8) so it is seed-independent."""
    return run_refuter_n(target, kind, artifact_src, seed, None)


def run_refuter_n(target: str, kind: str, artifact_src: bytes, seed: str,
                  n_override: int | None) -> tuple[str, str]:
    spec = TARGETS[target]
    checks = spec[kind]
    props, n = checks[0], (checks[1] if n_override is None else n_override)
    extra = checks[2] if len(checks) > 2 else None
    rng = random.Random(f"{seed}|{target}|{kind}")
    outcomes: list[str] = []
    verdict = "survived"
    try:
        fn = _compile(artifact_src.decode(), spec["fn"])
        for _ in range(n):
            args = spec["inputs"](rng)
            for line in props(fn, args):
                outcomes.append(line)
                if line.startswith("violated:"):
                    verdict = "refuted"
            if extra is not None:
                for line in extra(fn, args):
                    outcomes.append(line)
                    if line.startswith("violated:"):
                        verdict = "refuted"
    except Exception as exc:  # a crashing candidate is a kill, not an error
        outcomes.append(f"violated:exception:{type(exc).__name__}")
        verdict = "refuted"
    return verdict, _claim_witness(target, artifact_src)


def _claim_witness(target: str, artifact_src: bytes) -> str:
    """B8: the witness is the canonical form of the claim-relevant
    observable — the candidate's outputs on a FIXED probe set, independent
    of the trial seed. Two behavioral twins (cosmetic variants) share a
    witness; two behaviorally different survivors do not. That is what
    makes concordance measurable and discord loud."""
    spec = TARGETS[target]
    rng = random.Random(f"probe|{target}")
    probes = [spec["inputs"](rng) for _ in range(16)]
    fingerprint: list[str] = []
    try:
        fn = _compile(artifact_src.decode(), spec["fn"])
        for args in probes:
            try:
                r = fn(*args) if isinstance(args, tuple) else fn(list(args))
                fingerprint.append(repr(r))
            except Exception as exc:
                fingerprint.append(f"raise:{type(exc).__name__}")
    except SyntaxError:
        fingerprint.append("unparseable")
    return sha256("\n".join(fingerprint).encode())


# ----------------------------------------------------------------- mutator ----

class _Mutator(ast.NodeTransformer):
    BIN = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.Add, ast.FloorDiv: ast.Sub}
    CMP = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt,
           ast.Eq: ast.NotEq, ast.NotEq: ast.Eq}

    def __init__(self, site: int):
        self.site, self.count = site, -1

    def _hit(self) -> bool:
        self.count += 1
        return self.count == self.site

    def visit_BinOp(self, node):
        self.generic_visit(node)
        if type(node.op) in self.BIN and self._hit():
            node.op = self.BIN[type(node.op)]()
        return node

    def visit_Compare(self, node):
        self.generic_visit(node)
        if len(node.ops) == 1 and type(node.ops[0]) in self.CMP and self._hit():
            node.ops = [self.CMP[type(node.ops[0])]()]
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, int) and not isinstance(node.value, bool) and self._hit():
            node.value = node.value + 1
        return node


def mutants(src: str) -> list[tuple[str, str]]:
    """All single-site mutants of src, in deterministic AST order."""
    out = []
    for site in range(200):
        tree = ast.parse(src)
        m = _Mutator(site)
        m.visit(tree)
        if m.count < site:
            break
        mutated = ast.unparse(tree)
        if mutated != ast.unparse(ast.parse(src)):
            out.append((f"m{site}", mutated))
    return out


def build_defect_model(target: str) -> tuple[str, list[tuple[str, str]], int]:
    """Mutants with a demonstrated killing witness (B5): a differing behavior
    against the correct implementation on a seeded input search. Mutants no
    search input separates are dropped as possibly equivalent and COUNTED."""
    spec = TARGETS[target]
    correct = _compile(spec["src"], spec["fn"])
    kept, dropped = [], 0
    for mid, msrc in mutants(spec["src"]):
        try:
            mfn = _compile(msrc, spec["fn"])
        except SyntaxError:
            dropped += 1
            continue
        rng = random.Random(f"witness|{target}|{mid}")
        witness_found = False
        for _ in range(400):
            args = spec["inputs"](rng)
            try:
                a = correct(*args) if isinstance(args, tuple) else correct(list(args))
                b = mfn(*args) if isinstance(args, tuple) else mfn(list(args))
                if a != b:
                    witness_found = True
                    break
            except Exception:
                witness_found = True
                break
        if witness_found:
            kept.append((mid, msrc))
        else:
            dropped += 1
    d_hash = sha256(json.dumps([(m, sha256(s.encode())) for m, s in kept]).encode())[:16]
    return f"D-{target}-{d_hash}", kept, dropped


# --------------------------------------------------------------- generators ----

@functools.lru_cache(maxsize=None)
def detectability(target: str, mid: str) -> float:
    """Estimated per-input kill probability of the strong refuter against
    this mutant, from 64 single-input draws on a held-out estimation seed.
    Selection metadata only — never enters any kernel record."""
    msrc = dict(mutants(TARGETS[target]["src"]))[mid]
    kills = 0
    for i in range(64):
        verdict, _ = run_refuter_n(target, "strong", msrc.encode(), f"det|{target}|{mid}|{i}", 1)
        kills += verdict == "refuted"
    return kills / 64


@functools.lru_cache(maxsize=None)
def subtle_mutants(target: str) -> tuple[tuple[str, str], ...]:
    """The killable-but-subtle tier: mutants IN the defect model (a killing
    witness exists) ordered by ascending detectability. Obvious bugs die at
    trial; the ones that seal — and later escape — are these."""
    _, kept, _ = build_defect_model(target)
    ranked = sorted(kept, key=lambda e: (detectability(target, e[0]), e[0]))
    return tuple(ranked[:3])


def generate(target: str, scenario: str, line_no: int, k: int) -> list[bytes]:
    """k samples per line. honest: correct code under cosmetic variation.
    sloppy: one latent mutant in every sample (an internalized bug).
    unstable: behavior flips between samples. Simulated, never an LLM."""
    spec = TARGETS[target]
    rng = random.Random(f"{MASTER_SEED}|{target}|{scenario}|{line_no}")
    pool = subtle_mutants(target)

    def cosmetic(src: str, i: int) -> bytes:
        return (src + f"\n# variant {rng.randint(0, 10**9)}-{i}\n").encode()

    if scenario == "honest":
        return [cosmetic(spec["src"], i) for i in range(k)]
    if scenario == "sloppy":
        _, msrc = pool[line_no % len(pool)]
        return [cosmetic(msrc, i) for i in range(k)]
    if scenario == "unstable":
        _, msrc = pool[line_no % len(pool)]
        return [cosmetic(spec["src"] if i % 2 == 0 else msrc, i) for i in range(k)]
    raise ValueError(scenario)


# -------------------------------------------------------------------- runner ----

K = 3
E_MAX = 1
LINES = {"honest": 8, "sloppy": 24, "unstable": 6}
ESCAPE_NONCES = 40


def run_target(target: str, generator=None) -> dict:
    """Drive all three layers over one target.

    `generator` is the seam a real model plugs into. It has `generate`'s
    signature and defaults to it, so the simulated path is unchanged; passing
    `eval.generators.corpus.replay_generator(model, target)` runs the same
    kernel, refuters and seeds against what a model actually wrote. Which one
    ran is recorded in the result, because a table that does not say where its
    samples came from is not a record of anything.
    """
    gen = generator if generator is not None else generate
    spec = TARGETS[target]
    clock_state = {"t": 0}

    def clock() -> float:
        clock_state["t"] += 1
        return float(clock_state["t"])

    counter = {"n": 0}

    def nonce() -> str:
        counter["n"] += 1
        return f"n{counter['n']}"

    cls = f"{target}-line"
    # Scenario counts come from the generator, not from the module constant.
    # A recorded corpus has no scenarios: honest/sloppy/unstable are how the
    # simulated generator is *built*, so applying them to recorded samples
    # would run three passes over the same lines and report the same split
    # three times, as if it were three findings.
    corpus_doc = getattr(gen, "corpus", None)
    if corpus_doc is None:
        lines_by_scenario = dict(LINES)
    else:
        lines_by_scenario = {
            "recorded": len({s["line"] for s in corpus_doc["samples"]})}
    scenarios = list(lines_by_scenario)
    fcd = Enforcer(Policy(
        allow={cls: {"gen", "rev"}}, deny={cls: set()},
        phi={"gen": "sim:generator", "rev": "sim:reviewer"},
        required={cls: [("write", f"s{i}") for i in range(K)] + [("check", "c1")]},
        version="bench-v1"), clock=clock)

    d_hash, entries, dropped = build_defect_model(target)
    refuters = {("spec-weak", "v1"): "weak", ("spec-strong", "v1"): "strong"}
    adm = Admission(fcd, AdmissionPolicy({cls: ClassAdmission(
        claims=(ClaimSpec("meets_spec", f"spec-{target}", frozenset(refuters), d_hash),),
        k=K, theta=1.0, p_min=0.3,
        excluded=frozenset({"refuter_source"}),
        residual=(("the implementation is idiomatic", "check_stage"),),
    )}, version=f"bench-{target}-r1"), clock=clock, nonce=nonce)
    cal = CalibrationAuthority(adm, CalibrationPolicy(
        {cls: CalibrationClass(e_max=E_MAX, demotion_gate="seal")}), clock=clock)

    # Measure: the kernel counts the kills from real runs over the mutant set.
    power = {}
    for key, kind in refuters.items():
        adm.declare(Refuter(key[0], key[1], author=f"{kind}-author", mode="ledger"))
        ledger = []
        for mid, msrc in entries:
            verdict, _ = run_refuter(target, kind, msrc.encode(), seed=f"calibration|{mid}")
            ledger.append(LedgerEntry(mid, "killed" if verdict == "refuted" else "survived"))
        rec = adm.measure(key[0], key[1], DefectModel(d_hash, "bench-mutator"), ledger)
        power[key] = {"kills": rec.kills, "size": rec.size, "power": round(rec.power, 4)}

    outcomes = {s: {"sealed": 0, "V1": 0, "V2": 0, "other": 0} for s in scenarios}
    sealed_lines: list[str] = []
    for scenario in scenarios:
        for line_no in range(lines_by_scenario[scenario]):
            iid = f"{target}-{scenario}-{line_no}"
            fcd.open(iid, cls, sha256(f"{iid}-contract".encode()))
            cal.open(iid, "gen", "sim:greedy")
            fault = None
            for i, sample_bytes in enumerate(gen(target, scenario, line_no, K)):
                fcd.admit(iid, "gen"); fcd.bind(iid, True)
                fcd.observe(iid, "sim:generator"); fcd.decide_pass(iid)
                adm.sample(iid, sample_bytes, {"contract"}, "sim:greedy")
                for key in sorted(refuters):
                    seed = adm.seed_for(iid, i, key[0], key[1], "meets_spec")
                    verdict, witness = run_refuter(target, refuters[key], sample_bytes, seed)
                    adm.trial(iid, key[0], key[1], "meets_spec", i, seed,
                              sha256(sample_bytes), verdict, witness)
                    if verdict == "survived":
                        v2, w2 = run_refuter(target, refuters[key], sample_bytes, seed)
                        adm.replay(iid, len(adm.lines[iid].trials) - 1, v2, w2)
                    else:
                        fault = "V1"
                        break
                if fault:
                    break
            if not fault:
                fcd.admit(iid, "rev"); fcd.bind(iid, True)
                fcd.observe(iid, "sim:reviewer"); fcd.decide_pass(iid)
                try:
                    cal.seal(iid)
                    sealed_lines.append(iid)
                    outcomes[scenario]["sealed"] += 1
                except ValueError:
                    f = adm.lines[iid].fault
                    outcomes[scenario][f if f in ("V1", "V2") else "other"] += 1
            else:
                outcomes[scenario]["V1"] += 1

    # Standing: hunt escapes on every sealed line with the pinned strong
    # refuter at fresh finder nonces (tier A: kernel-derived seeds).
    for iid in sealed_lines:
        seal = adm.sealed[iid]
        # the designated sample's bytes are regenerated deterministically
        scenario = iid.split("-")[1]
        line_no = int(iid.rsplit("-", 1)[1])
        src_bytes = gen(target, scenario, line_no, K)[0]
        if sha256(src_bytes) != seal.artifact_hash:   # not assert: -O must not strip it
            raise RuntimeError(f"regenerated bytes diverge from the seal on {iid}")
        for j in range(ESCAPE_NONCES):
            fnonce = f"finder-{iid}-{j}"
            seed = derive_seed(fnonce, seal.artifact_hash, "spec-strong", "v1", "meets_spec")
            verdict, witness = run_refuter(target, "strong", src_bytes, seed)
            if verdict == "refuted":
                run = cal.file_escape(iid, "meets_spec", "spec-strong", "v1", fnonce,
                                      src_bytes, seed, witness, finder="bench-auditor")
                v2, w2 = run_refuter(target, "strong", src_bytes, seed)
                cal.replay_run(run.index, v2, w2)
                break

    # The published numbers are kernel queries, not bench tallies: outcomes
    # from the rga journal (seal/close events), standing from the ledger's
    # own run records, with per-scenario identity so the prose about WHERE
    # escapes fell is computable, never asserted.
    def scenario_of(line_id: str) -> str:
        return line_id.split("-")[1]

    outcomes = {sc: {"sealed": 0, "V1": 0, "V2": 0, "other": 0} for sc in scenarios}
    for ev in adm.events:
        if ev["type"] == "rga_seal":
            outcomes[scenario_of(ev["work_item_id"])]["sealed"] += 1
        elif ev["type"] == "rga_close":
            f = ev.get("fault")
            outcomes[scenario_of(ev["work_item_id"])][f if f in ("V1", "V2") else "other"] += 1
    impeached_ids = sorted(iid for iid in sealed_lines if cal.impeached(iid))
    escapes = {
        "filed": sum(1 for r in cal.runs if r.tier == "A"),
        "established": sum(1 for r in cal.runs if r.established),
        "impeached_lines": len(impeached_ids),
        "impeached_by_scenario": {sc: sum(1 for i in impeached_ids if scenario_of(i) == sc)
                                  for sc in scenarios},
    }

    charges = {f"{k[0]}@{k[1]}": cal.charges(k[0], k[1], cls) for k in sorted(refuters)}
    demoted = {f"{k[0]}@{k[1]}": cal.demoted(k[0], k[1], cls) for k in sorted(refuters)}

    # The ratchet: a successor defect model must cover the escape corpus.
    corpus_ids = [cal.derived_defect_id(r) for r in cal.corpus(cls)]
    ratchet = {"corpus": len(corpus_ids), "installed": False}
    if corpus_ids:
        adm.declare(Refuter("spec-strong", "v2", "strong-author", "ledger"))
        ledger2 = []
        for mid, msrc in entries:
            verdict, _ = run_refuter(target, "strong", msrc.encode(), seed=f"cal2|{mid}")
            ledger2.append(LedgerEntry(mid, "killed" if verdict == "refuted" else "survived"))
        escape_kills = 0
        for r in cal.corpus(cls):
            scenario = r.line_id.split("-")[1]
            line_no = int(r.line_id.rsplit("-", 1)[1])
            ebytes = gen(target, scenario, line_no, K)[0]
            verdict, _ = run_refuter(target, "strong", ebytes, seed=f"cal2|{r.line_id}")
            ledger2.append(LedgerEntry(cal.derived_defect_id(r),
                                       "killed" if verdict == "refuted" else "survived"))
            escape_kills += verdict == "refuted"
        d2_hash = f"{d_hash}-succ"
        rec2 = adm.measure("spec-strong", "v2", DefectModel(d2_hash, "bench-mutator"), ledger2)
        cal.install(AdmissionPolicy({cls: ClassAdmission(
            claims=(ClaimSpec("meets_spec", f"spec-{target}", frozenset({("spec-strong", "v2")}), d2_hash),),
            k=K, theta=1.0, p_min=0.3, excluded=frozenset({"refuter_source"}),
            residual=(("the implementation is idiomatic", "check_stage"),),
        )}, version=f"bench-{target}-r2"))
        ratchet.update({"installed": True, "successor_power": round(rec2.power, 4),
                        "escape_kills_at_calibration_seed": escape_kills})

    journals = {"fcd": len(fcd.events), "rga": len(adm.events), "cal": len(cal.events),
                "hashes": {"fcd": sha256(json.dumps(to_plain_json(fcd.events)).encode()),
                           "rga": sha256(json.dumps(to_plain_json(adm.events)).encode()),
                           "cal": sha256(json.dumps(to_plain_json(cal.events)).encode())}}
    subtle = {mid: round(detectability(target, mid), 3) for mid, _ in subtle_mutants(target)}
    provenance = ({"kind": "simulated"} if corpus_doc is None else
                  {"kind": "recorded", "model": corpus_doc["model"],
                   "task_sha256": corpus_doc["task_sha256"],
                   "samples": corpus_doc["sample_count"],
                   "lines": lines_by_scenario["recorded"]})
    return {"target": target, "generator": provenance,
            "defect_model": {"hash": d_hash, "size": len(entries),
                                               "dropped_possibly_equivalent": dropped},
            "subtle_tier": subtle,
            "power": {f"{k[0]}@{k[1]}": v for k, v in power.items()},
            "union_composite": round(
                adm.sealed[sealed_lines[0]].claims[0].composite, 4) if sealed_lines else None,
            "outcomes": outcomes, "escapes": escapes, "charges": charges,
            "demoted": demoted, "ratchet": ratchet, "journals": journals,
            "cut": [0, clock_state["t"]]}


def run(generators: dict | None = None) -> dict:
    return {"master_seed": MASTER_SEED, "k": K, "e_max": E_MAX, "lines": LINES,
            "targets": {t: run_target(t, (generators or {}).get(t))
                        for t in TARGETS}}


def write_results(results: dict, path: Path) -> None:
    L = []
    A = L.append
    A("# Bench results: the admissibility kernel, end to end\n")
    A("Generated by `python3 eval/bench/bench.py --write`. Do not edit; re-run.\n")
    A("## What these numbers are\n")
    names = ", ".join(f"`{t}`" for t in results["targets"])
    count = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five"}.get(
        len(results["targets"]), str(len(results["targets"])))
    A("A deterministic evaluation of the three-layer kernel (identity, scrutiny,")
    A(f"standing) on reference implementations of {count} well-established stdlib")
    A(f"specifications — {names} (`wrap` on the domain")
    A("where words fit the width) — with the stdlib itself as the strong")
    A("refuter's differential oracle. Defect models are built by a seeded AST")
    A("mutator; every mutant admitted to a model carries a demonstrated killing")
    A("witness (B5), and mutants no search input separates are dropped and")
    A("counted. Every number below is computed from the kernels' write-ahead")
    A("journals and run records on the named cut — line outcomes from rga_seal/")
    A("rga_close events, standing from the calibration ledger's own runs and")
    A("queries; nothing is declared.\n")
    A("**What they are not.** The generators are simulated — honest (correct")
    A("code under cosmetic variation), sloppy (a latent subtle mutant in every")
    A("sample), unstable (behavior flips between samples). No claim about any")
    A("LLM's defect rate follows from this table; the bench evaluates the")
    A("*machinery* — that seals require survival, that discord and refutation")
    A("close loudly, that escapes impeach, charge, demote and ratchet.\n")
    A("## Setup\n")
    A("| knob | value |\n|---|---|")
    A(f"| master seed | `{results['master_seed']}` |")
    A(f"| k (samples per line) | {results['k']} |")
    A(f"| e_max (charge tolerance) | {results['e_max']} |")
    A(f"| lines per scenario | {results['lines']} |")
    A("| trial budgets | weak: 2 inputs/sample (properties), strong: 4 inputs/sample (properties + stdlib oracle) |")
    A("| escape search | pinned strong refuter, 40 finder nonces per sealed line, kernel-derived seeds |")
    A("| witness (B8) | outputs on a fixed 16-probe set — seed-independent, so cosmetic twins agree and behavioral twins do not |\n")
    for t, r in results["targets"].items():
        dm = r["defect_model"]
        A(f"## Target: `{t}`\n")
        A(f"Defect model `{dm['hash']}`: **{dm['size']}** mutants with a killing")
        A(f"witness; **{dm['dropped_possibly_equivalent']}** dropped as possibly equivalent.\n")
        A("### Carried power (kernel-counted, kills/|D|)\n")
        A("| refuter | kills | \\|D\\| | power |\n|---|---|---|---|")
        for name, p in r["power"].items():
            A(f"| `{name}` | {p['kills']} | {p['size']} | **{p['power']}** |")
        comp = r["union_composite"]
        A(f"\nUnion composite carried on seals: **{comp}**.\n")
        A("### Line outcomes\n")
        A("| scenario | sealed | V1 refuted | V2 discord | other |\n|---|---|---|---|---|")
        for sc, o in r["outcomes"].items():
            A(f"| {sc} | {o['sealed']} | {o['V1']} | {o['V2']} | {o['other']} |")
        e = r["escapes"]
        by_sc = e["impeached_by_scenario"]
        A("\n### Standing\n")
        where = ", ".join(f"{sc}: {n}" for sc, n in by_sc.items())
        A(f"- Escapes: **{e['filed']} filed, {e['established']} established**, "
          f"{e['impeached_lines']} lines impeached — by scenario: {where}.")
        A(f"- Charges: {r['charges']} — demoted: {r['demoted']} (e_max={results['e_max']}).")
        rt = r["ratchet"]
        if rt["installed"]:
            A(f"- Ratchet: corpus {rt['corpus']}; successor policy installed; successor power "
              f"**{rt['successor_power']}** (was {r['power']['spec-strong@v1']['power']}); "
              f"{rt['escape_kills_at_calibration_seed']}/{rt['corpus']} escaped artifacts "
              f"killed by the successor at its calibration seed. The successor is the SAME "
              f"checker code re-versioned and re-measured at fresh calibration seeds over "
              f"D ∪ corpus — the power movement is seed-roll and corpus growth, not a "
              f"better checker — and demotion charges do not carry across versions: what "
              f"the ratchet proves is coverage (C4), not improvement.")
        else:
            A(f"- Ratchet: corpus {rt['corpus']}; no install — no escapes, nothing owed.")
        j = r["journals"]
        A(f"- Journals on cut [{r['cut'][0]}, {r['cut'][1]}]: "
          f"fcd {j['fcd']}, rga {j['rga']}, cal {j['cal']} events.\n")
    A("## Reading\n")
    for t, r in results["targets"].items():
        o, e = r["outcomes"], r["escapes"]
        by_sc = e["impeached_by_scenario"]
        subtle = ", ".join(f"{m}: {d}" for m, d in r["subtle_tier"].items())
        A(f"- `{t}` — honest lines sealed {o['honest']['sealed']}/{results['lines']['honest']}; "
          f"subtle tier by estimated per-input detectability ({subtle}); sloppy lines "
          f"sealed with a latent defect {o['sloppy']['sealed']}/{results['lines']['sloppy']}, "
          f"refuted at trial {o['sloppy']['V1']}; unstable lines closed "
          f"V1 {o['unstable']['V1']} / V2 discord {o['unstable']['V2']}.")
        # These sentences are computed from the per-scenario impeachment
        # record, never asserted; whichever holds this run is what prints.
        impeached_sloppy = by_sc.get("sloppy", 0)
        impeached_rest = e["impeached_lines"] - impeached_sloppy
        if impeached_rest == 0 and impeached_sloppy == o["sloppy"]["sealed"]:
            A(f"  Every latent-defect seal was impeached ({impeached_sloppy}/"
              f"{o['sloppy']['sealed']}) and no honest or unstable seal was.")
        else:
            A(f"  Impeached seals by scenario: {by_sc} of "
              f"{{sc: sealed}} = {{'honest': {o['honest']['sealed']}, "
              f"'sloppy': {o['sloppy']['sealed']}, 'unstable': {o['unstable']['sealed']}}}.")
    A("- Obvious defects die at trial (V1); only the subtle tier can seal, and the")
    A("  pinned refuter at fresh nonces is what impeaches it. Where no subtle mutant")
    A("  exists, the escape search finds nothing — the pipeline does not manufacture")
    A("  escapes to have something to show.")
    A("- Detectability estimates are bench selection metadata; they never enter a")
    A("  kernel record. The kernel carries only what it counted.")
    A("")
    path.write_text("\n".join(L))


if __name__ == "__main__":
    results = run()
    if "--write" in sys.argv:
        write_results(results, Path(__file__).with_name("RESULTS.md"))
        print("wrote RESULTS.md")
    else:
        print(json.dumps(results, indent=1))
