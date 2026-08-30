"""E8: decide artifacts by causation, and build records from both versions.

Every unimportable module is replaced by a permissive stub, so every value
reaching the code from outside is a value this harness invented. "Did the stub
cause this difference?" is therefore answerable by experiment rather than by
inspection: invent a *different* value and look again.

E5 asked whether the error text said "MagicMock". E7 asked whether a frame
mentioned a stubbed name. Both are proximity tests. This asks the question
itself -- a separation must survive substituting different stub answers.

MEASURED AFTERWARDS, AND THE REASON THIS FILE IS KEPT AS A RECORD RATHER THAN A
RECOMMENDATION: the rule is inert on this corpus. Over the full search across
all 42 testable candidates, 237 inputs passed R0 and R1 and R2 killed none of
them; a single-regime predicate agrees on 42/42. The dominant reason is that a
stub standing in a *type* position defeats value substitution completely --
`isinstance(x, MagicMock())` and `isinstance(x, Stand(""))` raise the
byte-identical message, so the regimes are indistinguishable rather than merely
uninformative. Nor is the invariance argument sound: substituting identically
on both sides can still manufacture a difference where the two versions use the
stub differently, and `Stand` implements fewer operators than `MagicMock`, so a
regime can acquire a difference of its own. See `eval/LOG.md`, "E8 --
Corrections after adversarial review".
"""
from __future__ import annotations

import ast
import copy
import inspect
import json
import pathlib
import random
import sys
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from harness import load_module                                # noqa: E402
from search_harness import (args_strategy, strategy_for, SEARCH,     # noqa: E402
                      WORDS, VALUES, urls, paths, texts)
from triage import fetch                                       # noqa: E402

from hypothesis import find                                     # noqa: E402
from hypothesis import strategies as st                         # noqa: E402
from hypothesis.errors import NoSuchExample, Unsatisfiable      # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent
MOCKS = (mock.MagicMock, mock.Mock, mock.NonCallableMagicMock, mock.NonCallableMock)


# ------------------------------------------------------ causal stub test ----

class Stand:
    """A stand-in with a fixed, known answer.

    Permissive like a mock -- callable, subscriptable, attribute-open -- but
    two stand-ins carrying the same value are indistinguishable. A mock
    fabricates a distinct identity for every access, so two sides holding
    "the same" mock render differently for no reason connected to the source.
    """

    __slots__ = ("_v",)

    def __init__(self, v):
        self._v = v

    def __call__(self, *a, **k):
        return self._v

    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)          # let dunder protocols fail
        return Stand(self._v)

    def __getitem__(self, key):
        return self._v

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0

    def __contains__(self, item):
        return False

    def __eq__(self, other):
        return isinstance(other, Stand) and other._v == self._v

    def __hash__(self):
        return hash(("Stand", self._v))

    def __repr__(self):
        return f"Stand({self._v!r})"

    def __str__(self):
        return str(self._v)

    def __bool__(self):
        return True


REGIMES = (None, "", "q")       # None = leave the mocks alone


def mocked_globals(fn) -> list[str]:
    """Names in the defining module's globals that are stubs."""
    g = getattr(fn, "__globals__", {})
    return [k for k, v in g.items() if isinstance(v, MOCKS)]


def observe(fn, args, value):
    """(kind, rendering) under one stub regime.

    `value is None` leaves the module as loaded. Otherwise every stubbed global
    is swapped for a stand-in answering `value` for the duration of the call,
    then restored -- the module is shared, so leaving it patched would change
    what a later observation sees.
    """
    g = getattr(fn, "__globals__", None)
    names = [] if (value is None or g is None) else mocked_globals(fn)
    saved = {n: g[n] for n in names}
    for n in names:
        g[n] = Stand(value)
    try:
        try:
            return ("value", repr(fn(*args))[:400])
        except Exception as exc:
            return ("raise", f"{type(exc).__name__}: {str(exc)[:160]}")
    finally:
        for n, v in saved.items():
            g[n] = v


def separates(a, b):
    """A separation must hold under every stub regime.

    Each side gets its own deep copy of the arguments (E7: a function that
    appends to its argument otherwise makes the second call see the first
    call's leftovers, and the measured difference is call order).
    """
    def pred(args):
        try:
            for value in REGIMES:
                oa = observe(a, copy.deepcopy(args), value)
                ob = observe(b, copy.deepcopy(args), value)
                if oa == ob:
                    return False                    # stub-dependent, or equal
                if oa[0] == "raise" and ob[0] == "raise":
                    return False                    # never counts
        except Exception:
            return False
        return True
    return pred


def regime_report(a, b, args) -> dict:
    """Per-regime outcomes, so a reader can see what the rule saw."""
    out = {}
    for value in REGIMES:
        key = "R0" if value is None else f"R{REGIMES.index(value)}({value!r})"
        out[key] = {"buggy": observe(a, copy.deepcopy(args), value),
                    "fixed": observe(b, copy.deepcopy(args), value)}
    return out


# ---------------------------------------------------- constructed objects ----

ATTR_STRATEGY = {
    "script": texts, "output": texts, "stdout": texts, "stderr": texts,
    "url": urls, "path": paths, "body": texts, "text": texts, "name": texts,
    "status": st.integers(100, 599), "code": st.integers(-5, 500),
    "script_parts": st.lists(st.sampled_from(WORDS), max_size=4),
    "parts": st.lists(st.sampled_from(WORDS), max_size=4),
    "args": st.lists(st.sampled_from(WORDS), max_size=4),
    "headers": st.dictionaries(st.sampled_from(WORDS), st.sampled_from(VALUES), max_size=3),
    "meta": st.dictionaries(st.sampled_from(WORDS), st.sampled_from(VALUES), max_size=3),
}


def attribute_names(module_src: str, symbol: str, param: str) -> set[str]:
    """Attributes the function body reads off `param`, from the source itself."""
    try:
        tree = ast.parse(module_src)
    except SyntaxError:
        return set()
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != symbol:
            continue
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name)
                    and sub.value.id == param):
                found.add(sub.attr)
    return found


class Record:
    """A plain carrier. Not a mock: a mock answers everything and would make
    both sides agree on nonsense, which hides differences rather than showing
    them."""

    def __repr__(self):
        return f"Record({', '.join(f'{k}={v!r}' for k, v in vars(self).items())})"


def record_strategy(names: list[str]):
    per = {n: ATTR_STRATEGY.get(n, texts) for n in names}

    @st.composite
    def build(draw):
        obj = Record()
        for n, s in per.items():
            setattr(obj, n, draw(s))
        return obj
    return build()


OPAQUE = {"command", "cmd", "response", "request", "spider", "crawler",
          "node", "leaf", "settings", "task", "obj", "conn", "loop",
          "parsed", "match", "line_obj", "form", "app", "client"}


def args_strategy_single(param):
    if param.name.lower() in OPAQUE and param.annotation is param.empty:
        return None
    return strategy_for(param)


def e8_strategy(fn, srcs: dict, symbol: str):
    """Inputs for `fn`, constructing opaque parameters from *both* sources.

    E7 built records from the fixed source only, and scored a candidate as
    separated because the buggy version reads an attribute the fixed one does
    not -- so the buggy side raised AttributeError on a field that was never
    there. The union is what either version might read.
    """
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return None, "no-signature"
    params = [p for p in sig.parameters.values()
              if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
              and p.name not in {"self", "cls"}]
    if not params or len(params) > 4:
        return None, "no-input-strategy"
    plain = args_strategy(fn)
    if plain is not None:
        return plain, None
    per = []
    for p in params:
        s = args_strategy_single(p)
        if s is not None:
            per.append(s)
            continue
        names = (attribute_names(srcs["fixed"], symbol, p.name)
                 | attribute_names(srcs["buggy"], symbol, p.name))
        if not names:
            return None, "no-attributes-named"
        per.append(record_strategy(sorted(names)))
    return st.tuples(*per), None


# ------------------------------------------------------------------- run ----

def load_pair(cand):
    srcs = {}
    for side, sha in (("buggy", cand["buggy"]), ("fixed", cand["fixed"])):
        s = fetch(cand["repo"], sha, cand["path"])
        if s is None:
            return None, None, "fetch-failed"
        srcs[side] = s
    if srcs["buggy"] == srcs["fixed"]:
        return None, None, "identical-source"
    fns = {}
    pkg = cand["path"].split("/")[0] if "/" in cand["path"] else ""
    for side in ("buggy", "fixed"):
        m = load_module(srcs[side], f"m5_{side}_{cand['project']}_{cand['bug']}", pkg)
        if m is None:
            return None, None, "module-exec-failed"
        fn = getattr(m, cand["symbol"], None)
        if not callable(fn):
            return None, None, "symbol-missing"
        fns[side] = fn
    return fns, srcs, None


def study(cand, negative_control=False):
    out = dict(cand)
    fns, srcs, err = load_pair(cand)
    if err:
        return {**out, "result": err}
    strategy, why = e8_strategy(fns["fixed"], srcs, cand["symbol"])
    if strategy is None:
        return {**out, "result": why}
    left = fns["fixed"] if negative_control else fns["buggy"]
    try:
        w = find(strategy, separates(left, fns["fixed"]), settings=SEARCH)
    except (NoSuchExample, Unsatisfiable):
        return {**out, "result": "not-separated",
                "stubs": len(mocked_globals(fns["fixed"]))}
    except Exception as exc:
        return {**out, "result": f"search-error: {type(exc).__name__}"}
    return {**out, "result": "separated",
            "stubs": len(mocked_globals(fns["fixed"])),
            "witness": {"args": [repr(a)[:110] for a in w],
                        "regimes": regime_report(left, fns["fixed"], w)}}


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    cands = [c for c in json.loads((ROOT / "manifest.json").read_text())
             if c["status"] == "candidate"]
    if only:
        cands = [c for c in cands if f"{c['project']}/{c['bug']}" == only]
    rows = []
    for i, c in enumerate(cands, 1):
        r = study(c)
        rows.append(r)
        mark = "  <== SEPARATED" if r["result"] == "separated" else ""
        print(f"[{i:>3}/{len(cands)}] {c['project']}/{c['bug']:<4} "
              f"{c['symbol'][:30]:<30} {r['result']}{mark}", flush=True)
    if only:
        print(json.dumps(rows, indent=1)[:4000])
        return
    (ROOT / "e8-results.json").write_text(json.dumps(rows, indent=1))

    testable = [r for r in rows if r["result"] in ("separated", "not-separated")]
    rng = random.Random(20260829)
    pool = [c for c in cands
            if any(r["project"] == c["project"] and r["bug"] == c["bug"]
                   and r["result"] in ("separated", "not-separated") for r in rows)]
    print("\n=== negative control: fixed vs fixed ===")
    bad = 0
    for c in rng.sample(pool, min(15, len(pool))):
        if study(c, negative_control=True)["result"] == "separated":
            bad += 1
            print(f"  VOID: {c['project']}/{c['bug']} separated against itself")
    print(f"  {min(15, len(pool))} checked, {bad} spurious -> "
          f"{'VOID' if bad else 'clean'}")

    pos = [r for r in rows if f"{r['project']}/{r['bug']}" == "youtube-dl/20"]
    print("\n=== positive control: youtube-dl/20 ===")
    print(f"  {pos[0]['result'] if pos else 'ABSENT'} -> "
          f"{'pass' if pos and pos[0]['result'] == 'separated' else 'FAIL'}")

    from collections import Counter
    print("\n=== results ===")
    for k, v in Counter(r["result"] for r in rows).most_common():
        print(f"  {v:>4}  {k}")
    sep = [r for r in rows if r["result"] == "separated"]
    print(f"\ntestable {len(testable)} (E5: 34, E7: 42) | separated {len(sep)} "
          f"| rate {len(sep)/max(1,len(testable))*100:.1f}%")
    print("  Do not quote this as a detection rate. E5 read 20.6% and E7 19.0%;")
    print("  neither is reportable, and the three-regime rule that distinguishes")
    print("  this run from E5 was measured afterwards and does not fire at all.")
    print("  Read eval/LOG.md and the README before using any of these numbers.")


if __name__ == "__main__":
    main()
