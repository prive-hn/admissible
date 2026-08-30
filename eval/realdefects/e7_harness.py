"""E7: build the objects these functions take, and identify artifacts by cause.

Two changes from E5, both pre-registered:

1. A parameter the harness used to refuse is constructed from the function's
   own body -- the attributes it names become the fields of a plain object.
   Both sides get the same object, so construction can mask a difference but
   never manufacture one.
2. An artifact is decided by what caused the outcome, not by what the error
   message says. E5 matched the string "MagicMock" and therefore missed a
   stub-induced TypeError that named no mock.
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


# ------------------------------------------------------- artifact by cause ----

def implicated_mock(exc: BaseException) -> bool:
    """Whether a stub is implicated in this failure.

    The pre-registration says "walk the traceback and treat it as an artifact
    if any frame's locals or globals hold a mock". Read literally that flags
    every failure in a stubbed module, since the module globals are full of
    stubs by construction. The intent is narrower and is what is implemented:
    a stub is implicated when the *failing code object itself references* a
    name that resolves to a mock, or when a mock is among that frame's locals.
    """
    tb = exc.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        for value in frame.f_locals.values():
            if isinstance(value, MOCKS):
                return True
        for name in frame.f_code.co_names:
            if isinstance(frame.f_globals.get(name), MOCKS):
                return True
        tb = tb.tb_next
    return False


def contains_mock(value) -> bool:
    if isinstance(value, MOCKS):
        return True
    if isinstance(value, (list, tuple, set)):
        return any(contains_mock(v) for v in value)
    if isinstance(value, dict):
        return any(contains_mock(v) for v in value.values())
    return False


def observe(fn, args):
    """(kind, rendering, artifact?) — artifact decided at the point of failure."""
    try:
        out = fn(*args)
    except Exception as exc:
        return ("raise", f"{type(exc).__name__}: {str(exc)[:160]}", implicated_mock(exc))
    return ("value", repr(out)[:400], contains_mock(out))


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


def attribute_names(module_src: str, symbol: str, param: str) -> list[str]:
    """Attributes the function body reads off `param`, from the source itself."""
    try:
        tree = ast.parse(module_src)
    except SyntaxError:
        return []
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
    return sorted(found)


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


def e6_strategy(fn, module_src: str, symbol: str):
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
    # Refused by E5. Try to construct the opaque parameters from the body.
    per = []
    for p in params:
        s = args_strategy_single(p)
        if s is not None:
            per.append(s)
            continue
        names = attribute_names(module_src, symbol, p.name)
        if not names:
            return None, "no-attributes-named"
        per.append(record_strategy(names))
    return st.tuples(*per), None


def args_strategy_single(param):
    OPAQUE = {"command", "cmd", "response", "request", "spider", "crawler",
              "node", "leaf", "settings", "task", "obj", "conn", "loop",
              "parsed", "match", "line_obj", "form", "app", "client"}
    if param.name.lower() in OPAQUE and param.annotation is param.empty:
        return None
    return strategy_for(param)


# ------------------------------------------------------------------- run ----

def separates(a, b):
    def pred(args):
        # Each side gets its own copy. E6 was voided because a function that
        # appends to one of its arguments made the second call see the first
        # call's leftovers, and the measured difference was call order.
        try:
            oa, ob = observe(a, copy.deepcopy(args)), observe(b, copy.deepcopy(args))
        except Exception:
            return False
        if oa[:2] == ob[:2]:
            return False
        if oa[0] == "raise" and ob[0] == "raise":
            return False                      # never counts
        if oa[2] or ob[2]:
            return False                      # a stub is implicated
        return True
    return pred


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
        m = load_module(srcs[side], f"m3_{side}_{cand['project']}_{cand['bug']}", pkg)
        if m is None:
            return None, None, "module-exec-failed"
        fn = getattr(m, cand["symbol"], None)
        if not callable(fn):
            return None, None, "symbol-missing"
        fns[side] = fn
    return fns, srcs["fixed"], None


def study(cand, negative_control=False):
    out = dict(cand)
    fns, fixed_src, err = load_pair(cand)
    if err:
        return {**out, "result": err}
    strategy, why = e6_strategy(fns["fixed"], fixed_src, cand["symbol"])
    if strategy is None:
        return {**out, "result": why}
    left = fns["fixed"] if negative_control else fns["buggy"]
    try:
        w = find(strategy, separates(left, fns["fixed"]), settings=SEARCH)
        mutates = _mutates(fns["fixed"], w)
    except (NoSuchExample, Unsatisfiable):
        return {**out, "result": "not-separated"}
    except Exception as exc:
        return {**out, "result": f"search-error: {type(exc).__name__}"}
    return {**out, "result": "separated", "mutates_args": mutates,
            "witness": {"args": [repr(a)[:110] for a in w],
                        "buggy": observe(left, copy.deepcopy(w)),
                        "fixed": observe(fns["fixed"], copy.deepcopy(w))}}


def _mutates(fn, args) -> bool:
    """Whether calling `fn` changes its own arguments — counted, per E7."""
    probe = copy.deepcopy(args)
    before = repr(probe)
    try:
        fn(*probe)
    except Exception:
        pass
    return repr(probe) != before


def main():
    cands = [c for c in json.loads((ROOT / "manifest.json").read_text())
             if c["status"] == "candidate"]
    rows = []
    for i, c in enumerate(cands, 1):
        r = study(c)
        rows.append(r)
        mark = "  <== SEPARATED" if r["result"] == "separated" else ""
        print(f"[{i:>3}/{len(cands)}] {c['project']}/{c['bug']:<4} "
              f"{c['symbol'][:30]:<30} {r['result']}{mark}", flush=True)
    (ROOT / "e7-results.json").write_text(json.dumps(rows, indent=1))

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

    from collections import Counter
    print("\n=== results ===")
    for k, v in Counter(r["result"] for r in rows).most_common():
        print(f"  {v:>4}  {k}")
    sep = [r for r in rows if r["result"] == "separated"]
    print(f"\ntestable {len(testable)} (E5: 34) | separated {len(sep)} "
          f"| rate {len(sep)/max(1,len(testable))*100:.1f}% (E5 confirmed: 20.6%)")


if __name__ == "__main__":
    main()
