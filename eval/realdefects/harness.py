"""Differential harness: does a real historical bug separate from its fix?

For each triaged candidate the buggy and fixed modules are loaded at their own
commits under this interpreter -- not the pinned 3.6-3.8 -- with unimportable
third-party modules stubbed. Both versions of the target function are then run
over the same generated inputs and their observable behaviour compared.

Identical stubs on both sides do NOT mean a stub cannot manufacture a
difference -- that only follows where the two versions use the stub the same
way. Where they do not, the stub is the whole cause: in `youtube-dl/11` the
fixed version's new `isinstance(int_str, compat_str)` touches the stub and
raises while the buggy version never touches it. An earlier revision of this
file stated the safe-sounding version as though it were a theorem; see
`eval/LOG.md`, "E8 -- Corrections after adversarial review".

Every negative is "not separated here", never "not a defect", and the two are
reported apart.
"""
from __future__ import annotations

import inspect
import json
import pathlib
import random
import sys
import types
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from triage import fetch  # noqa: E402

class _StubLoader:
    """Import hook: anything unimportable becomes a permissive mock.

    A utility function usually lives in a module that imports far more than it
    needs. Refusing the whole module because one unrelated import is missing
    would discard most of the corpus for no reason.
    """

    def find_module(self, name, path=None):
        return self

    def load_module(self, name):
        if name in sys.modules:
            return sys.modules[name]
        m = mock.MagicMock(name=name)
        m.__name__ = name
        m.__path__ = []
        m.__spec__ = None
        sys.modules[name] = m
        return m


def load_module(src: str, name: str, pkg: str = "") -> types.ModuleType | None:
    """Exec a module source under a synthetic package.

    `__package__` matters: a module that does `from .compat import x` cannot
    resolve it without one, and the failure happens in the import machinery
    before any stub hook is consulted. Registering a mock parent turns every
    relative import into a stub lookup like any other.
    """
    mod = types.ModuleType(name)
    mod.__dict__["__name__"] = name
    if pkg:
        # A REAL module, not a MagicMock: the import machinery reads the
        # parent's __spec__ when resolving `from .x import y`, and a mock
        # raises AttributeError for it before any stub hook is consulted.
        parent = types.ModuleType(pkg)
        parent.__path__ = []
        sys.modules[pkg] = parent
        mod.__dict__["__package__"] = pkg
        mod.__dict__["__path__"] = []
    hook = _StubLoader()
    sys.meta_path.append(hook)
    try:
        exec(compile(src, f"<{name}>", "exec"), mod.__dict__)
        return mod
    except Exception:
        return None
    finally:
        if hook in sys.meta_path:
            sys.meta_path.remove(hook)


# --------------------------------------------------------------- inputs ----

TEXTS = ["", "a", "hello world", "  padded  ", "a\nb", "Ünïcodé", "x" * 80,
         "<div class='t' hidden>p</div>", "<a href=x>y</a>", "a,b,,c",
         "http://e.com/p?q=1#f", "/a/../b", "1.2.3", "%41%42", "a\tb",
         "{'k': 1}", "[]", "null", "-0", "2020-01-02T03:04:05Z"]
NUMS = [0, 1, -1, 2, 3, 7, 10, 64, 80, 100, -5, 2**31]
LISTS = [[], [1], [1, 2, 3], ["a", "b"], [0, 0], list(range(5))]


def pool_for(param: inspect.Parameter, rng: random.Random):
    n = param.name.lower()
    ann = param.annotation
    if ann is int or n in {"width", "n", "count", "size", "length", "index",
                           "level", "depth", "limit", "timeout", "port"}:
        return rng.choice(NUMS)
    if ann is bool or n.startswith(("is_", "has_", "should_", "escape_")):
        return rng.choice([True, False])
    if ann is list or n in {"items", "options", "args", "values", "data",
                            "extensions", "parts", "lines"}:
        return rng.choice(LISTS)
    if ann is dict or n in {"kwargs", "mapping", "headers", "params"}:
        return rng.choice([{}, {"a": 1}, {"k": "v"}])
    return rng.choice(TEXTS)


def call_inputs(fn, rng: random.Random, trials: int):
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return []
    params = [p for p in sig.parameters.values()
              if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
              and p.name not in {"self", "cls"}]
    OPAQUE = {"command", "cmd", "response", "request", "spider", "crawler",
              "node", "leaf", "settings", "task", "obj", "conn", "loop",
              "parsed", "match", "line_obj", "form", "app", "client"}
    if not params or len(params) > 4:
        return []
    if any(p.name.lower() in OPAQUE and p.annotation is p.empty for p in params):
        return []   # inputs would be wrong-typed; a crash pair proves nothing
    return [tuple(pool_for(p, rng) for p in params) for _ in range(trials)]


def observe(fn, args):
    """Observable behaviour: a value, or the exception type and message."""
    try:
        return ("value", repr(fn(*args))[:400])
    except Exception as exc:
        return ("raise", f"{type(exc).__name__}: {str(exc)[:160]}")


# ---------------------------------------------------------------- study ----

def study(cand: dict, trials: int = 60) -> dict:
    out = dict(cand)
    srcs = {}
    for side, sha in (("buggy", cand["buggy"]), ("fixed", cand["fixed"])):
        s = fetch(cand["repo"], sha, cand["path"])
        if s is None:
            return {**out, "result": "fetch-failed"}
        srcs[side] = s
    if srcs["buggy"] == srcs["fixed"]:
        return {**out, "result": "identical-source"}

    fns = {}
    pristine = set(sys.modules)
    for side in ("buggy", "fixed"):
        pkg = cand["path"].split("/")[0] if "/" in cand["path"] else ""
        mod = load_module(srcs[side], f"m_{side}_{cand['project']}_{cand['bug']}", pkg)
        if mod is None:
            return {**out, "result": "module-exec-failed"}
        fn = getattr(mod, cand["symbol"], None)
        if not callable(fn):
            return {**out, "result": "symbol-missing"}
        fns[side] = fn
    for name in set(sys.modules) - pristine:
        sys.modules.pop(name, None)

    rng = random.Random(f"20260821|{cand['project']}|{cand['bug']}")
    args_list = call_inputs(fns["fixed"], rng, trials)
    if not args_list:
        return {**out, "result": "no-input-strategy"}

    separated, witness, both_raised, diverging_raise = 0, None, 0, 0
    for args in args_list:
        b, f = observe(fns["buggy"], args), observe(fns["fixed"], args)
        if b == f:
            continue
        if b[0] == "raise" and f[0] == "raise":
            # Both crashed, differently. Almost always our input was the wrong
            # type and the two versions merely touched a different attribute
            # first. Counted, never reported as a detection.
            both_raised += 1
            diverging_raise += 1
            continue
        separated += 1
        if witness is None:
            witness = {"args": [repr(a)[:90] for a in args], "buggy": b, "fixed": f}
    if not separated and diverging_raise > len(args_list) * 0.5:
        return {**out, "result": "input-type-mismatch", "trials": len(args_list)}
    return {**out, "result": "separated" if separated else "not-separated",
            "trials": len(args_list), "separated": separated,
            "both_raised": both_raised, "witness": witness}


def main() -> None:
    cands = [c for c in json.loads((ROOT / "manifest.json").read_text())
             if c["status"] == "candidate"]
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else len(cands)
    rows = []
    for i, c in enumerate(cands[:limit], 1):
        r = study(c)
        rows.append(r)
        print(f"[{i:>3}/{min(limit,len(cands))}] {c['project']}/{c['bug']:<4} "
              f"{c['symbol'][:34]:<34} {r['result']}"
              + (f"  {r.get('separated')}/{r.get('trials')}"
                 if r["result"] in ("separated", "not-separated") else ""),
              flush=True)
    (ROOT / "pilot-results.json").write_text(json.dumps(rows, indent=1))
    from collections import Counter
    print("\n=== results ===")
    for k, v in Counter(r["result"] for r in rows).most_common():
        print(f"  {v:>4}  {k}")


if __name__ == "__main__":
    main()
