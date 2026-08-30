"""Post-hoc characterisation of the E8 instrument.

Not part of the pre-registered metric. These are measurements of the harness
itself, made after the run and labelled as such, because the hand-adjudication
turned up two failure modes that the controls did not and that are worth
counting rather than anecdote.

1. Stubs used as *types*. `isinstance(x, compat_str)` with `compat_str` a mock
   raises TypeError regardless of what the mock returns -- so a value-
   substitution causal test cannot see it. How many candidates are exposed?
2. Candidates whose fixed side never returns a value on any generated input.
   NOTE, corrected after review: this does NOT mean they could not separate.
   The rule counts a separation when EITHER side returns and the other raises,
   and `youtube-dl/11` is in this list AND is one of the ten separations. The
   measurement is "the fixed side was never seen working", which is a weaker
   and different statement.
3. Candidates whose named function is byte-identical in both versions.
   `triage.py` maps NEW-file line numbers onto the OLD file, so where a patch
   inserts lines above the change the enclosing definition can be misread. A
   differential on such a candidate cannot show the fix, whatever it does.
"""
from __future__ import annotations

import ast
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from e8_harness import load_pair, e8_strategy, mocked_globals, observe   # noqa: E402
from search_harness import SEARCH                                            # noqa: E402
from hypothesis import given, settings, strategies as st               # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent


def type_position_names(src: str) -> set[str]:
    """Names used where a *class* is required, not merely a value."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return set()
    out: set[str] = set()

    def add(node):
        if isinstance(node, ast.Name):
            out.add(node.id)
        elif isinstance(node, ast.Tuple):
            for e in node.elts:
                add(e)
        elif isinstance(node, ast.Attribute):
            n = node
            while isinstance(n, ast.Attribute):
                n = n.value
            if isinstance(n, ast.Name):
                out.add(n.id)

    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in ("isinstance", "issubclass")
                and len(node.args) == 2):
            add(node.args[1])
        elif isinstance(node, ast.Compare):
            sides = [node.left] + list(node.comparators)
            if any(isinstance(s, ast.Call) and isinstance(s.func, ast.Name)
                   and s.func.id == "type" for s in sides):
                for s in sides:
                    add(s)
        elif isinstance(node, ast.ExceptHandler) and node.type is not None:
            add(node.type)
        elif isinstance(node, ast.ClassDef):
            for b in node.bases:
                add(b)
    return out


def function_ast(src: str, name: str):
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return ast.dump(n)
    return None


def exercised(fns, strategy) -> bool:
    """Did the fixed side ever return a value under this strategy?"""
    seen = {"value": False}

    @settings(SEARCH, max_examples=120)
    @given(strategy)
    def probe(args):
        if observe(fns["fixed"], args, None)[0] == "value":
            seen["value"] = True

    try:
        probe()
    except Exception:
        pass
    return seen["value"]


def main():
    cands = [c for c in json.loads((ROOT / "manifest.json").read_text())
             if c["status"] == "candidate"]
    e8 = {f"{r['project']}/{r['bug']}": r["result"]
          for r in json.loads((ROOT / "e8-results.json").read_text())}

    typed, never, identical = [], [], []
    for c in cands:
        key = f"{c['project']}/{c['bug']}"
        res = e8.get(key)
        fns, srcs, err = load_pair(c)
        if err:
            continue
        if function_ast(srcs["buggy"], c["symbol"]) == function_ast(
                srcs["fixed"], c["symbol"]):
            identical.append((key, c["symbol"], res))
        if res not in ("separated", "not-separated"):
            continue
        stubs = set(mocked_globals(fns["fixed"]))
        exposed = sorted(stubs & type_position_names(srcs["fixed"]))
        if exposed:
            typed.append((key, c["symbol"], res, exposed[:4]))
        strategy, _ = e8_strategy(fns["fixed"], srcs, c["symbol"])
        if strategy is not None and not exercised(fns, strategy):
            never.append((key, c["symbol"], res))
        print(f"  probed {key:<18}{res}", flush=True)

    n = sum(1 for r in e8.values() if r in ("separated", "not-separated"))
    print(f"\n=== stubs standing in for types ({len(typed)}/{n} testable) ===")
    print("    a mock in a type position raises TypeError whatever it returns,")
    print("    so substituting a different value cannot detect it.")
    print("    UPPER BOUND: this scans the whole module, not the named function;")
    print("    restricted to the function itself the count is 5 of 42.\n")
    for k, s, r, names in typed:
        print(f"  {k:<18}{s[:26]:<28}{r:<16}{', '.join(names)}")

    print(f"\n=== fixed side never seen returning a value ({len(never)}/{n}"
          f" testable) ===")
    print("    NOT the same as 'could not have separated': a separation counts")
    print("    when EITHER side returns. youtube-dl/11 is in this list and is")
    print("    one of the ten separations.\n")
    for k, s, r in never:
        print(f"  {k:<18}{s[:26]:<28}{r}")

    print(f"\n=== named function identical in both versions "
          f"({len(identical)}/{len(cands)} candidates) ===")
    print("    a differential on these cannot show the fix; they belong to a")
    print("    line-numbering fault in triage.py, not to the harness\n")
    for k, s, r in identical:
        print(f"  {k:<18}{s[:26]:<28}{r}")

    json.dump({"type_position": [list(t[:3]) + [t[3]] for t in typed],
               "never_exercised": [list(t) for t in never],
               "identical_function": [list(t) for t in identical]},
              open(ROOT / "e8-characterisation.json", "w"), indent=1)


if __name__ == "__main__":
    main()
