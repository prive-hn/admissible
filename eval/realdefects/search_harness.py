"""E5: search for a separating input instead of sampling for one.

The pilot (E4) drew inputs uniformly from fixed pools and found 3 of 34. Its
own positive control proved that was a generator limit, not a detection rate:
`youtube-dl/20` separates 40/40 by hand and 0/60 under that generator.

So the inputs become a *search*. Hypothesis shrinks toward and hunts for values
satisfying a predicate, and "the two versions disagree" is a predicate. Nothing
here is written for any particular bug: strategies are chosen from the
signature, and the same rules apply to every candidate. Tuning a strategy until
the positive control passes would destroy the control, so it is not done.
"""
from __future__ import annotations

import json
import inspect
import pathlib
import sys
import random

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from harness import load_module, observe                      # noqa: E402
from triage import fetch                                      # noqa: E402

from hypothesis import HealthCheck, Verbosity, find, settings  # noqa: E402
from hypothesis import strategies as st                        # noqa: E402
from hypothesis.errors import NoSuchExample, Unsatisfiable     # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent
SEARCH = settings(max_examples=300, deadline=None, database=None,
                  derandomize=True,          # else each run reseeds from OS
                  verbosity=Verbosity.quiet, # entropy and no witness reproduces
                  suppress_health_check=list(HealthCheck))

ATTRS = ["class", "id", "href", "data-x", "hidden", "itemprop", "checked"]
VALUES = ["a", "target", "1", "x y", ""]
WORDS = ["a", "bb", "ccc", "x.y", "..", ".", "-", "_"]


@st.composite
def html_docs(draw):
    """Elements whose attributes may be valueless.

    A bare attribute (`<div hidden>`) is ordinary HTML, so it belongs in any
    honest generator for this shape. It is included because HTML has it, not
    because a particular bug needs it.
    """
    tag = draw(st.sampled_from(["div", "span", "a", "p"]))
    attrs = draw(st.lists(st.tuples(st.sampled_from(ATTRS),
                                    st.one_of(st.none(), st.sampled_from(VALUES))),
                          max_size=3))
    rendered = "".join(
        f" {k}" if v is None else f' {k}="{v}"' for k, v in attrs)
    body = draw(st.sampled_from(["", "text", "payload", "<b>i</b>"]))
    return f"<{tag}{rendered}>{body}</{tag}>", attrs


paths = st.builds(
    lambda lead, segs: "/" * lead + "/".join(segs),
    st.integers(0, 3), st.lists(st.sampled_from(WORDS), max_size=4))
urls = st.builds(
    lambda s, h, p, q: f"{s}://{h}{p}{q}",
    st.sampled_from(["http", "https", ""]), st.sampled_from(["e.com", "a.b.c", ""]),
    st.sampled_from(["", "/p", "/a/../b"]), st.sampled_from(["", "?q=1", "#f"]))
texts = st.one_of(
    st.text(max_size=30), st.sampled_from(
        ["", " ", "a b", "a,b,,c", "%41", "1.2.3", "-0", "2020-01-02T03:04:05Z",
         "a\tb", "a\nb", "\\", "'q'", '"q"', "0x1f", "1e5"]),
    paths, urls, st.builds(lambda hd: hd[0], html_docs()))


def strategy_for(param: inspect.Parameter):
    n = param.name.lower()
    ann = param.annotation
    if ann is int or n in {"width", "n", "count", "size", "length", "index",
                           "level", "depth", "limit", "timeout", "port", "base"}:
        return st.integers(-8, 128)
    if ann is bool or n.startswith(("is_", "has_", "should_", "escape_", "strict")):
        return st.booleans()
    if ann is list or n in {"items", "options", "args", "values", "data",
                            "extensions", "parts", "lines", "keys"}:
        return st.lists(st.one_of(st.integers(-20, 20), st.sampled_from(WORDS)),
                        max_size=5)
    if ann is dict or n in {"kwargs", "mapping", "headers", "params", "query"}:
        return st.dictionaries(st.sampled_from(WORDS),
                               st.sampled_from(VALUES), max_size=3)
    if "html" in n or "markup" in n or n in {"page", "document", "body"}:
        return st.builds(lambda hd: hd[0], html_docs())
    if "url" in n or "uri" in n or "link" in n:
        return urls
    if "path" in n or "file" in n or n in {"p", "name", "basename"}:
        return paths
    return texts


DOCUMENT = {"html", "markup", "page", "document", "body", "text", "s", "string"}
KEYLIKE = {"attribute", "attr", "key", "name", "tag", "field"}
VALUELIKE = {"value", "val", "content"}


@st.composite
def correlated(draw, params):
    """Draw a document first, then draw the query out of it.

    A general rule, applied to every signature that has a document-shaped
    parameter alongside key- or value-shaped ones: independent draws almost
    never produce a key that occurs in the document, so a query function is
    tested only on its miss path. Nothing about this is specific to one bug --
    any lookup-in-a-document signature has the same problem.
    """
    doc, attrs = draw(html_docs())
    picked = draw(st.sampled_from(attrs)) if attrs else (draw(st.sampled_from(ATTRS)), None)
    out = []
    for p in params:
        n = p.name.lower()
        if n in DOCUMENT:
            out.append(doc)
        elif n in KEYLIKE:
            out.append(picked[0])
        elif n in VALUELIKE:
            out.append("" if picked[1] is None else picked[1])
        else:
            out.append(draw(strategy_for(p)))
    return tuple(out)


def args_strategy(fn):
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return None
    params = [p for p in sig.parameters.values()
              if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
              and p.name not in {"self", "cls"}]
    OPAQUE = {"command", "cmd", "response", "request", "spider", "crawler",
              "node", "leaf", "settings", "task", "obj", "conn", "loop",
              "parsed", "match", "line_obj", "form", "app", "client"}
    if not params or len(params) > 4:
        return None
    if any(p.name.lower() in OPAQUE and p.annotation is p.empty for p in params):
        return None
    names = {p.name.lower() for p in params}
    if names & DOCUMENT and names & (KEYLIKE | VALUELIKE):
        return correlated(params)
    return st.tuples(*(strategy_for(p) for p in params))


def stubbed(observation) -> bool:
    """A witness mentioning a mock is an artifact, per the pre-registered rule."""
    return "MagicMock" in observation[1] or "Mock name=" in observation[1]


def separates(a, b):
    """The pre-registered adjudication rule, and only it."""
    def pred(args):
        try:
            oa, ob = observe(a, args), observe(b, args)
        except Exception:
            return False
        if oa == ob:
            return False
        if oa[0] == "raise" and ob[0] == "raise":
            return False                      # never counts
        if stubbed(oa) or stubbed(ob):
            return False                      # artifact
        return True
    return pred


def load_pair(cand):
    srcs = {}
    for side, sha in (("buggy", cand["buggy"]), ("fixed", cand["fixed"])):
        s = fetch(cand["repo"], sha, cand["path"])
        if s is None:
            return None, "fetch-failed"
        srcs[side] = s
    if srcs["buggy"] == srcs["fixed"]:
        return None, "identical-source"
    fns = {}
    pkg = cand["path"].split("/")[0] if "/" in cand["path"] else ""
    for side in ("buggy", "fixed"):
        mod = load_module(srcs[side], f"m2_{side}_{cand['project']}_{cand['bug']}", pkg)
        if mod is None:
            return None, "module-exec-failed"
        fn = getattr(mod, cand["symbol"], None)
        if not callable(fn):
            return None, "symbol-missing"
        fns[side] = fn
    return fns, None


def study(cand, negative_control=False):
    out = dict(cand)
    fns, err = load_pair(cand)
    if err:
        return {**out, "result": err}
    strategy = args_strategy(fns["fixed"])
    if strategy is None:
        return {**out, "result": "no-input-strategy"}
    left = fns["fixed"] if negative_control else fns["buggy"]
    try:
        witness = find(strategy, separates(left, fns["fixed"]), settings=SEARCH)
    except (NoSuchExample, Unsatisfiable):
        return {**out, "result": "not-separated"}
    except Exception as exc:
        return {**out, "result": f"search-error: {type(exc).__name__}"}
    return {**out, "result": "separated",
            "witness": {"args": [repr(a)[:100] for a in witness],
                        "buggy": observe(left, witness),
                        "fixed": observe(fns["fixed"], witness)}}


def main():
    cands = [c for c in json.loads((ROOT / "manifest.json").read_text())
             if c["status"] == "candidate"]
    rows = []
    for i, c in enumerate(cands, 1):
        r = study(c)
        rows.append(r)
        mark = "  <== SEPARATED" if r["result"] == "separated" else ""
        print(f"[{i:>3}/{len(cands)}] {c['project']}/{c['bug']:<4} "
              f"{c['symbol'][:32]:<32} {r['result']}{mark}", flush=True)
    (ROOT / "e5-results.json").write_text(json.dumps(rows, indent=1))

    print("\n=== negative control: fixed vs fixed on a random sample ===")
    rng = random.Random(20260829)
    sample = rng.sample([c for c in cands], 12)
    bad = 0
    for c in sample:
        r = study(c, negative_control=True)
        if r["result"] == "separated":
            bad += 1
            print(f"  VOID: {c['project']}/{c['bug']} separated against itself")
    print(f"  {len(sample)} checked, {bad} spurious separations"
          f" -> {'VOID' if bad else 'clean'}")

    from collections import Counter
    print("\n=== results ===")
    for k, v in Counter(r["result"] for r in rows).most_common():
        print(f"  {v:>4}  {k}")


if __name__ == "__main__":
    main()
