"""E8 hand-adjudication of the not-separated arm.

For each sampled candidate the harness called `not-separated`, construct an
input by hand from the fix patch and run both versions on it. A separation
here is a harness false negative; no separation is a correct negative.

These inputs are written by reading the patch, which is exactly what the
harness is not allowed to do. That is the point: it measures how much of
"not separated" is "no difference" and how much is "not reached".
"""
from __future__ import annotations

import copy
import json
import pathlib
import sys
from types import FunctionType

from lxml import html

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from e8_harness import load_pair, observe            # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent
CANDS = {f"{c['project']}/{c['bug']}": c
         for c in json.loads((ROOT / "manifest.json").read_text())
         if c["status"] == "candidate"}


class Form:
    """Enough of an lxml form element for `_get_form_url` (scrapy/7)."""

    def __init__(self, base_url, action, present=True):
        self.base_url = base_url
        self.action = action
        self._present = present

    def get(self, key, default=None):
        if key == "action" and self._present:
            return self.action
        return default


HAND = {
    # patch: `return compat_chr(int(numstr, base))`
    #     -> the same wrapped in try/except ValueError. A codepoint out of
    #        range makes the real chr() raise; the fix falls through to the
    #        literal form.
    "youtube-dl/28": [("#x110000",), ("#1114112",)],

    # patch: get_unique_filename now trims to the filesystem's name limit.
    #        `exists` is a callable parameter; the harness only ever passes
    #        a string to it.
    "httpie/1": [("a" * 300, lambda p: False)],

    # patch: _match_one learns quoted string values.
    "youtube-dl/22": [('title = "foo bar"', {"title": "foo bar"}),
                      ("title = 'foo bar'", {"title": "foo bar"})],

    # patch: _match_one compares a numeric literal as a string when the
    #        field itself is a string.
    "youtube-dl/24": [("x = 10", {"x": "10"}), ("id != 42", {"id": "42"})],

    # patch: image inputs become clickable controls. A real lxml element makes
    #        the XPath behavior executable rather than argued from source.
    "scrapy/38": [(None, html.fromstring(
        "<form><input type='image' name='go' value='Go'></form>")),
    ],
}

NOT_ADJUDICABLE = {
    # The manifest names `_urlencode` for this bug, but the patch changes
    # `_get_form_url`; triage.py matched NEW-file line numbers against the OLD
    # file and a 3-line import insertion shifted them. Running a hand-built
    # form object through `_urlencode` produces a TypeError on both sides and
    # is evidence for nothing. What settles the verdict is that `_urlencode`
    # is byte-identical in both versions, so no input can separate it.
    "scrapy/7": "the manifest names a function the patch does not change "
                "(`_urlencode`, byte-identical in both versions); the patch "
                "changes `_get_form_url`. A correct negative, established by "
                "reading the two sources, not by running anything.",
}

class Rec:
    """A consistent domain object, written by hand from the fix."""

    def __init__(self, **kw):
        self.__dict__.update(kw)

    def __repr__(self):
        return f"Record({', '.join(f'{k}={v!r}' for k, v in vars(self).items())})"


# The two candidates the search found on a degenerate witness and the log
# initially adjudicated "not the defect". These are the in-precondition inputs
# written afterwards, carried here so the correction is executed rather than
# described. Each side gets its own deep copy: `get_new_command` appends to
# `command.script_parts`, and run naively both sides share one object -- which
# is the fault that voided E6.
HAND_SEPARATED = {
    "thefuck/10": [(Rec(script="man ls", script_parts=["man", "ls"], stderr=""),),
                   (Rec(script="man ls", script_parts=["man", "ls"],
                        stderr="No manual entry for ls"),)],
    "thefuck/20": [(Rec(script='unzip "a b.zip"',
                        split_script=["unzip", "a b.zip"]),)],
}


# Every intended case is executable in the pinned development environment.
# Keeping the category lets a missing future dependency fail closed in `main`.
ARGUED_ONLY: dict[str, str] = {}


REAL_DEPENDENCIES = {
    "youtube-dl/24": {"compat_str": str},
    "youtube-dl/28": {"compat_chr": chr},
}


def bind_real_dependencies(key: str, functions: dict[str, FunctionType]) -> None:
    """Bind real stdlib primitives where stubbing hides the documented fix."""
    for name, value in REAL_DEPENDENCIES.get(key, {}).items():
        for function in functions.values():
            function.__globals__[name] = value


def main() -> int:
    summary = {
        "executed": 0,
        "separated": 0,
        "expected_negative": 0,
        "not_run": 0,
        "failed": 0,
    }
    for key in (list(HAND) + list(HAND_SEPARATED) + list(ARGUED_ONLY)
                + list(NOT_ADJUDICABLE)):
        cand = CANDS[key]
        print("=" * 78)
        print(f"{key}  {cand['symbol']}  ({cand['path']})")
        if key in NOT_ADJUDICABLE:
            summary["expected_negative"] += 1
            print(f"  NOT ADJUDICABLE BY RUNNING: {NOT_ADJUDICABLE[key]}")
            continue
        if key in ARGUED_ONLY:
            summary["not_run"] += 1
            summary["failed"] += 1
            print(f"  NOT RUN: {ARGUED_ONLY[key]}")
            continue
        fns, srcs, err = load_pair(cand)
        if err:
            summary["failed"] += 1
            print(f"  load failed: {err}")
            continue
        assert fns is not None
        bind_real_dependencies(key, fns)
        summary["executed"] += 1
        case_separated = True
        for args in (HAND.get(key) or HAND_SEPARATED[key]):
            print(f"  args: {tuple(repr(a)[:60] for a in args)}")
            sep_all = True
            for value in (None, "", "q"):
                # Each observation gets its own deep copy. `get_new_command`
                # appends to `command.script_parts`; sharing one object let the
                # mutation accumulate across sides AND across regimes, which is
                # the call-order artifact that voided E6 -- reproduced, until
                # this line, inside the script that documents its correction.
                b = observe(fns["buggy"], copy.deepcopy(args), value)
                f = observe(fns["fixed"], copy.deepcopy(args), value)
                tag = "R0" if value is None else f"R({value!r})"
                same = (b == f) or (b[0] == "raise" and f[0] == "raise")
                sep_all &= not same
                print(f"    {tag:<8} buggy={b}")
                print(f"    {'':<8} fixed={f}   {'-> same/both-raise' if same else '-> DIFFER'}")
            case_separated &= sep_all
            if key in HAND_SEPARATED:
                label = ("SEPARATES — the documented change, on an in-precondition "
                         "input (the search found this candidate on a degenerate "
                         "witness)")
            else:
                label = "SEPARATES BY HAND (harness false negative)"
            print(f"    VERDICT: {label if sep_all else 'no separation on this input'}")
        if case_separated:
            summary["separated"] += 1
        else:
            summary["failed"] += 1

    print("HANDCHECK_SUMMARY " + json.dumps(summary, sort_keys=True))
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
