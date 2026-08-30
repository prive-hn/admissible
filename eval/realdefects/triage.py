"""Triage BugsInPy bugs down to differentially-testable module-level functions.

For each candidate bug: read the fix patch, find which lines of which file
changed, fetch the buggy module at its own commit, and ask the AST which
top-level function contains those lines. A bug that lands inside a module-level
`def` is a candidate; one that lands in a class body, at import scope, or in a
file that will not parse is not.
"""
from __future__ import annotations

import ast
import json
import pathlib
import re
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parent


def _corpus_root() -> pathlib.Path:
    """The BugsInPy checkout. `git clone` names it `BugsInPy`; this module
    used to look only for `bugsinpy`, and a missing tree yielded zero jobs
    and an exit status of 0 -- a clean-looking, entirely empty study."""
    for name in ("bugsinpy", "BugsInPy"):
        if (ROOT / name / "projects").is_dir():
            return ROOT / name / "projects"
    raise SystemExit(
        f"no BugsInPy checkout beside {ROOT}: expected bugsinpy/projects or "
        f"BugsInPy/projects.\n"
        f"  git clone --depth 1 https://github.com/soarsmu/BugsInPy.git "
        f"{ROOT / 'bugsinpy'}\n"
        f"Note: the frozen corpus is already committed as manifest.json; "
        f"re-triage only to rebuild it.")
CACHE = ROOT / "srccache"
CACHE.mkdir(exist_ok=True)

PILOT = ["youtube-dl", "scrapy", "thefuck", "black", "tqdm", "httpie",
         "cookiecutter", "PySnooper", "luigi", "sanic"]


def info(path: pathlib.Path) -> dict:
    out = {}
    for line in path.read_text(errors="replace").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"')
    return out


def changed(patch: str) -> tuple[str, list[int]] | None:
    """The single changed file and the NEW-file line numbers it touches."""
    files = re.findall(r"^diff --git a/(\S+) b/(\S+)", patch, re.M)
    if len(files) != 1:
        return None
    path = files[0][1]
    if not path.endswith(".py"):
        return None
    lines: list[int] = []
    for hunk in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", patch, re.M):
        start = int(hunk.group(1))
        body = patch[hunk.end():]
        body = body[:body.find("\n@@")] if "\n@@" in body else body
        n = start
        for ln in body.splitlines():
            if ln.startswith("+") and not ln.startswith("+++"):
                lines.append(n); n += 1
            elif ln.startswith("-") and not ln.startswith("---"):
                lines.append(n)
            elif not ln.startswith("\\"):
                n += 1
    return (path, sorted(set(lines))) if lines else None


def fetch(repo: str, sha: str, path: str) -> str | None:
    key = CACHE / f"{sha[:12]}_{path.replace('/', '_')}"
    if key.exists():
        return key.read_text(errors="replace")
    slug = repo.rstrip("/").removeprefix("https://github.com/")
    url = f"https://raw.githubusercontent.com/{slug}/{sha}/{path}"
    try:
        with urllib.request.urlopen(url, timeout=45) as r:
            text = r.read().decode("utf-8", "replace")
    except Exception:
        return None
    key.write_text(text)
    return text


def enclosing(src: str, lines: list[int]):
    """(name, kind) of the definition containing those lines, or None."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    best = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        end = getattr(node, "end_lineno", None)
        if end is None:
            continue
        if any(node.lineno <= ln <= end for ln in lines):
            span = end - node.lineno
            if best is None or span < best[2]:
                kind = ("class" if isinstance(node, ast.ClassDef)
                        else "async" if isinstance(node, ast.AsyncFunctionDef)
                        else "def")
                best = (node.name, kind, span)
    if best is None:
        return None
    # module-level only: a def whose parent is the module
    top = {n.name for n in tree.body
           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    return (best[0], best[1], best[0] in top)


def one(project: str, bug: pathlib.Path) -> dict | None:
    meta = info(bug / "bug.info")
    proj = info(_corpus_root() / project / "project.info")
    patch = (bug / "bug_patch.txt").read_text(errors="replace")
    ch = changed(patch)
    if ch is None:
        return None
    path, lines = ch
    src = fetch(proj.get("github_url", ""), meta.get("buggy_commit_id", ""), path)
    if src is None:
        return {"project": project, "bug": bug.name, "status": "fetch-failed"}
    enc = enclosing(src, lines)
    if enc is None:
        return {"project": project, "bug": bug.name, "path": path,
                "status": "no-enclosing-def"}
    name, kind, is_top = enc
    return {"project": project, "bug": bug.name, "path": path, "symbol": name,
            "kind": kind, "module_level": is_top, "changed_lines": len(lines),
            "buggy": meta.get("buggy_commit_id"), "fixed": meta.get("fixed_commit_id"),
            "repo": proj.get("github_url"), "python": meta.get("python_version"),
            "status": "candidate" if (is_top and kind == "def") else "not-module-level"}


def main() -> None:
    bip = _corpus_root()
    jobs = []
    for project in PILOT:
        for bug in sorted((bip / project / "bugs").glob("*")):
            if (bug / "bug_patch.txt").exists():
                jobs.append((project, bug))
    print(f"triaging {len(jobs)} bugs across {len(PILOT)} projects...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = [r for r in pool.map(lambda a: one(*a), jobs) if r]
    (ROOT / "manifest.json").write_text(json.dumps(rows, indent=1))
    from collections import Counter
    print("\nstatus:")
    for k, v in Counter(r["status"] for r in rows).most_common():
        print(f"  {v:>4}  {k}")
    cands = [r for r in rows if r["status"] == "candidate"]
    print(f"\ncandidates: {len(cands)}")
    for k, v in Counter(r["project"] for r in cands).most_common():
        print(f"  {v:>4}  {k}")


if __name__ == "__main__":
    main()
