# admissible-core

The authority-neutral kernel of [Admissible](https://github.com/prive-hn/admissible).

Everything here is arithmetic on documents:

| module | what it answers |
| --- | --- |
| `admissible_core.identity` | which repository, commit and tree is this, exactly — from an injected git reader's answers |
| `admissible_core.profiles` | what the shipped policy profiles say |
| `admissible_core.config` | is this policy document closed and well typed, and what is its digest |
| `admissible_core.evidence` | is this evidence record closed and well typed, and what is its digest |
| `admissible_core.decision` | given bound evidence, what is the decision, and how is it explained |
| `admissible_core.schema` | the shipped JSON Schema documents the wire formats are written against |
| `admissible_core.isolation` | the closed vocabulary of isolation assertions, and which of them a finalizer may accept |
| `admissible_core.fsutil` | strict path containment and bounded secret-file reads |
| `admissible_core.store_base` | where the store is, how a connection is configured, and what a capability facade is |
| `admissible_core.store_open` | the cross-process schema lock, and the read-only look that decides whether a build may open a home |
| `admissible_core.store_read` | a read-only view of a durable home |
| `admissible_core.store_candidate` | that view plus the writes that only record an observation |

It ships the research roots (`fcd`, `rga`, `atlas`) and the schema package
(`protocol`) so that every dependent resolves one copy of them.

## What it deliberately cannot do

Core starts no process at all — not a candidate's command and not `git`. It
serves no HTTP, speaks no agent protocol, loads no signing credential, issues
and finalises no receipt, and makes no policy enforceable. Those are
capabilities, and a capability in the floor is a capability every consumer of
the floor has. They belong to `admissible-ready` (execution) and
`admissible-trust` (signing), which depend on this package.

Identifying a repository still needs `git` run somewhere, so
`repository_identity` takes a reader and asks it six named questions —
`top_level`, `head_commit`, `tree_of`, `status`, `origin_url`, `root_commits`.
The reader is required and has no default: a default would be a runner living
in the floor, handed silently to every caller. Ready supplies the shipped
adapter. Core keeps the arithmetic — what a valid SHA looks like, which
mismatch is a refusal, and the closing read that makes the answer a snapshot.

The two store facades are the same idea applied to persistence. Neither holds
its backend as an attribute and neither hands back the backend's own bound
method; the backend sits in a module-private weak-keyed registry and an allowed
name is answered with a facade-owned call path. That is a guarantee about
mistakes — an over-grant fails a test instead of shipping — and not a sandbox:
one interpreter has no honest way to hide an object from code running in it.

It declares no dependencies and installs no console command. A floor with
dependencies can pull the split back together; a library with a command is a
program.

## Building

```
python -m build --no-isolation packages/core     # sdist and wheel
```

`fcd`, `rga`, `atlas` and `protocol` are owned by the repository root and are
never copied into this project's source. A committed copy would be a second
file claiming the same dotted module name — two `fcd.journal` implementations,
with import order deciding which one hashes a receipt — and the repository's
import census rejects exactly that.

Instead, `build_backend.py` (an in-tree PEP 517 backend wrapping setuptools)
refreshes a transient, byte-identical `_staged/` copy of those roots before
each hook and deletes it afterwards, with `atlas/tests` pruned at the copy.
`package-dir` points at `_staged/`, so the sdist and the wheel see the same
five packages and an sdist-derived wheel is identical to a direct one.

The naive spelling — `package-dir` pointing straight at `../../fcd` — builds a
correct wheel and a broken sdist: setuptools resolves the destination relative
to the staging root, so the copies land *outside* the archive, producing an
sdist missing four packages and four stray directories in the working tree.
`build_backend.py` explains this at the point where it matters.

Six properties of that arrangement are enforced rather than assumed, because
none of them shows up in a build's exit status:

| | |
| --- | --- |
| **One build at a time** | `_staged/` is a single fixed path, and a wheel build, an sdist build and a `pip install` can all reach it at once. The whole lifecycle — refresh, setuptools hook, cleanup — is held under one cross-process lock (`fcntl` or `msvcrt`) on `_staged.lock`, a file *beside* the staging tree that is created once and never removed. It records no owner, so a killed build denies nobody: the kernel drops the lock, and the next build refreshes the residue under it. Only genuine contention (`EACCES`/`EAGAIN`, or a Win32 lock violation) is waited out; a bad descriptor or a filesystem without locks is raised at once, with the reason the operating system gave, rather than as a timeout naming a build that never ran. |
| **The sources are identified, not merely adjacent** | "Four directories exist two levels up" is a statement about a parent directory, and the parent of an extracted sdist belongs to whoever extracted it. A checkout is recognised instead — exact path `<repo>/packages/core`, both `pyproject.toml` files naming their projects, the repository's own `.git`, each root a real directory with its package marker — and never when `PKG-INFO` is present, which every sdist has and no working tree does. |
| **No symlink is ever followed** | A link inside a staged root would copy whatever it points at into a published wheel. Links are refused by path, at any depth, file or directory, and the refusal names the file. |
| **Reads follow descriptors, not names** | A link check by path expires the moment it is made. Each directory is opened once with `O_DIRECTORY\|O_NOFOLLOW`, every descendant is named against that descriptor with `openat`, every file is confirmed by `fstat` on the descriptor about to be read, and nothing is reopened by path afterwards — so renaming a parent away mid-walk and putting a link in its place cannot redirect a single byte. Where a platform has no such primitives the same walk runs on `lstat`/`open`/`fstat`, re-checks every ancestor's inode at the moment the bytes are taken, and refuses rather than following a reparse point it cannot rule out. |
| **The staged bytes are closed** | `_staged/staged-manifest.json` pins every staged file by relative path and SHA-256, and travels inside the sdist. A wheel built from an sdist is built from the bytes that sdist shipped; missing, unexpected and altered are three refusals. It holds no clock reading and no absolute path, so two builds of one tree write it identically. |
| **The artefact is checked, not only the tree** | That closure is necessarily taken *before* setuptools reads anything, which leaves a window. So the built wheel is reopened as the ZIP it is and every member installing into a staged root is compared with the closure — exact path set, no extra, no missing, no altered byte, no member installing as a link — and the built sdist is reopened as the tar it is, with every `_staged/` member checked by path, type and bytes and every link member refused. A mismatch **deletes the artefact** and raises `ArtifactMismatch`. |

`tests/core/test_admissible_core_build_backend.py` asserts all six, including
simultaneous real builds compared byte for byte, and adversarial builds in which
a verified staged file — or the directory holding it — is replaced in the
instant between the closure and the packager.

### What that is not

It is not a sandbox, and is not offered as one. A process running as this user
can read, write and replace anything in the working tree, including the staging
tree, the lock file and `build_backend.py` itself, and can rewrite the manifest
to close over whatever it just wrote. Two things are claimed, exactly:

1. a **published artefact** cannot silently disagree with the closure its build
   verified — it is reopened, compared, and deleted on mismatch, so the outcome
   of winning that race is a failed build rather than a poisoned wheel; and
2. **source reads** are not redirectable by swapping a path component after it
   was checked, because the reads follow descriptors rather than names.

Neither survives an attacker who wins the race *and* rewrites the manifest, and
neither is meant to. The defence against that one is not building releases on a
machine where somebody else runs as you.

## License

Apache-2.0. The distribution includes the canonical repository `LICENSE` and
`NOTICE`; see the root `LICENSE.md` for scope.
