# admissible

The developer-convenience umbrella for
[Admissible](https://github.com/prive-hn/admissible): it keeps the `admissible`
command you already type working, by handing each invocation to the
distribution that owns it.

```bash
pip install admissible          # pulls admissible-core, -ready and -trust, all ==0.8.0
admissible check                # handled by admissible-ready
admissible finalize --preview preview.json ...   # handled by admissible-trust
```

## Forbidden in trusted infrastructure

Installing this distribution installs **both** authorities into one
environment. That is the whole point of it, and it is the whole reason it must
not be used anywhere a trusted claim is made:

- not in a finalizer environment;
- not in a reviewer or observer key environment;
- not in a policy signing or trust environment;
- not in any documented minimal trusted deployment;
- not as a dependency of anything that runs in one.

A trusted machine installs exactly one authority: `admissible-ready` where
candidate code runs, `admissible-trust` where a key is held. Those two
distributions cannot reach each other — neither ships the other's modules and
neither depends on the other, conditionally or otherwise. This one deliberately
depends on both, so it proves nothing about separation and must never be the
package a trusted process imports.

The umbrella also does not weaken the process rule it sits beside. Two
authorities installed on a laptop is a convenience; two authorities *used* in
one process to produce an admission is not, and no command here does that. Each
invocation loads exactly one of them.

## What is in the wheel

| module | what it does |
| --- | --- |
| `admissible.cli` | the static command-to-domain dispatch table, and the refusal for anything not in it |
| `admissible.config` | compatibility facade re-exporting `admissible_core.config` |
| `admissible.evidence` | compatibility facade re-exporting `admissible_core.evidence` |
| `admissible.github` | compatibility facade over a **split** surface: each documented name resolves to its own half |
| `admissible.identity` | compatibility facade re-exporting `admissible_core.identity` |
| `admissible.ready` | compatibility facade re-exporting `admissible_ready.ready` |
| `admissible.receipt` | compatibility facade re-exporting `admissible_trust.receipt` |

That is the whole payload. There is no runner, no MCP server, no loopback UI or
its assets, no receipt signer, no store, no schema and no research package
here: those belong to the three distributions this one pins, and a second copy
of any of them would be a second answer with installation order deciding which
one a process got. Four of these modules carry the *name* of a real
implementation — `config`, `identity`, `github`, `ready` — and none carries the
implementation: each is a docstring, a table, and the two attribute-lookup
hooks, which the repository's tests assert by shape rather than by hoping.

## Command ownership

Ownership is static. It is read off the command you typed and nothing else — no
credential, environment variable or installed key ever selects a domain, and a
command with no owner is refused rather than guessed at.

| handled by `admissible-ready` | handled by `admissible-trust` |
| --- | --- |
| `profiles`, `init`, `check`, `mcp`, `connect`, `ui` | `ready-status`, `attest-review`, `attest-evaluation`, `policy trust\|revoke\|list`, `finalize`, `verify`, `impeach` |
| `run --preview` — evaluate this commit | `run` without `--preview` — transitional alias for `finalize` |
| | `explain`, `status`, `export`, `import` |

`run` is the one verb both distributions implement, so it is the one verb with
a rule rather than a row: `--preview` on its own is the candidate-side
evaluation, and `--preview FILE` — or no `--preview` at all — is the
transitional alias for `finalize`. Ready's `run` takes no positional argument,
so a value after `--preview` cannot be a Ready invocation; the two shapes are
told apart by the argument list and by nothing else.

`run`, `explain`, `status`, `export` and `import` are the verbs the split made
ambiguous. They still work here for one release window, and a human running one
gets a line on stderr naming the explicit command that replaces it. A `--json`
caller gets no such line: their stdout is a wire format, and so is MCP's.

## Compatibility imports

Every `admissible.*` import this project documents — in its README, its docs,
its worked example, and the CI template `admissible init --ci` copies into your
repository — keeps working for the same window:

```python
from admissible.config import load_config             # admissible_core.config
from admissible.evidence import ReviewEvidence        # admissible_core.evidence
from admissible.identity import repository_identity   # admissible_core.identity
from admissible.ready import ReadyError, from_evaluation, from_problem
                                                      # admissible_ready.ready
from admissible.receipt import WorkflowReceipt        # admissible_trust.receipt
```

Each is a facade: it re-exports its owner's public surface and holds no
implementation, so the class you get is the owner's own class and not a second
copy of it. Importing a kernel facade loads no authority at all; importing
`admissible.receipt` loads `admissible-trust` and never `admissible-ready`, and
`admissible.ready` loads `admissible-ready` and never `admissible-trust`. None
emits anything on stdout — the deprecation notice is a `DeprecationWarning`,
which is stderr and is suppressible.

The set is exactly what is documented. A facade nobody documented is a promise
nobody made, and the repository's tests take that inventory mechanically out of
the files rather than from memory.

### `admissible.github`, the one surface the split cut

`docs/GITHUB_ACTIONS.md` names two functions from the legacy `admissible.github`
module, and they no longer live in the same distribution:

| name | now lives in | why |
| --- | --- | --- |
| `evaluation_context()` | `admissible_ready.github` | derives what a workflow may do from named environment inputs; holds no key |
| `assert_trusted_tool()` | `admissible_trust.github` | refuses a `--policy-root` that ships its own `admissible`; only matters once a key is in the process |

So this facade is a table rather than a re-export. **Importing
`admissible.github` imports neither half.** Reading `evaluation_context` imports
`admissible_ready.github` and nothing else; reading `assert_trusted_tool`
imports `admissible_trust.github` and nothing else. Both module names are
written as literals in the source, so the complete set of modules this file can
reach is readable in the file: there is no computed target and no delegation to
an arbitrary module. `__all__` is explicit and is exactly those two names; any
other name raises `AttributeError`.

Two names **fail closed on purpose**: `GitHubError` and `PREVIEW_SCHEMA` exist
in *both* halves as different objects, so answering them would mean picking an
authority on your behalf — an `except GitHubError` bound to the wrong half
catches nothing. Asking for either raises an `AttributeError` naming both
replacements, so you choose. Merging the two would be the same reconnection,
spelled as a convenience.

Nothing in any facade reads the environment: no module here imports `os`, so no
credential, keyring path or home directory can influence which half a name
comes from.

Trusted infrastructure must not use these facades either: importing one means
this distribution is installed, which means both authorities are.

## Source layout

The compatibility namespace lives in `compat/admissible/` rather than
`src/admissible/`. The repository root still holds the legacy monolith under
the same import name, and the repository's import census refuses two permanent
source files claiming one dotted module name. When the legacy package retires,
these sources move to `src/`.

That root project is also still named `admissible`, at `0.7.0`: it is the
pre-split monolith, and it is what the repository's own legacy suites run
against during the migration window. This project is the `0.8.0` successor to
it — same distribution name, none of the implementation — and it is the one
that pins the three split distributions.

## License

Apache-2.0. The distribution includes the canonical repository `LICENSE` and
`NOTICE`; see the root `LICENSE.md` for scope.
