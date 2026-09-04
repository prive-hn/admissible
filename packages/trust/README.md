# admissible-trust

The signing side of [Admissible](https://github.com/prive-hn/admissible): the
half that holds a credential and therefore never runs a candidate's code.

```bash
pip install admissible-trust     # pulls admissible-core==0.8.1, and nothing else
admissible-trust policy trust --repo /trusted/checkout
admissible-trust finalize --preview preview.json --sha "$SHA" \
    --policy-root /trusted/checkout --evaluation-attestation evaluation.json
admissible-trust verify "$SHA"
```

| module | what it does |
| --- | --- |
| `admissible_trust.cli` | the twelve credentialed commands, and only those |
| `admissible_trust.git_reader` | the one place this distribution runs `git`: six fixed identity queries, nothing else |
| `admissible_trust.review` | reviewer and authorship attestations: signing, parsing, keyring verification |
| `admissible_trust.attestation` | the external observer's evaluation attestation and its keyring |
| `admissible_trust.receipt` | workflow receipt bodies, HMAC authentication, monotone anchoring, issuance |
| `admissible_trust.store` | the durable home's schema, and the writes only an authority may make |
| `admissible_trust.standing` | authenticated standing, dependents and impact reporting |
| `admissible_trust.defects` | defect filing and dependency recording, both signed |
| `admissible_trust.github` | finalization: re-derive, recompute, refuse, then issue |
| `admissible_trust.ready_status` | the authenticated Ready projection, the only place `ready` is said |

## Commands

```text
ready-status   attest-review   attest-evaluation
policy trust | policy revoke | policy list
finalize   verify   explain   status   export   import   impeach
run
```

That is the whole surface. The last of those twelve, `run`, is transitional.
`profiles`, `init`, `run --preview`, `check`, `mcp`, `connect` and `ui` are
**not** here — not hidden behind a flag, but absent from the wheel, because
each of them starts a process the repository chose. They live in
`admissible-ready`, which installs no signing key loader, no verifier and no
receipt issuer.

`run` is listed above because this wheel really installs it, and it is listed
last because it is leaving. Bare `run` — no `--preview` — is retained for one
release window as an explicit alias for `finalize`: it consumes a retained
preview and never executes a check, and there is no runner here it could reach
even if it tried. `run --preview` is refused here with migration guidance.
Prefer `finalize`, which is what remains when the window closes.

## What this distribution cannot do

There is no runner, no MCP server, no HTTP server, no browser asset and no
candidate GitHub workflow invocation in this wheel. The one `subprocess` call
site is `admissible_trust.git_reader`, and its vocabulary is six fixed `git`
queries — `rev-parse`, `status`, `remote get-url origin`, `rev-list
--max-parents=0` — run with hooks, fsmonitor, system configuration and
terminal prompting disabled, and with every `GIT_*` variable and every
Admissible credential stripped from the environment. No policy string, no
configuration file and no CLI argument reaches an argument vector.

Finalization consumes retained files only. It re-derives repository, commit,
tree, configuration and policy through Core and that fixed reader, recomputes
the decision from the retained deterministic evidence and the trusted policy
baseline, and then issues and anchors one receipt in one transaction. It never
clones, builds, tests or launches anything.

## Three keys, and none substitutes for another

```text
ADMISSIBLE_HMAC_KEY        signs admissions        finalize, impeach, import, verify, status
ADMISSIBLE_REVIEW_KEY      signs reviews           attest-review
ADMISSIBLE_EVALUATION_KEY  signs evaluations       attest-evaluation
```

Each command loads only the key its own role needs. Key material is accepted
from those variables or from the permission-checked file each `*_FILE` variant
names, and from nowhere else: never a command-line argument, never the
database, never a log, never stdout. `finalize` additionally refuses when the
admission key it signs with also appears in the reviewer or observer keyring,
because a finalizer that can mint the reviews it honours is not a second party
to anything.

## Honest limits

Receipt authentication is HMAC-SHA256. That is shared-secret authenticity — a
holder of the key issued this — and never public non-repudiation. Because
verification and signing share the secret, an authenticated `ready` can only be
produced here, in the distribution that holds the key; `admissible-ready`
reports `checks_complete` instead, which is the honest answer without it.

Separate distributions are not an operating-system sandbox. Code running under
the same Unix account can still read this process's environment, edit the
store, and delete its files; a deleted or corrupted store fails closed, which
is a denial of service rather than a false answer. What the split removes is
*accidental capability adjacency*: the signing key is no longer one import away
from a process that runs whatever `.admissible.json` says.

## License

Apache-2.0. The distribution includes the canonical repository `LICENSE` and
`NOTICE`; see the root `LICENSE.md` for scope.
