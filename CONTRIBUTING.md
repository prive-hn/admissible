# Contributing to Admissible

Admissible is a security-sensitive admission kernel and a set of research
papers. Small, explicit changes are easier to validate than broad rewrites.

## Development setup

Python 3.10 or newer and Node.js 22.12–22.x are required.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
npm ci --prefix apps/cockpit
```

The repository pins the release build backend to `setuptools==83.0.0` so direct
and sdist-derived artifacts identify the same generator.

## Before opening a pull request

```bash
make test
make audit
make build
python3 scripts/sabotage_admissible.py
```

The sabotage suite is required for changes to authority boundaries, package
membership, signing/finalization, isolation, or the mutation harness. Pure prose
changes may use the focused documentation and paper-build tests plus
`git diff --check`, but the pull request must say exactly what was run.

For behavior changes, add a regression test first and show that it fails for the
intended reason before implementing the fix. Keep examples free of credentials,
customer data, local absolute paths, and private provider records.

## Architecture rules

- `admissible-core` has no runtime dependencies, console command, or signing
  authority.
- `admissible-ready` may execute candidate-controlled checks and must not hold
  Trust credentials or finalize receipts.
- `admissible-trust` may finalize and sign but must not execute candidate-owned
  commands.
- The `admissible` umbrella is developer convenience only and must not be
  installed on trusted infrastructure.
- A green evaluation is not an admission. Only an authenticated Trust receipt
  can carry `ADMITTED`.

Changes that weaken these boundaries need an explicit threat-model explanation,
negative control, and exact-head review.

## Pull requests

Keep one coherent change per pull request. Describe the security or correctness
invariant, tests, generated artifacts, and compatibility impact. Do not include
real keys, tokens, signed production receipts, customer content, or internal
provider-routing reports.

## Licensing of contributions

No contributor license agreement is currently required. Under section 5 of
Apache-2.0, an intentionally submitted software or documentation contribution
is offered under Apache-2.0 unless you conspicuously mark it otherwise before
acceptance. Paper-manuscript contributions are offered under CC BY 4.0.

Only submit work you have the right to license. Identify adapted or third-party
material and preserve all required notices.
