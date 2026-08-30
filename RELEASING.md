# Releasing Admissible

This runbook separates source acceptance, public repository creation, GitHub
Release publication, and PyPI publication. None implies another.

## 1. Freeze the candidate

Start from a clean, accepted `main` commit. Record the commit and tree IDs. Run
all repository, paper, sabotage, package-build, archive, and clean-install gates
before freezing. Any source edit invalidates prior exact-head reviews.

The coordinated public version is `0.8.0` for:

1. `admissible-core`
2. `admissible-ready`
3. `admissible-trust`
4. `admissible`

The source-checkout monolith remains `0.7.0` only for the documented migration
window and is not one of the four 0.8.0 distributions.

## 2. Build and inspect

```bash
source .venv/bin/activate
make test
make audit
make build  # cockpit production bundle
python3 paper/build_pdf.py
python3 paper/admissible/build_pdf.py
python3 paper/build_volume_pdf.py
python3 scripts/build_release_artifacts.py
# In a disposable exact-commit clone, run scripts/self_admit.py and retain its
# receipt outside the repository (see docs/PUBLIC_RELEASE_CUTOVER.md).
```

Build from a disposable exact-commit checkout with the pinned
`setuptools==83.0.0` backend. The release builder refuses dirty inputs by
default, verifies the exact eight-archive set and package metadata, and writes
names, sizes, SHA-256 values, and source identity to
`dist/artifact-manifest.json`. `source.tree` and `source.working_tree` must match
for a releasable build; `--allow-dirty` is development-only. Inspect `METADATA`,
`WHEEL`, `RECORD`, package membership, dependencies, entry points, `LICENSE`,
and `NOTICE`. Build a wheel from every sdist and require its metadata contract
to match the direct wheel.

Install the artifacts into clean environments with indexes disabled. Verify Core
alone, Ready+Core, Trust+Core, and the umbrella. The trusted-environment checks
must prove that Ready is absent from a Trust installation.

## 3. Publish source

Create the approved clean-history public repository from the frozen tracked
tree. Verify its tree content, default branch, visibility, security settings,
and absence of private-history material before announcing it.

Create an annotated `v0.8.0` tag on the accepted public commit. Push it once;
never move a published tag. Create the GitHub Release from that tag and attach
only the verified artifacts plus a checksum manifest. Read the tag, release,
and attached files back from GitHub.

## 4. Publish packages

Reserve/configure the four PyPI projects with Trusted Publishing bound to the
exact GitHub owner, repository, workflow filename, and protected environment.
Publication authority must not be available to pull-request code.

Publish in dependency order: Core, Ready, Trust, umbrella. Stop at the first
failure. PyPI versions are immutable; do not overwrite or repair `0.8.0` in
place. Use a new patch version for a published-package correction.

After each upload, read the official PyPI JSON endpoint, compare file hashes,
and install from PyPI in a fresh environment. Finish with one clean umbrella
installation and command/import smoke test.

## 5. Record the release

Update the changelog date only in the commit that will be tagged. Preserve the
accepted commit, tree, tag object, artifact checksums, GitHub Release URL, PyPI
file hashes, exact test commands, review verdicts, and any partial-publication
state. State explicitly that a source/package release is not a deployment.
