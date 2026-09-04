# Public repository cutover

This is the approved clean-history cutover for Admissible 0.8.1. It is an
operator runbook, not evidence that the external steps have occurred.

## Decision

- Preserve the existing private repository and its issues, pull requests, and
  development history as `prive-hn/admissible-internal`.
- Create a new public `prive-hn/admissible` repository with one root commit.
- Require the public root commit's Git tree to equal the accepted internal
  release tree exactly.
- Build, tag, release, and publish packages from the public root commit, not from
  the predecessor commit SHA.

The two commits necessarily have different commit IDs because the public commit
has no parent. Their identical tree ID is the controlled handoff.

## Owner gates

Do not perform any of these external mutations until the hardening PR is merged,
its accepted head is frozen, and the named gate is authorized:

1. rename the private repository;
2. create or change the visibility of the public repository;
3. push the public root commit;
4. create `v0.8.1` or a GitHub Release;
5. configure PyPI Trusted Publishing or upload packages.

Never move a published tag and never force-push either repository.

## 1. Accept the private release tree

From the clean private `main` checkout:

```bash
git fetch origin --prune --tags
git switch main
git pull --ff-only
make test
make audit
git diff --check
git status --short
```

Record:

```bash
git rev-parse HEAD
git rev-parse 'HEAD^{tree}'
```

Generate the self-admission receipt in a disposable clone so the tracked
historical receipt in the accepted tree is not rewritten during the freeze:

```bash
candidate=$(git rev-parse HEAD)
proof_dir=$(mktemp -d)
git clone --no-hardlinks . "$proof_dir/repo"
git -C "$proof_dir/repo" checkout --detach "$candidate"
python3 -m venv "$proof_dir/repo/.venv"
"$proof_dir/repo/.venv/bin/python" -m pip install -e "$proof_dir/repo[dev]"
(
  cd "$proof_dir/repo"
  .venv/bin/python scripts/self_admit.py
)
cp "$proof_dir/repo/eval/self/receipt.json" \
  "/path/to/release-evidence/self-admit-$candidate.json"
```

The receipt must name `candidate`, verify its pre/post commit and tree identity,
and report the complete defect-model ledger. The release evidence copy is
external; do not commit it back into the candidate.

The exact-head paper/code/security reviews must identify this commit and tree.
Any later source edit restarts the affected gates and produces a new tree.

## 2. Rename the private predecessor

After explicit mutation authorization:

```bash
gh api --method PATCH repos/prive-hn/admissible -f name=admissible-internal
gh repo view prive-hn/admissible-internal --json nameWithOwner,visibility,url
```

Confirm that the predecessor remains private and that its issues and pull
requests are intact. The temporary redirect from the old repository path is not
a release guarantee; creating the new public repository at that path replaces
it.

## 3. Create the one-commit public tree locally

Run the repository-contained exporter against the accepted, clean predecessor:

```bash
python3 scripts/export_public_repository.py \
  --source /path/to/admissible-internal \
  --output /path/to/admissible-public
```

The exporter refuses dirty input, existing output, submodules, and unsupported
Git entries. It copies blobs from the accepted commit, preserves executable and
symlink modes, creates one root commit on `main`, and refuses unless the source
and public Git tree IDs are identical.

Read back locally:

```bash
git -C /path/to/admissible-public rev-list --count HEAD
git -C /path/to/admissible-public rev-parse 'HEAD^{tree}'
git -C /path/to/admissible-public status --short
```

Expected: one commit, the accepted tree ID, and a clean status.

## 4. Create and verify the public repository

After explicit visibility/push authorization:

```bash
gh repo create prive-hn/admissible \
  --public \
  --source /path/to/admissible-public \
  --remote origin \
  --description "Fail-closed admissibility kernel for agent workflows"
git -C /path/to/admissible-public push -u origin main
```

Read back the exact remote commit, tree, visibility, default branch, and file
inventory. Configure public security settings, private vulnerability reporting,
and branch/ruleset protections separately; repository source cannot prove those
control-plane settings exist.

The public repository begins with no predecessor issues or pull requests.
Historical plans therefore label old issue/branch/commit references as private
predecessor history rather than linking to nonexistent public objects.

## 5. Rebuild from the public commit

Install the development environment in the clean public checkout, run the full
native gates again, and build release artifacts without `--allow-dirty`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e '.[dev]'
npm ci --prefix apps/cockpit
make test
make audit
make build
python3 paper/build_pdf.py
python3 paper/admissible/build_pdf.py
python3 paper/build_volume_pdf.py
python3 scripts/build_release_artifacts.py
# Repeat the disposable-clone self_admit procedure from section 1 against this
# public root commit; retain the receipt outside the repository.
```

The artifact manifest must name the public root commit and tree, prove that
`source.tree` equals `source.working_tree`, declare a clean source, list exactly
four wheels and four sdists, and record verified Apache-2.0 metadata, canonical
`LICENSE`/`NOTICE` files, generator identity, byte sizes, and SHA-256 hashes.

## 6. Tag, release, and publish

Only after exact public-commit read-back and release authorization:

1. verify the `0.8.1` date, citation metadata, and generated PDFs in the exact
   commit that will be tagged;
2. create annotated tag `v0.8.1` on the accepted public commit;
3. push and read back the tag object and peeled commit;
4. create the GitHub Release and attach the verified artifacts and manifest;
5. configure PyPI Trusted Publishing for the exact owner, repository, workflow,
   and protected environment;
6. publish Core, Ready, Trust, then umbrella;
7. read all four projects and file hashes back from PyPI;
8. install from PyPI in clean environments and smoke imports and commands.

A public source repository, GitHub Release, PyPI publication, and runtime
deployment are four separate states. Report each separately.
