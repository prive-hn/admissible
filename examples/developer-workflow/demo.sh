#!/usr/bin/env bash
# End-to-end demonstration of the Admissible developer gate.
#
# Creates a throwaway git repository and a throwaway ADMISSIBLE_HOME, then walks
# the whole product surface: init and its scaffolded ignores, an evaluation with
# its attempt id, an exact-identity cache hit that spawns nothing, the four-step
# admission path, a same-temp-store process restart, an actionable refusal,
# the high-risk review handoff, an impeachment, and the standing that follows.
#
# The shape worth watching is the admission. `run` evaluates and never signs --
# it starts commands the repository controls, so it must not hold a key while it
# does. Turning an evaluation into a receipt takes three more parties:
#
#   the observer   signs what the evaluation produced, once it is over
#   the operator   says, once, which policy is enforceable here
#   the finalizer  holds the admission key and anchors the receipt
#
# This demo plays all of them in one shell, for brevity. In reality they are
# different machines holding different keys, and that separation is the product.
#
# No network, no language model, no dependency beyond Python 3.10+ and git.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
python_command="${PYTHON:-python3}"
if [[ "$python_command" == */* && "$python_command" != /* ]]; then
  python_command="$root/$python_command"
fi
python="$("$python_command" -c 'import sys; print(sys.executable)')"
work="$(mktemp -d "${TMPDIR:-/tmp}/admissible-demo.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# This is a temporary demonstration store, not a production durable home. It
# proves continuity across separate CLI processes and is deleted at script exit.
export ADMISSIBLE_HOME="$work/home"
export ADMISSIBLE_HMAC_KEY_ID="demo"
export PYTHONPATH="$root${PYTHONPATH:+:$PYTHONPATH}"
# Import the checkout without leaving __pycache__ beside its sources. Every
# file this demo creates now lives under the temporary directory above.
export PYTHONDONTWRITEBYTECODE=1
# The evaluating side of the gate holds no keyring of any kind, and no signing
# key. Those are exported only for the steps that are entitled to them.
unset ADMISSIBLE_HMAC_KEY ADMISSIBLE_REVIEW_KEYRING || true
unset ADMISSIBLE_EVALUATION_KEYRING || true
# The evaluator honestly reports no isolation. Killing a check's process group
# does not reach a descendant that called setsid(): that descendant runs as this
# user after the evaluation believes the check is over and can rewrite the
# handoff. Preview isolation is diagnostic and never authorizes finalization.
#
# To exercise the complete API, this demo's pretend observer later asserts
# pid-namespace and does not have one. It runs in your shell with no container
# or separate user, just as it plays observer, operator and finalizer in one
# process and writes its own "external" source receipt. This is an explicit
# demo-only false assumption, not deployment proof. A real observer must check
# external infrastructure evidence before supplying --isolation.
export ADMISSIBLE_ISOLATION=none
observer_isolation=pid-namespace

admissible() { "$python" -m admissible "$@"; }
step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
show() { "$python" "$here/show.py" "$@"; }

# The three keys this product uses, kept apart on purpose. Demo values: they are
# in a public file, so they are worth exactly nothing. Never reuse them.
observer_key="demo-only-observer-key"
signing_key="demo-only-signing-key"
umask 077
printf '{"demo-observer": "%s"}' "$observer_key" > "$work/observers.json"
chmod 600 "$work/observers.json"

repo="$work/widget"

# One commit, all the way to an anchored receipt: evaluate, observe, finalize.
# Four steps in three trust domains, because there is no shorter honest path.
admit() {
  local target="$1" reviews="${2:-}"
  local preview="$work/preview-$target.json"
  local attested="$work/evaluation-$target.json"
  local source="$work/source-receipt-$target.json"
  local args=(run --preview --sha "$target" --preview-out "$preview" --json)
  admissible "${args[@]}" > "$work/decision-$target.json" || true
  # What the observer says it read from a system outside this evaluation. In a
  # real deployment this is the CI provider's own record of the run: its run
  # id, the head sha it ran on, and the conclusion it reported. Here it is
  # written by the demo, which is exactly the adapter-honesty assumption the
  # documentation keeps: Admissible does not fetch this and cannot check it.
  cat > "$source" <<RECEIPT
{"schema": "admissible/v0.6/external-source-receipt",
 "provider": "demo-local-runner",
 "run_id": "demo-run-$target",
 "commit_sha": "$target",
 "conclusion": "success",
 "source_document": {"note": "the demo ran these checks locally"}}
RECEIPT
  ADMISSIBLE_EVALUATION_KEY_ID=demo-observer \
  ADMISSIBLE_EVALUATION_KEY="$observer_key" \
    admissible attest-evaluation --preview "$preview" --out "$attested" \
      --source-receipt "$source" --isolation "$observer_isolation" > /dev/null
  local finalize_args=(finalize --preview "$preview" --sha "$target"
    --policy-root "$repo" --evaluation-attestation "$attested")
  if [ -n "$reviews" ]; then finalize_args+=(--reviews "$reviews"); fi
  ADMISSIBLE_HMAC_KEY="$signing_key" \
  ADMISSIBLE_REVIEW_KEYRING="${DEMO_REVIEW_KEYRING:-}" \
  ADMISSIBLE_EVALUATION_KEYRING="$work/observers.json" \
    admissible "${finalize_args[@]}"
}

mkdir -p "$repo"
cd "$repo"
git init -q -b main
git config user.email demo@example.invalid
git config user.name "Admissible Demo"
git remote add origin https://github.com/acme/widget.git

cat > widget.py <<'SOURCE'
def total(cents):
    return sum(cents)
SOURCE
cat > test_widget.py <<'SOURCE'
from widget import total


def test_total():
    assert total([1, 2, 3]) == 6
SOURCE

step "1. the eight risk-shaped starter profiles"
admissible profiles | head -30

step "2. init writes a conservative policy and ignores what its checks produce"
# The gate refuses a dirty worktree, so init also makes sure the artefacts this
# profile's own checks write (__pycache__, dist/) are ignored. Otherwise the
# very first run would block on output the policy itself asked for.
admissible init --profile python-library
cat .gitignore
# Point the policy at commands this demo repository really has.
show retarget-checks .admissible.json
cat > test_runner.py <<'SOURCE'
from test_widget import test_total

test_total()
print("1 test passed")
SOURCE

git add -A
git commit -q -m "widget: total()"
sha="$(git rev-parse HEAD)"

step "3. evaluate this exact commit -- and notice that nothing is signed"
admissible run --preview --sha "$sha" --json > "$work/first.json"
show first-run "$work/first.json"

step "4. an identical re-run reuses the evidence and spawns nothing"
admissible run --preview --sha "$sha" --json > "$work/second.json"
show reused-run "$work/second.json"

step "5. the operator trusts this policy once, deliberately"
# A candidate may propose a policy; only an operator makes one enforceable. A
# finalizer holding no baseline for a class refuses everything for that class,
# because it cannot tell a tightened policy from a weakened one.
admissible policy trust

step "6. the observer signs, the finalizer anchors: only now is there a receipt"
admit "$sha"

step "7. the receipt survives a process restart inside this temporary store"
ADMISSIBLE_HMAC_KEY="$signing_key" admissible verify "$sha"

step "8. an unclean worktree is refused, with the reason"
echo "# scratch" >> widget.py
set +e
admissible run --preview --sha "$sha"
echo "exit code: $?"
set -e
git checkout -q -- widget.py

step "9. a failing check refuses, and says which one"
git checkout -q -b broken
cat > test_runner.py <<'SOURCE'
raise SystemExit("total() mishandles empty input")
SOURCE
git add -A
git commit -q -m "break the runner"
broken_sha="$(git rev-parse HEAD)"
set +e
admissible run --preview --sha "$broken_sha"
echo "exit code: $?"
set -e
git checkout -q main

step "10. a money-touching class: the payment-change profile, at its own floors"
git checkout -q -b payments
# The real starter profile for this risk, not the library profile with its
# review count raised. Everything that decides admission below -- two
# independent reviews, a two-day freshness bound on them, the cost and wall
# ceilings, and the rule that an author key may never count as a reviewer --
# is what this profile wrote. Only the three check commands are stood in for,
# and the helper prints exactly which and why.
admissible init --profile payment-change --force --no-gitignore | head -6
show adopt-payment-profile .admissible.json
git add -A
git commit -q -m "payments: adopt the payment-change profile"
pay_sha="$(git rev-parse HEAD)"

# Reviews bind to the exact repository, commit, tree and policy, so they are
# written after the commit exists -- and never committed into the tree they
# review, because that would change the tree they are bound to.
show write-reviews "$repo" "$work"

ADMISSIBLE_REVIEW_KEY_ID=reviewer-a ADMISSIBLE_REVIEW_KEY=demo-reviewer-a-secret \
  admissible attest-review --review "$work/review-0.json" \
                           --out "$work/attested-0.json" > /dev/null
ADMISSIBLE_REVIEW_KEY_ID=reviewer-b ADMISSIBLE_REVIEW_KEY=demo-reviewer-b-secret \
  admissible attest-review --review "$work/review-1.json" \
                           --out "$work/attested-1.json" > /dev/null
# The author signs too. Without an authenticated authorship claim there is no
# key to exclude from reviewing, so "two independent reviews" would be a
# statement about strings the submitter chose -- and this class admits nothing.
ADMISSIBLE_REVIEW_KEY_ID=author-key ADMISSIBLE_REVIEW_KEY=demo-author-secret \
  admissible attest-review --review "$work/authorship.json" --authorship \
                           --out "$work/attested-author.json" > /dev/null
show bundle-reviews "$work"

step "10a. evaluation holds no reviewer keyring, so it cannot admit -- and says so"
set +e
admissible run --preview --sha "$pay_sha" \
  --preview-out "$work/pending-preview.json" --evidence "$work/reviews.json" \
  --json > "$work/pending.json"
echo "exit code: $? (1 = refused, not admitted)"
set -e
show pending "$work/pending.json"

step "10b. the finalizer holds the pinned keyring, and only it can admit"
show write-keyring "$work"
chmod 600 "$work/keyring.json"
# The payment class enforces something different, so it needs its own baseline.
admissible policy trust
DEMO_REVIEW_KEYRING="$work/keyring.json" admit "$pay_sha" "$work/reviews.json"
git checkout -q main

step "11. reality disagrees later: file a defect against the admitted commit"
cat > "$work/defect.json" <<JSON
{
  "kind": "defect",
  "defect_id": "WID-1",
  "repository": "github.com/acme/widget",
  "commit_sha": "$sha",
  "severity": "high",
  "summary": "total() silently accepts floats and loses cents",
  "missed_check_ids": ["unit"],
  "regression_test_id": "unit",
  "discovered_at": 1756000000
}
JSON
ADMISSIBLE_HMAC_KEY="$signing_key" \
  admissible impeach "$sha" --evidence "$work/defect.json" --test unit

step "12. standing changed; the old receipt is still authentic"
export ADMISSIBLE_HMAC_KEY="$signing_key"
set +e
admissible verify "$sha"
echo "exit code: $? (1 = not current)"
set -e
# verify exits 1 for an impeached artefact, which is the point of this step.
set +e
admissible verify "$sha" --json > "$work/verify.json"
set -e
show verify "$work/verify.json"

step "13. status"
set +e
admissible status
set -e

printf '\n\033[1mDemo complete.\033[0m Nothing outside %s was touched.\n' "$work"
