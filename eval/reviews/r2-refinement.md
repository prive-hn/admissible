# Refinement review r2

Reviewed head: 3e9d70fe6600348f063250d4f30114011355e916
Verdict: SURVIVES WITH CONDITIONS

Lens: refinement / proof obligations. Read-only. Scope: `paper/DRAFT.md`,
`paper/INVARIANTS.md`, and the non-paper artifacts that a real client would
have to become (`metrics/SCHEMA.md`, `scripts/collect_routing_metrics.py`,
`README.md`). The safety invariants I1–I9 are sound *as an abstract machine*.
The two obligations that couple that machine to a running client, A1 and A2,
are load-bearing in one half and question-begging in the other half, and the
shipped adapter is far from a refinement of the machine. Details below.

## Are A1 and A2 load-bearing or circular

Both. Each of A1 and A2 bundles two distinct claims, and the split is the
whole story.

**A1 (Enforcer totality)** as written asserts: "Every data-plane call while a
stage is `Running` is observed **and satisfies** `norm(m_exec) = norm(φ(a))`."
That is two obligations glued together:

- **A1a — totality/observability** (load-bearing): every executed inference
  call while `Running` produces an event, and no call occurs outside the
  observed set. This is a genuine coupling to the world. The abstract machine
  cannot discharge it internally, because it is a statement about the *absence*
  of unrecorded calls, which no transition of the machine can witness. This is
  the real content the paper is entitled to lean on (§9, line 115: "A1 and A2
  are the only coupling to a running client").

- **A1b — the equality holds** (question-begging): the clause "and satisfies
  `norm(m_exec)=norm(φ(a))`" *is* the conclusion of I1. The I1 proof
  (`INVARIANTS.md:64`) reads: "Bind is the only writer of `m_exec` and writes
  `φ(a)`. A1 forbids any other write while Running." So I1 = (write-once
  discipline of the machine) + (A1b). The machine half is trivial; the
  non-trivial half is imported verbatim from the assumption. I1 is therefore
  close to a projection of A1 onto `Passed` states, not an independently earned
  theorem.

The sharpest symptom of the smuggle is internal: **A1b makes F1 unmeasurable.**
F1 is defined (both tables) as "Pass with `norm(m_exec) ≠ norm(φ(a))`." A1b
declares that state impossible by fiat. You cannot simultaneously *assume* no
executed model ever diverges from the bound one and *measure a misbind rate*
for exactly that divergence (§6 / SCHEMA "misbind on first_attempt"). One of
the two has to give. The correct resolution is to weaken A1 to A1a only
(totality of observation), let the equality be an *enforced* machine invariant
(Bind is the sole writer of `m_exec`), and let F1 be the *observable violation*
that appears when a real implementation breaks the write-once discipline or
lets a post-`call` fallback swap the served identity. Under that split I1 is a
real, contingent theorem and F1 is a real, countable fault. Under the current
wording, one of them is vacuous.

**A2 (Exit trap)** has the identical structure. "Process or client death while
`Running` is mapped to a published `fail_closed`" bundles:

- **A2a — detectability** (load-bearing): `Running` exits are observable
  (needs a lease / heartbeat / write-ahead so a crash is noticed). This is a
  real, undischargeable-from-inside obligation.
- **A2b — the mapping happens** (question-begging): asserting the fail-closed
  publication *occurs*. If assumed, F4 ("Running exit with `pub=0`") is
  impossible by fiat and its silent-fail rate is unmeasurable — the same
  contradiction as A1b/F1.

So neither assumption is purely circular (each carries a genuine totality
premise that the machine cannot self-supply), and neither is purely
load-bearing (each also asserts the outcome it is supposed to guarantee). The
paper *already names the honest half correctly* elsewhere: §6/line 95 and
`INVARIANTS.md:118` say zeros on misbind/bleed/silent-fail are proofs "only if
`stage` is write-ahead and `call`/`decide` are total" — that is A1a+A2a and
nothing more. The assumptions in §0 overreach past that line by also asserting
compliance. **Condition 1 for survival:** restate A1 and A2 as totality-of-
observation only (A1a, A2a); demote the equality and the mapping to
machine-enforced invariants whose failure is F1 and F4. This is a rewording,
not a structural collapse, which is why the verdict is SURVIVES WITH
CONDITIONS rather than REVISE.

## What a real client must implement

Refining the machine to a real client requires substantially more than the
shipped `scripts/collect_routing_metrics.py`, which is a read-only, post-hoc,
call-level log summarizer. Concretely, a faithful refinement must provide:

1. **Write-ahead `stage`** at the control-plane start, emitted transactionally
   *before* Admit/Bind, carrying class, `body_hash`, assigned specialist,
   declared model, authors, and as-of `policy_version` (SCHEMA `stage`). If the
   stage is not written before work begins, the silent-fail denominator is
   unknown and I5/I7 accounting is unrecoverable.

2. **A non-bypassable `call` interceptor** — the operational meaning of A1a.
   Every outbound inference while `Running` must emit `call` with
   `executed_model`, `on_bind`, `first_attempt`, `signal`, and
   `runtime_instance`. "Total" means the client *cannot physically* issue an
   inference that skips this point. The shipped adapter does the opposite: it
   scrapes already-written log lines with regexes (`MODEL_RE`, `SIGNAL_RE`), so
   any call not printed, printed in another format, or made by a path that does
   not log is invisible. That is sampling, not totality — an estimator "biased
   clean," exactly as §6 concedes.

3. **A real, pinned `norm`** (A5) shared by control and data plane. The
   adapter's `canon()` (split on `":"` then `"["`) is a stand-in with no
   evidence it equals the normalization the policy uses.

4. **A death detector realizing A2a** — a lease/heartbeat around `Running` that
   converts an observed crash into a published `decide result=fail_closed`. The
   adapter has none.

5. **Policy as data, versioned and complete.** The machine needs `π`, `δ`,
   `π_chk = π\authors`, `tried`, and versioned `φ` as-of `ts`. The adapter
   hardcodes a single static specialist→model-set map, has **no deny set δ, no
   author set, no tried set, and no policy version**. It can compute only
   set-membership (`on_policy`), so it cannot even represent I2 (`π*\δ`), I6
   (`π_chk`), or I7 (`tried` monotonicity), let alone enforce them.

6. **An accept-guarded artifact store** (I5/I8): a store that rejects any write
   that is not an `accept` of an item whose every `Required(c)` stage has a
   `pass` record. Absent from the adapter entirely.

7. **Stage/retry state**, not call counting. The adapter is call-denominated,
   which the paper itself flags as "gameable by abort" (§6). A refinement must
   carry per-stage `pc`, `tried`, and retry-into-`π*\δ\tried`.

Net: the adapter is a metrics estimator, not an enforcer. It measures an
on-policy call fraction; it does not admit, bind, fail closed, gate the store,
or observe totality, and it cannot witness F1/F2/F4 as forbidden transitions.
The machine can be refined to a real client, but the shipped artifact is not
that client and should not be read as evidence that one exists.

## What still cannot transfer from the machine to a log

Even a faithful client leaves residue that a log — as a record of events that
*did* occur — can never certify:

- **Totality is not log-verifiable from inside the log.** A1a is a claim about
  the *absence* of unrecorded calls. A log can only exhibit the calls it
  recorded; it cannot prove none were missed. Refinement pushes this onto a
  deployment assumption ("the interceptor cannot be bypassed"), which is an
  assertion about the environment, not a theorem the machine or the log
  supplies. This is irreducible.

- **The paper's own delta is the hardest thing to witness.** `INVARIANTS.md:105`
  claims `φ` is "the **data-plane** model identity after session restore and
  fallback." A `call` event records the *requested* model; a mid-run flip
  (A3), a session restore, or a silent provider fallback can change the
  *served/billed* identity after the event is emitted. Unless `executed_model`
  is read back from the response/billing identity rather than the request,
  the exact divergence the paper advertises as its contribution is the one
  divergence the current schema and adapter cannot see. F1 witness quality
  hinges entirely on this, and it does not transfer for free.

- **F1 vs F2 needs `runtime_instance`**, which the schema marks optional and
  the adapter never populates. Without it, two specialists sharing one runtime
  instance (weight/session sharing, explicitly out of I6 per DRAFT line 84) is
  invisible, so I6's separation-of-duty and F2 have no log witness.

- **Silent-fail undercounts whenever `stage` is not write-ahead.** If a client
  dies before emitting `stage`, the missing stage is not in the denominator;
  the machine *assumes* the denominator, the log cannot reconstruct stages that
  were never written. Right-censoring (§6) presumes a complete well-formed set
  that a crashing client does not guarantee.

- **Liveness never transfers, by the paper's own admission.** Item termination
  is not a theorem (§4, `INVARIANTS.md:91`); a log cannot certify "some allowed
  bind eventually becomes usable" or that Ask/Retry are not ignored forever.
  This is correctly scoped out and is not a defect — only a boundary.

## Bottom line

The abstract machine is coherent and its safety invariants are genuine modulo
a wording fix. A1 and A2 are load-bearing in their totality half and
conclusion-smuggling in their outcome half; as literally written they make F1
and F4 unmeasurable, which is self-contradictory with §6. Restating A1/A2 as
totality-of-observation only (Condition 1) removes the smuggle and leaves I1
and the silent-fail metric as real, contingent claims. The machine *can* be
refined to a real client, but the shipped adapter is a biased-clean estimator,
not a refinement, and two properties (log-internal totality, and read-back of
the served/billed identity that is the paper's stated delta) remain outside
what any log can certify without an out-of-band enforcement assumption.
Survives with those conditions.
