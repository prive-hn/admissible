# Metrics review r3

Reviewed head: 6b450a508fab00227ccc7da9028a314a955dc12e
Verdict: SURVIVES WITH CONDITIONS

Lens: measurement. Sources read: `paper/DRAFT.md` §6, `metrics/SCHEMA.md`,
`paper/INVARIANTS.md` §6–§7 (the invariant companion, read as the rate contract),
and `scripts/collect_routing_metrics.py` (the only shipped instrument). No other
`eval/reviews` files read. Read-only; no paper file edited.

The four rates are individually well-formed and carry the correct anti-gaming
pairings; the design is honest about its own bias floor ("estimates biased
clean"). It survives, but three normative documents disagree on two sample
spaces, the window `W` is underspecified and circularly sourced, the
"never publish without silent-fail" co-publication rule is prose rather than a
schema obligation, and the entire anti-silent-abort chain rests on a write-ahead
precondition for `open`/`stage` that no axiom names. Those are the conditions.

## Named cut: defined? gameable? remaining fix

**Defined.** A cut is `[t0,t1]`, a pinned `(π,δ,φ)` version, and a window `W`,
with right-censor `ts > t1 − W` excluded, and policy evaluated **as-of event
`ts`** (pinned version only a default when no as-of row exists). The as-of rule
is the right primitive and is stated consistently across all three files. The
right-censor is correct: a stage with less than a full `W` of observation cannot
be scored for completion, so it is dropped rather than counted clean.

**Gameable.**
- `W` is "taken from the class reply-time distribution" with **no estimator,
  anchor, or per-class/global scope named**. `W` is a free knob that moves both
  silent-fail and time-to-stage: grow `W` and hung stages read non-silent longer;
  shrink `W` and the excluded tail swallows most of the sample. Its provenance is
  circular — `W` is derived from the same reply-time distribution whose censoring
  it then governs.
- No left-boundary handling. Right-censor covers `t1`; nothing covers stages that
  opened before `t0` but decide inside `[t0,t1]`, whose numerator is truncated.
- The fraction of events resolved by the **pinned default** (no as-of row) versus
  true as-of is never required to be published, so the default silently absorbs
  policy-resolution gaps.

**Remaining fix.** Pin `W` inside the cut as a named statistic on a named
reference period (e.g. a fixed quantile of a prior window's reply-times), declare
it per-class, and publish the as-of-vs-default resolution split alongside every
cut. State a left-truncation rule symmetric to the right-censor.

## Each rate: defined? gameable? remaining fix

### Misbind
**Defined.** Sample space is stated identically in DRAFT §6 and INVARIANTS §6:
first bind attempt per stage, condition `norm(m_exec) ≠ norm(φ(a))`. Correctly
disclaimed as an observation-gap / A1-breach rate, **not** F1 (F1 requires Pass).
Execution-side, and cleanly separated from bleed (admission-side).

**Gameable — by silent abort, exactly as the contract concedes.** The denominator
is stages that emitted a first-attempt `call`. Abort before the `call` event and
the stage leaves the misbind sample space entirely. The stated defense is the
paired silent-fail ("Never publish without silent-fail" / "Call-denominated
misbind is gameable by abort"). But that pairing is **advisory prose, not a
schema-level obligation** — nothing in the contract forces the two numbers to be
emitted as one artifact, so a partial publisher can ship a clean misbind alone.

**Remaining fix.** Promote co-publication to a schema obligation: a single record
carrying both misbind and silent-fail over the same cut, refused if either half
is absent. Make the write-ahead precondition for `stage`/`call` a stated
publication requirement, not a footnote.

### Silent fail
**Defined — but the sample space is inconsistent across the three documents.**
DRAFT §6 and SCHEMA both define it as *well-formed stages with no `decide`/`accept`
within `W`, **plus work items that `open` and never emit a stage***. INVARIANTS §6
(the "proofs" companion) lists the sample space as **"well-formed stages" only**,
dropping the orphan-`open` term. That orphan term is precisely the anti-gaming
provision, and the normative invariant file is the one that omits it. "Fail-closed
counts as published" is correct and prevents fail-closed inflation from reading as
silent.

**Gameable.** Silent-fail is the backstop, so its residual surface is the base of
the whole chain. It catches (a) a well-formed stage that never decides and (b) an
item that opens but never stages. It does **not** catch (c) an item that never
`open`s — no term covers that. The honesty of every zero therefore rests on `open`
and `stage` being write-ahead and total, which the contract assumes but never
axiomatizes (A1 covers data-plane calls while `Running`; A2 covers death while
`Running`; neither covers the pre-`Running` Open→Admit→Bind gap).

**Remaining fix.** Reconcile INVARIANTS §6 to include the orphan-`open` term.
Add an explicit axiom — call it write-ahead observability for `open`/`stage` —
as a named precondition of any published silent-fail zero, parallel to A1/A2.

### Bleed
**Defined — but the condition is inconsistent across documents.** DRAFT §6 and
SCHEMA use `π*(c)` (i.e. `π_chk` on check stages), so an author-specialist admitted
on a check stage is bleed. INVARIANTS §6 writes the condition as `a ∉ π(c)`, using
`π` not `π*`, which **fails to flag the author-on-check-stage case** and thus
under-counts bleed on check stages relative to DRAFT/SCHEMA. Admission-denominated
(assigned specialist vs as-of policy), correctly distinct from misbind; an
off-policy admit that then fails to bind is still bleed, which is right — the
illegal admission stands regardless of bind outcome.

**Gameable.** Like misbind, keyed on well-formed `stage` events, so an off-policy
admit aborted before the `stage` write escapes; caught only by silent-fail's
orphan term, and only under the same unaxiomatized write-ahead assumption. The
"pair with silent-fail" defense is again prose.

**Remaining fix.** Reconcile the bleed condition to `π*(c)` across all three files.
Bind the silent-fail pairing at schema level as for misbind.

### Time-to-stage
**Defined and well-constructed.** Duration from well-formed stage to `decide`/
`accept`, **right-censored survival, "not a mean," paired with `1 − silent-fail`.**
This is the correct anti-gaming shape: refusing the mean blocks the classic
"mean of completed" trick that drops hung stages, and pairing with `1 − silent-fail`
ties the curve to the completion mass so a fast curve cannot be quoted over a
half-silent population.

**Gameable — mild, two seams.** (1) It inherits the write-ahead-`stage` floor:
a stage aborted before its `stage` write is absent from the survival sample and
its non-completion is invisible here, visible only through silent-fail's orphan
term. (2) The pairing is across **mismatched denominators**: silent-fail's space is
`well-formed stages ∪ orphan opens`, while time-to-stage's space is
`well-formed stages` only, so `1 − silent-fail` is not exactly the completion
probability of the survival sample.

**Remaining fix.** State the denominator alignment for the pairing explicitly, or
define the survival on the same augmented space so `1 − silent-fail` is the true
completion complement.

## Instrument realizability

The only shipped collector emits execution-model call counts and signal counts by
agent against a **static, pinned** allow set. It carries no `stage`, `open`,
`decide`, or `accept` events, no `first_attempt`/`well_formed`/`stage_id` fields,
no cut, no `W`, and no as-of policy. Consequently **none of the four rates are
computable from the shipped instrument**: silent-fail and time-to-stage have no
inputs at all, and the on-policy count conflates misbind (executed ≠ `φ(a)`) with
bleed (assigned off-policy) while violating the as-of requirement. The rates are
defined against a schema that the head's own tool does not populate. This does not
break the contract — the collector is scoped as an adapter — but at this head there
is no realized measurement of any rate, so every zero is currently vacuous.

## Faults still informal under the contract

- **F2** (two specialists, one runtime instance): the distinguishing
  `runtime_instance` field is **optional** in the schema, so F2 is unmeasured by
  default; the fault is informal wherever the field is absent.
- **F3** (a call after `u=0` outside unused allow with no fail-closed): requires a
  guaranteed ordering of `call`/`decide` events after `BindFail`. The schema carries
  `signal` and `on_bind` but no write-ahead/sequencing guarantee, so F3 is informal
  without the unaxiomatized totality assumption.
- **F4** (running exit with no published close): rests on A2, which only covers
  death **while `Running`**. Deaths in the pre-`Running` Open→Admit→Bind window are
  uncovered, so F4 is informal for the pre-`Running` segment.
- **F8** (run with no well-formed stage): this is exactly the abort-before-`stage`
  case. It is measurable only if `stage` is write-ahead — the base assumption the
  contract never names as an axiom.
- **F9** (conversation end with `status ≠ accepted`): the schema has **no
  conversation-end / terminal event**. Without a terminal marker, F9 cannot be
  witnessed and remains informal.

F1, F5, F6, F7, F10 are measurable under the schema fields as written (Pass +
`on_bind`, `norm`/404, `assigned_specialist_id` vs as-of `δ`, `authors`, and the
`class`/`tried` history), given the same write-ahead precondition.
