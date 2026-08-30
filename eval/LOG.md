# Evaluation log

A running record of what was tried, what it showed, and what was decided — kept
because an empirical claim is only as good as the account of how it was
produced. Entries are append-only. A result that came out badly stays in.

Two conventions, both load-bearing:

- **Pre-registration.** Before a run, the entry states the hypothesis, the
  metric, the adjudication rule and the stopping rule. Written first and
  committed first, so the analysis cannot be shaped by the data. An entry whose
  plan was written after the numbers says so in its header.
- **Positive controls.** A negative result is only informative if the method
  can be shown to detect something. Every detection run carries at least one
  case known to be detectable; if the control fails, the run measures the
  instrument, not the subject.

---

## E1 — Kernel bench on stdlib targets *(retrospective; pre-dates this log)*

**What it is.** `eval/bench` drives all three layers over reference
implementations of stdlib specifications, with the stdlib as the differential
oracle and a seeded AST mutator building the defect models.

**What it measures.** That the machinery is internally consistent: seals
require survival, discord and refutation close loudly, escapes impeach.

**What it does not measure.** Anything about a generator. Scenarios are
assigned and the sample is constructed to match, so `honest` is the reference
implementation itself and seals 8/8 by construction. Two of the three bars in
its figure are true by definition.

**Decision.** Keep as a machinery check. Do not cite it as evidence of value.

---

## E2 — Widening the target set *(retrospective)*

**Hypothesis.** Two textbook targets (`median`, `wrap`) are too thin; harder
targets will carry more defect surface.

**Method.** Added `normpath` and `quantiles`. Both reference implementations
verified byte-exact against `posixpath.normpath` and
`statistics.quantiles(..., method="inclusive")` over 4,000 generated inputs
before being wired in.

**Result.** |D| 14 → 44 (quantiles alone 21). Escapes established 2 → 7.
Standing layer exercised on three targets instead of one. `normpath`'s strong
refuter lands at 0.6667 — the first target where it is meaningfully imperfect.

**Incident.** The `normpath` property refuter flagged any result ending in a
slash. `normpath("//")` is `"//"` — POSIX leaves exactly two leading slashes
implementation-defined — so the property refuted the *reference
implementation*: five of eight honest lines closed V1 and three escapes were
filed against correct code. Caught by reading the outcomes table; confirmed
load-bearing by reintroducing the bug and watching
`test_every_honest_line_seals_and_none_is_impeached` go red.

**Lesson recorded.** A property refuter is code and can be wrong. An honest
line that fails to seal is an instrument fault until proven otherwise.

---

## E3 — Gate against a real generator *(retrospective)*

**Hypothesis.** Replacing the simulated generator with a real one will produce
defects the gate can catch.

**Method.** 60 implementations collected from 60 independent contexts (one
sample per context, so `k` samples per line are independent draws). Identical
instructions; contexts told not to verify against the standard library, which
isolates first-draft output — the condition the gate exists for.

**Result — false positives.** 16/16 lines sealed, zero false refusals. The 12
`normpath` samples were 12 *textually distinct* implementations; a checker
comparing source would have refused most. Independently confirmed all 48 match
their oracle on 3,000 inputs, so the seals are correct rather than lucky.

**Result — detection.** Not measurable. Zero of 60 samples were defective.
`splitext` was added as a trap: its leading-dot rule (`.bashrc` →
`(".bashrc", "")`) was deliberately not mentioned in the instruction. Five of
six contexts emitted the CPython algorithm verbatim, the sixth an equivalent
restructuring; all correct over 6,000 inputs.

**Conclusion.** The ceiling is structural. Every bench target is a stdlib
reference checked against the stdlib, and both halves are in a modern
generator's training data — it recalls the answer, and the answer is the
oracle. The differential refuter compares the oracle to itself. Adding harder
stdlib targets does not help: `normpath` and `quantiles` did no better than
`median`.

**Decision.** Detection must be measured on targets whose correct answer is not
recallable. Proceed to real historical defects.

---

## E4 — Real-defect pilot *(retrospective)*

**Method.** BugsInPy: 501 real bugs, 17 projects. Filtered to 320 localized
(single file, ≤12 changed lines), triaged 197 across ten projects, 63 landing
in a module-level function. Modules fetched at their own commits and run under
Python 3.11 despite pinning 3.6–3.8 — no Docker, no project installs.

**Result.** 34 testable, 5 raw separations, **3 confirmed real** on inspection
(`js_to_json` mangling 2020→216; `parse_dfxp_time_expr` returning 0.0 for the
empty string; a bytes pattern applied to a `str`). Two were artifacts of
stubbing.

**Known false negative.** `youtube-dl/20` (`get_elements_by_attribute`, a regex
alternation missing its empty branch) reports *not-separated*, yet separates
**40/40** by hand once inputs carry a valueless sibling attribute. Four
hand-picked inputs found 0/4 before the shape was right.

**Conclusion.** 3/34 is a floor on the input generator, not a detection rate,
and the false negative proves it. The README refuses to quote it as a rate.

**Two instrument faults recorded.** A `MagicMock` parent package fails
relative-import resolution — the import machinery reads the parent's
`__spec__` before any stub hook runs — costing 45 of 63 modules until replaced
with a real `types.ModuleType` (then 2). And exception-vs-exception was scoring
as detection: two versions crashing differently on a wrong-typed input is not a
defect, and four such pairs were being counted before the rule was tightened.

---

## E5 — Real-defect detection with a searching input generator

**Status: PRE-REGISTERED. Written and committed before the run.**

**Question.** Does the differential refuter separate real historical defects
from their fixes, once input generation stops being the bottleneck?

**Hypothesis (H1).** Replacing uniform-random inputs with a *search* —
Hypothesis-driven, which shrinks toward and hunts for separating inputs rather
than sampling blindly — raises confirmed separations materially above the
pilot's 3/34 on the same corpus.

**Null (H0).** No material change, i.e. the pilot's rate was not
generator-limited and something else binds.

**Subject.** The 63 candidates already in `eval/realdefects/manifest.json`.
Frozen: no bug is added, removed or re-triaged after this entry.

**Primary metric.** Confirmed separations ÷ candidates with a usable input
strategy.

**Adjudication rule, fixed in advance.** A separation counts only when:
- both sides return a value and the values differ, **or**
- one side returns a value and the other raises.

Exception-vs-exception **never** counts, however different the exceptions. Any
separation whose witness involves a stubbed object on either side is an
artifact and is excluded — this rule cost 2 of 5 in the pilot and is retained
unchanged.

**Positive control.** `youtube-dl/20` must separate. It is known separable
(40/40 by hand). If it does not, the run measures the generator and the
detection number is not reportable. This is the run's own honesty check, the
same role `test_every_honest_line_seals_and_none_is_impeached` plays in E2.

**Negative control.** For a random sample of candidates the harness will also
compare **fixed against fixed**. Any separation there is a bug in the harness —
nondeterminism, state leakage between loads, or input reuse — and invalidates
the run.

**Stopping rule.** One run over the frozen corpus with one generator
configuration. No per-bug tuning after seeing results; if a bug needs a bespoke
strategy it is recorded as not-separated and named in the entry. Any change to
the generator means a new entry and a re-run of the whole corpus, not a patch
to this one.

**Pre-committed threshold.** H1 is supported if confirmed separations reach
≥ 25% of testable candidates *and* the positive control passes. Between the
pilot rate and 25%, the result is reported as inconclusive and the generator is
still the suspect. Below the pilot rate, H1 is rejected.

**What this cannot show, stated now.** The fixed version is both oracle and
ground truth, so this measures whether a differential refuter can separate a
known fix — not whether the gate would catch the bug cold, with no fix to
compare against. The corpus is also filtered to module-level pure functions
(63 of 501), so stateful, async, I/O and environmental defects are excluded by
construction and no population-level rate follows.

*Result to be appended below after the run.*

### E5 — Result

**Ran 2026-08-29 against the corpus frozen at the pre-registration commit.**

| | |
| --- | ---: |
| Candidates | 63 |
| Testable (had an input strategy) | 34 |
| Raw separations | 8 |
| Artifacts excluded on inspection | 1 |
| **Confirmed separations** | **7** |
| **Rate** | **20.6%** |
| Pre-registered threshold for H1 | ≥ 25% |

**Verdict: inconclusive. H1 is not supported at the stated bar.** 20.6% falls
between the pilot's 8.8% and the threshold, which the pre-registration defines
as "report as inconclusive and the generator is still the suspect". The bar was
fixed before the run and is not moved now.

**Positive control: PASSED.** `youtube-dl/20` separated, having failed under
the pilot's generator. Worth recording precisely: the search found a *different*
witness than the hand demo did. By hand, a valueless sibling attribute made the
buggy version miss a match; Hypothesis instead found `<div class class
class="a"></div>`, on which the buggy version returns `[]` and the fixed one
raises `AssertionError`. Both are genuine behavioural differences between the
two commits, and the control's question — can this method detect this pair at
all — is answered yes. But the specific defect the control was built around is
still not what the generator found.

**Negative control: CLEAN.** Twelve candidates compared fixed-against-fixed;
zero separations. The harness is not manufacturing differences through
nondeterminism, state leakage between loads, or input reuse.

**Confirmed defects found.** Real bugs from real projects, each with a
minimal witness the search shrank to:

- `js_to_json` turns `"100"` into `"10"` — silent numeric corruption
- `js_to_json` turns `"0E"` into `'0"E"'`
- `url_basename` returns `""` for `http://e.com/a/../b` instead of `"b"`
- `parse_dfxp_time_expr` returns `0.0` for the empty string instead of `None`
- `_unquotepath` returns `str` where the fix returns `bytes`
- `_parse_operations` applies a bytes pattern to a `str`
- `get_elements_by_attribute` (the control)

**Instrument fault found, and it cost a finding.** The artifact filter tested
the *message text* for `"MagicMock"`. `youtube-dl/11` produced
`TypeError: isinstance() arg 2 must be a type` — caused entirely by a stubbed
`compat_str`, with no mock named in the message. It passed the filter and was
only caught by reading the witness. The filter must instead ask whether any
symbol the call touched is stubbed, rather than pattern-matching the error.
Recorded here rather than fixed silently: changing it means a new entry and a
full re-run, per the stopping rule.

**The binding constraint has moved.** `no-input-strategy` is now the largest
bucket at 27 of 63 (43%) — the harness declines to try, because the function
takes a domain object (a `Command`, a settings bag, a parsed node) it cannot
construct. String generation is no longer what limits detection; object
construction is. That is a different piece of work from better text
strategies, and it is where E6 should go.

**What is not claimed.** 20.6% is not a detection rate for the gate. It is a
lower bound on this harness, over a corpus filtered to module-level pure
functions (63 of 501), with the fixed version serving as both oracle and
ground truth. No population-level figure follows.

---

## E6 — Domain objects, and an artifact rule that does not read error text

**Status: PRE-REGISTERED. Written and committed before the run.**

**Why there is an E6.** E5 owes two things. Its artifact filter matched the
string `"MagicMock"` in an error message and therefore missed a stub-induced
`TypeError` whose message named no mock. And `no-input-strategy` became its
largest bucket at 27 of 63 — the harness declining to try, because the function
takes a domain object it cannot build. The stopping rule forbids patching a
finished run, so both are addressed here with a full re-run of the frozen
corpus.

**Question.** Once the harness can construct the objects these functions
actually take, and once artifacts are identified by cause rather than by
message text, how many real defects does the differential refuter separate?

**Hypothesis (H2).** Most `no-input-strategy` candidates are refused for a
mechanical reason, not a fundamental one: the parameter is a small record whose
fields the function body names outright. Building that record from the body's
own attribute accesses converts a large share into testable candidates, and the
confirmed rate over the enlarged set holds at or above E5's.

**Null (H0).** Constructing objects does not materially enlarge the testable
set, or the enlarged set separates at a lower rate — meaning what the harness
declined was declined for good reason.

**Subject.** The same 63 candidates in `eval/realdefects/manifest.json`, frozen
since E5. No bug added, removed or re-triaged.

**Method, fixed in advance.**
1. For a parameter the harness currently refuses, AST-scan the target
   function for attribute accesses on that parameter (`command.script`,
   `response.url`). Build a plain object carrying exactly those attributes,
   with values drawn from the same name-directed strategies used for ordinary
   parameters. If the body names no attribute of that parameter, it stays
   refused.
2. Both sides receive the **same** constructed object, so construction cannot
   manufacture a difference — only mask one, exactly as stubbing can.

**Artifact rule, replacing E5's.** An observation is an artifact when a stubbed
object is *implicated in the outcome*, determined by cause and not by text: for
a raise, walk the exception's traceback and treat it as an artifact if any
frame's locals or globals hold a mock; for a returned value, treat it as an
artifact if a mock appears in the value. E5's substring test is retired — it is
the fault this entry exists to fix.

**Adjudication rule.** Unchanged from E5. A separation counts only when both
sides return values that differ, or one returns and the other raises.
Exception-vs-exception never counts.

**Primary metric.** Confirmed separations ÷ testable candidates. Reported
alongside the E5 figures on the same corpus, since only the harness changed.

**Positive control.** `youtube-dl/20`, as in E5. Must separate.

**Negative control.** Fixed-against-fixed on a random sample, including
candidates newly testable through constructed objects — the construction path
is new code and is the most likely place for a spurious difference to enter.

**Pre-committed thresholds.** H2 is supported if **testable candidates rise
from 34 to ≥ 45** *and* **confirmed separations are ≥ 25% of testable** *and*
both controls pass. Meeting one but not the other is reported as partial and
named as such. If the testable set grows while the rate falls below E5's
20.6%, that is evidence the refused candidates were refused correctly, and it
is reported as H0 not rejected.

**Stopping rule.** One run over the frozen corpus. No per-bug strategies. Any
further change to construction or adjudication means E7, not an edit here.

**What this still cannot show.** Unchanged from E5: the fixed version is both
oracle and ground truth, the corpus is filtered to module-level functions, and
no population-level rate follows.

*Result to be appended below after the run.*

### E6 — Result: **VOID**

**The negative control failed.** `thefuck/10` separated against itself:
fixed-versus-fixed produced a difference. The pre-registration says any such
separation invalidates the run, so the run is void and its headline figure —
42 testable, 8 separated, 19.0% — **is not reported as a result**. It is
recorded here only to show what was discarded.

**Cause, diagnosed.** `get_new_command` appends to `command.script_parts`. It
*mutates its argument*. Both sides received the same constructed object, so the
first call changed the state the second call saw:

```
object before : Record(script='', script_parts=['a', ' 2 ', ' 2 '], stderr='')
call 1        -> ['a 3  2  2 ', 'a 2  2  2 ', ' 2  --help']
object after  : Record(script='', script_parts=['a', ' 2 ', ' 2 ', ' 2 '], ...)
call 2        -> ['a 3  2  2  2 ', 'a 2  2  2  2 ', ' 2  --help']
```

Same function, same object, different answers. The measured difference was call
order.

**This is a fault E6 introduced.** E5 passed strings and integers, which are
immutable, so shared arguments were safe and the negative control passed. The
moment the harness began constructing records the assumption silently stopped
holding — and the pre-registration's insistence that the negative control
include newly-testable candidates is the only reason it was caught rather than
being published as an eight-detection result.

**Not salvaged.** Some of the eight separations are on plain-string candidates
and cannot be affected by mutation. Picking those out after seeing which
survived is exactly the post-hoc selection the pre-registration exists to
prevent. The whole run is discarded and re-run in E7.

**Kept.** The artifact rule change is sound and untouched by this fault: no
separation in E6 was attributed to a stub, where E5's substring rule let one
through.

---

## E7 — E6 with argument isolation

**Status: PRE-REGISTERED. Written and committed before the run.**

**Why.** E6 was voided by argument mutation, not by anything about its
hypothesis. E7 is the same experiment with the fault fixed.

**Change, and only this change.** Each side receives its own deep copy of the
generated arguments, so one call cannot alter what the other sees. Nothing else
about construction, adjudication or the corpus moves.

**Hypothesis, thresholds, controls, stopping rule.** Identical to E6: H2
supported if testable rises from E5's 34 to ≥ 45 **and** confirmed separations
are ≥ 25% of testable **and** both controls pass. The negative control again
includes candidates newly testable through constructed objects, since that is
where the last fault lived.

**Additional pre-committed check.** Any candidate whose function mutates its
arguments is recorded, since that is now known to be common enough to have
broken a run and is worth counting rather than merely defending against.

*Result to be appended below after the run.*

### E7 — Result: **detection figure not reportable**

**Negative control: CLEAN.** 15 fixed-against-fixed comparisons, zero
separations. The deep-copy fix worked; E6's fault is closed.

**Positive control: FAILED.** `youtube-dl/20` came back *not-separated*, having
separated in E5. Per the pre-registration this means the run measures the
instrument, not the subject, and its detection figure is not reportable.

**Thresholds, for the record.** Testable rose 34 → **42**, short of the ≥ 45
required. Rate **19.0%**, short of the ≥ 25% required and below E5's 20.6%.
H2 is not supported on either arm, and would not have been even had the
control passed.

**Fault 1 — the artifact rule over-corrected.** E5's rule matched the string
`"MagicMock"` and was too narrow. E7's replacement flags a raise if any frame
in the traceback *references* a stubbed name. The control's witness raises
`AssertionError` inside `unescapeHTML`, which mentions the stubbed
`compat_str` without `compat_str` having anything to do with the failure — so
a genuine separation was discarded as an artifact.

Narrow rule let one artifact in; broad rule threw a real detection out. Both
are proximity tests standing in for a causal question. A correct rule has to
*test causation*: re-run the failing call with the stub replaced by a real
value and see whether the failure survives.

**Fault 2 — records are built from one side only.** `thefuck/20` separated
because the constructed object lacked an attribute the buggy version reads:

```
attrs named in FIXED source : ['split_script']
attrs named in BUGGY source : ['script']
```

The `Record` was built from the fixed source, so the buggy side raised
`AttributeError` on a field that simply was not there. That is the harness
failing, scored as the subject failing. Construction must take the **union** of
both sides' attribute names.

**Where this leaves the number.** Three runs, three distinct instrument faults,
each caught by a control or by reading witnesses — none by the summary
statistics, which looked plausible every time (8.8%, 20.6%, 19.0%).

E5's 7/34 is still the best-supported figure, but it is now *less* supported
than when it was written: its positive control passed on a witness that E7's
stricter rule classifies as an artifact. Whether that witness is genuine
depends on the causal test neither run implements. **The detection rate for
this harness is not established, and no figure from E5–E7 should be cited.**

**What E8 needs, before any further tuning.**
1. A causal artifact test — substitute a real value for the stub and check
   whether the failure persists — replacing both proximity heuristics.
2. Records built from the union of both versions' attribute reads.
3. Re-adjudication of E5's control witness under the causal rule, since the
   best available figure currently rests on it.

**A judgement worth recording.** The harness is gaining complexity faster than
it is gaining validity: each fix has introduced its own failure mode. Before
E8, it is worth asking whether a differential-against-the-fix design can
produce a clean number at all, or whether the honest deliverable is the
characterised instrument plus a small set of hand-verified defects rather than
a rate.

---

## E8 — An artifact rule that tests causation, and a pre-committed end to tuning

**Status: PRE-REGISTERED. Written and committed before the run.**

**Why there is an E8, and why it is the last one of its kind.** E5, E6 and E7
each failed for a different reason, and none of the three failures was visible
in its summary statistics. E7 diagnosed the remaining fault precisely: both
artifact rules so far — E5's substring match on the error text, E7's walk of
the traceback for stubbed names — are *proximity* tests standing in for a
*causal* question. Proximity was too narrow in E5 and let an artifact in; it
was too broad in E7 and threw the positive control out. No third proximity
threshold is worth trying, so E8 asks the causal question directly.

**Question.** When the harness reports that a buggy version and its fix behave
differently, is that difference produced by the source difference, or by the
values the harness invented for the modules it could not import?

**Hypothesis (H2, unchanged from E6/E7 so the runs stay comparable).**
Constructing the domain objects these functions take converts a large share of
`no-input-strategy` candidates into testable ones, and the confirmed rate over
the enlarged set holds at or above E5's 20.6%.

**Null (H0).** The testable set does not materially enlarge, or it enlarges and
separates at a lower rate — meaning the refused candidates were refused for
good reason.

**Subject.** The same 63 candidates in `eval/realdefects/manifest.json`, frozen
since E5. No bug added, removed or re-triaged.

### Change 1 — the artifact rule becomes a causal test

Both proximity heuristics are retired. In their place, a separation must be
**invariant to what the stubs return**.

Every unimportable module is a permissive mock, so every value that reaches the
code from outside is a value the harness invented. The question "did the stub
cause this?" is therefore answerable by experiment: *invent a different value
and look again.*

Three regimes are defined. In each, the same substitution is applied to **both**
sides, so a regime can mask a difference but never manufacture one — the same
argument that licenses stubbing at all.

| regime | every mock in the module's globals is |
| --- | --- |
| `R0` | left as it is |
| `R1` | replaced by a stand-in that answers `""` |
| `R2` | replaced by a stand-in that answers `"q"` |

The stand-in is not a mock. It is callable, subscriptable and attribute-open
like a mock, but two stand-ins carrying the same value are indistinguishable —
so, unlike two mocks, they cannot differ merely by identity.

**A witness separates iff it separates under all three regimes.** If the two
sides agree under any regime, or both raise under any regime, the difference
depended on a value the harness made up and the witness is rejected. The test
is applied inside the search predicate, not as a filter afterwards, so the
search hunts for stub-invariant separations directly and a rejected witness
does not end the search.

This subsumes both retired rules. A mock-valued return separates under `R0` by
identity alone and collapses under `R1`. A stub-induced crash that names no
mock — E5's escape — disappears when the stub answers a real string. A genuine
assertion failure that merely *mentions* a stubbed name — E7's false artifact —
survives all three, because it never depended on the stub.

**What it cannot see, stated now.** Only mocks bound in the module's own
globals are substituted. A mock reaching the code some other way — captured in
a closure, stored on a class, frozen into a default argument — is not perturbed,
so the rule is a test that can pass wrongly, not a proof.

### Change 2 — records are built from both versions

E7 scored `thefuck/20` as a separation because the constructed object was built
from the fixed source's attribute reads (`split_script`) and the buggy version
reads a different one (`script`), so the buggy side raised `AttributeError` on
a field that was simply absent. Attribute names are now taken from the
**union** of both versions' bodies. A field neither version reads is still not
invented.

### Change 3 — E5's positive-control witness is re-adjudicated

E5's 7/34 is the best-supported figure in this log and it rests on a control
that E7's rule calls an artifact. `youtube-dl/20` is therefore re-run under the
causal rule and the verdict recorded either way. If it fails here, E5's figure
is retired along with E6's and E7's.

### Change 4 — twelve candidates are adjudicated by hand

The controls test the harness against itself. They cannot tell whether a
reported separation *is the documented defect*, and three runs have shown that
summary statistics hide instrument faults. So a stratified random sample —
seed `20260830`, six candidates the harness calls `separated` and six it calls
`not-separated` — is adjudicated by reading the fix patch, before any figure is
reported.

Two questions per candidate, both answerable by a reader from what is recorded:

- **Separated:** does the witness reach the lines the patch changed, and does
  the difference in output follow from what those lines do? If not, the
  harness found *a* difference but not *this bug*.
- **Not separated:** can a separating input be constructed by hand from the
  patch? If yes the harness has a false negative; if the change cannot be
  observed through this function's return value at all, the negative is
  correct.

Each verdict is recorded with the patch hunk and the witness beside it.

**A bias this does not remove.** The adjudicator is the same agent that wrote
the harness, and has already seen some of these witnesses. That is a real
threat to this measurement and is not fixed by recording it. What recording the
evidence does buy is that a reader can overturn any individual verdict without
re-running anything.

### Metric, controls, thresholds

**Primary metric.** Confirmed separations ÷ testable candidates, reported
beside E5's figures on the same corpus, since only the harness changed.

**Positive control.** `youtube-dl/20` must separate.

**Negative control.** Fixed-against-fixed on ≥ 15 candidates sampled from the
testable set, including candidates newly testable through constructed objects.

**Pre-committed thresholds.** Unchanged from E6/E7. H2 is supported if testable
rises from 34 to **≥ 45** *and* confirmed separations are **≥ 25%** of testable
*and* both controls pass.

**Stopping rule for the run.** One run over the frozen corpus. No per-bug
strategies.

### Stopping rule for the programme — the part that matters

**E8 is the last run permitted to change the adjudication rule.**

- If both controls pass, the rate is reported, with the hand-adjudicated
  precision beside it and a confidence interval that reflects the sample size.
- If either control fails, **the rate is abandoned as a deliverable.** No
  fourth artifact rule is written. What is reported instead is the instrument
  as characterised by its controls, plus the individual defects that survive
  hand-adjudication, presented as cases and not as a rate.

This is written before the run precisely so that the choice between "report a
rate" and "report cases" cannot be made on the basis of whether the number came
out well. Three consecutive runs have produced a plausible-looking figure that
turned out to measure the harness; the burden of proof has moved, and an
instrument gets a fixed number of chances to earn a rate.

**What this still cannot show.** Unchanged from E5: the fixed version is both
oracle and ground truth, so this measures whether a differential refuter can
separate a known fix — not whether the gate would catch the bug cold. The
corpus is filtered to module-level functions (63 of 501), so stateful, async,
I/O and environmental defects are excluded by construction and no
population-level rate follows.

*Result to be appended below after the run.*

### E8 — Result: **both controls pass; the rate is reportable, and it does not mean what it says**

**Ran 2026-08-30 against the corpus frozen at E5.** Harness
`eval/realdefects/e8_harness.py`, results `e8-results.json`.

**Negative control: CLEAN.** 15 fixed-against-fixed comparisons, zero
separations.

**Positive control: PASS.** `youtube-dl/20` separates under the causal rule.

**Change 3, discharged.** E5's positive-control witness survives substitution
of the stub values, so E5's figure is not retired on the ground E7 raised. It
is superseded on other grounds, below.

**Thresholds.**

| | E5 | E7 | E8 | required |
| --- | ---: | ---: | ---: | ---: |
| testable | 34 | 42 | **42** | ≥ 45 |
| separations | 7 | 8 | **10** | — |
| rate | 20.6% | 19.0% | **23.8%** | ≥ 25% |

**H2 is not supported.** Testable did not reach 45 and the rate did not reach
25%. Both are reported as measured; neither is adjusted to reach its
threshold.

E8's separations are a strict superset of E7's: the causal rule recovered
`youtube-dl/11` and `youtube-dl/20`, which E7's proximity rule had discarded,
and discarded nothing.

### The hand adjudication — separated arm

Pre-registered sample of six (seed `20260830`), plus, as a deviation recorded
here, the remaining four. Adjudicating all ten is more evidence, not selected
evidence, but it does mean the separated arm is no longer blind. The
pre-registered six are marked ★.

| candidate | changed line | witness | verdict |
| --- | --- | --- | --- |
| ★ `youtube-dl/15` | identifier alternative excludes `E` after a digit | `'0E'` → `'0"E"'` vs `'0E'` | **the defect** |
| ★ `youtube-dl/26` | `\b` added before the octal alternative | `'100'` → `'10'` vs `'100'` | **the defect** |
| ★ `youtube-dl/6` | `return 0.0` → `return` | `''` → `0.0` vs `None` | **the defect** |
| ★ `scrapy/16` | `unquote` → `unquote_to_bytes` | `''` → `''` vs `b''` | **the defect** |
| ★ `thefuck/8` | bytes regex → str regex | `''` → `TypeError` vs `[]` | **the defect**, with a caveat¹ |
| `youtube-dl/43` | `[^/?#]+/` → `[^?#]+/` | `'http://e.com/a/../b'` → `''` vs `'b'` | **the defect** |
| ★ `youtube-dl/20` | bare attributes now match | `'<div class class class="a">…'` → `[]` vs `AssertionError` | **mixed**² |
| `youtube-dl/11` | `is None` → `isinstance(…, compat_str)` | `'0'` → `0` vs `TypeError` | **artifact**³ |
| `thefuck/10` | reordering + a new branch | `Record(script='', script_parts=[])` | **not the defect**⁴ |
| `thefuck/20` | `script.split()[1:]` → `split_script[1:]` | `Record(script='', split_script='00')` | **artifact**⁵ |

1. The fix also changed the *caller's* convention (`proc.stdout.read()` →
   `.decode()`), so the buggy version is being run on a `str` it would never
   have received. The witness demonstrates the type mismatch the bug is about,
   so it is counted, and the caveat is recorded.
2. Right cause, wrong manifestation. The fixed regex *does* match where the
   buggy one does not — that is the documented defect — but it then reaches
   `assert type(s) == compat_str` inside `unescapeHTML`, and `compat_str` is a
   stub. It should have returned `['']`.
3. `isinstance(int_str, compat_str)` raises `TypeError: isinstance() arg 2 must
   be a type` because `compat_str` is a mock. With the real `compat_str` both
   versions return `0`.
4. The difference follows from the reordering, but only on `script_parts=[]`,
   which the rule's own `match()` guard excludes. A behaviour difference
   outside the function's precondition.
5. `script` and `split_script` were drawn independently; in reality
   `split_script == script.split()`, and it is a list, not the string `'00'`.
   The union-of-attributes fix supplied both fields and the strategy then
   filled them inconsistently.

**Precision.** Pre-registered sample **5/6 = 83.3%** [43.6%, 97.0%]; census of
all ten **6/10 = 60.0%** [31.3%, 83.2%]. Counting the mixed case as the defect,
7/10.

### The hand adjudication — not-separated arm, which is the finding

Six candidates, separating inputs written by reading the patch — which is what
the harness may not do. Two ran and separated outright, one separated on a
contaminated witness, two are separable only outside this harness, one is a
corpus error.

| candidate | hand verdict | why the harness missed it |
| --- | --- | --- |
| `httpie/1` | **separates** (`'a'×300`, `exists=lambda p: False`) | `exists` is a callable parameter; the strategy passes a string. Generated names are ≤ 30 chars, the trim triggers at 255. |
| `youtube-dl/22` | **separates** (`'title = "foo bar"'`, `{'title': 'foo bar'}`) | needs a well-formed filter expression correlated with a key of the dict argument. |
| `youtube-dl/24` | separates, but the visible difference is the `compat_str` artifact | same stub-as-type hole as `youtube-dl/11`; the real defect is reachable with a real `compat_str`. |
| `youtube-dl/28` | **not separable under stubbing** | the fix catches a `ValueError` only the real `chr` raises; the stub never raises, so both sides agree. Separable against the real library. |
| `scrapy/38` | argued, not run | needs a real `lxml` form element; `lxml` is not installed here. |
| `scrapy/7` | **correct negative** | the named function `_urlencode` is byte-identical in both versions — a corpus error, below. |

**Five of six negatives are the harness failing to reach the code, not the two
versions agreeing.** "Not separated" therefore carries almost no information
about the subject, and the denominator of the headline rate is not the set of
candidates where a difference could have been found.

### Post-hoc characterisation of the instrument

Measured after the run, labelled as such, not part of the pre-registered
metric. Script `e8_characterise.py`, data `e8-characterisation.json`.

| measurement | count |
| --- | ---: |
| testable candidates where a stub stands in a **type position** (`isinstance`, `type(x) ==`, an `except` clause, a base class) | **23 / 42** |
| testable candidates the harness **never exercised** — the fixed side returned a value on no generated input | **19 / 42** |
| candidates whose **named function is byte-identical** in both versions | **6 / 63** |

Each is consequential.

**The type-position hole is the causal rule's blind spot, and it is exact.** A
mock in `isinstance(x, mock)` raises `TypeError` whatever the mock *returns*,
so substituting a different return value — which is precisely what E8's rule
does — cannot detect it. It affects 55% of the testable set and it produced
one of the ten separations outright and contaminated another.

**Nineteen of the 42 could not have separated at all.** Under the standing rule
that exception-vs-exception never counts, a candidate whose fixed side never
returns a value has no path to a separation. On the 23 the harness actually
exercised, the raw rate is 10/23 = 43.5% [25.6%, 63.2%] and the hand-confirmed
rate is 6/23 = 26.1% [12.5%, 46.5%].

*These are not offered as the result.* Re-deriving a denominator after seeing
that the pre-registered one missed its threshold is the move the
pre-registration exists to prevent. **The pre-registered figure is 23.8% and
H2 is not supported.** The 23-candidate denominator is reported because it
describes the instrument, and it is not used to claim a threshold was met.

**Six candidates name a function the fix does not change.** `triage.py`
computes NEW-file line numbers and then asks which definition encloses them in
the OLD file; where a patch inserts lines above the change, the two numberings
diverge. Three of the six sit in the `not-separated` bucket. No separation is
affected, so the numerator is sound, and the fault is in the corpus builder,
not the harness.

### The numbers, assembled

| | value | 95% CI (Wilson) |
| --- | ---: | --- |
| Pre-registered rate: separations ÷ testable | **10/42 = 23.8%** | [13.5%, 38.5%] |
| Hand-confirmed ÷ testable | 6/42 = 14.3% *(8/42 = 19.0% after the corrections below)* | [6.7%, 27.8%] |
| Precision, pre-registered sample | 5/6 = 83.3% | [43.6%, 97.0%] |
| Precision, census of all ten | 6/10 = 60.0% | [31.3%, 83.2%] |

### What is not being done, and why

The type-position hole has an obvious fix: add a regime in which the stand-in
is a real class. **It is not being added.** The pre-registration says E8 is the
last run permitted to change the adjudication rule, and changing it now — after
seeing which separations it would rescue — is exactly the post-hoc tuning that
voided the credibility of E6 and E7's numbers. The hole is recorded, with the
23/42 exposure measured, for whoever runs the next study under a new
pre-registration.

Two further defects, recorded for the same reason and likewise not patched
here: the strategy fills a constructed record's fields independently, so an
object can carry `script=''` beside `split_script='00'`; and it will not
produce a callable for a parameter that plainly needs one.

### Decision

The pre-registered rule was: controls pass → report the rate with its
adjudicated precision. Both controls passed, so **the rate is reported: 10 of
42 testable candidates, 23.8%, of which 6 are hand-confirmed as the documented
defect** — eight, after the corrections appended below. H2 is not supported.

What follows is a judgement made after the fact and marked as such. **The rate
is the least useful thing this run produced.** Its denominator is 45%
candidates that could not have separated and 14% whose negative the hand check
overturned; its numerator is 60% precise. Three things here are worth more than
the number and are what the study should be cited for:

1. **Six defects separated and hand-verified against the fix that closed
   them**, each with a witness a reader can re-run — `youtube-dl/15`, `/26`,
   `/6`, `/43`, `scrapy/16`, `thefuck/8`.
2. **A characterised instrument**: the failure modes are named, counted, and
   have their causes identified — stubs in type positions (23/42), candidates
   never exercised (19/42), a corpus line-numbering fault (6/63).
3. **A method that catches its own faults.** Four runs, four faults. E6's was
   caught by a control, E7's by a control, E8's two by the hand adjudication
   the pre-registration required. Not one was visible in the summary statistic,
   which read 8.8%, 20.6%, 19.0% and 23.8% — all plausible, three of them
   wrong for reasons only the controls exposed.

**The programme stops here.** No E9 under this design. A differential against
the fix can produce verified cases, and the honest deliverable is cases plus a
characterised instrument. Getting a defensible *rate* out of it would need a
corpus of functions whose dependencies are actually importable, so that no
stub stands between the input and the behaviour — a different study, with a
different corpus, pre-registered separately.

---

## E8 — Corrections after adversarial review

**Written after four independent reviews of the E8 entry above. That entry is
left standing, errors included, because this log is append-only and a result
that came out badly stays in.** Everything below was verified by re-running,
not accepted on a reviewer's word; where a reviewer was wrong that is recorded
too.

### The finding that matters: the causal rule never fired

E8's whole methodological contribution was the three-regime causal artifact
rule. **It is inert on this corpus.** Instrumenting the predicate across the
full search for all 42 testable candidates:

| | |
| --- | ---: |
| inputs that passed R0 | 237 |
| of those, killed by R1 (`Stand("")`) | **0** |
| of those, killed by R2 (`Stand("q")`) | **0** |
| verdicts a single-regime (R0-only) predicate agrees with | **42 / 42** |

So E8's ten separations are not "recovered by the causal rule". They are what
E5's rule gives once E7's over-broad proximity filter is deleted. The rule
added nothing, and the E8 entry's "the causal rule recovered `youtube-dl/11`
and `youtube-dl/20` … and discarded nothing" reads as evidence it works when
the measurement says it was never exercised.

**The mechanism is worse than the entry states.** It says a stub in a type
position "cannot be detected" by value substitution. In fact
`isinstance(x, MagicMock())` and `isinstance(x, Stand(""))` raise the
**byte-identical** message, so the three regimes are not merely uninformative
there — they are indistinguishable. `youtube-dl/11`'s witness shows the same
`TypeError` under R0, R1 and R2: the artifact passes the causal test by
producing itself three times.

**Therefore the positive control's pass was not earned.** `youtube-dl/20`'s
witness is an `AssertionError` from `assert type(s) == compat_str` inside
`unescapeHTML`. `Stand` is never a type, so that assertion fails under every
regime the harness can build. The rule had zero power to reject the control's
witness. "Change 3, discharged" is vacuous: the control's pass is inherited
from E5, not re-established.

### The premise the design rests on is false

Both the README and `harness.py` state flatly that "both sides receive
identical stubs, so a stub cannot manufacture a difference; it can only hide
one." That holds only where the two versions *use* the stub identically. Where
they do not, the stub is the entire cause of the difference — which is exactly
`youtube-dl/11`: the fixed version's new `isinstance(int_str, compat_str)`
touches the stub and raises; the buggy version's `is None` does not touch it
and returns.

A reviewer demonstrated a second route with a runnable case: `Stand` implements
none of `__add__`, `__mul__`, `__int__`, `__enter__`, `__setattr__` and others
that `MagicMock` supports, so R1/R2 can acquire a difference *of their own* and
confirm an artifact rather than collapse it. Two functions identical under the
real library are reported separated. Not triggered by any of the ten accepted
separations — I checked every regime report — but the rule offers no protection
against it.

### Two verdicts were wrong in the run's own favour

`thefuck/10` and `thefuck/20` were adjudicated "not the defect" and "artifact"
on the strength of degenerate witnesses. Both are **genuine detectable
defects**; the harness merely shrank to a bad witness. Verified by running the
loaded pairs on in-precondition inputs:

```
thefuck/10  Record(script='man ls', script_parts=['man','ls'], stderr='')
  buggy ['ls --help', 'man 3 ls', 'man 2 ls']   fixed ['man 3 ls', 'man 2 ls', 'ls --help']
thefuck/10  ... stderr='No manual entry for ls'
  buggy ['ls --help', 'man 3 ls', 'man 2 ls']   fixed ['ls --help']
thefuck/20  Record(script='unzip "a b.zip"', split_script=['unzip','a b.zip'])
  buggy '"a.zip'                                fixed 'a b.zip'
```

The first pair is the reordering and the new `stderr` branch; the second is the
quoting defect. **Footnote 4 of the E8 entry is false** — the difference does
not require `script_parts=[]`. So the hand-verified case set is **eight, not
six**, and candidate-level precision is 8/10, not 6/10. This correction runs in
the run's favour and is held to the same standard as the rest: it is recorded
because it is true, not because it helps.

### Arithmetic and definitions

- **"Nineteen of the 42 could not have separated at all" is false**, and
  `10/23 = 43.5%` is incoherent. `never_exercised` measures the *fixed* side
  never returning a value, but the adjudication rule counts a separation when
  **either** side returns and the other raises. `youtube-dl/11` is in
  `never_exercised` *and* is one of the ten, so the numerator is not a subset
  of the denominator. The exercised-arm figure is **9/23 = 39.1%**
  [22.2%, 59.2%]. `6/23 = 26.1%` is unaffected by *this* error; under the eight-case correction below it becomes 8/23 = 34.8% [18.8%, 55.1%], since neither `thefuck/10` nor `thefuck/20` is in the unexercised 19.
- **The cross-run table mixes definitions.** `e5-results.json` holds **8**
  separated rows; the table's E5 cell of 7 is E5's hand-*confirmed* count,
  while E7's 8 and E8's 10 are raw. Like-for-like, raw: E5 8/34 = 23.5% vs E8
  10/42 = 23.8% — indistinguishable. Hand-confirmed, before this entry's
  correction: E5 7/34 = 20.6% vs E8 6/42 = 14.3% — E8 worse. The same mixing
  is in the entry's closing "8.8%, 20.6%, 19.0% and 23.8%".
- **"14% whose negative the hand check overturned"** should be 5/42 = 11.9%;
  14.3% is 6/42, the fraction *examined*.
- **"byte-identical"** describes an `ast.dump` comparison. Independently
  recomputed: all six are in fact byte-identical, so the claim is true — but
  the check does not establish it, and returns `None == None` for a symbol
  absent from both sides.
- **The 23/42 type-position count is an upper bound, not a measurement.** The
  scan walks the whole module; restricted to the named function, only **5 of
  23** have a stubbed name in a type position. Three of the "exposed" 23
  (`youtube-dl/6`, `/15`, `/26`) separated cleanly and the hole had nothing to
  do with them.

### The corpus funnel is not a funnel

`triage.py` applies **no line-count filter**. The "single-file, ≤12 changed
lines → 320" row is not a stage on the path to the 63: only 136 of the 197
pilot bugs satisfy it, and **14 of the 63 candidates exceed 12 changed lines** —
including `scrapy/16` at 145 by triage's own count (160 added+removed), one of
the headline hand-verified defects. `manifest.json` holds **173** rows, not the
197 the funnel calls "Triaged": `changed()` returns `None` for the 24
multi-file patches and `main()` drops them, so those alone carry no exclusion
reason, contradicting "carries every triaged bug with its exclusion reason".

### The instrument, as actually built

- **`no-attributes-named` discards three testable candidates through a guard
  bug.** `thefuck/26`, `/30`, `/32` are all `get_new_command(command, settings)`;
  `settings` yields no attributes because the body never reads it, and the
  guard treats "opaque and unread" as unconstructable. A parameter nothing
  touches is the easiest case, not an impossible one. Testable is 42; the
  pre-registered threshold was ≥ 45. **These three are exactly the gap.** All
  three would be `not-separated`, so the rate would read 10/45 = 22.2% and H2
  still fails on the rate — but "testable did not reach 45" rests on a bug, not
  on the corpus.
- **The negative control compares a function object with itself.**
  `left = fns["fixed"]` makes both sides the same object with the same globals,
  so it cannot fail except on nondeterminism or cross-call state — which is
  what it caught in E6, and is all it can catch. It has no power over the
  failure mode that would actually void the run: the two module loads sharing
  `sys.modules` stubs. A reviewer built the stronger control (fixed source
  loaded **twice**, through the same load sequence): **15/15 clean**. The
  conclusion survives; the control as written did not earn it.
- **The substitution is not symmetric for 3 of 42**, including two separations
  (`scrapy/16`, `thefuck/20`): `mocked_globals` is computed per side and the
  sides do not agree on which names are stubs.
- **The restore is incomplete.** R0 patches nothing and so restores nothing, so
  a function that rebinds one of its own stubbed globals has that write kept
  under R0 and reverted under R1/R2 — the regimes do not run the same program
  state. A module that memoises a stub-derived value pins whichever regime ran
  first, and R0 always runs first.
- **The search was not reproducible.** `database=None` was set;
  `derandomize` was not, so Hypothesis reseeded from OS entropy each run.
  Verdicts were stable across runs but recorded witnesses were not — which is
  what "a witness a reader can re-run" was supposed to mean. Fixed:
  `derandomize=True`, and the results file regenerated under it.
- **Witnesses are order-dependent.** `scrapy/16` run standalone reports 12
  stubs where the corpus run records 4, because earlier candidates leave real
  modules in `sys.modules`. The verdict survives; the published witness does
  not reproduce from the single-candidate mode the README advertises.
- **`e8_characterise.py` could not run as committed** — it imported the
  pre-commit module name. The commit that introduced it advertised fixing that
  exact defect in `e7_harness.py`. Two reviewers independently confirmed that
  with the import corrected it reproduces `e8-characterisation.json` byte for
  byte, so the numbers were sound and only the script was broken.
- **A literal run of the README produced an empty study with exit status 0.**
  `triage.py` looked for `bugsinpy/`; the README's clone command produces
  `BugsInPy/`; a missing tree yielded zero jobs, zero candidates, and a
  reported rate of 0.0%. The positive control's `FAIL` line was the only thing
  between a reader and a fabricated number. Fixed: the corpus root is now
  discovered under either name and its absence is a hard exit.
- **`manifest.json` was inert.** It is byte-identical to the uncommitted
  `triage.json` that every harness actually read, so a clean checkout crashed
  with the frozen corpus sitting beside it, and "frozen since E5" was not
  mechanised. Fixed: one name per artifact — the harnesses read `manifest.json`
  and write the `*-results.json` files the README names.
- **`hypothesis` is an undeclared dependency**, in a repository whose stated
  posture is zero runtime dependencies.

### Where a reviewer was wrong

One review reported that the not-separated hand-adjudication was not the
pre-registered sample, having re-seeded `Random(20260830)` for the second
stratum. Both strata were drawn **sequentially from one generator**, and that
sequence reproduces both arms exactly — independently confirmed by a second
reviewer. The accusation is wrong. It is recorded here because the reason it
was made is a real fault: **the sampling code was never committed**, so a
competent reviewer could not reproduce the draw and reasonably concluded it had
been substituted. The draw now ships as code.

### What this does to the result

The pre-registered figure is unchanged and still not supported: **10 of 42
testable, 23.8%, against a ≥ 25% threshold and a ≥ 45 testable threshold.**
What is withdrawn is the *reason to believe E8 improved on E5*. E8 measured
E5's adjudication rule on a wider corpus with E7's filter removed; its own
contribution was inert.

The durable deliverable is unchanged in kind and larger in size: **eight real
defects, separated by a blind input search and hand-verified against the patch
that closed them** — `youtube-dl/15`, `/26`, `/6`, `/43`, `scrapy/16`,
`thefuck/8`, `thefuck/10`, `thefuck/20`.

**Fifth run, fifth fault, and again invisible in the summary statistic** —
23.8% looked exactly as plausible as 8.8%, 20.6% and 19.0% did. The difference
this time is that the controls did not catch it and the hand adjudication did
not catch it; four independent readings of the committed artifacts did. That is
the honest lesson of this programme, and it is worth more than the number: an
instrument's own controls are written by the person who wants it to work.

### A correction that reaches back to E3

E3's entry, and `eval/generators/RUN-2026-08-29.md`, report a `splitext` trap in
which contexts reproduced the CPython algorithm including its undisclosed
leading-dot rule. **Those samples were never committed.** No
`corpora/worker-pool.splitext.json` exists; the repository holds 48 samples
across four targets and no more. The observation is therefore not reproducible
and has been demoted, in the run record, to an unverified note.

What survives without it: **zero of 48 committed samples was defective**, across
12 textually distinct `normpath` implementations, all 48 matching their stdlib
oracle on 3,000 generated inputs. That is enough for E3's actual conclusion —
that a target whose oracle is a well-known library function cannot measure a
modern generator — and it is checkable from the repository. The `splitext`
anecdote was the sharpest version of the argument and is now the part that
cannot be checked.

The same run record asserted both "60 independent contexts — one sample per
context" and "12 contexts × 4". Those cannot both be true, the corpus schema
carries no per-sample context id, and so **the independence of the k samples
within a line is not established by anything committed.** Corrected in place,
with the limitation named.

### E8 — Corrections, round two (documentation review)

Three further reviews, of the documentation rather than the run. Verified the
same way: by re-running, including the two findings that run in the study's
favour.

**The `no-attributes-named` counterfactual was wrong, and in the run's favour.**
The corrections above assert that the three guard-refused candidates "would all
be `not-separated`, so the rate would read 10/45 = 22.2%". Re-running the
unmodified predicate with the documented fix — an attribute-free carrier for a
parameter the body never reads — gives:

```
thefuck/26: SEPARATED   witness=(Record(script='  '), Record())
              buggy  <MagicMock 'shells.and_()'>
              fixed  [<MagicMock 'shells.and_()'>, <MagicMock 'shells.and_()'>]
thefuck/30: not-separated        thefuck/32: not-separated
```

`vagrant_up.py`'s fix returns a two-element list where the buggy version returns
a scalar, which is exactly that shape difference, and it survives all three
regimes because it is structural rather than a matter of mock identity — though
the witness is mock-valued and would need hand adjudication like any other.
So testable would be **45, meeting that threshold**, and the rate **11/45 =
24.4%** [14.2%, 38.7%] — short of 25% by a single candidate. The earlier claim
that H2 missed on *both* arms is withdrawn: with the guard bug fixed it misses
on one, by 0.6 points.

**The "237 inputs passed R0" count does not reproduce.** An independent
instrumentation measured 319 on the same committed code and Hypothesis version.
The count is load-order sensitive and no committed script produces it. What does
reproduce, and is what the finding rests on, is stated instead: **R1 and R2
rejected no input the unperturbed predicate accepted, and an R0-only predicate
reproduces all 42 verdicts.** A further fact worth recording: only the ten
separated candidates ever produced an R0-passing input at all, so "across the
full search for all 42 candidates" describes the search, not the exercise.

**Two of the eight witnesses need argument isolation to reproduce.**
`thefuck/10`'s `get_new_command` appends to `command.script_parts`. Run the
obvious way — both sides against one object — the fixed side returns
`['man 3  2 ls', 'man 2  2 ls', 'ls --help']`, not the recorded value. That is
E6's voiding fault, live, in a witness whose reproduction the documents left to
the reader. Each side must get its own deep copy; `e8_handcheck.py` now carries
both hand-written cases so this is executed rather than described.

**Withdrawals that reach back, now named.** E4's entry states the corpus chain
in prose ("Filtered to 320 localized … triaged 197 … 63 landing in a
module-level function") and is withdrawn on the same grounds as the funnel. E3's
entry asserts "60 independent contexts — one sample per context"; the committed
corpora carry no per-sample context id, so that is not established either, and
its "zero of 60" is zero of 48.

**`task_sha256` does not hash an instruction.** `eval/generators/README.md` and
`corpus.py` describe it as the exact prompt text, hashed so a comparison is only
fair while the hashes match. The committed corpora hash the target *label*
(`spec:normpath`), so the four hashes necessarily differ and the fairness check
it defines cannot fire. Corrected in both places; that the instruction was
identical across contexts is asserted, not recorded, on the same footing as
sample independence.

**Single-candidate mode reproduces seven of the eight witnesses**, not none.
`scrapy/16` is the exception and materially so: standalone it stubs 12 names
instead of 4 and the buggy side returns a mock rather than `''`, because the
corpus run happens to leave the real `six` in `sys.modules`. Its verdict
survives; its published buggy value does not.

**And the framing.** "Five runs, five instrument faults" is a narrative shape,
not a count. The corrections above enumerate roughly a dozen distinct defects,
E4 records two of its own, E7 two. The tidy one-per-run reading is the single
place this log's honesty framing got ahead of its own ledger, and it is noted
here rather than smoothed over.
