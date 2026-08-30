# Real-defect study

Does the differential refuter separate **real historical defects**, or only
seeded mutants?

`eval/bench/` measures the machinery on stdlib functions under generators that
are honest, sloppy or unstable *by construction*. It is a self-consistency
check and says so. The paper's §11 names **coupling** — that mutation-derived
power predicts real faults — as an assumption it relies on and does not prove.
This study attacks that assumption directly, with real bugs from real projects.

Not part of the gate. Nothing here is admissible evidence; it is research code
that fetches from the network and executes third-party source.

**Read `eval/LOG.md` before citing anything from here.** It is the full account:
five runs, five instrument faults, none of them visible in the run's own summary
statistic. In particular the entry *"E8 — Corrections after adversarial review"*
withdraws several claims an earlier version of this file made, and this file has
been brought into line with it.

## What this study establishes

**Eight real defects, separated from their fixes by a blind input search and
verified by hand against the patch that closed them.** Every witness re-runs:
the six found by the search come back from `e8_harness.py`, and the two written
by hand from `e8_handcheck.py`.

| bug | function | the change | witness |
| --- | --- | --- | --- |
| `youtube-dl/15` | `js_to_json` | identifier alternative excludes `E` after a digit | `'0E'` → `'0"E"'` vs `'0E'` |
| `youtube-dl/26` | `js_to_json` | `\b` added before the hex/octal group | `'100'` → `'10'` vs `'100'` |
| `youtube-dl/6` | `parse_dfxp_time_expr` | `return 0.0` → `return` | `''` → `0.0` vs `None` |
| `youtube-dl/43` | `url_basename` | `[^/?#]+/` → `[^?#]+/` | `'http://e.com/a/../b'` → `''` vs `'b'` |
| `scrapy/16` | `_unquotepath` | `unquote` → `unquote_to_bytes`¹ | `''` → `''` vs `b''` |
| `thefuck/8` | `_parse_operations` | bytes regex → str regex¹ | `''` → `TypeError` vs `[]` |
| `thefuck/10` | `get_new_command` | reorder, and a new `stderr` branch² | `Record(script='man ls', script_parts=['man','ls'], stderr='No manual entry for ls')` → `['ls --help','man 3 ls','man 2 ls']` vs `['ls --help']` |
| `thefuck/20` | `_zip_file` | `script.split()[1:]` → `split_script[1:]`² | `Record(script='unzip "a b.zip"', split_script=['unzip','a b.zip'])` → `'"a.zip'` vs `'a b.zip'` |

1. The fix also changed the *caller's* convention, so the buggy version is being
   run on an input it would not have received in its own tree. The witness
   demonstrates the defect's mechanism; it is not a drop-in reproduction.
2. Found by the search on a degenerate witness and initially adjudicated *not*
   the defect. The witness above was written by hand afterwards and shows the
   documented change on an in-precondition input. See the corrections entry.

**A characterised instrument.** Its failure modes are named, counted and
diagnosed rather than left as noise — see *Known faults*.

## What this study does not establish

**A detection rate.** The final run's pre-registered figure is **10 separations
÷ 42 testable = 23.8%**, against thresholds of ≥ 25% and ≥ 45 testable set
before the run. Neither was met; the hypothesis is not supported.

Do not quote 23.8% as a detection rate:

- **The run's own methodological contribution was inert.** E8's three-regime
  causal artifact rule was measured after the fact: **the two perturbed regimes
  rejected no input the unperturbed one accepted, and a single-regime predicate
  reproduces all 42 verdicts.** E8 is E5's rule on a wider corpus with E7's
  over-broad filter removed. (An earlier version of this file gave a count of
  R0-passing inputs; it is load-order sensitive, an independent instrumentation
  measured a different number, and no committed script produces it, so only the
  invariants above are stated. Only the ten separated candidates ever produced
  an R0-passing input at all.)
- **Two of the ten separations are not the defect** (`youtube-dl/11`, a pure
  stubbing artifact; `youtube-dl/20`, right cause and stub-corrupted
  manifestation). Candidate-level precision is 8/10.
- **Negatives are weak evidence.** Of six hand-adjudicated `not-separated`
  candidates, three were overturned by running a hand-written input
  (`httpie/1`, `youtube-dl/22`, `youtube-dl/24` — the last on a contaminated
  witness), one is separable only outside this harness (`scrapy/38`, needs
  `lxml`), one is not separable *under stubbing* at all (`youtube-dl/28` — the
  fix catches a `ValueError` only the real `chr` raises), and one is a corpus
  error (`scrapy/7`). "Not separated" mostly means "not reached".
- **Three candidates are excluded by a guard bug**, not by the corpus.
  `thefuck/26`, `/30` and `/32` are refused because a parameter their body never
  reads yields no attributes to build. They are exactly the gap between the 42
  measured and the 45 the threshold wanted. Re-running the predicate with an
  attribute-free carrier, `thefuck/26` **separates** — its fix returns a
  two-element list where the buggy version returns a scalar — while `/30` and
  `/32` do not. So testable would be 45, **meeting that threshold**, and the
  rate 11/45 = 24.4%, short of 25% by one candidate.

Beyond the instrument: the corpus is filtered to module-level functions (63 of
501), so stateful, async, I/O and environmental defects are excluded by
construction and no population-level rate follows. The fixed version is both
oracle and ground truth, so this measures "can a differential refuter separate a
known fix", not "would the gate catch it cold". And the bugs pin Python 3.6–3.8
while the harness runs them under 3.11 — convenient, and a threat to validity
for a behavioural differential.

## Corpus

[BugsInPy](https://github.com/soarsmu/BugsInPy) — 501 real bugs across 17
projects, each with a buggy commit, a fixed commit and the failing test. Frozen
at E5 and mechanised: `manifest.json` is the frozen triage output and is what
the harnesses read, so a clean checkout runs the same corpus without
re-triaging. No BugsInPy revision is pinned, which is a gap.

These are **independent filters, not a funnel** — an earlier version of this
file presented them as a chain, and they do not nest:

| Filter | Bugs |
| --- | ---: |
| BugsInPy total | 501 |
| Single-file patch | 410 |
| Single-file **and** ≤ 12 changed lines (*not applied by `triage.py`*) | 320 |
| In the 10 pilot projects, with a patch | 197 |
| …of which single-file, so carrying a triage verdict (`manifest.json`) | 173 |
| Change lands in a **module-level function** — the candidates | **63** |
| Module loaded at both commits | 61 |
| A usable input strategy exists | 42 |

`triage.py` applies **no line-count filter**. Counting added+removed diff lines —
the definition that reproduces the 320 row — **14 of the 63 candidates exceed 12**,
`scrapy/16` worst at 160. By `manifest.json`'s own deduplicated `changed_lines`
field the same bug reads 145 and only 8 candidates exceed 12. Both counts are
reported because the two definitions disagree and the funnel above uses the
first.

The 24 multi-file patches among the 197 are dropped without a recorded exclusion
reason; every other exclusion path records one.

## Method

Every bug pins Python 3.6–3.8, which normally means Docker and six interpreter
builds. It is avoidable: for a module-level function the two module *sources*
are fetched at their own commits and executed side by side under one modern
interpreter, with unimportable third-party modules stubbed.

Inputs are a **search**, not a sample: Hypothesis hunts for values satisfying
"the two versions disagree". Strategies are chosen from the signature and the
same rules apply to every candidate — no per-bug tuning, which would destroy the
controls.

**A separation counts only when** both sides return values that differ, or one
returns and the other raises. Exception-vs-exception never counts: two versions
crashing differently on a wrong-typed input is not a defect.

**On stubbing.** Both sides receive identical stubs. That does **not** mean a
stub cannot manufacture a difference — it only follows where both versions use
the stub the same way, and where they do not, the stub is the whole cause.
`youtube-dl/11` is exactly that. Three successive artifact rules were written to
catch such cases (a substring match on the error text, a traceback walk for
stubbed names, and value substitution); the first was too narrow, the second too
broad, and the third does not fire at all. `eval/LOG.md` E5–E8 records each.

## Known faults, measured

Recorded and *not* patched: the pre-registration made E8 the last run permitted
to change the adjudication rule, and rewriting it after seeing which separations
a change would rescue is the post-hoc tuning that voided two earlier runs.

| fault | exposure | why it matters |
| --- | ---: | --- |
| **The causal rule never fires.** R1 and R2 reject no input R0 accepts. | 42 / 42 candidates | The run's distinguishing contribution is a no-op, and its positive control passes inside the rule's blind spot rather than because of it. |
| **A stub in a type position.** `isinstance(x, MagicMock())` and `isinstance(x, Stand(""))` raise the *byte-identical* message. | 5 / 42 inside the named function (23 / 42 anywhere in the module) | Value substitution cannot see it. Produced one false separation and corrupted another. |
| **Uncorrelated record fields.** A constructed object can carry `script=''` beside `split_script='00'`. | 1 degenerate witness | Real objects have invariants between fields; the strategy fills them independently, and the bad witness caused a true positive to be misjudged. |
| **No callable-valued parameters.** `exists=os.path.exists` receives a string. | 1 confirmed false negative | Both sides raise `TypeError`, which correctly never counts — so the candidate sits in the denominator unable to separate. |
| **`no-attributes-named` refuses an unread parameter.** | 3 / 63 | Exactly the gap to the pre-registered testable threshold. |
| **The negative control compares a function object with itself.** | — | It cannot fail except on nondeterminism or cross-call state. A stronger control (the fixed source loaded twice through the same sequence) was run separately: 15/15 clean. |
| **Line numbering in `triage.py`.** NEW-file line numbers are matched against the OLD file. | 6 / 63 | Those candidates name a function byte-identical in both versions. No separation is affected. |
| **Witnesses are order-dependent.** `scrapy/16` standalone reports 12 stubs where the corpus run records 4. | 1 / 8 verified | Verdicts survive; that one published witness does not reproduce from single-candidate mode, and standalone its buggy side returns a mock. |

## Files

| | |
| --- | --- |
| `triage.py` | BugsInPy → `manifest.json`; decides which bugs are candidates |
| `manifest.json` | the frozen corpus — read by every harness, so no re-triage is needed |
| `harness.py` | E4 pilot: uniform sampling. Superseded. |
| `search_harness.py` | E5: Hypothesis search replaces sampling |
| `e7_harness.py` | E7: constructed domain objects, argument isolation. Positive control failed; not reportable. |
| `e8_harness.py` | E8: the current harness. Its causal rule is inert — see the docstring. |
| `sample.py` | the pre-registered seed-20260830 hand-adjudication draw |
| `e8_handcheck.py` | hand-written separating inputs for the not-separated arm |
| `e8_characterise.py` | the fault measurements above |
| `*-results.json`, `e8-characterisation.json` | per-run output |

## Reproducing

Requires **`hypothesis`** (`pip install hypothesis`) — the only dependency in a
repository that otherwise declares none.

```bash
python3 e8_harness.py        # -> e8-results.json, plus both controls
python3 e8_handcheck.py      # the not-separated arm, by hand
python3 e8_characterise.py   # -> e8-characterisation.json
python3 sample.py            # the pre-registered adjudication draw
```

These read the committed `manifest.json` and fetch each module's source from
`raw.githubusercontent.com`, caching by commit in `srccache/` (gitignored). To
rebuild the manifest instead of using the frozen one:

```bash
git clone --depth 1 https://github.com/soarsmu/BugsInPy.git bugsinpy
python3 triage.py            # -> manifest.json   (overwrites the frozen corpus)
```

Run these from `eval/realdefects/`. **`e8_harness.py` rewrites the committed
`e8-results.json`**; `git checkout` it to restore. `e8_characterise.py` reads
that file, so run it after. A full run is a few minutes, plus network fetches on
a cold `srccache/`; a single candidate is seconds.

`python3 e8_harness.py youtube-dl/20` runs a single candidate. It reproduces the
recorded witness for seven of the eight verified defects; `scrapy/16` is the
exception and materially so — standalone it stubs 12 names instead of 4 and the
buggy side returns a mock rather than `''`, because the corpus run leaves the
real `six` in `sys.modules` from an earlier candidate. Its verdict survives, its
published buggy value does not. The search is seeded (`derandomize=True`),
so a full run reproduces both verdicts and witnesses exactly. No Hypothesis
version is pinned; the committed results were produced under 6.165.10 and
reproduce byte-for-byte there, and a different version may shrink to a different
witness.
