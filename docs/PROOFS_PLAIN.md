# The proofs, in plain words

Every theorem in `paper/PROOFS.md` (FCD, I1–I17) and `paper/RGA/PROOFS.md` (RGA, R1–R13, and the escape ledger's C1–C7), one plain sentence each. Rules, as in `docs/UI_GLOSSARY.md`: plain phrase first, exact term kept; a plain reading may never weaken the guarantee; every sentence restates something a proof already says, never more.

The two systems answer two different questions. **FCD answers: did the worker we chose actually do the work?** **RGA answers: was the work attacked hard enough, by an independent test, before we accepted it — and did the worker even agree with itself?** Neither proves the work is *good*. Both prove the paperwork cannot lie about what happened.

## FCD — the identity proofs (I1–I17)

FCD treats "we run specialists" as a claim that must be checkable. Its machine only lets work through a gate when the identity story holds together.

| Theorem | Plain reading |
|---|---|
| I1 Bind integrity | A stage passes only when the model that *actually ran* is the model we *said* we'd use. The two names come from different witnesses — intent is written at Bind, reality at Observe — so the check can genuinely fail. |
| I2 Class admission | Whoever is running the work was picked from the approved list for this kind of work, never from outside it. |
| I3 No unbound hop | Putting I1 and I2 together: nothing ever passes on a model outside the approved list. When a bind dies, the system stops; it never quietly continues on a different model. |
| I4 Frozen class and body | Once work opens, what it is and what it's about can never be rewritten. A change is a new work item, full stop. |
| I5 Accept coverage | "Accepted" means every required stage passed — not most, not the important ones, all. |
| I6 Dual control | The reviewer of a piece of work is never one of its authors. You cannot grade your own homework. |
| I7 Bounded admits | Retries can't loop forever: each retry must use a worker not yet tried, and the list is finite. |
| I8 Store only accepted | The store of finished work has exactly one door, and only fully accepted work goes through it. Nothing gets in by a side path. |
| I9 Retry preserves class | A retry is the same job again, never a quietly different job. |
| I10 Pinning | The moment work starts, it locks the exact project state, memory and setup it will run under; nothing swaps those underneath it. |
| I11 Package receipt | The gate passes only if the worker reports back the exact fingerprint of the context it was handed. Different bytes, no pass. |
| I12 Fresh-blind | A blind review provably excludes the author's notes, reasoning and prior verdicts, and cannot resume the author's session. |
| I13 Serialized promotion | Project memory changes only when accepted work wins a one-at-a-time race; a loser writes nothing. |
| I14 No silent drift | If the project moved on while work was in flight, that work cannot pretend it didn't; someone must sign off on the difference. |
| I15 Steering acknowledged | Mid-flight instructions can't rewrite the contract, can't touch finished work, and the run must prove it saw the latest one before passing. |
| I16 Cache identity | A cache shortcut is honored only when *everything* about the attempt is identical. Close enough is a miss. |
| I17 Current-attempt receipts | Paperwork from a previous attempt can never authorize this one. |

**What FCD honestly does not prove:** that the work is any *good*; that a worker who *lies* about what ran is caught (it proves the report is consistent, not that the report is true — that is assumption A10); that the work ever finishes. The paper says all of this itself.

## RGA — the scrutiny proofs (R1–R13)

RGA's machine only seals work when a pre-registered, re-runnable attack on it was actually carried out, at a strength that was measured, on outputs that agree with each other.

| Theorem | Plain reading |
|---|---|
| R1 No admission without survival | Nothing seals unless every declared test was run against every one of the k outputs and every single one came back "survived." A failed test, a test that timed out, or a missing test each keeps the seal shut. |
| R2 Power carried, never inferred | The strength number on the seal is the one the kernel itself computed — by counting kills against a named set of planted defects, or from declared, visible parameters — written once, before sealing, and impossible to raise afterwards. Nobody hands the kernel a flattering number. |
| R3 Separation of duty, extended | The worker didn't write its own test, the test existed before the worker started, the planted defects weren't authored by the worker or the test's author, and the worker's inputs provably excluded the test materials. The exam was locked before the student saw the paper. |
| R4 Concordance is a precondition | The k outputs must agree on the substance with the *first* one, at a declared rate. Disagreement closes the gate; the machine never holds a vote and picks a winner. |
| R5 Nondeterminism refuses | Re-run any test and get a different answer once, and that test is banned everywhere, forever. An unreliable inspector loses the badge. |
| R6 Replay exercised | Every test used on this work was re-run at least once, on this work, with an identical result — the re-runnability isn't taken on faith. |
| R7 Sample integrity (inherited) | Every one of the k outputs came through FCD's identity gate first, so we know all k came from the same worker on the same job. This is where FCD's proofs are reused, not redone. |
| R8 Seal implies Accept | Everything RGA seals was already fully accepted by FCD — the strict store is a subset of the honest store — and once sealed, the underlying record can't be failed or swapped out from under it. |
| R9 Artifact binding | The tests ran against the exact bytes the kernel fingerprinted, and the seal names those bytes. Not "an output like this one" — *this one*. |
| R10 Seed after artifact | Test inputs that depend on randomness are derived only *after* the output exists, so the worker could not have tuned its output to inputs it had already seen. |
| R11 RGA writes no FCD field | RGA only reads the identity machine, never edits it — which is exactly why every FCD proof still holds with RGA on top. |
| R12 Frozen line | The rules of this run — which claims, how many samples, what threshold, what floor — are locked at the start and can't be adjusted mid-flight. |
| R13 Bounded | Sample counts, tests per slot, and strength records are all hard-capped and write-once. Nothing accumulates its way around a limit. |

**The faults (V1–V15), in one sentence:** every way of cheating the above — sealing past a failure, counting a timeout as a pass, an under-strength seal, a plurality vote, a self-authored test, a tampered seed, an unmeasured or unreplayed test, a double-written strength record — is a named, forbidden step: the first five close the gate loudly, the rest are refused before they can write anything. And each protection is tested by *removing it* and proving the cheat then works (`tests/test_rga_mutation.py`).

**What RGA honestly does not prove:** that the work is *correct* — surviving a test is not being right; that the planted defects resemble the mistakes this worker really makes (that link is a stated assumption); that a harness reporting the verdicts is truthful (same boundary as FCD's A10 — but here a lie is catchable later, because the test can be re-run by anyone); that a worker who has memorized a public test can't game it. The seal also carries an explicit list of what was **not** attacked, so a pass on the checkable part can never be dressed up as a verdict on the judgment part.

## The calibration layer — the escape ledger (C1–C7)

A third, thinner set of proofs sits on top of RGA and answers: *what happens when a sealed artifact turns out to be wrong anyway?*

| Theorem | Plain reading |
|---|---|
| C1 Established, never asserted | A "we found a defect in sealed work" report counts only if it is re-runnable: the very test the seal trusted, re-run at a new input the finder chose, killing the work — replayed identically. Anything else needs a named human decision on the record before it counts. |
| C2 Charge totality and unit | When a miss is proven, every test that vouched for that work is charged — read off the record, automatically — and one miss is one charge, no matter how many ways it is demonstrated. |
| C3 Impeachment entailed and checkable | A proven miss revokes the work's standing everywhere it is consulted, the certificate never gets rewritten, and nobody has the discretion to decline the revocation — the proof itself entails it. |
| C4 The ratchet | Nobody can quietly ship a new test battery that forgets a proven miss. Either the new battery covers it, or someone puts their name and their reason on the record for leaving it out. Forgetting is loud. |
| C5 Track record carried, and the stamp proves who approved | Every new approval is stamped with its instruments' history — how many proven misses, across how much work — as raw counts, never a percentage, with the stated warning that zero misses may only mean nobody looked. The stamp is also the proof that the ledger saw this approval at all: work that got its certificate without passing the ledger has no stamp, and the system says so out loud instead of treating it as fully approved. |
| C6 Demotion | Every kind of work must state its miss budget up front — a kind of work nobody configured is refused outright, rather than quietly treated as having an unlimited budget. A test past its declared budget can't be trusted with new work, and — where the class chose strictness — can't finish work in flight either; the shutout is loud, carries the numbers, and never rewrites anything already approved. |
| C7 Non-interference | The ledger only reads the layers below; every proof of the two systems underneath survives untouched. |

**What the ledger honestly does not prove:** that the misses it knows about resemble the misses that exist. It is a ledger of *found* problems — attackers can pad it with true-but-chosen entries, silence in it is unreadable, and no one can be forced to look.

**And one more, found by review rounds and worth stating plainly:** replay alone detects internal inconsistencies, but it cannot distinguish a coherent replacement of root inputs or prove that no page is missing. v0.5 adds the missing publication layer: the three authority journals are read-only snapshots, each authority stack has its own registry namespace, successor heads prove the anchored prefix through a cumulative event chain, and one signed receipt carries those exact heads together with the kernel-derived result. After a trusted first anchor, a registry-current verified receipt rejects a cleanly shortened or forked history, a state-stale copy, a cross-wired stack, or predicates somebody merely typed. The first anchor cannot prove which coherent earlier history actually ran, and its signed time is metadata rather than expiry. This protection exists only when the receipt is issued and semantically verified against that external registry; schema validation alone cannot enforce the namespace/head equality. Bypass the path and the old replay-only limitation remains. If the signer/key and registry are both compromised or rolled back, the theorem has lost its trust roots. Everything else about forgetting stays loud.

## The one-line version of each

**FCD: the right worker provably did the work.** **RGA: the work provably survived a fair, measured, repeatable attempt to break it — several times over, consistently.** **The ledger: anything found against approved work afterwards sticks to it, automatically, and no new test battery can quietly forget it.** The first is an ID check; the second is a crash test with the test's strength printed on the certificate; the third is the recall notice that nobody can tear up. None of the three will ever tell you the work is perfect, and all three are built to make that impossible to forget.

**How to read the label.** Work carries one of three marks. **I** — we know who did it, and nothing more is claimed. **IR** — it also survived the tests, but the ledger never counter-signed it, so its standing is not being tracked. **IRC** — all three: identity, scrutiny, and standing that stays live, so if a defect turns up next month the mark changes by itself. A missing letter is never a smaller version of the next one up; it is a different, smaller claim.
