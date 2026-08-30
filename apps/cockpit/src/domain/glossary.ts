/**
 * Plain-language layer over the paper's vocabulary.
 *
 * The cockpit keeps the machine's exact words — they are load-bearing and they
 * match `paper/INVARIANTS.md` — but an engineer must never have to read the
 * paper to operate the instrument. Every machine term on screen therefore
 * carries a one-sentence plain reading here, plus the formal reference it maps
 * to. `docs/UI_GLOSSARY.md` mirrors this table by hand and is kept aligned in
 * review; there is no generator.
 *
 * Rules for entries:
 *   plain  — what an operator does or sees. No symbols.
 *   formal — the exact transition, symbol or invariant it comes from.
 * Nothing here may soften a guarantee: "reachable" never becomes "affected",
 * "candidate" never becomes "done".
 */

export interface GlossEntry {
  /** Canonical display term. */
  term: string;
  /** One sentence, operator's side of the screen. */
  plain: string;
  /** Where it comes from in the paper. */
  formal?: string;
  /** Grouping for the legend panel. */
  group: "lifecycle" | "route" | "context" | "evidence" | "object";
}

export const GLOSSARY = {
  // ---- objects -------------------------------------------------------
  line: {
    term: "Line",
    plain:
      "One unit of work taking form through its required gates. It ends as an accepted artifact, or it stays closed.",
    formal: "work item · status ∈ {open, failed, accepted}",
    group: "object",
  },
  gate: {
    term: "Gate",
    plain:
      "One required stage of a line. Each gate binds an agent, one exact model and a context policy.",
    formal: "stage · Required(c)",
    group: "object",
  },
  writeGate: {
    term: "Write gate",
    plain: "Produces the work. Whoever passes it is recorded as an author of the line.",
    formal: "write stage · authors ∪= {a}",
    group: "object",
  },
  checkGate: {
    term: "Check gate",
    plain: "Reviews the work. It cannot admit anyone who authored this line.",
    formal: "check stage · π_chk(c, authors) = π(c) \\ authors (A6, I6)",
    group: "object",
  },
  candidate: {
    term: "Candidate",
    plain:
      "Produced but not accepted. It sits outside the store and can still be retried or discarded.",
    formal: "status ≠ accepted",
    group: "object",
  },
  acceptedArtifact: {
    term: "Accepted artifact",
    plain: "Accepted and immutable. A fix is a new line, never an edit of this one. Accepted is the identity layer's word; sealed is the scrutiny layer's, and it is stronger.",
    formal: "id ∈ S (I8) · distinct from id ∈ S_R (R8)",
    group: "object",
  },
  class: {
    term: "Class",
    plain:
      "What kind of work this is. It decides the allow set and the required gates, and it is fixed the moment the line opens.",
    formal: "c · write-once after Open (I4)",
    group: "object",
  },

  // ---- lifecycle -----------------------------------------------------
  open: {
    term: "Open",
    plain: "The line starts. Its class and body are fixed here and can never be rewritten.",
    formal: "Open · c, body write-once (I4)",
    group: "lifecycle",
  },
  admit: {
    term: "Admit",
    plain:
      "The machine takes one specialist from the allow set for this gate. Admitting freezes the envelope: agent, exact model, context package and steering base stop being editable.",
    formal: "Admit(a) · a ∈ π*(c) \\ δ(c) \\ tried",
    group: "lifecycle",
  },
  bind: {
    term: "Bind",
    plain:
      "The machine writes down which exact model it intends to use. Bind records intent only — never what actually ran.",
    formal: "Bind · m_decl ← φ(a)",
    group: "lifecycle",
  },
  observe: {
    term: "Observe",
    plain:
      "The provider reports which model actually ran. This is the only place executed identity is ever written.",
    formal: "Observe(m) · m_exec ← m (A1)",
    group: "lifecycle",
  },
  pass: {
    term: "Pass",
    plain:
      "The gate holds. Allowed only when the model that ran matches the model that was bound.",
    formal: "Pass · norm(m_exec) = norm(m_decl) (I1)",
    group: "lifecycle",
  },
  failClosed: {
    term: "Fail closed",
    plain:
      "The gate broke and the break was published. Nothing downstream runs, and the machine never quietly moves the work somewhere else.",
    formal: "Close · pc = Closed, pub = 1",
    group: "lifecycle",
  },
  hop: {
    term: "Hop",
    plain:
      "Silently continuing on a different model after a break. This machine has no such transition — a break stays a break until you choose what happens next.",
    formal: "no hop transition",
    group: "lifecycle",
  },
  retry: {
    term: "Retry",
    plain:
      "Reopen the same gate with a different allowed specialist. The contract is never rewritten, and a specialist already tried is not offered again.",
    formal: "Retry · c unchanged (I9), a ∉ tried (A7)",
    group: "lifecycle",
  },
  accept: {
    term: "Accept",
    plain:
      "The only writer of the store. Every required gate must have held first, and accepting is what seals the artifact.",
    formal: "Accept · S ← S ∪ {id} (A8, I5)",
    group: "lifecycle",
  },
  notStarted: {
    term: "Not started",
    plain:
      "An earlier gate broke, but the line is still open. This gate has not run, and it will only run if that gate is retried and holds.",
    formal: "pc = Open below a Closed stage, status = open · Retry available (A7)",
    group: "lifecycle",
  },
  notReached: {
    term: "Not reached",
    plain:
      "This gate never ran. An earlier gate broke and the line stayed closed, so this is not queued work — it is work that did not happen.",
    formal: "pc = Open below a Closed stage",
    group: "lifecycle",
  },
  watchdog: {
    term: "Watchdog",
    plain:
      "Runs outside the worker and reports its death. It can only close a line; it can never accept one.",
    formal: "A2, A9",
    group: "lifecycle",
  },

  // ---- route ---------------------------------------------------------
  allowSet: {
    term: "Allow set",
    plain:
      "The specialists this gate is permitted to admit. On a check gate it excludes everyone who authored the line.",
    formal: "π*(c) = π_chk on check gates, else π (A6)",
    group: "route",
  },
  denySet: {
    term: "Deny set",
    plain: "Specialists this class may never admit. Deny always overrides allow.",
    formal: "δ(c) · π(c) ∩ δ(c) = ∅ (A0)",
    group: "route",
  },
  modelMap: {
    term: "Model map",
    plain: "Which exact provider model each specialist resolves to.",
    formal: "φ: specialist → API identity",
    group: "route",
  },
  declared: {
    term: "Declared",
    plain: "The model the machine bound for this gate — the intent.",
    formal: "m_decl",
    group: "route",
  },
  executed: {
    term: "Executed",
    plain: "The model the provider says actually ran — the fact.",
    formal: "m_exec",
    group: "route",
  },
  norm: {
    term: "Identity match",
    plain:
      "Two model names match only as API identities. Vendor prefixes count; a display suffix is not an identity.",
    formal: "norm(x) = norm(y) (A5)",
    group: "route",
  },
  specialist: {
    term: "Specialist",
    plain: "A named worker the policy can admit, distinct from the model it maps to.",
    formal: "a ∈ A",
    group: "route",
  },
  policyVersion: {
    term: "Policy version",
    plain:
      "The identity of the rules this line runs under. A line finishes under the version it opened with; reusing a version string with different content is refused.",
    formal: "version pinned at Open",
    group: "route",
  },
  executionAdapter: {
    term: "Execution adapter",
    plain:
      "The outside worker that actually runs the gate. It produces candidates and receipts; it can never pass or accept.",
    formal: "ExecutionAdapter",
    group: "route",
  },
  routeReadiness: {
    term: "Route readiness",
    plain:
      "Explicit checks that this exact provider route can run right now. Any failed check blocks Admit rather than degrading quietly.",
    formal: "execution-readiness · unknown adapters fail closed",
    group: "route",
  },

  // ---- context -------------------------------------------------------
  envelope: {
    term: "Envelope",
    plain:
      "The frozen record of one attempt: agent, exact model, context package and the steering it started from. It is immutable until the gate closes.",
    formal: "X, nonce · immutable until Close (I10)",
    group: "context",
  },
  contextPackage: {
    term: "Context package",
    plain:
      "The exact bytes handed to the executor. A pass requires the executor to report back the same hash the machine expects.",
    formal: "I11",
    group: "context",
  },
  receipt: {
    term: "Receipt",
    plain:
      "The executor's statement of what it ran and what context it received. A stale or mismatched receipt refuses the pass.",
    formal: "AdapterReceipt · I17",
    group: "context",
  },
  steering: {
    term: "Steering",
    plain:
      "Free instructions you attach to a scope. Steering is evidence the run must acknowledge; it cannot rewrite the contract.",
    formal: "I15",
    group: "context",
  },
  continuity: {
    term: "Continuity",
    plain:
      "Whether the executor starts a new session, resumes its own, or forks it. Resuming and forking need declared adapter capability.",
    formal: "fresh | executor_continue | executor_fork",
    group: "context",
  },
  freshBlind: {
    term: "fresh_blind",
    plain:
      "A fresh package with the author's transcript, reasoning and prior verdicts excluded. It forces a fresh session, so a reviewer cannot inherit the builder's context.",
    formal: "I12",
    group: "context",
  },
  head: {
    term: "Head",
    plain:
      "The project and memory versions accepted right now. A line pins these when it opens, and finishes against the pin even after the head moves on.",
    formal: "current (P_v, K_v) · advanced only by Accept under CAS (I13)",
    group: "context",
  },
  pin: {
    term: "Pin",
    plain:
      "The project and memory versions this line opened against. They never change underneath it.",
    formal: "(P_v, K_v) write-once at Open (I10, I14)",
    group: "context",
  },
  drift: {
    term: "Drift",
    plain:
      "The accepted project moved on after this line opened. The line keeps its pin, and you must review the impact before it can be accepted.",
    formal: "ImpactReview (A12, I13)",
    group: "context",
  },
  executorCache: {
    term: "Executor cache",
    plain:
      "What the executor says it reused from a previous run. It is the executor's own report, it is not checked, and no guarantee rests on it.",
    formal: "telemetry outside the transition table (INVARIANTS §2)",
    group: "context",
  },
  fcdCache: {
    term: "FCD cache",
    plain:
      "The machine's own cache identity, tied to one attempt, envelope and continuation. A hit requires all three to match; anything else misses and clears.",
    formal: "I16 · not the executor's cache",
    group: "context",
  },

  // ---- evidence ------------------------------------------------------
  observedBand: {
    term: "Observed",
    plain: "It happened, and the journal shows it.",
    formal: "certainty band",
    group: "evidence",
  },
  reachableBand: {
    term: "Reachable",
    plain:
      "Analysis proves it may be affected. It has not been seen, and it must never be read as if it had.",
    formal: "certainty band",
    group: "evidence",
  },
  unknownBand: {
    term: "Unknown",
    plain: "The evidence does not bound it. This is not a list of safe things.",
    formal: "certainty band",
    group: "evidence",
  },
  journal: {
    term: "Journal",
    plain:
      "The append-only record the machine replays from. Every mark in this cockpit resolves to an event in it.",
    formal: "open | stage | bind | call | decide | accept",
    group: "evidence",
  },
  authority: {
    term: "Authority",
    plain:
      "This cockpit sends intents and never writes the store. Admit, bind, observe, pass and accept belong to the machine alone.",
    formal: "Clark–Wilson separation",
    group: "evidence",
  },

  // ---- admissibility (layers R and C) --------------------------------
  seal: {
    term: "Seal",
    plain:
      "The scrutiny layer's acceptance. A line seals only after its samples survived every pinned refuter, and the seal carries the measured strength of that scrutiny. Write-once; nothing on it can be raised later.",
    formal: "Seal · id ∈ S_R ⊆ S (R1, R8) · rga/core.py",
    group: "evidence",
  },
  layerBadge: {
    term: "Layer",
    plain:
      "Which layers' guarantees govern this line. I: the identity layer alone — nothing beyond class dispatch is claimed, and the line's own state says how far it got. IR: it also sealed under scrutiny, but the calibration authority never counter-signed the seal, so its standing is not tracked. IRC: all three. A missing letter is a smaller claim, never a weaker version of the next one.",
    formal: "admissible(id) := id ∈ S_R ∧ mediated ∧ ¬tainted ∧ ¬impeached",
    group: "evidence",
  },
  mediated: {
    term: "Mediated",
    plain:
      "The calibration authority counter-signed this seal: exactly one track-record stamp, bound to this seal and no other. Without it the line sealed at the scrutiny layer only — it reads IR, and it is not admissible.",
    formal: "mediated(id): one cal_stamp bound to seal.sealed_at (C5) · rga/calibration.py",
    group: "evidence",
  },
  admissible: {
    term: "Admissible",
    plain:
      "Counter-signed, not tainted, not impeached — right now. Admissibility is a live query against the escape ledger, never a stored flag: it is recomputed on every read, so it cannot be set. What the ledger cannot see is an entry deleted from its own record — that needs an append-only store, which this kernel does not have.",
    formal: "admissible(id) = sealed ∧ mediated ∧ ¬tainted ∧ ¬impeached — pure queries, never writes (C3, §8.2) · rga/calibration.py",
    group: "evidence",
  },
  impeached: {
    term: "Impeached",
    plain:
      "A valid escape stands against a sealed claim: either the seal's own pinned refuter, re-run at an input a finder chose, killed the artifact (automatic once replayed), or another checker did and an adjudicator accepted the claim-match. The seal never rewrites; the record of the find stands beside it, and it lapses only by journal facts — a discredited checker — never by discretion.",
    formal: "impeached(id) entailed by a valid escape (C3); tier A past kernel checks, tier B past journaled adjudication (C1)",
    group: "evidence",
  },
  tainted: {
    term: "Tainted",
    plain:
      "A refuter this seal relied on was later caught giving different answers on replay. Everything that trusted it is marked, monotonically — the mark never comes off.",
    formal: "tainted(id): sealed line relied on a refuter refused after sealing — refusal is R5-monotone; tainted is a pure query (§4, rga/core.py tainted())",
    group: "evidence",
  },
  residual: {
    term: "Residual",
    plain:
      "What the seal does not cover: every claim that was not attacked by any refuter, named on the seal with how it was left — reviewed at a check gate, or not reviewed at all.",
    formal: "seal.residual · (claim, check_stage | unreviewed) — check_stage requires a Passed check stage (§4, V15)",
    group: "evidence",
  },
  carriedPower: {
    term: "Carried power",
    plain:
      "How hard the refuters actually tried, as a number the kernel counted: kills over a named defect set, or a bound computed from declared trial parameters. Never a scalar anyone wrote down.",
    formal: "power = kills/|D| or 1−(1−ε)^N — write-once (R2)",
    group: "evidence",
  },
  concordance: {
    term: "Concordance",
    plain:
      "Whether independent samples of the same work agreed on the claim's observable behaviour. Shown as (agreeing, k); at k=1 it is visibly unmeasured, not silently perfect.",
    formal: "witness agreement vs the designated sample at θ (R4)",
    group: "evidence",
  },
} as const satisfies Record<string, GlossEntry>;

export type GlossKey = keyof typeof GLOSSARY;

/**
 * Fault labels the machine can publish.
 *
 * `name` is the complete name shown beside the code, because a bare "F1" tells
 * an operator nothing. `plain` is the full reading for the hover card, and
 * `formal` is the line from the paper's fault table.
 */
export const FAULTS: Record<string, { name: string; plain: string; formal: string }> = {
  F1: {
    name: "executed model did not match the bind",
    plain: "The model that ran was not the model that was bound.",
    formal: "Pass with norm(m_exec) ≠ norm(φ(a))",
  },
  F2: {
    name: "two specialists shared one runtime instance",
    plain: "Two specialists shared one runtime instance.",
    formal: "needs a runtime-instance field to measure",
  },
  F3: {
    name: "the bound model was unusable",
    plain:
      "The bound model was unusable, or a call continued outside the unused allow set instead of failing closed.",
    formal: "after u = 0, another call without fail-closed",
  },
  F4: {
    name: "the worker died with no published close",
    plain: "The worker exited while the gate was running and no close was published.",
    formal: "Running exit with no published close",
  },
  F5: {
    name: "the mapped model is not an API identity",
    plain: "The mapped model is not a real API identity.",
    formal: "φ(a) not an API identity",
  },
  F6: {
    name: "passed on a denied specialist",
    plain: "A gate passed on a denied specialist.",
    formal: "Pass with a ∈ δ(c)",
  },
  F7: {
    name: "a check gate admitted an author of this line",
    plain: "A check gate admitted someone who authored this line.",
    formal: "check admit with a ∈ authors",
  },
  F8: {
    name: "ran without a well-formed gate",
    plain: "Something ran without a well-formed stage.",
    formal: "run without a well-formed stage",
  },
  F9: {
    name: "stopped while not accepted",
    plain: "The line was stopped in conversation while it was not accepted.",
    formal: "Stop in chat with status not accepted",
  },
  F10: {
    name: "the class changed, or a tried specialist was retried",
    plain: "The same id came back with a different class, or a specialist already tried was retried.",
    formal: "same id, class changes; or retry of a ∈ tried",
  },
};

/** Program-counter labels, already plain, kept here so the legend can list them. */
export const PC_MEANINGS: Record<string, string> = {
  Open: "Declared, not yet admitted.",
  Admitted: "A specialist is taken; the envelope is frozen.",
  Running: "Bound and executing.",
  Passed: "Held — executed identity matched the bind.",
  Closed: "Broke and published. Nothing downstream ran.",
  Stopped: "Closed and deliberately ended.",
};

export function gloss(key: GlossKey): GlossEntry {
  return GLOSSARY[key];
}
