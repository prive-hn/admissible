/**
 * Domain model for the fail-closed class dispatch cockpit.
 *
 * These types mirror the machine in `fcd/core.py`: a work item takes form
 * through required write/check stages; each stage either holds (Passed) or
 * breaks (Closed, fail-closed with an F-fault). When every stage holds the
 * item becomes an accepted artifact. Nothing here can mutate canonical
 * state — the cockpit only renders what the server reports and issues
 * intents (steer/action/answer) back to it.
 */

/** Program counter of a single stage, matching `Stage.pc`. */
export type StagePc =
  | "Open"
  | "Admitted"
  | "Running"
  | "Passed"
  | "Closed"
  | "Stopped";

/** Lifecycle of a work item, matching `Item.status`. */
export type ItemStatus = "open" | "failed" | "accepted";

/** Fault labels F1..F10 the machine can publish on a fail-closed close. */
export type FaultCode =
  | "F1"
  | "F2"
  | "F3"
  | "F4"
  | "F5"
  | "F6"
  | "F7"
  | "F8"
  | "F9"
  | "F10";

/** How a broken stage recommends resuming, from the `decide.next` field. */
export type NextAction = "accept" | "ask" | "retry" | "stop" | "hold";

/**
 * Impact of a failure, deliberately split into three certainty bands so the
 * operator never conflates what was seen with what is merely possible.
 */
export interface FailureImpact {
  /** Concretely seen in the journal. */
  observed: string[];
  /** Reachable from the broken bind but not (yet) seen. */
  reachable: string[];
  /** Cannot be bounded from available evidence. */
  unknown: string[];
}

/** A single evidence row backing a claim — every mark ties to a journal event. */
export interface EvidenceItem {
  id: string;
  /** Journal event type: open | stage | bind | call | decide | accept. */
  kind: string;
  label: string;
  detail?: string;
  /** Journal index, when the server exposes ordering. */
  journalIndex?: number;
  ts?: number;
}

/** Failure detail shown when a stage is Closed. */
export interface FailureDetail {
  fault: FaultCode | null;
  /** Plain-language "what happened". */
  whatHappened: string;
  /** Plain-language "what remains safe" — the fail-closed guarantee. */
  whatRemainsSafe: string;
  impact: FailureImpact;
  evidence: EvidenceItem[];
  /** Recovery paths the operator can take (map to action slugs). */
  recovery: RecoveryOption[];
}

export interface RecoveryOption {
  label: string;
  /** Action verb submitted to POST /action, e.g. "retry" | "discard". */
  action: string;
  /** Optional specialist to bind on retry (inside the allow set). */
  specialist?: string;
  hint?: string;
}

/** A node in the center pane: one stage of the selected work item. */
export interface StageNode {
  /** Stable id, e.g. "W1.0". */
  id: string;
  kind: "write" | "check";
  name: string;
  pc: StagePc;
  /** Bound specialist for this stage, if admitted. */
  specialist?: string | null;
  /** Declared model (written by Bind). */
  declaredModel?: string | null;
  /** Executed model (written by Observe). */
  executedModel?: string | null;
  /** Allow set the stage may admit from (π*). */
  allowSet?: string[];
  /** Specialists already tried on this stage. */
  tried?: string[];
  /** One-sentence summary of the current state. */
  sentence: string;
  /** Present when pc === "Closed". */
  failure?: FailureDetail | null;
  /** Evidence rows for the drilldown, independent of failure. */
  evidence?: EvidenceItem[];
}

/** An open question that pauses a work item until answered. */
export interface Question {
  id: string;
  workItemId: string;
  stageId?: string;
  prompt: string;
  /** Optional constrained choices (e.g. which allowed specialist to retry). */
  options?: QuestionOption[];
  /** Free-text answer allowed alongside options. */
  allowFreeText?: boolean;
  context?: string;
}

export interface QuestionOption {
  value: string;
  label: string;
  hint?: string;
}

/**
 * The admissibility record for one line, verbatim from the server's
 * `_admissibility()` projection. Which layer's guarantee this work carries,
 * said plainly: accepted-but-unsealed is layer I with the reason, never a
 * smaller green.
 */
export interface Admissibility {
  /**
   * Which layers' guarantees this line carries, read off the record:
   * "I" identity only, "IR" sealed under scrutiny but never mediated by the
   * calibration authority (no track-record stamp binds the seal), "IRC" all
   * three. IR is not a smaller IRC — it is a different claim.
   */
  layer: "I" | "IR" | "IRC";
  sealed: boolean;
  /** A unique calibration stamp binds this seal (C5 totality). */
  mediated?: boolean;
  admissible: boolean;
  impeached: boolean;
  tainted: boolean;
  /** Why the line could not enter the scrutiny layer, when it could not. */
  failure?: string | null;
  /** One server-authored sentence stating exactly what is claimed. */
  sentence: string;
  /** Present only when sealed. */
  powerMin?: number;
  k?: number;
  agreeing?: number;
  /** Claims not attacked, each with its disposition (check_stage | unreviewed). */
  residual?: [string, string][];
  trackRecords?: Record<string, unknown> | null;
}

/** A live work item — the object taking form. */
export interface WorkItem {
  id: string;
  title: string;
  cls: string;
  status: ItemStatus;
  policyVersion: string;
  projectVersion?: number;
  memoryVersion?: number;
  contextFailure?: string | null;
  paused?: boolean;
  /** Index of the current stage (Item.pointer). */
  pointer: number;
  stages: StageNode[];
  dependsOn: string[];
  authors: string[];
  /** Compiled contract shown before the flow begins. */
  contract?: Contract;
  /** Id of an open question blocking this item, if any. */
  openQuestionId?: string | null;
  createdAt?: number;
  updatedAt?: number;
  /** Per-line admissibility (absent on demo/legacy states). */
  admissibility?: Admissibility | null;
}

/**
 * A compiled contract: the visible, reviewable translation of a free-text
 * prompt into the class/stages/allow-set the machine will enforce.
 */
export interface ContractClass {
  id: string;
  name: string;
  summary: string;
  gates: { kind: string; name: string }[];
}

export interface Contract {
  /** Which declared class this line will open under. Write-once at Open (I4). */
  className?: string;
  classSummary?: string;
  /** What intake read from the prompt, before any operator override. */
  proposedClass?: string | null;
  classChosenBy?: "intake" | "operator" | "default";
  classNote?: string;
  /** Every class the project declares, so the operator can switch before Open. */
  classes?: ContractClass[];
  cls: string;
  title: string;
  summary: string;
  policyVersion: string;
  requiredStages: { kind: "write" | "check"; name: string }[];
  allowSet: string[];
  /** Acceptance mode label, e.g. "strict-match v0". */
  acceptanceMode: string;
  dependsOn: string[];
}

/** Capability → component drilldown for the left atlas. */
export interface Capability {
  id: string;
  name: string;
  /** Outcome roll-up for this capability. */
  outcome: OutcomeCounts;
  components: Component[];
}

export interface Component {
  id: string;
  name: string;
  /** Work item ids realizing this component. */
  workItemIds: string[];
  outcome: OutcomeCounts;
}

/** Counts across the four states surfaced in the atlas. */
export interface OutcomeCounts {
  active: number;
  accepted: number;
  degraded: number;
  question: number;
}

/** Project-level acceptance / intake / repair configuration. */
export interface ProjectSettings {
  /** Versioned label, e.g. "settings v3". */
  versionLabel: string;
  acceptanceMode: "strict-match" | "quorum" | "manual-final";
  intakeMode: "class-inferred" | "explicit-class" | "guarded";
  repairMode: "retry-in-allow-set" | "ask-first" | "stop-on-break";
}

/** Runnable artifact supplied by an execution adapter. */
export interface ArtifactRecord {
  workItemId: string;
  title: string;
  kind: "html" | "document" | "api" | "test" | string;
  state: "candidate" | "accepted";
  srcDoc: string;
  beforeSrcDoc?: string;
}

/** Project loaded and verified before any work line can open. */
export interface ProjectSummary {
  id: string;
  name: string;
  local_path: string;
  github: string;
  base_branch: string;
  current_branch: string;
  verified: boolean;
  project_version: number;
  memory_version: number;
  policy_version: string;
  skin: string;
}

export interface ExecutionReadiness {
  executor_id: string;
  declared_executor_id: string;
  executor_connected: boolean;
  provider: string;
  model_api_id: string;
  installed: boolean;
  authenticated: boolean;
  model_resolves: boolean;
  project_access: boolean;
  tools_available: boolean;
  canary: boolean;
  receipt_available: boolean;
  death_observable: boolean;
  ready: boolean;
}

export interface ModelDefinition {
  id: string;
  revision: number;
  provider: string;
  api_id: string;
  display: string;
  context_profile: string;
  reasoning: string;
  readiness?: ExecutionReadiness;
}

export interface AgentDefinition {
  id: string;
  revision: number;
  name: string;
  instructions: string;
  default_model_id: string;
  tools: string[];
  authority: string[];
}

export interface GatePolicy {
  id: string;
  revision: number;
  name: string;
  agent_id: string;
  executor_id: string;
  model_id: string;
  context_mode: string;
  continuity: string;
}

export interface GateConfig {
  work_item_id: string;
  gate_id: string;
  name: string;
  agent_id: string;
  executor_id: string;
  model_id: string;
  context_mode: string;
  continuity: string;
  editable: boolean;
  attempt_id: string | null;
  locked: boolean;
  readiness?: ExecutionReadiness;
}

export interface GateEnvelope {
  attempt_id: string;
  work_item_id: string;
  gate_id: string;
  attempt_counter: number;
  state: string;
  agent_id: string;
  specialist: string;
  executor_id: string;
  model_provider: string;
  model_api_id: string;
  context_mode: string;
  project_version: number;
  memory_version: number;
  locked: boolean;
  package_status: string;
  receipt_status: string;
  steering_sequence_acknowledged: boolean;
  executor_reuse_reported: boolean | null;
}

export interface ContextDrift {
  work_item_id: string;
  pinned_head: [number, number];
  current_head: [number, number];
  status: "needs_review" | "reviewed";
  classification: string | null;
  decision: string | null;
}

export interface ContextAtlasState {
  project: { id: string; project_version: number; memory_version: number; policy_version: string } | null;
  counts: { work_items?: number; attempts?: number; drift: number; drift_reviewed?: number };
  drift: ContextDrift[];
}

export type SteeringScope = "project" | "work" | "gate" | "stage" | "artifact" | "evidence" | "failure";
export interface SteeringTarget {
  scope: SteeringScope;
  id: string;
  label: string;
}

/** Whole cockpit state returned by GET /api/state. */
export interface CockpitState {
  /** Server-declared connection state; the client sets "disconnected". */
  connection: "live" | "demo-disconnected";
  atlas: {
    outcome: OutcomeCounts;
    capabilities: Capability[];
  };
  workItems: WorkItem[];
  questions: Question[];
  settings: ProjectSettings;
  projects?: ProjectSummary[];
  currentProject?: ProjectSummary | null;
  models?: ModelDefinition[];
  agents?: AgentDefinition[];
  gatePolicies?: GatePolicy[];
  gateConfigs?: GateConfig[];
  envelopes?: GateEnvelope[];
  contextAtlas?: ContextAtlasState;
  adapter?: string;
  interactions?: Record<string, unknown>[];
  /** Real runnable artifacts supplied by execution adapters. */
  artifacts?: ArtifactRecord[];
  /** Monotonic revision for cheap change detection. */
  revision?: number;
}
