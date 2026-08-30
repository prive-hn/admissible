import type {
  CockpitState,
  Contract,
  GateConfig,
  ProjectSettings,
  ProjectSummary,
} from "../domain/types";

/**
 * Cockpit API client. Consumes the server contract EXACTLY:
 *
 *   GET  /api/state
 *   POST /api/work-items                       { prompt, contract }
 *   POST /api/work-items/{id}/steer            { nodeId?, command, text }
 *   POST /api/work-items/{id}/action           { action, nodeId?, specialist? }
 *   POST /api/questions/{id}/answer            { value?, text? }
 *
 * The client never mutates canonical state locally; it only reads state and
 * issues intents. On any transport failure the caller falls back to the
 * labeled demo state.
 */

const JSON_HEADERS = { "Content-Type": "application/json" };

/**
 * A refused intent carries the authority's own reason.
 *
 * The server answers a refusal with `{"error": "..."}` naming exactly what it
 * would not do — an unverified repository, a locked envelope, a route that
 * cannot Admit. Collapsing that to a status code would make a published
 * refusal indistinguishable from nothing happening, which is the one thing
 * this machine is built not to do.
 */
export class IntentRefused extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "IntentRefused";
    this.status = status;
  }
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    let reason = "";
    try {
      reason = (JSON.parse(text) as { error?: string }).error ?? "";
    } catch {
      reason = text.trim();
    }
    throw new IntentRefused(reason || `the server answered ${res.status}`, res.status);
  }
  return (text ? JSON.parse(text) : {}) as T;
}

/** The reason to show an operator, whatever kind of failure this was. */
export function refusalReason(error: unknown): string {
  if (error instanceof IntentRefused) return error.message;
  if (error instanceof TypeError) return "The authority is unreachable.";
  return error instanceof Error && error.message ? error.message : "The intent did not complete.";
}

export async function fetchState(signal?: AbortSignal): Promise<CockpitState> {
  const res = await fetch("/api/state", { signal, headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`GET /api/state -> ${res.status}`);
  const data = (await res.json()) as CockpitState;
  return { ...data, connection: data.connection ?? "live" };
}

/**
 * Ask the authority to compile the contract for a prompt. Nothing is opened.
 * The cockpit shows this — never a locally guessed contract — so the terms an
 * operator approves are the terms the machine will enforce.
 */
export async function compileWorkItemContract(
  prompt: string,
  cls?: string,
): Promise<Contract> {
  const { contract } = await postJson<{ contract: Contract }>(
    "/api/work-items/compile", { prompt, cls });
  return contract;
}

/**
 * Send the operator's settings to the authority.
 *
 * These used to live only in React state, so choosing `guarded` intake changed
 * a label and nothing else — the server kept its own default and went on
 * inferring. A control that cannot reach the authority is not a setting.
 */
export async function saveSettings(
  changes: Partial<Pick<ProjectSettings, "acceptanceMode" | "intakeMode" | "repairMode">>,
): Promise<ProjectSettings> {
  const { settings } = await postJson<{ settings: ProjectSettings }>("/api/settings", changes);
  return settings;
}

export interface CreateWorkItemInput {
  prompt: string;
  contract: Contract;
}

export async function createWorkItem(input: CreateWorkItemInput): Promise<{ id: string }> {
  return postJson<{ id: string }>("/api/work-items", input);
}

export interface SteerInput {
  /** Node the steering is scoped to, if any. */
  nodeId?: string;
  scope?: string;
  /** Slash command without the leading slash, e.g. "inspect". */
  command: string;
  /** Free-text remainder. */
  text: string;
}

export async function steerWorkItem(id: string, input: SteerInput): Promise<void> {
  await postJson<unknown>(`/api/work-items/${encodeURIComponent(id)}/steer`, input);
}

export interface ActionInput {
  action: string;
  nodeId?: string;
  specialist?: string;
}

export async function actOnWorkItem(id: string, input: ActionInput): Promise<void> {
  await postJson<unknown>(`/api/work-items/${encodeURIComponent(id)}/action`, input);
}

export interface AnswerInput {
  value?: string;
  text?: string;
}

export async function answerQuestion(id: string, input: AnswerInput): Promise<void> {
  await postJson<unknown>(`/api/questions/${encodeURIComponent(id)}/answer`, input);
}

export interface ProjectCandidate {
  local_path: string;
  name: string;
  github: string;
  base_branch: string;
  current_branch: string;
}

/**
 * Repositories the server can see, filtered by what the operator has typed.
 *
 * The browser cannot read a filesystem, so a path had to be typed from memory
 * before this existed. The client sends only a filter — never a directory — so
 * discovery stays confined to the server's own roots.
 */
export async function discoverProjects(
  query: string,
  signal?: AbortSignal,
): Promise<{ roots: string[]; candidates: ProjectCandidate[] }> {
  const res = await fetch(`/api/projects/discover?q=${encodeURIComponent(query)}`, {
    signal,
    headers: { Accept: "application/json" },
  });
  if (!res.ok) throw new IntentRefused(`discovery unavailable (${res.status})`, res.status);
  return (await res.json()) as { roots: string[]; candidates: ProjectCandidate[] };
}

export interface LoadProjectInput {
  id: string;
  name: string;
  local_path: string;
  github: string;
  base_branch: string;
}

export async function loadProject(input: LoadProjectInput): Promise<ProjectSummary> {
  return postJson<ProjectSummary>("/api/projects/load", input);
}

export async function selectProject(id: string): Promise<ProjectSummary> {
  return postJson<ProjectSummary>(`/api/projects/${encodeURIComponent(id)}/select`, {});
}

export async function configureGate(workItemId: string, gateId: string,
  changes: Partial<Pick<GateConfig, "agent_id" | "executor_id" | "model_id" | "context_mode" | "continuity">>): Promise<GateConfig> {
  return postJson<GateConfig>(`/api/work-items/${encodeURIComponent(workItemId)}/gates/${encodeURIComponent(gateId)}/configure`, changes);
}

export async function reviewImpact(workItemId: string, classification: string,
  decision: string, actor = "owner"): Promise<void> {
  await postJson<unknown>(`/api/work-items/${encodeURIComponent(workItemId)}/impact-review`,
    { classification, decision, actor });
}

/**
 * Subscribe to server-sent state, if the server exposes it. Returns an
 * unsubscribe function. When SSE is absent (constructor throws or the first
 * connection errors before any message), the caller keeps polling.
 */
export function subscribeState(
  onState: (s: CockpitState) => void,
  onError: () => void,
): () => void {
  let source: EventSource | null = null;
  try {
    source = new EventSource("/api/state/stream");
  } catch {
    onError();
    return () => {};
  }
  source.onmessage = (ev) => {
    try {
      const data = JSON.parse(ev.data) as CockpitState;
      onState({ ...data, connection: data.connection ?? "live" });
    } catch {
      /* ignore malformed frame */
    }
  };
  source.onerror = () => {
    source?.close();
    onError();
  };
  return () => source?.close();
}

export const defaultSettings: ProjectSettings = {
  versionLabel: "settings v0",
  acceptanceMode: "strict-match",
  intakeMode: "class-inferred",
  repairMode: "retry-in-allow-set",
};
