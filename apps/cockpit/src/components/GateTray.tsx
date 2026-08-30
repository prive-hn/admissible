import { useEffect, useState } from "react";
import type { AgentDefinition, GateConfig, GateEnvelope, ModelDefinition, StageNode } from "../domain/types";
import { Gloss } from "./Gloss";
import { sameModelIdentity } from "../domain/modelIdentity";

interface Props {
  config: GateConfig | null;
  envelope: GateEnvelope | null;
  agents: AgentDefinition[];
  models: ModelDefinition[];
  onConfigure: (changes: Partial<Pick<GateConfig, "agent_id" | "executor_id" | "model_id" | "context_mode" | "continuity">>) => void;
  /** The gate as the machine sees it: what it bound, what it tried, whether it has run. */
  stage?: StageNode | null;
  /** True when holding this gate accepts the whole line — an irreversible write. */
  sealsOnHold?: boolean;
  /** Admit and run. Absent when the gate is not runnable. */
  onRun?: (verb: "run" | "retry") => void;
}

/** What each package mode actually does to the compiled context. */
const CONTEXT_MODES: { value: string; note: string }[] = [
  { value: "project_shared", note: "Carries the project's shared context package." },
  { value: "fresh_scoped", note: "Fresh package limited to this gate's declared categories." },
  { value: "fresh_blind", note: "Fresh package with author transcript, reasoning and prior verdicts excluded. Forces fresh continuity." },
  { value: "contract_only", note: "Nothing but the compiled contract." },
];

const CONTINUITY: { value: string; note: string }[] = [
  { value: "fresh", note: "A new executor session." },
  { value: "executor_continue", note: "Resume the executor's own session. Needs adapter capability." },
  { value: "executor_fork", note: "Fork the executor's session. Needs adapter capability." },
];

/** Readiness keys are wire names; an operator reads sentences. */
const CHECK_LABELS: Record<string, string> = {
  installed: "adapter installed",
  authenticated: "authenticated",
  model_resolves: "model resolves",
  project_access: "project access",
  tools_available: "tools available",
  canary: "canary call",
  receipt_available: "receipt support",
  death_observable: "death observable",
  executor_connected: "executor connected",
};

export function GateTray({ config, envelope, agents, models, onConfigure, stage, sealsOnHold, onRun }: Props) {
  const [agent, setAgent] = useState(config?.agent_id ?? "");
  const [model, setModel] = useState(config?.model_id ?? "");
  const [mode, setMode] = useState(config?.context_mode ?? "project_shared");
  const [continuity, setContinuity] = useState(config?.continuity ?? "fresh");

  useEffect(() => {
    setAgent(config?.agent_id ?? "");
    setModel(config?.model_id ?? "");
    setMode(config?.context_mode ?? "project_shared");
    setContinuity(config?.continuity ?? "fresh");
  }, [config?.work_item_id, config?.gate_id, config?.attempt_id]);

  if (!config) return null;
  const editable = config.editable;
  const selectedAgent = agents.find((a) => a.id === agent);
  // Readiness of the route that will actually run. Following the unsaved
  // dropdown made the button lie in both directions: Run does not save, so it
  // fires against the persisted config — a not-yet-saved choice disabled a
  // button whose saved route would have run, and a ready one enabled a button
  // the server then refused. Run is disabled while there are unsaved edits.
  const readiness = config.readiness ?? models.find((m) => m.id === config.model_id)?.readiness;
  // Unknown readiness is not readiness. The adapter contract fails closed on an
  // unknown route, and the surface has to say the same thing rather than
  // defaulting an unreported check to "ready".
  const reported = readiness != null;
  const executorConnected =
    config.readiness?.executor_connected ?? readiness?.executor_connected ?? false;
  const routeReady = reported && readiness.ready === true && executorConnected;
  const failedChecks = reported
    ? Object.entries(readiness).filter(([key, value]) => key !== "ready" && value === false).map(([key]) => key)
    : [];
  if (reported && !executorConnected && !failedChecks.includes("executor_connected")) {
    failedChecks.push("executor_connected");
  }
  // Blocker 4: the allow set is finite and a tried specialist is never offered
  // again (A7). When it is spent the only move left is discard, so say that
  // instead of offering a control that can now only be refused.
  const tried = stage?.tried ?? [];
  const allowSet = stage?.allowSet ?? [];
  // An empty allow set means no specialist may be admitted — the strictest
  // possible state. Reading it as "fine" left the run button live and the
  // "no specialists left to try" copy unreachable in the one case it was
  // written for. No stage at all is a different thing: the line has no
  // machine state yet, so nothing is known about the allow set, and that is
  // not the same as knowing it is empty.
  const remaining = stage == null || allowSet.some((a) => !tried.includes(a));
  const hasRun = Boolean(stage && stage.pc !== "Open");
  // What the gate is configured to use, versus what this attempt actually
  // bound. A retry can admit a different specialist, and the two diverge.
  const configuredRoute = envelope ? `${envelope.model_provider}:${envelope.model_api_id}` : null;
  const boundDiverges = Boolean(
    stage?.declaredModel && configuredRoute &&
    !sameModelIdentity(stage.declaredModel, configuredRoute),
  );
  const execMatches = sameModelIdentity(stage?.declaredModel, stage?.executedModel);
  const modeNote = CONTEXT_MODES.find((m) => m.value === mode)?.note;
  const continuityNote = CONTINUITY.find((c) => c.value === continuity)?.note;
  const dirty =
    agent !== config.agent_id ||
    model !== config.model_id ||
    mode !== config.context_mode ||
    continuity !== config.continuity;

  return (
    <section
      className={`gate-tray gate-tray--${editable ? "editable" : "locked"}`}
      aria-label="Gate execution envelope"
    >
      <div className="gate-tray__head">
        <div className="gate-tray__id">
          <strong>{config.name}</strong>
          <span className="chip">{config.gate_id}</span>
        </div>
        <Gloss
          term={editable ? "admit" : "envelope"}
          className={`gate-lock gate-lock--${!editable ? "locked" : !remaining ? "spent" : "open"}`}
          focusable
        >
          {!editable
            ? "Locked at Admit"
            : !remaining
              ? "No specialists left to try"
              : envelope
                ? "Retryable — the next attempt is editable"
                : "Editable before Admit"}
        </Gloss>
      </div>

      {envelope && (
        <div className="gate-receipt">
          <div><span>attempt</span><code>{envelope.attempt_id}</code></div>
          <div><span>agent</span><b>{envelope.agent_id}</b></div>
          <div>
            <span>route configured</span>
            <b>{envelope.model_provider} / {envelope.model_api_id}</b>
          </div>
          <div>
            <span>bound this attempt</span>
            <b className={boundDiverges ? "mismatch" : undefined}>
              {stage?.declaredModel ?? "not bound"}
              {/* The divergence used to be red text and nothing else, so it
                  was invisible to a screen reader and to anyone who does not
                  separate these hues. It is the I1 readout; it gets a word. */}
              {boundDiverges && <em className="mismatch__word"> differs from the route</em>}
            </b>
          </div>
          <div>
            <span>executed</span>
            <b className={stage?.executedModel && !execMatches ? "mismatch" : undefined}>
              {stage?.executedModel ?? "not observed"}
              {stage?.executedModel && !execMatches && (
                <em className="mismatch__word"> does not match the bind</em>
              )}
            </b>
          </div>
          <div><span>context</span><b>{envelope.context_mode}</b></div>
          <div><Gloss term="pin"><span>project pin</span></Gloss><b>P{envelope.project_version} · K{envelope.memory_version}</b></div>
          <div><Gloss term="contextPackage"><span>package</span></Gloss><b className={`tag tag--${envelope.package_status}`}>{envelope.package_status}</b></div>
          <div>
            <Gloss term="receipt"><span>receipt</span></Gloss>
            <b className={`receipt receipt--${envelope.receipt_status}`}>{envelope.receipt_status}</b>
          </div>
          <div><Gloss term="executorCache"><span>executor cache</span></Gloss><b>{envelope.executor_reuse_reported == null ? "not reported" : envelope.executor_reuse_reported ? "reported reuse" : "reported fresh"}</b></div>
        </div>
      )}

      {editable ? (
        <div className="gate-editor">
          <label><Gloss term="specialist">Specialist</Gloss>
            <select aria-label="Specialist" value={agent} onChange={(e) => setAgent(e.target.value)}>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>{a.name}:{config.gate_id} · r{a.revision}</option>
              ))}
            </select>
            <small>
              Admitted as <code>{agent}:{config.gate_id}</code>. The model below follows from it.
            </small>
          </label>
          <label><Gloss term="executionAdapter">Execution adapter</Gloss>
            <input aria-label="Execution adapter" value={config.executor_id} disabled />
            <small>Set by the project. The adapter is a worker, never an authority.</small>
          </label>
          <label><Gloss term="modelMap">Model it binds</Gloss>
            <select aria-label="Exact model" value={model} onChange={(e) => setModel(e.target.value)}>
              {models.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.provider} / {m.api_id}{m.readiness ? (m.readiness.ready ? " · ready" : " · not ready") : ""}
                </option>
              ))}
            </select>
            <small>
              What this specialist runs on. Pass requires the model that ran to be this one.
            </small>
          </label>
          <label>Context
            <select aria-label="Context mode" value={mode} onChange={(e) => {
              const next = e.target.value; setMode(next); if (next === "fresh_blind") setContinuity("fresh");
            }}>
              {CONTEXT_MODES.map((m) => <option key={m.value} value={m.value}>{m.value}</option>)}
            </select>
            <small>{modeNote}</small>
          </label>
          <label><Gloss term="continuity">Continuity</Gloss>
            <select aria-label="Executor continuity" value={continuity} disabled={mode === "fresh_blind"}
              onChange={(e) => setContinuity(e.target.value)}>
              {CONTINUITY.map((c) => <option key={c.value} value={c.value}>{c.value}</option>)}
            </select>
            <small>{mode === "fresh_blind" ? "fresh_blind forbids continuity." : continuityNote}</small>
          </label>

          {selectedAgent && (
            <div className="gate-instructions">
              <div className="gate-instructions__body">
                <span>Agent instructions · r{selectedAgent.revision}</span>
                <p>{selectedAgent.instructions}</p>
              </div>
              <dl className="gate-instructions__meta">
                <div><dt>tools</dt><dd>{selectedAgent.tools.join(", ") || "none"}</dd></div>
                <div><dt>authority</dt><dd>{selectedAgent.authority.join(", ") || "none"}</dd></div>
              </dl>
            </div>
          )}

          <div className={`route-readiness route-readiness--${routeReady ? "ready" : "blocked"}`}>
            <Gloss term="routeReadiness" className="route-readiness__verdict">
              <b>{routeReady ? "Route ready" : reported ? "Route not ready" : "Route unknown"}</b>
            </Gloss>
            {routeReady ? (
              <span className="route-readiness__note">Every declared check passes. This gate can Admit.</span>
            ) : !reported ? (
              <span className="route-readiness__note">
                This adapter reported no readiness checks, so the route is not treated as
                available.
              </span>
            ) : (
              <ul className="route-readiness__checks">
                {failedChecks.map((key) => (
                  <li key={key}>{CHECK_LABELS[key] ?? key.replace(/_/g, " ")}</li>
                ))}
              </ul>
            )}
          </div>

          <div className="gate-editor__commit">
            {onRun && (
              <button
                className="btn btn--accent"
                disabled={!routeReady || !remaining || dirty}
                onClick={() => onRun(hasRun ? "retry" : "run")}
              >
                {hasRun ? "Run this gate again" : "Admit and run this gate"}
                {sealsOnHold && (
                  <span className="btn__meta">accepts the line if it holds</span>
                )}
              </button>
            )}
            <button
              className="btn"
              disabled={!routeReady}
              onClick={() => onConfigure({ agent_id: agent, executor_id: config.executor_id, model_id: model, context_mode: mode, continuity })}
            >
              Save without running
            </button>
            {/* A disabled button cannot hold focus, so a `title` on it is
                unreachable by keyboard. Every reason Run is unavailable is
                stated beside it instead. */}
            {!remaining && (
              <span className="hint hint--stop">
                {allowSet.length === 0
                  ? "No specialist may be admitted to this gate. On a check gate, everyone allowed has already authored this line."
                  : "Every allowed specialist has been tried. This line can only be discarded."}
              </span>
            )}
            {remaining && !routeReady && (
              <span className="hint hint--stop">
                {reported
                  ? `This route cannot run: ${failedChecks.join(", ")}.`
                  : "The adapter reported no readiness checks, so this route fails closed."}
              </span>
            )}
            {remaining && routeReady && dirty && (
              <span className="hint hint--stop">
                Save first. Running uses the saved route, not the edits above.
              </span>
            )}
            <span className="hint">
              {dirty
                ? "Unsaved. Saving replaces the inherited choice for this gate only."
                : "Matches the project default. Locks at Admit; a retry opens a new attempt."}
            </span>
          </div>
        </div>
      ) : !envelope ? (
        <p className="hint hint--pad">
          This gate is locked and the executor has not returned a receipt yet.
        </p>
      ) : null}
    </section>
  );
}
