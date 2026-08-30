import { useDialog } from "../domain/useDialog";
import type { AgentDefinition, GatePolicy, ModelDefinition } from "../domain/types";
import { Gloss } from "./Gloss";

interface Props {
  models: ModelDefinition[];
  agents: AgentDefinition[];
  gates: GatePolicy[];
  adapter?: string;
  onClose: () => void;
}

/** Readiness keys are wire names; an operator reads sentences. */
const CHECKS: { key: string; label: string; why: string }[] = [
  { key: "installed", label: "adapter installed", why: "The execution adapter is present on this machine." },
  { key: "authenticated", label: "authenticated", why: "The adapter holds credentials the provider accepts." },
  { key: "model_resolves", label: "model resolves", why: "The provider recognises this exact API id." },
  { key: "project_access", label: "project access", why: "The adapter can read the loaded project." },
  { key: "tools_available", label: "tools available", why: "The tools the agent declares are present." },
  { key: "canary", label: "canary call", why: "A throwaway call proved the route answers before real work runs." },
  { key: "receipt_available", label: "receipt support", why: "The adapter can return a receipt, without which no gate can pass." },
  { key: "death_observable", label: "death observable", why: "A worker that dies can be reported, so a hung gate can be closed." },
  { key: "executor_connected", label: "executor connected", why: "The adapter this route declares is the one that is connected." },
];

/**
 * Every model this project can run, and whether it can run right now.
 *
 * The cockpit had this data from the first frame and never showed it: a model
 * was only visible by selecting a line, selecting a gate, and opening a
 * dropdown. "Which models does this system use" is a question an operator asks
 * before opening any work at all, so it gets its own surface.
 *
 * Readiness is reported by the execution adapter, not asserted here. A route
 * with any declared check false cannot Admit, and an adapter that reports
 * nothing is treated as unavailable rather than assumed fine.
 */
export function RoutesPanel({ models, agents, gates, adapter, onClose }: Props) {
  const dialog = useDialog<HTMLElement>(onClose);
  const ready = models.filter((m) => m.readiness?.ready).length;

  return (
    <div className="modal-scrim" onClick={onClose}>
      <aside
        ref={dialog}
        className="legend"
        role="dialog"
        aria-modal="true"
        aria-label="Models and routes"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="legend__head">
          <div>
            <span className="modal__title">Models &amp; routes</span>
            <p className="legend__lead">
              Every exact provider model this project can bind, which gate uses it, and whether
              the execution adapter says it can run right now.
            </p>
          </div>
          <button className="icon-btn icon-btn--quiet" onClick={onClose} aria-label="Close models and routes">
            ✕
          </button>
        </div>

        <div className="legend__search routes__summary">
          <span>
            <b>{ready}</b>/{models.length} routes ready
          </span>
          <span className="hint">
            execution adapter <code>{adapter ?? "none"}</code>
          </span>
        </div>

        <div className="legend__body">
          {models.map((model) => {
            const usedBy = gates.filter((g) => g.model_id === model.id);
            const r = model.readiness;
            const failing = r ? CHECKS.filter((c) => r[c.key as keyof typeof r] === false) : [];
            const state = !r ? "unknown" : r.ready ? "ready" : "blocked";
            return (
              <section className={`route route--${state}`} key={model.id}>
                <div className="route__head">
                  <div>
                    <h3>{model.display || model.api_id}</h3>
                    <p className="route__id mono">
                      {model.provider} / {model.api_id}
                    </p>
                  </div>
                  <span className={`route__state route__state--${state}`}>
                    {state === "ready" ? "ready" : state === "blocked" ? "not ready" : "unknown"}
                  </span>
                </div>

                <dl className="route__facts">
                  <div>
                    <dt>Used by</dt>
                    <dd>
                      {usedBy.length
                        ? usedBy.map((g) => `${g.name} (${g.agent_id})`).join(", ")
                        : "no gate — available but unused"}
                    </dd>
                  </div>
                  <div>
                    <dt>Context profile</dt>
                    <dd>{model.context_profile || "—"}</dd>
                  </div>
                  <div>
                    <dt>Reasoning</dt>
                    <dd>{model.reasoning || "—"}</dd>
                  </div>
                  <div>
                    <dt>Runs on</dt>
                    <dd>{r?.executor_id ?? adapter ?? "—"}</dd>
                  </div>
                </dl>

                {!r ? (
                  <p className="route__note route__note--stop">
                    This adapter reported no readiness checks. An unknown route fails closed, so
                    no gate can Admit on it.
                  </p>
                ) : failing.length === 0 ? (
                  <p className="route__note">Every declared check passed when the adapter last reported.</p>
                ) : (
                  <ul className="route__checks">
                    {failing.map((c) => (
                      <li key={c.key}>
                        <b>{c.label}</b>
                        <span>{c.why}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            );
          })}

          {models.length === 0 && (
            <div className="empty">
              <p className="empty__lead">No models declared</p>
              <p>Load a project and its models appear here with their readiness.</p>
            </div>
          )}

          <section className="legend__group">
            <h3>Agents</h3>
            <p className="legend__blurb">
              An agent plus a gate forms the{" "}
              <Gloss term="specialist">specialist</Gloss> the machine admits.
            </p>
            <dl className="legend__list">
              {agents.map((a) => (
                <div className="legend__row" key={a.id}>
                  <dt>{a.name}</dt>
                  <dd>
                    {a.instructions}
                    <code>
                      default model {a.default_model_id} · tools {a.tools.join(", ") || "none"} ·
                      authority {a.authority.join(", ") || "none"}
                    </code>
                  </dd>
                </div>
              ))}
            </dl>
          </section>
        </div>

        <div className="legend__foot">
          <span className="hint">
            A route with any failed check cannot Admit. Readiness is the adapter's report, not a
            promise by the cockpit.
          </span>
        </div>
      </aside>
    </div>
  );
}
