import { useEffect, useRef, useState } from "react";
import type { Contract, ProjectSettings } from "../domain/types";
import { compileContract } from "../domain/compileContract";
import { compileWorkItemContract, IntentRefused } from "../api/client";

interface Props {
  settings: ProjectSettings;
  specialists: string[];
  connection: "live" | "demo-disconnected";
  projectLoaded: boolean;
  /** Controlled from the shell so ⌘K can open the sheet from anywhere. */
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onOpenSettings: () => void;
  onOpenLegend: () => void;
  onOpenRoutes: () => void;
  /** Fired when the operator accepts the compiled contract to open a line. */
  onSubmit: (prompt: string, contract: Contract) => void;
}

/**
 * Right half of the command rail plus the compose sheet.
 *
 * A prompt does NOT open a line: it compiles to a visible contract (class,
 * required gates, allow set, acceptance mode, dependencies) that the operator
 * reads and commits separately. Opening a line is rare and consequential, so
 * the composer is a deliberate sheet rather than a permanent text box holding
 * the best real estate on the instrument.
 */
export function TopComposer({
  settings,
  specialists,
  connection,
  projectLoaded,
  open,
  onOpenChange,
  onOpenSettings,
  onOpenLegend,
  onOpenRoutes,
  onSubmit,
}: Props) {
  const [prompt, setPrompt] = useState("");
  const [contract, setContract] = useState<Contract | null>(null);
  const [compiling, setCompiling] = useState(false);
  /** Whether the visible contract came from the authority or the offline shape. */
  const [authoritative, setAuthoritative] = useState(true);
  const [refusal, setRefusal] = useState<string | null>(null);
  const promptRef = useRef(prompt);
  promptRef.current = prompt;
  const areaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (open) areaRef.current?.focus();
  }, [open]);

  // The authority owns the policy, so it compiles the contract. Falling back
  // to the local shape is only for the disconnected surface, and the card says
  // which one is on screen.
  const compile = async (cls?: string) => {
    if (!prompt.trim() || compiling) return;
    setCompiling(true);
    setRefusal(null);
    // Editing the prompt clears the card, but an in-flight response used to
    // land afterwards and refill it with terms compiled for text that is no
    // longer in the box — so the card described one prompt while commit sent
    // another. A response for a prompt that has since changed is discarded.
    const issuedFor = prompt;
    try {
      const compiled = await compileWorkItemContract(prompt, cls);
      if (promptRef.current !== issuedFor) return;
      setContract(compiled);
      setAuthoritative(true);
    } catch (error) {
      // A refusal is an answer. The bare catch treated "guarded intake will
      // not guess a class" the same as "the server is gone", and replaced the
      // authority's own sentence with a locally invented contract under the
      // caption "the authority is unreachable" — the one caption that was
      // certainly wrong.
      if (promptRef.current !== issuedFor) return;
      if (error instanceof IntentRefused) {
        setContract(null);
        setRefusal(error.message);
      } else {
        setContract(compileContract(prompt, { settings, specialists }));
        setAuthoritative(false);
      }
    } finally {
      setCompiling(false);
    }
  };

  const commit = () => {
    if (!contract) return;
    onSubmit(prompt, contract);
    setPrompt("");
    setContract(null);
    onOpenChange(false);
  };

  const close = () => {
    setContract(null);
    onOpenChange(false);
  };

  return (
    <>
      <div className="rail__right">
        <span className={`conn conn--${connection}`} data-testid="connection-status">
          <span className="conn__dot" aria-hidden />
          {connection === "live" ? "Live" : "Demo disconnected"}
        </span>
        <button className="icon-btn" onClick={onOpenRoutes}
          title="Every model this project can bind, and whether it can run now">
          Models
        </button>
        <button className="icon-btn" onClick={onOpenLegend} title="What every term on this instrument means">
          Legend
        </button>
        <button className="icon-btn" onClick={onOpenSettings} title={settings.versionLabel}>
          Settings
        </button>
        <button
          className="btn btn--accent"
          disabled={!projectLoaded}
          aria-expanded={open}
          onClick={() => (open ? close() : onOpenChange(true))}
          title={projectLoaded ? "Compose a contract and open a line" : "Load a project first"}
        >
          New line
          <kbd className="kbd">⌘K</kbd>
        </button>
      </div>

      {open && (
        <div className="sheet" role="group" aria-label="Open a new line">
          <div className="sheet__head">
            <span className="sheet__title">Open a new line</span>
            <span className="sheet__note">
              A prompt never opens a line. It compiles to a contract you approve first.
            </span>
            <button className="icon-btn icon-btn--quiet" onClick={close} aria-label="Close composer">
              ✕
            </button>
          </div>

          <div className="composer">
            <textarea
              ref={areaRef}
              aria-label="Prompt composer"
              disabled={!projectLoaded}
              rows={3}
              placeholder={
                projectLoaded
                  ? "Describe the issue or feature to build."
                  : "Load a project to start work"
              }
              value={prompt}
              onChange={(e) => {
                setPrompt(e.target.value);
                if (contract) setContract(null);
              }}
              onKeyDown={(e) => {
                if (e.key === "Escape") close();
                if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
                  e.preventDefault();
                  if (contract) commit();
                  else void compile();
                }
              }}
            />
            <button
              className="btn"
              onClick={() => void compile()}
              disabled={!projectLoaded || !prompt.trim() || compiling}
            >
              {compiling ? "Compiling…" : "Compile contract"}
              <kbd className="kbd">⌘↵</kbd>
            </button>
          </div>

          {refusal && (
            <p className="composer__refusal" role="alert" data-testid="compile-refusal">
              <b>The authority refused to compile this.</b> {refusal}
            </p>
          )}

          {contract ? (
            <div className="contract" data-testid="contract-card">
              <div className="contract__row">
                <span className="contract__title">{contract.title}</span>
                <span className="chip chip--class">class {contract.cls}</span>
                <span className="chip">policy {contract.policyVersion}</span>
                {!authoritative && (
                  <span className="chip chip--warn" title="The authority was unreachable, so this is the offline shape, not the enforced terms.">
                    offline shape
                  </span>
                )}
              </div>
              {contract.classes && contract.classes.length > 1 && (
                <div className="contract__class">
                  <div className="contract__class-head">
                    <span>
                      Kind of work
                      {contract.classChosenBy === "operator"
                        ? " · you chose this"
                        : contract.classChosenBy === "intake"
                          ? " · read from your prompt"
                          : " · nothing matched, so a default was used"}
                    </span>
                    {contract.classNote && <em>{contract.classNote}</em>}
                  </div>
                  <div className="contract__class-options">
                    {contract.classes.map((c) => (
                      <button
                        key={c.id}
                        className={`class-option ${c.id === contract.cls ? "class-option--on" : ""}`}
                        aria-pressed={c.id === contract.cls}
                        // `compile` bails while one is in flight, so without
                        // this a click during recompilation did nothing at all
                        // and the card kept showing the previous class — which
                        // invites committing under the class you thought you
                        // had just replaced.
                        disabled={compiling}
                        onClick={() => void compile(c.id)}
                      >
                        <span className="class-option__name">{c.name}</span>
                        <span className="class-option__summary">{c.summary}</span>
                        <span className="class-option__gates">
                          {c.gates.map((g) => (
                            <span key={g.name} className={`chip chip--${g.kind}`}>
                              {g.kind}·{g.name}
                            </span>
                          ))}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <dl className="contract__grid">
                <div>
                  <dt>Required gates</dt>
                  <dd>
                    {contract.requiredStages.map((s) => (
                      <span key={s.name} className={`chip chip--${s.kind}`}>
                        {s.kind}·{s.name}
                      </span>
                    ))}
                  </dd>
                </div>
                <div>
                  <dt>Specialists it may admit</dt>
                  <dd className="mono">{contract.allowSet.join(", ") || "—"}</dd>
                </div>
                <div>
                  <dt>Acceptance</dt>
                  <dd className="mono">{contract.acceptanceMode}</dd>
                </div>
                <div>
                  <dt>Depends on</dt>
                  <dd className="mono">
                    {contract.dependsOn.length ? contract.dependsOn.join(", ") : "nothing"}
                  </dd>
                </div>
              </dl>
              <div className="contract__actions">
                <span className="hint">
                  {authoritative
                    ? "Compiled by the authority. These are the terms it will enforce."
                    : "The authority is unreachable. This is a shape, not the enforced terms."}
                </span>
                <button className="btn btn--primary" onClick={commit} disabled={!authoritative}>
                  Open line under this contract
                </button>
                <button className="btn btn--ghost" onClick={() => setContract(null)}>
                  Amend prompt
                </button>
              </div>
            </div>
          ) : (
            <p className="sheet__hint">
              Compiling asks the authority for the class, required gates, allow set and
              acceptance mode it will enforce. It opens nothing, and nothing runs until you
              commit.
            </p>
          )}
        </div>
      )}
    </>
  );
}
