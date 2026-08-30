import type { ReactNode } from "react";
import type { GateConfig, ModelDefinition, RecoveryOption, StageNode, WorkItem } from "../domain/types";
import { instrumentSkin, type Skin } from "../skins/skin";
import { PC_MEANINGS } from "../domain/glossary";
import { sameModelIdentity } from "../domain/modelIdentity";
import { FailureDetailView } from "./FailureDetailView";
import { EvidenceList } from "./EvidenceList";
import { FaultStamp, Gloss } from "./Gloss";

interface Props {
  item: WorkItem | null;
  selectedNodeId: string | null;
  /** Node whose drilldown is expanded (click opens without route change). */
  openNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
  onToggleDrill: (nodeId: string) => void;
  onRecover: (nodeId: string, option: RecoveryOption) => void;
  gateConfigs?: GateConfig[];
  models?: ModelDefinition[];
  skin?: Skin;
  /** Envelope surface injected under the gate it belongs to. */
  renderGateSlot?: (stage: StageNode) => ReactNode;
  /** Item-scoped banner (impact review) rendered above the load path. */
  banner?: ReactNode;
  onAnswerQuestion?: () => void;
}

/**
 * The bind readout: what the machine declared against what it observed.
 * I1 is decided here — a Pass is legal only when these two match — so the
 * pair is rendered as one unit rather than two loose fields.
 */
function Route({
  stage,
  config,
  model,
}: {
  stage: StageNode;
  config?: GateConfig;
  model?: ModelDefinition;
}) {
  const decl = stage.declaredModel ?? "—";
  const exec = stage.executedModel;
  // The Pass guard compares model *identities*, not strings: a bracketed
  // context suffix is not part of the identity. Raw equality flagged gates the
  // authority had held.
  const matched = sameModelIdentity(stage.declaredModel, exec);
  const cls = exec == null ? "" : matched ? "match" : "mismatch";
  return (
    <div className="stage-node__models">
      {config ? (
        <>
          <Gloss term="specialist" className="route__part">
            {config.agent_id}:{config.gate_id}
          </Gloss>
          {model && <span className="route__part route__part--model">{model.provider} / {model.api_id}</span>}
          <span className="route__part">{config.context_mode}</span>
          {config.continuity && config.continuity !== "fresh" && (
            <span className="route__part">{config.continuity}</span>
          )}
        </>
      ) : (
        <>
          <Gloss term="declared" className="route__part">declared {decl}</Gloss>
          {stage.specialist && <span className="route__part">{stage.specialist}</span>}
        </>
      )}
      {exec != null && (
        <Gloss term={matched ? "norm" : "executed"} className={`route__part route__exec ${cls}`}>
          executed {exec}
          {/* The only textual carrier of the pass verdict; hiding it from
              assistive tech left the verdict as colour alone. */}
          <i className="route__verdict">{matched ? "match" : "mismatch"}</i>
        </Gloss>
      )}
    </div>
  );
}

export function CenterStages({
  item,
  selectedNodeId,
  openNodeId,
  onSelectNode,
  onToggleDrill,
  onRecover,
  gateConfigs = [],
  models: modelDefinitions = [],
  skin = instrumentSkin,
  renderGateSlot,
  banner,
  onAnswerQuestion,
}: Props) {
  // A fail-closed break means everything below it never ran. Say so, rather
  // than leaving downstream gates looking merely queued.
  const breakIndex = item
    ? item.stages.findIndex((s) => s.pc === "Closed" || s.pc === "Stopped")
    : -1;
  // A finished line gets a terminal on the path. Accepted is the identity
  // layer's word; whether it also SEALED is the admissibility record's to
  // say, and the terminal repeats that record rather than improving on it.
  const terminal =
    item?.status === "accepted" ? "accepted" : item?.status === "failed" ? "failed" : null;
  const adm = item?.admissibility ?? null;

  return (
    <section className="pane pane--work" aria-label="Selected work line and its gates">
      <div className="pane__head">
        <span className="pane__title">Work line</span>
        {item && <span className="pane__sub mono">{item.id}</span>}
      </div>

      <div className="pane__body">
        {!item && (
          <div className="empty">
            <p className="empty__lead">No line selected</p>
            <p>Pick a line in the atlas, or open a new one to compile a contract.</p>
          </div>
        )}

        {item && (
          <>
            <header className="line-head">
              <div className="line-head__top">
                <h1 className="line-head__title">{item.title}</h1>
                <span className={`status-pill status-pill--${item.status}`}>{item.status}</span>
              </div>
              <div className="line-head__meta">
                <span><Gloss term="class"><i>class</i></Gloss> {item.cls}</span>
                <span><Gloss term="policyVersion"><i>policy</i></Gloss> {item.policyVersion}</span>
                {adm && (
                  <span>
                    <Gloss term="layerBadge"><i>layer</i></Gloss>{" "}
                    <span
                      className={`layer-chip layer-chip--${adm.layer}`}
                      data-testid="layer-chip"
                      data-state={
                        adm.impeached
                          ? "impeached"
                          : adm.tainted
                            ? "tainted"
                            : adm.sealed && adm.layer === "IRC"
                              ? "sealed"
                              : adm.sealed
                                ? "unmediated"
                                : item.status === "accepted"
                                  ? "unsealed-accepted"
                                  : "pending"
                      }
                    >
                      {adm.layer}
                      {adm.impeached ? " · impeached" : adm.tainted ? " · tainted" : ""}
                    </span>
                  </span>
                )}
                {item.dependsOn.length > 0 && (
                  <span><i>depends on</i> {item.dependsOn.join(", ")}</span>
                )}
                {item.authors.length > 0 && (
                  <span><i>authors</i> {item.authors.join(", ")}</span>
                )}
              </div>
              {item.openQuestionId && onAnswerQuestion && (
                <div className="line-head__question">
                  <span>
                    Paused on a question. Only this node is blocked — other lines keep running.
                  </span>
                  <button className="btn btn--accent" onClick={onAnswerQuestion}>
                    Answer it
                  </button>
                </div>
              )}
            </header>

            {banner}

            <ol className="loadpath">
              {item.stages.map((stage, i) => {
                const tone = skin.stageTone(stage.pc);
                const isSelected = stage.id === selectedNodeId;
                const isOpen = stage.id === openNodeId;
                // A break only means "never ran" once the line is finished.
                // While it is still open the broken gate can be retried, so a
                // gate below it has not started — which is a different claim.
                const belowBreak = breakIndex >= 0 && i > breakIndex && stage.pc === "Open";
                const unreached = belowBreak && item.status !== "open";
                const notStarted = belowBreak && item.status === "open";
                const config = gateConfigs.find(
                  (g) => g.work_item_id === item.id && g.gate_id === stage.name,
                );
                const model = config
                  ? modelDefinitions.find((m) => m.id === config.model_id)
                  : undefined;
                const gateSlot = isSelected ? renderGateSlot?.(stage) : null;
                return (
                  <li
                    className="lp"
                    key={stage.id}
                    data-tone={tone}
                    data-unreached={belowBreak || undefined}
                    data-first={i === 0 || undefined}
                    data-last={(!terminal && i === item.stages.length - 1) || undefined}
                  >
                    <div className="lp__rail" aria-hidden>
                      <span className="lp__seg lp__seg--in" />
                      <span className="lp__node" />
                      <span className="lp__seg lp__seg--out" />
                    </div>

                    <div className="lp__body">
                      <div
                        className={`stage-node ${isSelected ? "stage-node--selected" : ""}`}
                        data-testid={`stage-node-${stage.id}`}
                        data-pc={stage.pc}
                      >
                        {/* Only the summary is the control. The drilldown holds
                            its own buttons and must not nest inside one. */}
                        <button
                          type="button"
                          className="stage-node__summary"
                          aria-pressed={isSelected}
                          aria-expanded={isOpen}
                          // Without this the accessible name is the whole card
                          // concatenated — kind, name, fault, state, sentence
                          // and the entire route row — announced as one string
                          // on focus and again on every state change.
                          aria-label={`${stage.kind} gate ${stage.name}, ${
                            unreached ? "not reached" : notStarted ? "not started" : skin.pcLabel(stage.pc)
                          }${stage.failure?.fault ? `, fault ${stage.failure.fault}` : ""}`}
                          onClick={() => {
                            onSelectNode(stage.id);
                            onToggleDrill(stage.id);
                          }}
                        >
                        {/* Spans, not divs and paragraphs: a button's content
                            model is phrasing content, and the block elements
                            that used to be here were not valid inside it. The
                            stylesheet gives them back their block display. */}
                        <span className="stage-node__top">
                          <Gloss
                            term={stage.kind === "check" ? "checkGate" : "writeGate"}
                            className={`kind-tag kind-tag--${stage.kind}`}
                          >
                            {stage.kind}
                          </Gloss>
                          <span className="stage-node__name">{stage.name}</span>
                          {stage.failure?.fault && <FaultStamp code={stage.failure.fault} />}
                          {unreached ? (
                            <Gloss term="notReached" className="stage-node__pc stage-node__pc--unreached">
                              not reached
                            </Gloss>
                          ) : notStarted ? (
                            <Gloss term="notStarted" className="stage-node__pc stage-node__pc--unreached">
                              not started
                            </Gloss>
                          ) : (
                            <span className="stage-node__pc" title={PC_MEANINGS[stage.pc]}>
                              {skin.pcLabel(stage.pc)}
                            </span>
                          )}
                        </span>
                        <span className="stage-node__sentence">{stage.sentence}</span>
                        {unreached && (
                          <span className="stage-node__derived">
                            The line closed at an earlier gate, so this one never ran.
                          </span>
                        )}
                        {notStarted && (
                          <span className="stage-node__derived">
                            An earlier gate broke. This one has not started, and will only run
                            if that gate is retried and holds.
                          </span>
                        )}
                        <Route stage={stage} config={config} model={model} />
                        </button>

                        {isOpen && (
                          <div className="drill" data-testid={`drill-${stage.id}`}>
                            {stage.failure ? (
                              <FailureDetailView
                                failure={stage.failure}
                                onRecover={(opt) => onRecover(stage.id, opt)}
                              />
                            ) : (
                              <>
                                <div className="failure__section-title">Evidence</div>
                                <EvidenceList
                                  items={stage.evidence ?? []}
                                  empty="No journal events for this gate yet."
                                />
                              </>
                            )}
                          </div>
                        )}
                      </div>

                      {gateSlot}
                    </div>
                  </li>
                );
              })}

              {terminal && (
                <li
                  className="lp lp--terminal"
                  data-tone={terminal === "accepted" ? "held" : "broken"}
                  data-last
                >
                  <div className="lp__rail" aria-hidden>
                    <span className="lp__seg lp__seg--in" />
                    <span className="lp__cap" />
                  </div>
                  <div className="lp__body">
                    <div
                      className={`terminal terminal--${terminal}${
                        terminal === "accepted" && adm
                        && (adm.impeached || adm.tainted || !adm.sealed || adm.layer !== "IRC")
                          ? " terminal--qualified"
                          : ""
                      }`}
                      data-testid="line-terminal"
                      data-lost-standing={adm && (adm.impeached || adm.tainted) ? "true" : undefined}
                    >
                      {terminal === "accepted" ? (
                        adm ? (
                          <>
                            <span className="terminal__label">
                              {adm.impeached ? (
                                <Gloss term="impeached">Impeached</Gloss>
                              ) : adm.tainted ? (
                                <Gloss term="tainted">Tainted</Gloss>
                              ) : adm.sealed && adm.layer === "IRC" ? (
                                <Gloss term="seal">Sealed</Gloss>
                              ) : adm.sealed ? (
                                <Gloss term="layerBadge">Sealed — layer IR, not mediated</Gloss>
                              ) : (
                                <Gloss term="acceptedArtifact">Accepted — layer I</Gloss>
                              )}
                            </span>
                            <p>{adm.sentence}</p>
                            {adm.sealed && (
                              <span className="terminal__adm">
                                <Gloss term="carriedPower" className="adm-chip">
                                  power {adm.powerMin}
                                </Gloss>
                                <Gloss term="concordance" className="adm-chip">
                                  concordance ({adm.agreeing}, {adm.k})
                                </Gloss>
                                <Gloss term="admissible" className={`adm-chip adm-chip--${adm.admissible ? "yes" : "no"}`}>
                                  {adm.admissible ? "admissible" : "not admissible"}
                                </Gloss>
                              </span>
                            )}
                            {adm.sealed && (adm.residual?.length ?? 0) > 0 && (
                              <span className="terminal__residual">
                                <Gloss term="residual"><i>residual</i></Gloss>{" "}
                                {adm.residual!.map(([claim, disposition]) => (
                                  <span className="adm-chip adm-chip--residual" key={claim}>
                                    {claim} — {disposition === "check_stage" ? "reviewed at the check gate" : "unreviewed"}
                                  </span>
                                ))}
                              </span>
                            )}
                          </>
                        ) : (
                          <>
                            <span className="terminal__label">Accepted</span>
                            <p>
                              Every required gate held, so this line was accepted into the store.
                              It cannot change in place — a fix is a new line.
                            </p>
                          </>
                        )
                      ) : adm?.sealed ? (
                        <>
                          {/* A failed label over a sealed record is a state
                              conflict, not a truth: the record wins, and the
                              conflict itself is rendered rather than either
                              half being improved into a story. */}
                          <span className="terminal__label">Marked failed — record disagrees</span>
                          <p>
                            This line is marked failed, but the record shows it sealed into the
                            store. Trust the record: {adm.sentence}
                          </p>
                        </>
                      ) : (
                        <>
                          <span className="terminal__label">Closed</span>
                          <p>
                            The line stayed closed. Nothing was written to the store, and the
                            gates below the break never ran.
                          </p>
                        </>
                      )}
                    </div>
                  </div>
                </li>
              )}
            </ol>
          </>
        )}
      </div>
    </section>
  );
}
