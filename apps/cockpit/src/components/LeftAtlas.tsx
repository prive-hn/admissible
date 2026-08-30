import { useEffect, useState } from "react";
import type { Capability, ContextDrift, OutcomeCounts, WorkItem } from "../domain/types";

interface Props {
  outcome: OutcomeCounts;
  capabilities: Capability[];
  workItems?: WorkItem[];
  drift?: ContextDrift[];
  onSelectWorkItem: (workItemId: string) => void;
  selectedWorkItemId: string | null;
  onCollapse?: () => void;
}

const OUTCOME_KEYS: { key: keyof OutcomeCounts; label: string; hint: string }[] = [
  { key: "active", label: "active", hint: "Lines still taking form" },
  { key: "accepted", label: "accepted", hint: "Sealed artifacts in the store" },
  { key: "degraded", label: "degraded", hint: "Lines that broke and stayed closed" },
  { key: "question", label: "question", hint: "Lines waiting on your answer" },
];

/** Non-zero counts only: four zeroes in a row is noise, not a reading. */
function MiniCounts({ o }: { o: OutcomeCounts }) {
  const shown = OUTCOME_KEYS.filter(({ key }) => o[key] > 0);
  return (
    <span className="cap__mini" aria-label="outcome counts">
      {shown.map(({ key, label }) => (
        // Four identical dots told apart only by hue, with the category name
        // in a `title` that assistive tech does not read as a name. The count
        // now says what it counts.
        <span key={key} className={`mini mini--${key}`}>
          <i className="mini__dot" aria-hidden />
          <b>{o[key]}</b>
          <span className="mini__label">{label}</span>
        </span>
      ))}
      {shown.length === 0 && <span className="mini mini--empty">0</span>}
    </span>
  );
}

export function LeftAtlas({
  outcome,
  capabilities,
  workItems = [],
  drift = [],
  onSelectWorkItem,
  selectedWorkItemId,
  onCollapse,
}: Props) {
  const [expanded, setExpanded] = useState<Set<string>>(
    () => new Set(capabilities.map((c) => c.id)),
  );
  const capabilityKey = capabilities.map((c) => c.id).join(" ");
  useEffect(() => {
    setExpanded((prev) => {
      const next = new Set(prev);
      for (const cap of capabilities) next.add(cap.id);
      return next;
    });
  }, [capabilityKey]);

  const toggle = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  return (
    <section className="pane pane--atlas" aria-label="Capability and outcome atlas">
      <div className="pane__head">
        <span className="pane__title">Atlas</span>
        <span className="pane__sub">capability / component / line</span>
        {onCollapse && (
          <button className="pane-collapse" onClick={onCollapse} title="Hide the atlas"
            aria-expanded aria-label="Hide the atlas">‹</button>
        )}
      </div>

      <div className="outcome-strip" role="group" aria-label="Outcome roll-up">
        {OUTCOME_KEYS.map(({ key, label, hint }) => (
          <div key={key} className={`outcome outcome--${key}`} title={hint}>
            <div className="outcome__n" data-outcome={key}>{outcome[key]}</div>
            <div className="outcome__k">{label}</div>
          </div>
        ))}
      </div>

      <div className="pane__body">
        {capabilities.map((cap) => {
          const open = expanded.has(cap.id);
          return (
            <div className={`cap ${open ? "cap--open" : ""}`} key={cap.id}>
              <button className="cap__head" aria-expanded={open} onClick={() => toggle(cap.id)}>
                <span className="cap__caret" aria-hidden>{open ? "▾" : "▸"}</span>
                <span className="cap__name">{cap.name}</span>
                <MiniCounts o={cap.outcome} />
              </button>
              {open && (
                <div className="cap__components">
                  {cap.components.map((cmp) => (
                    <div className="component-group" key={cmp.id}>
                      <div className="component-group__head">
                        <span className="component-group__name">{cmp.name}</span>
                        <MiniCounts o={cmp.outcome} />
                      </div>
                      <div className="work-lines">
                        {cmp.workItemIds.map((id) => {
                          const item = workItems.find((w) => w.id === id);
                          const driftState = drift.find((d) => d.work_item_id === id);
                          const status = item?.status ?? "open";
                          return (
                            <button
                              key={id}
                              className="work-line"
                              data-status={status}
                              aria-pressed={selectedWorkItemId === id}
                              // Named explicitly rather than concatenated from
                              // status, id, title and every flag.
                              aria-label={`${id} ${item?.title ?? ""}, ${status}${
                                item?.openQuestionId ? ", waiting on your answer" : ""
                              }${driftState ? `, drift ${driftState.status}` : ""}`}
                              onClick={() => onSelectWorkItem(id)}
                            >
                              {/* Status was a 2px border colour and nothing
                                  else. The word is the carrier; the colour
                                  agrees with it. */}
                              <span className={`work-line__status work-line__status--${status}`}>
                                {status === "accepted" ? "accepted" : status === "failed" ? "closed" : "open"}
                              </span>
                              <span className="work-line__id">{id}</span>
                              <span className="work-line__title">{item?.title ?? id}</span>
                              <span className="work-line__flags">
                                {item?.openQuestionId && (
                                  <span className="flag flag--question" title="Waiting on your answer">
                                    ?
                                  </span>
                                )}
                                {driftState && (
                                  <span
                                    className={`flag flag--drift flag--drift-${driftState.status}`}
                                    title={
                                      driftState.status === "reviewed"
                                        ? "Drift reviewed"
                                        : "Pinned head fell behind; review before Accept"
                                    }
                                  >
                                    {driftState.status === "reviewed" ? "drift reviewed" : "drift"}
                                  </span>
                                )}
                              </span>
                            </button>
                          );
                        })}
                        {cmp.workItemIds.length === 0 && (
                          <div className="empty empty--inline">No lines under this component</div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}

        {capabilities.length === 0 && (
          <div className="empty">
            <p className="empty__lead">No capabilities yet</p>
            <p>Open a line and the atlas fills in from what the machine actually admits.</p>
          </div>
        )}
      </div>
    </section>
  );
}
