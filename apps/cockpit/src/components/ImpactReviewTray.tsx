import type { ContextDrift } from "../domain/types";
import { Gloss } from "./Gloss";

interface Props {
  drift: ContextDrift;
  onReview: (classification: "reachable" | "unknown", decision: "continue_pinned" | "refresh" | "owner_override") => void;
  onAction: (action: "retry" | "discard") => void;
}

const BANDS = [
  {
    key: "observed",
    label: "Observed",
    gloss: "observedBand",
    body: "The accepted project head advanced after this line opened.",
  },
  {
    key: "reachable",
    label: "Reachable",
    gloss: "reachableBand",
    body: "This candidate may intersect capabilities changed at the newer head.",
  },
  {
    key: "unknown",
    label: "Unknown",
    gloss: "unknownBand",
    body: "Executor-internal context and untraced runtime paths are not asserted safe.",
  },
] as const;

/**
 * Drift banner. The line keeps the project and memory versions it pinned at
 * Open — that pin cannot move underneath it — so the only question is what the
 * newer head means for this candidate. Until that is answered on the record,
 * Accept stays blocked.
 */
export function ImpactReviewTray({ drift, onReview, onAction }: Props) {
  const reviewed = drift.status === "reviewed";
  return (
    <section className={`impact-review impact-review--${reviewed ? "reviewed" : "blocked"}`}
      aria-label="Context drift impact review">
      <div className="impact-review__head">
        <div className="impact-review__id">
          <strong>Impact review</strong>
          <span className="chip">{drift.work_item_id}</span>
        </div>
        <span className={`gate-lock gate-lock--${reviewed ? "locked" : "open"}`}>
          {reviewed ? `${drift.classification} · ${drift.decision}` : "Accept blocked"}
        </span>
      </div>

      <p className="impact-review__lead">
        The project moved on while this line was open. Its{" "}
        <Gloss term="pin">pin</Gloss> has not moved, and nothing has been rebased. Say what the
        newer head means for this candidate and the record keeps your answer.
      </p>

      <div className="impact-review__heads">
        <span className="head-mark head-mark--pinned">
          <i>pinned at open</i>P{drift.pinned_head[0]} · K{drift.pinned_head[1]}
        </span>
        <span className="head-mark__arrow" aria-hidden />
        <span className="head-mark head-mark--current">
          <i>accepted now</i>P{drift.current_head[0]} · K{drift.current_head[1]}
        </span>
      </div>

      <div className="impact-groups">
        {BANDS.map((band) => (
          <div className={`impact impact--${band.key}`} key={band.key}>
            <div className="impact__band">
              <Gloss term={band.gloss} focusable>{band.label}</Gloss>
            </div>
            <p>{band.body}</p>
          </div>
        ))}
      </div>

      <div className="recovery impact-review__actions">
        <button className="btn btn--primary" onClick={() => onReview("reachable", "continue_pinned")}>
          Continue pinned
          <span className="btn__meta">finish against P{drift.pinned_head[0]}</span>
        </button>
        <button className="btn" onClick={() => onReview("reachable", "refresh")}>
          Refresh / rebase
          <span className="btn__meta">new revision</span>
        </button>
        <button className="btn" onClick={() => onAction("retry")}>Retry the gate</button>
        <button className="btn btn--danger" onClick={() => onAction("discard")}>Discard the line</button>
      </div>
    </section>
  );
}
