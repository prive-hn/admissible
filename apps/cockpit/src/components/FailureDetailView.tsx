import type { FailureDetail, RecoveryOption } from "../domain/types";
import { EvidenceList } from "./EvidenceList";
import { Gloss } from "./Gloss";
import { FAULTS, type GlossKey } from "../domain/glossary";

interface Props {
  failure: FailureDetail;
  onRecover?: (option: RecoveryOption) => void;
}

/**
 * Failure detail. Deliberately structured: what happened, what remains safe,
 * then impact split into three certainty bands, the backing evidence, and the
 * recovery paths.
 *
 * The band split is the point. Each band carries its own definition on screen
 * because the one thing an operator must never do is read "reachable" as
 * "happened" or "unknown" as "safe".
 */
const BANDS: {
  key: "observed" | "reachable" | "unknown";
  label: string;
  caption: string;
  gloss: GlossKey;
}[] = [
  { key: "observed", label: "Observed", caption: "Seen in the journal", gloss: "observedBand" },
  {
    key: "reachable",
    label: "Reachable",
    caption: "Analysis proves it may be affected. Not seen",
    gloss: "reachableBand",
  },
  {
    key: "unknown",
    label: "Unknown",
    caption: "Evidence does not bound this. Not a safe list",
    gloss: "unknownBand",
  },
];

export function FailureDetailView({ failure, onRecover }: Props) {
  return (
    <div className="failure" data-testid="failure-detail">
      <div className="failure__head">
        <span className="failure__fault">{failure.fault ?? "Fail-closed"}</span>
        {failure.fault && FAULTS[failure.fault] && (
          <span className="failure__fault-name">· {FAULTS[failure.fault].name}</span>
        )}
        <Gloss term="failClosed" className="failure__mode">fail closed &amp; published</Gloss>
      </div>

      <div className="failure__section-title">What happened</div>
      <p className="failure__prose">{failure.whatHappened}</p>

      <div className="failure__section-title">What remains safe</div>
      <p className="failure__prose failure__prose--safe">{failure.whatRemainsSafe}</p>

      <div className="failure__section-title">Impact</div>
      <div className="impact-groups" data-testid="impact-groups">
        {BANDS.map(({ key, label, caption, gloss }) => {
          const rows = failure.impact[key];
          return (
            <div className={`impact impact--${key}`} data-band={key} key={key}>
              <div className="impact__band">
                <Gloss term={gloss} focusable>{label}</Gloss>
              </div>
              <div className="impact__caption">{caption}</div>
              {rows.length > 0 ? (
                <ul>
                  {rows.map((x, i) => (
                    <li key={i}>{x}</li>
                  ))}
                </ul>
              ) : (
                <p className="impact__none">Nothing recorded in this band</p>
              )}
            </div>
          );
        })}
      </div>

      <div className="failure__section-title">Evidence</div>
      <EvidenceList items={failure.evidence} empty="No journal events back this failure yet." />

      {failure.recovery.length > 0 && (
        <>
          <div className="failure__section-title">Recovery</div>
          <div className="recovery">
            {failure.recovery.map((r, i) => (
              <button
                key={i}
                className={`btn ${r.action === "discard" ? "btn--danger" : i === 0 ? "btn--primary" : ""}`}
                onClick={() => onRecover?.(r)}
                title={r.hint}
              >
                {r.label}
                {r.specialist && <span className="btn__meta">{r.specialist}</span>}
              </button>
            ))}
          </div>
          <p className="hint">
            Recovery stays inside the <Gloss term="allowSet">allow set</Gloss>. The line never{" "}
            <Gloss term="hop">hops</Gloss> out of it.
          </p>
        </>
      )}
    </div>
  );
}
