import { useMemo, useState } from "react";
import type { ArtifactRecord, WorkItem } from "../domain/types";
import { renderArtifact, type ArtifactView } from "../domain/artifact";
import { Gloss } from "./Gloss";

interface Props {
  item: WorkItem | null;
  artifact?: ArtifactRecord;
  onCollapse?: () => void;
}

const VIEWS: { key: ArtifactView; label: string }[] = [
  { key: "candidate", label: "Candidate" },
  { key: "accepted", label: "Accepted" },
  { key: "before-after", label: "Before / after" },
];

/**
 * Right pane: the real artifact an owner can evaluate, rendered in a sandboxed
 * iframe via srcDoc (no scripts, no same-origin), so neither the artifact nor a
 * skin can reach cockpit authority.
 *
 * Two honesty rules are visible here. A harness-supplied artifact and a
 * synthesized one are never presented alike — a missing artifact is labeled
 * fallback. And "accepted" is never implied: until Accept writes the store the
 * accepted view says so plainly instead of showing the candidate again.
 */
export function RightArtifact({ item, artifact, onCollapse }: Props) {
  const [view, setView] = useState<ArtifactView>("candidate");
  const [overlay, setOverlay] = useState(true);

  const accepted = item?.status === "accepted";
  const fromHarness = Boolean(artifact) && (view === "candidate" || (view === "accepted" && accepted));

  const srcDoc = useMemo(() => {
    if (artifact && view === "candidate") return artifact.srcDoc;
    if (artifact && view === "accepted" && artifact.state === "accepted") return artifact.srcDoc;
    return renderArtifact(item ?? undefined, view);
  }, [artifact, item, view]);

  const stageCount = item?.stages.length ?? 0;
  const heldCount = item?.stages.filter((s) => s.pc === "Passed").length ?? 0;
  const sealed = accepted;

  return (
    <section className="pane pane--artifact" aria-label="Artifact and evidence">
      <div className="pane__head">
        <span className="pane__title">Artifact</span>
        {item && (
          <Gloss
            term={sealed ? "acceptedArtifact" : "candidate"}
            className={`seal seal--${sealed ? "accepted" : "candidate"}`}
            focusable
          >
            {sealed ? "accepted" : "candidate"}
          </Gloss>
        )}
        {onCollapse && (
          <button className="pane-collapse" onClick={onCollapse} title="Hide the artifact"
            aria-expanded={true} aria-label="Hide the artifact">›</button>
        )}
      </div>

      <div className="artifact-toolbar">
        <div className="seg" role="group" aria-label="Artifact view">
          {VIEWS.map((v) => (
            <button key={v.key} aria-pressed={view === v.key} onClick={() => setView(v.key)}>
              {v.label}
            </button>
          ))}
        </div>
        <button
          className="icon-btn icon-btn--quiet"
          aria-pressed={overlay}
          onClick={() => setOverlay((v) => !v)}
        >
          {overlay ? "Evidence on" : "Evidence off"}
        </button>
      </div>

      <div className="artifact-stage">
        {!item ? (
          <div className="empty">
            <p className="empty__lead">Nothing to evaluate yet</p>
            <p>Select a line and its artifact renders here, exactly as the harness produced it.</p>
          </div>
        ) : view === "accepted" && !accepted ? (
          <div className="artifact-locked">
            <span className="artifact-locked__mark" aria-hidden />
            <p className="empty__lead">Not in the store</p>
            <p>
              Nothing is sealed until every required gate holds.{" "}
              <Gloss term="accept">Accept</Gloss> is the only writer.
            </p>
          </div>
        ) : view === "before-after" && artifact ? (
          <div className="artifact-mat artifact-compare" data-testid="artifact-compare">
            <figure>
              <figcaption>Before · accepted</figcaption>
              <div className="artifact-screen">
                <iframe
                  className="artifact-frame"
                  title="artifact before"
                  sandbox=""
                  srcDoc={artifact.beforeSrcDoc || renderArtifact(item ?? undefined, "accepted")}
                />
              </div>
            </figure>
            <figure>
              <figcaption>After · candidate</figcaption>
              <div className="artifact-screen">
                <iframe
                  className="artifact-frame"
                  title="artifact candidate"
                  sandbox=""
                  srcDoc={artifact.srcDoc}
                />
              </div>
            </figure>
          </div>
        ) : (
          <div className="artifact-mat">
            <div className="artifact-screen">
              <iframe
                className="artifact-frame"
                title="artifact"
                data-testid="artifact-frame"
                data-view={view}
                sandbox=""
                srcDoc={srcDoc}
              />
            </div>
          </div>
        )}
      </div>

      {item && (
        <div className="artifact-foot">
          <span className="artifact-foot__held" data-testid="evidence-overlay">
            <b>{heldCount}</b>/{stageCount} gates held
          </span>
          {overlay && (
            <span className={`artifact-foot__origin ${fromHarness ? "" : "artifact-foot__origin--fallback"}`}>
              {fromHarness
                ? `from the harness · ${artifact?.kind ?? "html"}`
                : "deterministic fallback · no harness artifact"}
            </span>
          )}
          <span className="artifact-foot__sandbox">sandboxed · no scripts, no same-origin</span>
        </div>
      )}
    </section>
  );
}
