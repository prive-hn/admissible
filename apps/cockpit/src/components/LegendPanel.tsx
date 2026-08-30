import { useDialog } from "../domain/useDialog";
import { useState } from "react";
import { FAULTS, GLOSSARY, PC_MEANINGS, type GlossEntry } from "../domain/glossary";

interface Props {
  onClose: () => void;
}

const GROUPS: { key: GlossEntry["group"]; title: string; blurb: string }[] = [
  { key: "object", title: "What you are looking at", blurb: "The objects the cockpit renders." },
  { key: "lifecycle", title: "What the machine does", blurb: "Every transition a line can take." },
  { key: "route", title: "Who runs it, on what", blurb: "Specialists, models and the match that gates a pass." },
  { key: "context", title: "What it was given", blurb: "The frozen envelope around one attempt." },
  { key: "evidence", title: "How sure the cockpit is", blurb: "Certainty bands and where marks come from." },
];

/**
 * The legend: every term on the instrument in plain words, next to the exact
 * transition or invariant it comes from. This is the accessible route to the
 * same content the inline glosses show on hover, and it mirrors
 * `docs/UI_GLOSSARY.md`.
 */
export function LegendPanel({ onClose }: Props) {
  const dialog = useDialog<HTMLElement>(onClose);
  const [query, setQuery] = useState("");
  const needle = query.trim().toLowerCase();
  const entries = Object.values(GLOSSARY) as GlossEntry[];
  const match = (e: GlossEntry) =>
    !needle ||
    e.term.toLowerCase().includes(needle) ||
    e.plain.toLowerCase().includes(needle) ||
    (e.formal ?? "").toLowerCase().includes(needle);
  const faultRows = Object.entries(FAULTS).filter(
    ([code, f]) =>
      !needle || code.toLowerCase().includes(needle) || f.plain.toLowerCase().includes(needle),
  );

  return (
    <div className="modal-scrim" onClick={onClose}>
      <aside
        ref={dialog}
        className="legend"
        role="dialog"
        aria-modal="true"
        aria-label="Legend"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="legend__head">
          <div>
            <span className="modal__title">Legend</span>
            <p className="legend__lead">
              Every term this instrument shows, in plain words, next to the rule it comes from.
            </p>
          </div>
          <button className="icon-btn icon-btn--quiet" onClick={onClose} aria-label="Close legend">
            ✕
          </button>
        </div>

        <div className="legend__search">
          <input
            aria-label="Search the legend"
            placeholder="Search terms, meanings or fault codes"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>

        <div className="legend__body">
          {GROUPS.map(({ key, title, blurb }) => {
            const rows = entries.filter((e) => e.group === key && match(e));
            if (rows.length === 0) return null;
            return (
              <section className="legend__group" key={key}>
                <h3>{title}</h3>
                <p className="legend__blurb">{blurb}</p>
                <dl className="legend__list">
                  {rows.map((e) => (
                    <div className="legend__row" key={e.term}>
                      <dt>{e.term}</dt>
                      <dd>
                        {e.plain}
                        {e.formal && <code>{e.formal}</code>}
                      </dd>
                    </div>
                  ))}
                </dl>
              </section>
            );
          })}

          {(!needle || "gate state".includes(needle)) && (
            <section className="legend__group">
              <h3>Gate states</h3>
              <p className="legend__blurb">The label on the right of every gate.</p>
              <dl className="legend__list">
                {Object.entries(PC_MEANINGS).map(([pc, meaning]) => (
                  <div className="legend__row" key={pc}>
                    <dt className="mono">{pc}</dt>
                    <dd>{meaning}</dd>
                  </div>
                ))}
              </dl>
            </section>
          )}

          {faultRows.length > 0 && (
            <section className="legend__group">
              <h3>Fault codes</h3>
              <p className="legend__blurb">
                Stamped on a gate that broke. A fault is published, never swallowed.
              </p>
              <dl className="legend__list">
                {faultRows.map(([code, f]) => (
                  <div className="legend__row" key={code}>
                    <dt className="mono legend__fault">{code}</dt>
                    <dd>
                      {f.plain}
                      <code>{f.formal}</code>
                    </dd>
                  </div>
                ))}
              </dl>
            </section>
          )}
        </div>

        <div className="legend__foot">
          <span className="hint">
            Full mapping from paper to interface lives in <code>docs/UI_GLOSSARY.md</code>.
          </span>
        </div>
      </aside>
    </div>
  );
}
