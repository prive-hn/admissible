import { useState } from "react";
import type { EvidenceItem } from "../domain/types";

interface Props {
  items: EvidenceItem[];
  empty: string;
}

/**
 * Evidence rows. Every visual mark in the cockpit has to resolve to a journal
 * event, so the row shows the event kind, its human label and its journal
 * index. Raw payloads are real evidence but they are not a reading — they stay
 * folded behind an explicit toggle and are pretty-printed when they are JSON.
 */
function formatDetail(detail: string): string {
  const trimmed = detail.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return detail;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    return detail;
  }
}

function EvidenceRow({ item }: { item: EvidenceItem }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="evidence-row" data-kind={item.kind}>
      <div className="evidence-row__line">
        <span className="evidence-row__kind">{item.kind}</span>
        <span className="evidence-row__label">{item.label}</span>
        {item.journalIndex != null && (
          <span className="evidence-row__idx" title="Journal index">#{item.journalIndex}</span>
        )}
        {item.detail && (
          <button
            className="evidence-row__more"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? "Hide payload" : "Payload"}
          </button>
        )}
      </div>
      {item.detail && open && (
        <pre className="evidence-row__detail">{formatDetail(item.detail)}</pre>
      )}
    </li>
  );
}

export function EvidenceList({ items, empty }: Props) {
  if (items.length === 0) return <p className="hint">{empty}</p>;
  return (
    <ul className="evidence">
      {items.map((item) => (
        <EvidenceRow key={item.id} item={item} />
      ))}
    </ul>
  );
}
