import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { FAULTS, GLOSSARY, type GlossKey } from "../domain/glossary";

interface Placement {
  left: number;
  top?: number;
  bottom?: number;
}

const POP_WIDTH = 300;
const EDGE = 10;

/**
 * Shared hover/focus card used by every glossed term.
 *
 * It renders into a fixed layer on `document.body` rather than inside the
 * wrapper: the three panes are scroll containers, and a popover positioned
 * inside one would be clipped at the pane edge exactly when a term sits near
 * the boundary. The card is `aria-hidden` — it is a visual aid only, and the
 * same content is available in full, keyboard-reachable, in the legend panel.
 */
function useGlossCard() {
  const anchor = useRef<HTMLSpanElement>(null);
  const [place, setPlace] = useState<Placement | null>(null);

  const show = useCallback(() => {
    const el = anchor.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const left = Math.min(
      Math.max(EDGE, r.left - 8),
      Math.max(EDGE, window.innerWidth - POP_WIDTH - EDGE),
    );
    // Prefer above; flip below when the term sits near the top of the viewport.
    setPlace(
      r.top < 200
        ? { left, top: Math.round(r.bottom + 8) }
        : { left, bottom: Math.round(window.innerHeight - r.top + 8) },
    );
  }, []);

  const hide = useCallback(() => setPlace(null), []);

  useEffect(() => {
    if (!place) return;
    const onScroll = () => hide();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") hide();
    };
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("keydown", onKey);
    };
  }, [place, hide]);

  return { anchor, place, show, hide };
}

function GlossCard({ place, plain, formal }: { place: Placement; plain: string; formal?: string }) {
  if (typeof document === "undefined") return null;
  return createPortal(
    <span
      className="gloss__pop"
      aria-hidden="true"
      style={{ left: place.left, top: place.top, bottom: place.bottom, width: POP_WIDTH }}
    >
      <span className="gloss__plain">{plain}</span>
      {formal && <code className="gloss__formal">{formal}</code>}
    </span>,
    document.body,
  );
}

interface Props {
  term: GlossKey;
  children: ReactNode;
  /** Give the term its own tab stop. Use on standalone marks, not inside buttons. */
  focusable?: boolean;
  className?: string;
}

/**
 * Wraps a machine term with its plain reading. The wrapper keeps the label as
 * its own direct text, so the visible wording of the instrument is unchanged —
 * only explained.
 */
export function Gloss({ term, children, focusable, className }: Props) {
  const entry = GLOSSARY[term];
  const { anchor, place, show, hide } = useGlossCard();
  return (
    <span
      ref={anchor}
      className={`gloss ${className ?? ""}`}
      data-gloss={term}
      // A focusable span with no role and no accessible name is a dead tab
      // stop, and the card it reveals is `aria-hidden`. The term's own text is
      // the name; the plain reading rides as the description, so the
      // definition is announced without swallowing the term it defines.
      tabIndex={focusable ? 0 : undefined}
      role={focusable ? "note" : undefined}
      title={entry.plain}
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
    >
      {children}
      {place && <GlossCard place={place} plain={entry.plain} formal={entry.formal} />}
    </span>
  );
}

/**
 * A published fault label. The code is the machine's word; the card says what
 * it means without sending anyone to the paper.
 */
export function FaultStamp({ code, focusable }: { code: string; focusable?: boolean }) {
  const fault = FAULTS[code];
  const { anchor, place, show, hide } = useGlossCard();
  return (
    <span
      ref={anchor}
      className="fault-stamp gloss"
      tabIndex={focusable ? 0 : undefined}
      role={focusable ? "note" : undefined}
      aria-label={fault ? `Fault ${code}: ${fault.name}. ${fault.plain}` : `Fault ${code}`}
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
    >
      <b className="fault-stamp__code">{code}</b>
      {fault && <span className="fault-stamp__name">· {fault.name}</span>}
      {fault && place && <GlossCard place={place} plain={fault.plain} formal={fault.formal} />}
    </span>
  );
}
