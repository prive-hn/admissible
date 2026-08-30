interface Props {
  reason: string;
  onDismiss: () => void;
}

/**
 * What the authority refused, in its own words.
 *
 * A refusal is published here rather than logged and forgotten. It does not
 * time out: an operator who looked away must still be able to tell a refused
 * intent from one that never left the cockpit, and dismissing it is a
 * deliberate act.
 */
export function RefusalStrip({ reason, onDismiss }: Props) {
  return (
    <div className="refusal" role="alert">
      <span className="refusal__mark">refused</span>
      <span className="refusal__reason">{reason}</span>
      <button className="icon-btn icon-btn--quiet" onClick={onDismiss} aria-label="Dismiss refusal">
        ✕
      </button>
    </div>
  );
}
