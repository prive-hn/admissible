import { useRef } from "react";

interface Props {
  side: "left" | "right";
  /** Current width of the pane this handle resizes. */
  width: number;
  min: number;
  max: number;
  label: string;
  onResize: (width: number) => void;
  onNudge: (delta: number) => void;
  onReset: () => void;
}

const STEP = 16;

/**
 * The divider between two panes, and a real control.
 *
 * It is a `separator` with a value, so it is not mouse-only: arrow keys move it
 * a step at a time, Home and End take it to its limits, and Enter or a
 * double-click puts it back where it started. Pointer capture keeps the drag
 * alive when the cursor outruns the handle.
 */
export function PaneResizer({ side, width, min, max, label, onResize, onNudge, onReset }: Props) {
  const origin = useRef<{ x: number; width: number } | null>(null);

  const onPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault();
    origin.current = { x: e.clientX, width };
    e.currentTarget.setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const from = origin.current;
    if (!from) return;
    // The right pane grows as the pointer moves left, so its delta inverts.
    const delta = side === "left" ? e.clientX - from.x : from.x - e.clientX;
    onResize(from.width + delta);
  };

  const end = (e: React.PointerEvent<HTMLDivElement>) => {
    origin.current = null;
    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const grow = side === "left" ? "ArrowRight" : "ArrowLeft";
    const shrink = side === "left" ? "ArrowLeft" : "ArrowRight";
    if (e.key === grow) { e.preventDefault(); onNudge(STEP); }
    else if (e.key === shrink) { e.preventDefault(); onNudge(-STEP); }
    else if (e.key === "Home") { e.preventDefault(); onResize(min); }
    else if (e.key === "End") { e.preventDefault(); onResize(max); }
    else if (e.key === "Enter") { e.preventDefault(); onReset(); }
  };

  return (
    <div
      className="pane-resizer"
      role="separator"
      aria-orientation="vertical"
      aria-label={label}
      aria-valuenow={width}
      aria-valuetext={`${width} pixels`}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={end}
      onPointerCancel={end}
      onDoubleClick={onReset}
      onKeyDown={onKeyDown}
    >
      <span className="pane-resizer__grip" aria-hidden />
    </div>
  );
}
