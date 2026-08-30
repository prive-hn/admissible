import { useCallback, useEffect, useState } from "react";

/**
 * Pane widths and collapse, remembered.
 *
 * The three panes are the product's claim — atlas, live line and artifact
 * reachable together — but "locked composition" only ever meant all three stay
 * reachable, not that they stay the same size. How much room each gets is the
 * operator's call, and it survives a reload.
 *
 * Widths are stored as pixels for the two side panes; the centre takes the
 * rest. Below the layout breakpoints the stylesheet overrides the grid
 * entirely, so these values simply stop applying rather than fighting it.
 */
export interface PaneLayout {
  left: number;
  right: number;
  leftCollapsed: boolean;
  rightCollapsed: boolean;
}

export const PANE_LIMITS = {
  left: { min: 180, max: 420, initial: 264 },
  right: { min: 260, max: 720, initial: 420 },
} as const;

const KEY = "fcd.cockpit.panes";

const DEFAULTS: PaneLayout = {
  left: PANE_LIMITS.left.initial,
  right: PANE_LIMITS.right.initial,
  leftCollapsed: false,
  rightCollapsed: false,
};

function clamp(value: number, side: "left" | "right"): number {
  const { min, max } = PANE_LIMITS[side];
  return Math.min(max, Math.max(min, Math.round(value)));
}

function read(): PaneLayout {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw) as Partial<PaneLayout>;
    return {
      left: clamp(parsed.left ?? DEFAULTS.left, "left"),
      right: clamp(parsed.right ?? DEFAULTS.right, "right"),
      leftCollapsed: Boolean(parsed.leftCollapsed),
      rightCollapsed: Boolean(parsed.rightCollapsed),
    };
  } catch {
    return DEFAULTS;
  }
}

export function usePaneLayout() {
  const [layout, setLayout] = useState<PaneLayout>(read);

  useEffect(() => {
    try {
      window.localStorage.setItem(KEY, JSON.stringify(layout));
    } catch {
      /* a private-mode browser is not a reason to break the instrument */
    }
  }, [layout]);

  const resize = useCallback((side: "left" | "right", width: number) => {
    setLayout((prev) => ({ ...prev, [side]: clamp(width, side) }));
  }, []);

  const nudge = useCallback((side: "left" | "right", delta: number) => {
    setLayout((prev) => ({ ...prev, [side]: clamp(prev[side] + delta, side) }));
  }, []);

  const reset = useCallback((side: "left" | "right") => {
    setLayout((prev) => ({ ...prev, [side]: PANE_LIMITS[side].initial }));
  }, []);

  const toggle = useCallback((side: "left" | "right") => {
    const key = side === "left" ? "leftCollapsed" : "rightCollapsed";
    setLayout((prev) => ({ ...prev, [key]: !prev[key] }));
  }, []);

  return { layout, resize, nudge, reset, toggle };
}
