/**
 * Operator view preferences: how big the text is and how tight the layout.
 *
 * These are functional, not decorative, so they belong to this layer rather
 * than to a skin — an instrument someone reads all day has to meet their eyes
 * and their screen. They are applied on top of whatever skin is active, and
 * they only ever touch tokens the contract already declares.
 *
 * Text size moves `--type-rem` alone. Every font size in the sheet is relative
 * to it while gaps, radii and control heights are not, so text scales without
 * the layout stretching with it.
 */
export type TextSize = "small" | "medium" | "large";
export type Density = "compact" | "comfortable" | "roomy";

export interface ViewPrefs {
  textSize: TextSize;
  density: Density;
}

export const DEFAULT_VIEW: ViewPrefs = { textSize: "medium", density: "comfortable" };

export const TEXT_SIZES: { value: TextSize; label: string; rem: string }[] = [
  { value: "small", label: "Small", rem: "12px" },
  { value: "medium", label: "Medium", rem: "13px" },
  { value: "large", label: "Large", rem: "15px" },
];

export const DENSITIES: { value: Density; label: string; scale: number }[] = [
  { value: "compact", label: "Compact", scale: 0.85 },
  { value: "comfortable", label: "Comfortable", scale: 1 },
  { value: "roomy", label: "Roomy", scale: 1.25 },
];

const KEY = "fcd.cockpit.view";

export function readViewPrefs(): ViewPrefs {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return DEFAULT_VIEW;
    const parsed = JSON.parse(raw) as Partial<ViewPrefs>;
    return {
      textSize: TEXT_SIZES.some((t) => t.value === parsed.textSize)
        ? (parsed.textSize as TextSize)
        : DEFAULT_VIEW.textSize,
      density: DENSITIES.some((d) => d.value === parsed.density)
        ? (parsed.density as Density)
        : DEFAULT_VIEW.density,
    };
  } catch {
    return DEFAULT_VIEW;
  }
}

export function writeViewPrefs(prefs: ViewPrefs): void {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(prefs));
  } catch {
    /* storage refused; the session still honours the choice */
  }
}

/**
 * Apply preferences over the active skin. Called after `applySkinTokens`, so a
 * skin change never silently discards the operator's own settings.
 */
export function applyViewPrefs(prefs: ViewPrefs): void {
  const root = document.documentElement;
  const size = TEXT_SIZES.find((t) => t.value === prefs.textSize) ?? TEXT_SIZES[1];
  const density = DENSITIES.find((d) => d.value === prefs.density) ?? DENSITIES[1];
  root.setAttribute("data-text-size", prefs.textSize);
  root.setAttribute("data-density", prefs.density);
  // Set the two knobs the contract declares for this; do not write the
  // spacing steps. Overwriting them replaced whatever the skin answered, so
  // the contract's promise that a skin owns density was not true, and the
  // formula silently disagreed with the declared defaults at every setting.
  root.style.setProperty("--type-rem", size.rem);
  root.style.setProperty("--density-scale", String(density.scale));
}
