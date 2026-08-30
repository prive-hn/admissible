/**
 * The presentation contract.
 *
 * This is the layer above `fcd` and below the skins. `fcd` owns meaning; a
 * skin owns mood; this file owns the vocabulary between them. Everything the
 * structural stylesheet paints with is declared here, and every token is named
 * for what it *means* rather than what it looks like.
 *
 * That naming rule is the whole point. A token called `--amber` bakes a mood
 * into the layer that is supposed to be mood-free: a skin that wanted a violet
 * "needs you" state would be stuck shipping violet under a token called amber,
 * and the stylesheet would be quietly lying. A token called `--holding` can be
 * any colour a skin likes and still means the one thing it is allowed to mean.
 *
 * What a skin may do here: every value below. Colour, type, density, radius
 * and motion are all presentation.
 *
 * What a skin may not do — enforced by there being no token for it — is change
 * which state a gate is in, collapse two certainty bands into one appearance,
 * or make a candidate look accepted. Those are `fcd`'s to decide and this
 * layer's to keep distinct.
 */

/** Surfaces, from the ground up. */
export type SurfaceToken =
  | "--surface-app"
  | "--surface-pane"
  | "--surface-raised"
  | "--surface-inset"
  | "--surface-overlay";

/** Drawn structure. Rules, not shadows. */
export type LineToken = "--line" | "--line-strong" | "--focus" | "--scrim";

/**
 * Text, in two degrees of emphasis.
 *
 * Two, not three. A third neutral step light enough to read as tertiary
 * measures 3.84:1 on the pane and 3.37:1 on `--surface-inset` — under AA for
 * body text — so a third degree could only exist by making some labels
 * unreadable. The contract declared three and both shipped skins answered the
 * second and third with the same hex, which is the honest count showing
 * through. Rank below secondary is carried by type instead: `.label` sets the
 * mono face, uppercase and tracking, which reads as subordinate at full
 * contrast.
 */
export type InkToken = "--ink" | "--ink-2";

/**
 * Machine state. These four are the load path's own vocabulary and map
 * one-to-one onto `Skin.stageTone`.
 *
 * Each has three forms, because a state has to read three ways: `-solid` is
 * the mark itself (a load-path node, a rail), `-ink` writes with it and must
 * clear 4.5:1 on `--surface-pane`, `-wash` is a fill to sit other things on.
 */
export type StateToken =
  | "--held-solid" | "--held-ink" | "--held-wash"
  | "--holding-solid" | "--holding-ink" | "--holding-wash"
  | "--broke-solid" | "--broke-ink" | "--broke-wash"
  | "--idle-solid" | "--idle-ink" | "--idle-wash";

/**
 * Certainty bands. Deliberately separate tokens from machine state even where
 * a skin points them at the same value: `docs/EVIDENCE_MODEL.md` requires the
 * three to stay distinguishable, so the contract keeps three names a skin has
 * to answer for.
 */
export type BandToken =
  | "--observed-solid" | "--observed-ink" | "--observed-wash"
  | "--reachable-solid" | "--reachable-ink" | "--reachable-wash"
  | "--unknown-solid" | "--unknown-ink" | "--unknown-wash";

/** Selection, identity, and anything the operator is pointing at. */
export type IdentityToken = "--identity-solid" | "--identity-ink" | "--identity-wash";

/** Type. A skin may change the faces; it must supply a real stack. */
export type TypeToken =
  | "--font-sans" | "--font-mono" | "--font-display" | "--type-rem"
  | "--density-scale"
  | "--text-2xs" | "--text-xs" | "--text-sm" | "--text-md"
  | "--text-lg" | "--text-xl" | "--text-2xl" | "--text-3xl";

/** Form: how tight, how round, how fast. */
export type FormToken =
  | "--space-1" | "--space-2" | "--space-3" | "--space-4" | "--space-5" | "--space-6"
  | "--radius-sm" | "--radius" | "--radius-lg"
  | "--rail-h"
  | "--lift-1" | "--lift-2" | "--lift-3"
  | "--motion-fast" | "--motion-base" | "--motion-ease";

export type SkinToken =
  | SurfaceToken
  | LineToken
  | InkToken
  | StateToken
  | BandToken
  | IdentityToken
  | TypeToken
  | FormToken;

/** Every token a complete skin answers for. A skin may omit none. */
export const SKIN_TOKENS: readonly SkinToken[] = [
  "--surface-app", "--surface-pane", "--surface-raised", "--surface-inset", "--surface-overlay",
  "--line", "--line-strong", "--focus", "--scrim",
  "--ink", "--ink-2",
  "--held-solid", "--held-ink", "--held-wash",
  "--holding-solid", "--holding-ink", "--holding-wash",
  "--broke-solid", "--broke-ink", "--broke-wash",
  "--idle-solid", "--idle-ink", "--idle-wash",
  "--observed-solid", "--observed-ink", "--observed-wash",
  "--reachable-solid", "--reachable-ink", "--reachable-wash",
  "--unknown-solid", "--unknown-ink", "--unknown-wash",
  "--identity-solid", "--identity-ink", "--identity-wash",
  "--font-sans", "--font-mono", "--font-display", "--type-rem", "--density-scale",
  "--text-2xs", "--text-xs", "--text-sm", "--text-md",
  "--text-lg", "--text-xl", "--text-2xl", "--text-3xl",
  "--space-1", "--space-2", "--space-3", "--space-4", "--space-5", "--space-6",
  "--radius-sm", "--radius", "--radius-lg", "--rail-h",
  "--lift-1", "--lift-2", "--lift-3",
  "--motion-fast", "--motion-base", "--motion-ease",
] as const;

export type SkinTokens = Readonly<Record<SkinToken, string>>;

/**
 * Form and motion defaults.
 *
 * A skin that only wants to repaint spreads these and overrides colour; a skin
 * that wants a different density or a different feel overrides them too. They
 * live here rather than in the stylesheet so that "how tight is this
 * instrument" is a skin decision, not a hard-coded one.
 */
export const BASE_FORM: Readonly<Record<TypeToken | FormToken, string>> = {
  "--font-sans": '"Inter Variable", Inter, system-ui, -apple-system, sans-serif',
  "--font-mono": '"JetBrains Mono", ui-monospace, "SF Mono", Menlo, monospace',
  "--font-display": '"Inter Variable", Inter, system-ui, -apple-system, sans-serif',
  // A virtual rem: text scales without also resizing gaps, radii and controls.
  "--type-rem": "13px",
  // Eight steps, all derived from the rem above, so one setting moves every
  // size on screen and nothing drifts out of proportion with the rest.
  "--text-2xs": "calc(var(--type-rem) * 0.80)",
  "--text-xs": "calc(var(--type-rem) * 0.86)",
  "--text-sm": "calc(var(--type-rem) * 0.93)",
  "--text-md": "var(--type-rem)",
  "--text-lg": "calc(var(--type-rem) * 1.10)",
  "--text-xl": "calc(var(--type-rem) * 1.25)",
  "--text-2xl": "calc(var(--type-rem) * 1.55)",
  "--text-3xl": "calc(var(--type-rem) * 1.95)",
  // A density multiplier the operator sets and a skin may override. The six
  // steps are written through it rather than being replaced: the settings
  // panel used to write literal pixels over whatever the skin answered, so
  // "a skin owns density" was false, and its formula never reproduced the
  // 24px/32px declared here at any setting — these two defaults had never
  // rendered.
  "--density-scale": "1",
  "--space-1": "calc(4px * var(--density-scale))",
  "--space-2": "calc(8px * var(--density-scale))",
  "--space-3": "calc(12px * var(--density-scale))",
  "--space-4": "calc(16px * var(--density-scale))",
  "--space-5": "calc(24px * var(--density-scale))",
  "--space-6": "calc(32px * var(--density-scale))",
  "--radius-sm": "3px",
  "--radius": "6px",
  "--radius-lg": "10px",
  // Height of the command rail. Density is a skin decision, so it lives here.
  "--rail-h": "calc(46px * var(--density-scale))",
  "--lift-1": "0 1px 2px rgb(0 0 0 / 0.06)",
  "--lift-2": "0 6px 18px rgb(0 0 0 / 0.10), 0 1px 3px rgb(0 0 0 / 0.08)",
  "--lift-3": "0 18px 44px rgb(0 0 0 / 0.16), 0 2px 6px rgb(0 0 0 / 0.10)",
  "--motion-fast": "120ms",
  "--motion-base": "220ms",
  "--motion-ease": "cubic-bezier(0.2, 0, 0, 1)",
};

/** Tokens a skin left unanswered. Used by the conformance test. */
export function missingTokens(tokens: Partial<SkinTokens>): SkinToken[] {
  return SKIN_TOKENS.filter((token) => !tokens[token]);
}
