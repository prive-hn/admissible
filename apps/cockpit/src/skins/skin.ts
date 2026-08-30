import type { CockpitState } from "../domain/types";
import { BASE_FORM, SKIN_TOKENS, missingTokens, type SkinTokens } from "./contract";
import type { SkinView } from "./view";
import { FocusView } from "../views/FocusView";

/**
 * Read-only skin interface.
 *
 * A skin may ONLY read canonical state and return presentation tokens plus a
 * few pure label/format helpers. It is handed a frozen snapshot and returns
 * plain values; it is given no setters, no dispatch, and no handles to the
 * store. This mirrors the machine's own rule: the UI cannot choose φ and
 * cannot write the store. A skin that tries to mutate state simply has no
 * capability to do so — the type surface exposes none.
 *
 * The tokens it answers are declared in `./contract.ts` and named for meaning,
 * not appearance, so a skin is free to be a mood without the layer beneath it
 * having to know what that mood is.
 */
export interface Skin {
  readonly id: string;
  readonly name: string;
  /** One line on what this skin is for. Shown in settings. */
  readonly note: string;
  /** The complete contract. Applied to :root[data-skin]. */
  readonly tokens: SkinTokens;
  /** Human label for a stage program-counter. Pure. */
  pcLabel(pc: string): string;
  /** Semantic tone for a stage, used only for styling classes. Pure. */
  stageTone(pc: string): "holding" | "held" | "broken" | "idle";
  /** One-line caption for the whole board given a read-only snapshot. Pure. */
  headline(state: Readonly<CockpitState>): string;
  /**
   * An alternate representation of the main region. Omit it to use the
   * reference three-pane view; supply one to draw this machine however you
   * like — a city, a processor die, a room of avatars. The shell still owns
   * the rail, refusals, steering and settings, so a view cannot strand the
   * operator or hide a published failure, and it is handed no writer, so it
   * cannot decide what held.
   */
  readonly view?: SkinView;
}

const PC_LABELS: Record<string, string> = {
  Open: "open",
  Admitted: "admitted",
  Running: "running",
  Passed: "held",
  Closed: "broke",
  Stopped: "stopped",
};

export function pcTone(pc: string): "holding" | "held" | "broken" | "idle" {
  switch (pc) {
    case "Running":
    case "Admitted":
      return "holding";
    case "Passed":
      return "held";
    case "Closed":
    case "Stopped":
      return "broken";
    default:
      return "idle";
  }
}

/**
 * Instrument — the reference skin, and deliberately not a mood.
 *
 * Its colour is Radix Colors' scales rather than a hand-mixed palette: sage
 * for neutrals, grass/amber/tomato/blue for state, taken at the steps Radix
 * designs for the job (9 solid, 11 text, 3 wash). Nothing here was picked by
 * eye; `scripts/skin-tokens.mjs` regenerates it and prints the contrast.
 *
 * The default is quiet on purpose. Expression belongs in a skin someone else
 * writes; this one's job is to be the thing they can see past.
 */
export const instrumentSkin: Skin = {
  id: "instrument",
  name: "Instrument",
  note: "The quiet reference. Radix neutrals, state colour only where it means something.",
  tokens: {
    ...BASE_FORM,
    "--surface-app": "#f7f9f8",
    "--surface-pane": "#ffffff",
    "--surface-raised": "#f7f9f8",
    "--surface-inset": "#eef1f0",
    "--surface-overlay": "#ffffff",
    "--line": "#cbcfcd",
    "--line-strong": "#7c8481",
    "--focus": "#0d74ce",
    "--scrim": "rgb(26 33 30 / 0.34)",
    "--ink": "#1a211e",
    "--ink-2": "#5f6563",
    "--held-solid": "#46a758",
    "--held-ink": "#203c25",
    "--held-wash": "#e9f6e9",
    "--holding-solid": "#ffc53d",
    "--holding-ink": "#4f3422",
    "--holding-wash": "#fff7c2",
    "--broke-solid": "#e54d2e",
    "--broke-ink": "#5c271f",
    "--broke-wash": "#feebe7",
    "--idle-solid": "#868e8b",
    "--idle-ink": "#5f6563",
    "--idle-wash": "#eef1f0",
    "--observed-solid": "#e54d2e",
    "--observed-ink": "#5c271f",
    "--observed-wash": "#feebe7",
    "--reachable-solid": "#ffc53d",
    "--reachable-ink": "#4f3422",
    "--reachable-wash": "#fff7c2",
    "--unknown-solid": "#868e8b",
    "--unknown-ink": "#5f6563",
    "--unknown-wash": "#eef1f0",
    "--identity-solid": "#0090ff",
    "--identity-ink": "#113264",
    "--identity-wash": "#e6f4fe",
  },
  pcLabel: (pc) => PC_LABELS[pc] ?? pc.toLowerCase(),
  stageTone: pcTone,
  headline: (state) => {
    const o = state.atlas.outcome;
    return `${o.active} active · ${o.accepted} accepted · ${o.degraded} degraded · ${o.question} question`;
  },
};

/**
 * Nocturne — the same contract answered dark.
 *
 * It exists to prove the layer is genuinely mood-free: nothing in the
 * stylesheet knows whether it is painting on white or on near-black, because
 * nothing in the stylesheet names a colour. Radix's dark scales keep every
 * `-ink` token above 8:1 here.
 */
export const nocturneSkin: Skin = {
  id: "nocturne",
  name: "Nocturne",
  note: "The same instrument after dark. Proves the contract carries a ground it never names.",
  tokens: {
    ...BASE_FORM,
    "--surface-app": "#111113",
    "--surface-pane": "#18191b",
    "--surface-raised": "#212225",
    "--surface-inset": "#111113",
    "--surface-overlay": "#212225",
    "--line": "#363a3f",
    "--line-strong": "#696e77",
    "--focus": "#70b8ff",
    "--scrim": "rgb(0 0 0 / 0.62)",
    "--ink": "#edeef0",
    "--ink-2": "#b0b4ba",
    "--held-solid": "#46a758",
    "--held-ink": "#71d083",
    "--held-wash": "#1b2a1e",
    "--holding-solid": "#ffc53d",
    "--holding-ink": "#ffca16",
    "--holding-wash": "#302008",
    "--broke-solid": "#e54d2e",
    "--broke-ink": "#ff977d",
    "--broke-wash": "#391714",
    "--idle-solid": "#696e77",
    "--idle-ink": "#b0b4ba",
    "--idle-wash": "#212225",
    "--observed-solid": "#e54d2e",
    "--observed-ink": "#ff977d",
    "--observed-wash": "#391714",
    "--reachable-solid": "#ffc53d",
    "--reachable-ink": "#ffca16",
    "--reachable-wash": "#302008",
    "--unknown-solid": "#696e77",
    "--unknown-ink": "#b0b4ba",
    "--unknown-wash": "#212225",
    "--identity-solid": "#0090ff",
    "--identity-ink": "#70b8ff",
    "--identity-wash": "#0d2847",
  },
  pcLabel: (pc) => PC_LABELS[pc] ?? pc.toLowerCase(),
  stageTone: pcTone,
  headline: (state) =>
    `atlas — ${state.atlas.capabilities.length} capabilities under watch`,
};

/**
 * Focus — the same state, a different composition.
 *
 * Not a mood: a worked example of the seam, kept in-tree so the contract has
 * something proving it beyond prose. It drops the panes and shows one line at
 * a time.
 */
export const focusSkin: Skin = {
  ...instrumentSkin,
  id: "focus",
  name: "Focus",
  note: "One line at a time, no panes. A worked example that a skin may replace the whole composition.",
  view: FocusView,
};

export const skins: Skin[] = [instrumentSkin, nocturneSkin, focusSkin];

const DECLARED = new Set<string>(SKIN_TOKENS);
/** A token value may not reach out of the page. */
const FETCHES = /url\s*\(|image-set\s*\(|@import/i;

/**
 * Apply a skin's tokens, and only its tokens.
 *
 * This used to write whatever keys the object carried, so a skin could set
 * `display: none` on the root or point a token at `url(https://…)` and beacon
 * out of the operator's machine. Both are now refused: keys must be declared in
 * the contract, and values may not fetch.
 */
export function applySkinTokens(skin: Skin): void {
  const root = document.documentElement;
  root.setAttribute("data-skin", skin.id);
  for (const [key, value] of Object.entries(skin.tokens)) {
    if (!DECLARED.has(key)) continue;
    if (typeof value !== "string" || FETCHES.test(value)) continue;
    root.style.setProperty(key, value);
  }
  // The stylesheet holds no colour of its own and defines no fallbacks, so a
  // token nobody answers resolves to nothing rather than to a default. The
  // suite catches that for the skins that ship here; this catches it for one
  // written elsewhere, at the moment it is applied.
  const unanswered = missingTokens(skin.tokens);
  if (unanswered.length) {
    root.setAttribute("data-skin-incomplete", "true");
    console.error(
      `Skin ${skin.id} answers no value for: ${unanswered.join(", ")}. ` +
        "Those parts of the instrument will render unstyled.",
    );
  } else {
    root.removeAttribute("data-skin-incomplete");
  }
}
