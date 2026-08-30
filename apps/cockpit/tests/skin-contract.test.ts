/**
 * The presentation contract, enforced.
 *
 * This layer's claim is that it carries structure and meaning but no mood: a
 * skin supplies every colour, and the stylesheet names none. That is only
 * worth claiming if it is checkable, so it is checked here — a hex literal
 * added to the sheet, a token a skin forgot, or a state colour that drops
 * below 4.5:1 all fail the build rather than the design review.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { SkinToken } from "../src/skins/contract";
import { SKIN_TOKENS, missingTokens } from "../src/skins/contract";
import { skins } from "../src/skins/skin";

const sheet = readFileSync(resolve(__dirname, "../src/styles.css"), "utf8");
/** Everything after the header comment — the rules themselves. */
const body = sheet.split(
  "--------------------------------------------------------------------------- */",
)[1];

const COLOUR_LITERAL = /(?<![-\w])(#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\))/g;

function channels(value: string): [number, number, number] {
  const hex = value.trim().replace("#", "");
  const full = hex.length === 3 ? hex.split("").map((c) => c + c).join("") : hex;
  const n = parseInt(full.slice(0, 6), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function relativeLuminance(value: string): number {
  const [r, g, b] = channels(value).map((c) => {
    const s = c / 255;
    return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(fg: string, bg: string): number {
  const a = relativeLuminance(fg);
  const b = relativeLuminance(bg);
  const [hi, lo] = a > b ? [a, b] : [b, a];
  return (hi + 0.05) / (lo + 0.05);
}

describe("the structural sheet carries no mood", () => {
  it("names no colour of its own", () => {
    expect(body.match(COLOUR_LITERAL) ?? []).toEqual([]);
  });

  it("writes with -ink and marks with -solid", () => {
    // The contract says -solid is a mark and -ink is what writes. A `color:`
    // set to a -solid token is the shape of a contrast bug: the solid steps
    // are chosen to sit against a surface, not to be read on one.
    const misused = [
      ...body.matchAll(
        /(?<![-\w])color:\s*var\((--(?:held|holding|broke|idle|observed|reachable|unknown|identity)-solid)\)/g,
      ),
    ].map((m) => m[1]);
    expect(misused).toEqual([]);
  });

  it("paints only with declared tokens", () => {
    const used = new Set(
      [...body.matchAll(/var\((--[a-z0-9-]+)\)/g)].map((m) => m[1]),
    );
    // Locally scoped variables the sheet defines for itself, not skin surface.
    const local = new Set(["--tone", "--seg"]);
    const undeclared = [...used].filter(
      (t) => !local.has(t) && !(SKIN_TOKENS as readonly string[]).includes(t),
    );
    expect(undeclared).toEqual([]);
  });
});

describe.each(skins.map((s) => [s.id, s] as const))("skin: %s", (_id, skin) => {
  it("answers every token in the contract", () => {
    expect(missingTokens(skin.tokens)).toEqual([]);
  });

  it("keeps every ink legible on every ground it can be painted on", () => {
    // Not just the pane. Measuring against `--surface-pane` alone is how six
    // instrument inks shipped between 4.06 and 4.46:1 — the guarantee was true
    // of the one surface it was tested against, while the sheet paints state
    // ink on the raised rail, on `--surface-inset` and on each state's own
    // wash as well.
    const grounds = SKIN_TOKENS.filter((t) => t.startsWith("--surface-"));
    const inkTokens = SKIN_TOKENS.filter((t) => t.endsWith("-ink") || t === "--ink" || t === "--ink-2");
    const failures: string[] = [];
    for (const token of inkTokens) {
      const own = (/^--[a-z]+-ink$/.test(token)
        ? token.replace(/-ink$/, "-wash")
        : null) as SkinToken | null;
      const against = [...grounds, ...(own && skin.tokens[own] ? [own] : [])];
      for (const ground of against) {
        const ratio = contrast(skin.tokens[token], skin.tokens[ground]);
        if (ratio < 4.5) failures.push(`${token} on ${ground} ${ratio.toFixed(2)}:1`);
      }
    }
    expect(failures).toEqual([]);
  });

  it("keeps every component boundary visible on every ground", () => {
    // `--line-strong` is the only boundary a button, input, chip, option or
    // segmented control has, and WCAG 1.4.11 asks 3:1 for the visual boundary
    // of a user-interface component. It measured 1.92:1 in the light skin, so
    // form fields had no perceptible edge.
    const failures = SKIN_TOKENS.filter((g) => g.startsWith("--surface-"))
      .map((g) => ({ g, ratio: contrast(skin.tokens["--line-strong"], skin.tokens[g]) }))
      .filter(({ ratio }) => ratio < 3)
      .map(({ g, ratio }) => `--line-strong on ${g} ${ratio.toFixed(2)}:1`);
    expect(failures).toEqual([]);
  });

  it("keeps the focus ring visible on every ground", () => {
    // WCAG 1.4.11: a focus indicator is a non-text mark and needs 3:1. The
    // generator used to emit the step-8 border colour here, which measures
    // 2.33:1 on white — so following the documented regeneration step would
    // have made the ring disappear.
    const failures = SKIN_TOKENS.filter((t) => t.startsWith("--surface-"))
      .map((g) => ({ g, ratio: contrast(skin.tokens["--focus"], skin.tokens[g]) }))
      .filter(({ ratio }) => ratio < 3)
      .map(({ g, ratio }) => `--focus on ${g} ${ratio.toFixed(2)}:1`);
    expect(failures).toEqual([]);
  });

  it("keeps the three certainty bands distinguishable", () => {
    const bands = ["--observed-ink", "--reachable-ink", "--unknown-ink"] as const;
    const values = bands.map((b) => skin.tokens[b]);
    // EVIDENCE_MODEL.md: reachable must never be readable as observed.
    expect(new Set(values).size).toBe(bands.length);
  });

  it("never paints a candidate the same as an accepted artifact", () => {
    expect(skin.tokens["--holding-ink"]).not.toBe(skin.tokens["--held-ink"]);
  });
});
