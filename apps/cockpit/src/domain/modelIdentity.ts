/**
 * Model identity comparison, mirroring `fcd.core.norm`.
 *
 * The cockpit previously compared the declared and executed model with `===`.
 * The machine does not: `norm()` strips a bracketed context suffix before
 * comparing, so `claude-x[1m]` and `claude-x` are the *same* identity and a
 * gate carrying them passes. Raw equality rendered that gate as a mismatch —
 * a red MISMATCH on a gate the authority had held, under a tooltip stating the
 * exact rule the code was breaking.
 *
 * Keep this in step with `fcd/core.py`:
 *
 *   - strip a bracketed context suffix only (`claude-x[1m]` -> `claude-x`);
 *   - vendor/namespace prefixes stay significant, because stripping them made
 *     distinct APIs collide (`vendorA:gpt` == `vendorB:gpt`), which round 4
 *     flagged;
 *   - `null` in, `null` out, so callers can tell "not observed" from
 *     "observed as empty".
 *
 * Collisions fail toward refusal, never toward pass.
 */
export function modelIdentity(value: string | null | undefined): string | null {
  if (value == null) return null;
  return value.split("[", 1)[0].trim();
}

/** The comparison the Pass guard actually makes (I1). */
export function sameModelIdentity(
  declared: string | null | undefined,
  executed: string | null | undefined,
): boolean {
  const a = modelIdentity(declared);
  const b = modelIdentity(executed);
  return a != null && b != null && a === b;
}
