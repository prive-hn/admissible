/**
 * Deep-freeze a snapshot before it leaves the shell.
 *
 * A skin view is in-bundle code in the same realm as the cockpit, so "the view
 * is handed a read-only snapshot" is only true if the object is actually
 * immutable. It was not: a hostile view mutated the state in place, flipped
 * candidates to accepted, and the forgery survived a switch back to the honest
 * skin, which then rendered it.
 *
 * This closes the mutation path. It does not make a view trustworthy — see
 * `docs/SKIN_PROTOCOL.md` for what actually enforces authority.
 */
export function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  const object = value as unknown as object;
  if (seen.has(object) || Object.isFrozen(object)) return value;
  seen.add(object);
  for (const key of Object.keys(object)) {
    deepFreeze((object as Record<string, unknown>)[key], seen);
  }
  return Object.freeze(value);
}
