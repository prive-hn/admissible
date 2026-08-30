# Skin protocol

A skin is a **read-only projection** of `AtlasSnapshot`. It may change composition, density, color, motion, spatial metaphor and accessibility presentation. It cannot change meaning.

## Layering

```text
fcd            owns meaning      — what a gate is, whether it held
interaction    owns structure    — apps/cockpit, this layer, no mood
skin           owns mood         — colour, type, density, motion
```

The middle layer is the one worth being strict about. It lays out the
instrument and says what every element means; it says nothing about what
anything looks like. `apps/cockpit/src/styles.css` contains no colour literal
at all — every value comes from the contract below, and a skin answers all of
it.

That is checkable, not aspirational. `apps/cockpit/tests/skin-contract.test.ts`
fails the build when a hex, `rgb()` or `hsl()` literal appears in the sheet,
when the sheet paints with an undeclared token, when a `color:` is set to a
`-solid` token (those steps are marks, not text), when a skin leaves a token
unanswered, or when any `-ink` token drops below 4.5:1 on that skin's own
`--surface-pane`.

## Two kinds of skin

A skin may **repaint** or **re-represent**.

A repaint answers the token contract and uses the reference view. A
re-representation supplies `view` — a component receiving the same snapshot —
and owns the whole main region. The machine drawn as a city, a processor die,
a room of avatars or a game board is a re-representation; none of it needs
permission beyond implementing `SkinView`.

What a view is handed is declared in `apps/cockpit/src/skins/view.ts`:

- `state` — the canonical snapshot, read-only.
- `selection` — what is selected, already derived.
- `intents` — **the only way to act.** Every authority request goes to the
  server; there is no local writer in the surface at all.
- `skin`, `panes`, `refusal`, `composerOpen`, `activeQuestionId` — chrome
  context a view may use or ignore.

**Where the guarantee actually lives.** A view is in-bundle code in the same
realm as the shell. It has ambient `fetch` and can import the API client
directly, so `CockpitIntents` is a convenience surface, not a sandbox. An
earlier version of this document claimed otherwise; an audit disproved it by
running a hostile view that forged a `/discard`, mutated the snapshot into
"accepted", and suppressed the refusal strip.

What holds the line is the authority, not the type surface. `fcd` performs
Admit, Bind, Observe, Pass and Accept; the server refuses an Accept for an item
that is not in the store, and refuses a gate whose route cannot Admit. A skin
cannot make a gate hold because the machine does not ask it.

The cockpit closes what it can, and these are enforced in code, not asserted:

- the snapshot is deep-frozen before any view sees it (`domain/freeze.ts`);
- steering verbs are resolved against the fixed set, so a forged
  `SlashCommand` cannot turn an inquiry into a state change;
- `CockpitIntents` has no way to dismiss a published refusal;
- `applySkinTokens` writes only declared tokens and rejects values that fetch.

**Until a view runs in a sandboxed frame over a message channel, treat a skin
as trusted in-bundle code.** A view can still render a `<style>` element or a
fixed-position overlay, so it can hide the shell's spine from a *sighted*
operator. That is the remaining gap, and it is why third-party skins need the
isolation boundary below before they are safe to load.

### What the shell keeps

A view owns the main region. The shell keeps a spine no skin can remove:

- the command rail — project identity, counts, settings, legend, new line;
- the refusal strip — a skin must not be able to hide a published refusal;
- the steering bar — the operator can always steer and always reach the fixed
  verb set;
- the question sheet and the settings/legend surfaces — including the way back
  to another skin.

That list is short on purpose. It is what stops a representation from
stranding an operator inside itself, and it mirrors the rule that a skin
cannot hide a failure by changing semantic state.

`FocusView` is a worked example kept in-tree: one line at a time, no panes,
same snapshot. It exists so the seam has something proving it beyond prose.

## Token contract

Declared in `apps/cockpit/src/skins/contract.ts`. Names describe meaning, never
appearance: a token called `--amber` would force a skin that wanted violet for
"needs you" to ship violet under a name that lies about it.

| Group | Tokens | Meaning |
|---|---|---|
| Surface | `--surface-app` `--surface-pane` `--surface-raised` `--surface-inset` `--surface-overlay` | Ground, pane, header, inset, floating |
| Structure | `--line` `--line-strong` `--focus` `--scrim` | Hairline, divider, focus ring, modal ground |
| Ink | `--ink` `--ink-2` | Two degrees of emphasis. There is no third: the next neutral step down measures 3.84:1 on the pane, so a third degree could only exist by making labels unreadable. Rank below secondary is carried by type — the mono face, uppercase, tracked. |
| Machine state | `--held-*` `--holding-*` `--broke-*` `--idle-*` | One per `Skin.stageTone` |
| Certainty band | `--observed-*` `--reachable-*` `--unknown-*` | Kept separate from state on purpose |
| Identity | `--identity-*` | Selection and what the operator is pointing at |
| Type | `--font-sans` `--font-mono` `--font-display` `--type-rem` | Machine voice, operator voice, the work's name |
| Form | `--space-1..6` `--radius-sm/-/-lg` `--rail-h` `--lift-1..3` `--motion-*` | Density, roundness, depth, timing |

Every state and band token comes in three forms. `-solid` is the mark — a
load-path node, a rail, a border. `-ink` writes and must clear 4.5:1 on
`--surface-pane`. `-wash` is a fill to sit content on.

State never rides on colour alone: a gate also reads through its marker shape,
its rail and its label, so the load path survives with colour removed.

## Reference skins

`instrument` (light) and `nocturne` (dark) answer the same contract. Their
colour is read from [Radix Colors](https://www.radix-ui.com/colors) scales at
the steps Radix designs for each job — 9 solid, 11 text, 3 wash — rather than
mixed by eye; `apps/cockpit/scripts/skin-tokens.mjs` regenerates them and
prints the measured contrast.

Both are deliberately quiet. Mood is a skin author's territory, not this
layer's.

## Inputs

- immutable atlas/context snapshot,
- project/work/gate selection and viewport state,
- execution-envelope, receipt and evidence references,
- theme tokens.

## Outputs

- rendered pixels,
- selection intent,
- viewport intent,
- `Command` objects submitted through the interaction API.

## Forbidden

A skin cannot:

- create/alter journal events,
- write the fcd store,
- convert candidate to accepted,
- hide a failure by changing semantic state,
- label reachable impact as observed,
- submit commands without an explicit user action,
- widen π/δ/φ or change policy version,
- reuse executable cache across specialists/stages,
- hide exact provider/API model identity, context mode, P/K pin, drift, cache authority label or receipt state,
- turn an editable pre-Admit envelope into an editable post-Admit envelope,
- replace project/work/artifact navigation with a sessions hierarchy.

## Reference skin

`apps/cockpit/src/skins/skin.ts` implements `instrument`: restrained sage/amber/green/red tokens backed by semantic state (`nocturne` is the slate one). Each ink clears 4.5:1 against **every** ground it can be painted on — the pane, the app, the raised rail, `--surface-inset` and its own wash — and `--focus` clears 3:1 on all of them, both enforced by `tests/skin-contract.test.ts`. Colour is never the only carrier: gate state also reads through the load-path marker's shape and the `pc` word, a pass verdict through the words `match`/`mismatch`, a line's status through the word beside its id, and a bind divergence through a sentence rather than red text alone. CSS tokens are presentation only. The artifact iframe is sandboxed without scripts or same-origin authority.

Third-party mood boards/skins may live in other packages. Conformance means
they consume the same schemas and pass `apps/cockpit/tests/skin-contract.test.ts`,
which checks the token contract and its contrast floor.

It does **not** yet check immutability or authority — an earlier version of this
document cited tests that were never written. Loading a skin from outside this
repository is not supported until a view runs in a sandboxed frame over a
`postMessage` intent channel.
