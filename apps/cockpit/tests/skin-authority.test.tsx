/**
 * The skin immutability and authority tests.
 *
 * `docs/SKIN_PROTOCOL.md` cited these before they existed. A security audit
 * then wrote a hostile view and disproved three of the claims the document was
 * making, so these exist to hold what has actually been closed — and to keep
 * the document honest about the rest.
 *
 * What is enforced here: the snapshot cannot be mutated, a forged steering verb
 * cannot become a state change, a view has no way to dismiss a refusal, and a
 * skin cannot write undeclared CSS or a value that fetches.
 *
 * What is NOT enforced, by design and stated plainly: a view is in-bundle code
 * and can still render its own markup. Real isolation needs a frame boundary.
 */
import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { deepFreeze } from "../src/domain/freeze";
import { applySkinTokens, instrumentSkin, type Skin } from "../src/skins/skin";
import { SKIN_TOKENS } from "../src/skins/contract";
import { makeDemoState } from "../src/domain/demoState";
import { CenterStages } from "../src/components/CenterStages";
import type { CockpitIntents } from "../src/skins/view";

describe("a view cannot rewrite the snapshot", () => {
  it("refuses in-place mutation of a work item's status", () => {
    const state = deepFreeze(makeDemoState());
    const line = state.workItems[1];
    expect(line.status).toBe("failed");
    // Exactly what the hostile view did: flip a candidate to accepted.
    expect(() => {
      (line as { status: string }).status = "accepted";
    }).toThrow(TypeError);
    expect(state.workItems[1].status).toBe("failed");
  });

  it("freezes nested stages and evidence, not just the top level", () => {
    const state = deepFreeze(makeDemoState());
    const stage = state.workItems[1].stages[1];
    expect(Object.isFrozen(stage)).toBe(true);
    expect(() => {
      (stage as { pc: string }).pc = "Passed";
    }).toThrow(TypeError);
    for (const evidence of stage.evidence ?? []) {
      expect(Object.isFrozen(evidence)).toBe(true);
    }
  });

  it("survives a cyclic snapshot without hanging", () => {
    const cyclic: Record<string, unknown> = { name: "a" };
    cyclic.self = cyclic;
    expect(Object.isFrozen(deepFreeze(cyclic))).toBe(true);
  });
});

describe("a skin cannot write outside the token contract", () => {
  function tokensOn(skin: Skin): Record<string, string> {
    const written: Record<string, string> = {};
    const root = document.documentElement;
    const spy = vi.spyOn(root.style, "setProperty").mockImplementation((k, v) => {
      written[k] = String(v);
    });
    applySkinTokens(skin);
    spy.mockRestore();
    return written;
  }

  it("drops undeclared properties", () => {
    const hostile = {
      ...instrumentSkin,
      id: "hostile",
      tokens: { ...instrumentSkin.tokens, display: "none", "pointer-events": "none" },
    } as unknown as Skin;
    const written = tokensOn(hostile);
    expect(written["display"]).toBeUndefined();
    expect(written["pointer-events"]).toBeUndefined();
    expect(Object.keys(written).every((k) => (SKIN_TOKENS as readonly string[]).includes(k))).toBe(true);
  });

  it("drops a declared token whose value would fetch", () => {
    const beacon = {
      ...instrumentSkin,
      id: "beacon",
      tokens: { ...instrumentSkin.tokens, "--surface-app": "url(https://attacker.example/b.png)" },
    } as unknown as Skin;
    expect(tokensOn(beacon)["--surface-app"]).toBeUndefined();
  });

  it("still applies every honest token", () => {
    const written = tokensOn(instrumentSkin);
    expect(written["--surface-app"]).toBe(instrumentSkin.tokens["--surface-app"]);
  });
});

describe("the intent surface withholds what the shell must own", () => {
  it("offers no way to dismiss a published refusal", () => {
    // A view that could clear the strip could hide a failure, which is the one
    // thing SKIN_PROTOCOL's Forbidden list is built around.
    const surface = {} as unknown as CockpitIntents;
    const keys = Object.keys(surface as unknown as Record<string, unknown>);
    expect(keys).not.toContain("dismissRefusal");
    // Compile-time guard: restoring it to CockpitIntents makes this line fail
    // typecheck, so the omission cannot be undone silently.
    type HasDismiss = "dismissRefusal" extends keyof CockpitIntents ? true : false;
    const withheld: HasDismiss = false;
    expect(withheld).toBe(false);
  });
});

describe("the bind verdict follows the machine's own comparison", () => {
  it("does not flag a gate the authority would pass", () => {
    const item = structuredClone(makeDemoState().workItems[0]);
    item.stages[0].declaredModel = "vendorA:model-a[1m]";
    item.stages[0].executedModel = "vendorA:model-a";
    const { container } = render(
      <CenterStages item={item} selectedNodeId={null} openNodeId={null}
        onSelectNode={() => {}} onToggleDrill={() => {}} onRecover={() => {}} />,
    );
    expect(container.querySelector(".stage-node__models .mismatch")).toBeNull();
  });
});
