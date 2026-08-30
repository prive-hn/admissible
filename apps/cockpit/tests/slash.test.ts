import { describe, it, expect } from "vitest";
import { suggestSlash, parseSteer, SLASH_COMMANDS } from "../src/domain/slash";

describe("slash command suggestions", () => {
  it("returns nothing for non-slash input", () => {
    expect(suggestSlash("retry now")).toHaveLength(0);
    expect(suggestSlash("")).toHaveLength(0);
  });

  it("returns the full fixed set for a bare slash", () => {
    const all = suggestSlash("/");
    expect(all).toHaveLength(SLASH_COMMANDS.length);
    expect(all.map((c) => c.cmd)).toEqual(
      expect.arrayContaining([
        "/inspect",
        "/why",
        "/impact",
        "/fix",
        "/retry",
        "/pause",
        "/discard",
        "/accept",
      ]),
    );
  });

  it("prefix-filters case-insensitively", () => {
    expect(suggestSlash("/in").map((c) => c.cmd)).toEqual(["/inspect"]);
    expect(suggestSlash("/I").map((c) => c.cmd)).toEqual(["/inspect", "/impact"]);
    expect(suggestSlash("/re").map((c) => c.cmd)).toEqual(["/retry"]);
  });

  it("stops suggesting once a complete command is followed by a space", () => {
    expect(suggestSlash("/retry ")).toHaveLength(0);
    expect(suggestSlash("/retry carol")).toHaveLength(0);
  });

  it("parses a command and its free-text remainder", () => {
    const parsed = parseSteer("/retry with carol please");
    expect(parsed.command?.cmd).toBe("/retry");
    expect(parsed.text).toBe("with carol please");
  });

  it("parses plain text as a free node-scoped steering event", () => {
    const parsed = parseSteer("Keep keyboard navigation and use the existing API");
    expect(parsed.command?.cmd).toBe("/steer");
    expect(parsed.command?.channel).toBe("steer");
    expect(parsed.text).toBe("Keep keyboard navigation and use the existing API");
  });

  it("returns a null command for unknown slash tokens", () => {
    expect(parseSteer("/bogus x").command).toBeNull();
  });
});
