import type { Contract, ProjectSettings } from "../domain/types";

/**
 * Offline fallback for the contract preview.
 *
 * The authority compiles the real contract (`POST /api/work-items/compile`)
 * and that is what the composer shows whenever the server is reachable. This
 * local version exists only for the labeled demo/disconnected surface, and the
 * card that renders it says so — it is a shape, not a guarantee.
 */

const SLASH = /^\//;

interface CompileContext {
  settings: ProjectSettings;
  /** Known specialists available to admit from (from policy φ domain). */
  specialists?: string[];
}

const DEFAULT_SPECIALISTS = ["alice", "carol", "dave"];

/**
 * The demo policy declares a single class. Branching on the prompt here would
 * only invent a distinction the machine does not make.
 */
const FALLBACK_CLASS = "impl";

function titleFrom(prompt: string): string {
  const firstLine = prompt.trim().split("\n")[0] ?? "";
  const clean = firstLine.replace(SLASH, "").trim();
  if (clean.length <= 72) return clean || "Untitled work item";
  return clean.slice(0, 69).trimEnd() + "…";
}

/**
 * Detect dependency ids referenced as `depends:W1,W2` or `#W1` tokens so a
 * new line can be stacked only on accepted artifacts (DAG gate).
 */
function extractDeps(prompt: string): string[] {
  const deps = new Set<string>();
  const explicit = prompt.match(/depends?:\s*([\w,\s]+)/i);
  if (explicit) {
    explicit[1]
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .forEach((d) => deps.add(d));
  }
  for (const m of prompt.matchAll(/#(\w+)/g)) deps.add(m[1]);
  return [...deps];
}

export function compileContract(prompt: string, ctx: CompileContext): Contract {
  const cls = FALLBACK_CLASS;
  const specialists = ctx.specialists?.length ? ctx.specialists : DEFAULT_SPECIALISTS;
  // Every impl line requires a write that holds then an independent check
  // (dual control): the check allow set excludes the writer at admit time.
  const requiredStages: Contract["requiredStages"] = [
    { kind: "write", name: "w1" },
    { kind: "check", name: "c1" },
  ];
  return {
    cls,
    title: titleFrom(prompt),
    summary: prompt.trim().slice(0, 240),
    policyVersion: ctx.settings.versionLabel.includes("v")
      ? ctx.settings.versionLabel.replace(/^settings\s*/, "")
      : "v0",
    requiredStages,
    allowSet: specialists,
    acceptanceMode: ctx.settings.acceptanceMode,
    dependsOn: extractDeps(prompt),
  };
}
