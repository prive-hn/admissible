import type { StageNode, WorkItem } from "../domain/types";

/**
 * Build a real, self-contained HTML artifact for the right pane. The cockpit
 * renders whatever the server ships as the artifact; when none is provided we
 * synthesize an honest, evidence-backed document from the work item's own
 * stages so the pane always shows a concrete artifact rather than a stub.
 *
 * The three views map to the fail-closed lifecycle:
 *   - candidate: the in-flight body as currently bound (not yet accepted)
 *   - accepted:  the frozen artifact, only present once in the store
 *   - before-after: candidate vs. accepted side by side
 */
export type ArtifactView = "candidate" | "accepted" | "before-after";

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] as string,
  );
}

function stageBlock(stage: StageNode, showExec: boolean): string {
  const decl = stage.declaredModel ?? "—";
  const exec = showExec ? stage.executedModel ?? "(not observed)" : "(sealed)";
  const tone =
    stage.pc === "Passed" ? "#1f4d2a" : stage.pc === "Closed" ? "#7a2620" : "#3a3f2a";
  return `
    <section class="stage" style="border-left-color:${tone}">
      <h3>${esc(stage.kind)} · ${esc(stage.name)} <em>${esc(stage.pc)}</em></h3>
      <p>${esc(stage.sentence)}</p>
      <dl>
        <div><dt>declared</dt><dd>${esc(decl)}</dd></div>
        <div><dt>executed</dt><dd>${esc(exec)}</dd></div>
        <div><dt>specialist</dt><dd>${esc(stage.specialist ?? "—")}</dd></div>
      </dl>
    </section>`;
}

const BASE_CSS = `
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font: 13px/1.5 -apple-system, system-ui, sans-serif; margin: 0; padding: 18px; color: #1c2128; background: #fbfbfa; }
  header { border-bottom: 1px solid #e2e2df; padding-bottom: 10px; margin-bottom: 14px; }
  h1 { font-size: 16px; margin: 0 0 2px; }
  .sub { color: #6b7280; font-size: 12px; }
  .stage { border: 1px solid #e2e2df; border-left: 3px solid #999; border-radius: 6px; padding: 10px 12px; margin-bottom: 10px; background: #fff; }
  .stage h3 { margin: 0 0 4px; font-size: 13px; }
  .stage h3 em { font-style: normal; font-family: ui-monospace, monospace; font-size: 11px; color: #6b7280; margin-left: 6px; }
  .stage p { margin: 0 0 8px; color: #374151; }
  dl { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; margin: 0; }
  dt { font-size: 10px; text-transform: uppercase; letter-spacing: .05em; color: #9ca3af; }
  dd { margin: 0; font-family: ui-monospace, monospace; font-size: 11px; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .col h2 { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: #6b7280; }
  .seal { display: inline-block; font: 700 11px ui-monospace, monospace; color: #1f4d2a; border: 1px solid #1f4d2a; border-radius: 4px; padding: 1px 6px; }
  .draft { display: inline-block; font: 700 11px ui-monospace, monospace; color: #92600f; border: 1px solid #c4a35a; border-radius: 4px; padding: 1px 6px; }
`;

function doc(title: string, sub: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><style>${BASE_CSS}</style></head>
  <body><header><h1>${esc(title)}</h1><div class="sub">${sub}</div></header>${body}</body></html>`;
}

export function renderArtifact(item: WorkItem | undefined, view: ArtifactView): string {
  if (!item) {
    return doc("No work item selected", "Select a live line to render its artifact.", "");
  }
  const accepted = item.status === "accepted";
  const candidateBody = item.stages.map((s) => stageBlock(s, true)).join("");
  const acceptedBody = accepted
    ? item.stages.map((s) => stageBlock(s, true)).join("")
    : `<p class="sub">This line is not in the store. Accept is the only writer; nothing is sealed until every required stage holds.</p>`;

  if (view === "candidate") {
    return doc(
      item.title,
      `<span class="draft">CANDIDATE</span> class ${esc(item.cls)} · policy ${esc(item.policyVersion)}`,
      candidateBody,
    );
  }
  if (view === "accepted") {
    return doc(
      item.title,
      accepted
        ? `<span class="seal">ACCEPTED ARTIFACT</span> stored via Accept only`
        : `<span class="draft">NOT ACCEPTED</span>`,
      acceptedBody,
    );
  }
  return doc(
    item.title,
    `before / after — candidate vs. accepted`,
    `<div class="cols">
      <div class="col"><h2>Before · candidate</h2>${candidateBody}</div>
      <div class="col"><h2>After · accepted</h2>${acceptedBody}</div>
    </div>`,
  );
}
