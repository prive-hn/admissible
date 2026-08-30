/**
 * The terminal may not claim more than the admissibility record does.
 *
 * Four lines, four different truths: sealed-and-admissible, accepted with
 * no seal (layer I, the reason stated), impeached, tainted. The UI's only
 * job is to repeat the server's sentence and tone it honestly — these
 * tests go red if "accepted" is ever rendered as "Sealed" again, or if an
 * impeached line keeps a green terminal.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CenterStages } from "../src/components/CenterStages";
import { makeDemoState } from "../src/domain/demoState";
import type { Admissibility, WorkItem } from "../src/domain/types";

const base = makeDemoState().workItems.find((w) => w.id === "W4")!;

function withAdm(adm: Admissibility | null): WorkItem {
  return { ...base, admissibility: adm };
}

function renderItem(item: WorkItem) {
  return render(
    <CenterStages item={item} selectedNodeId={null} openNodeId={null}
      onSelectNode={() => {}} onToggleDrill={() => {}} onRecover={() => {}} />,
  );
}

const sealed: Admissibility = {
  layer: "IRC", sealed: true, mediated: true, admissible: true, impeached: false, tainted: false,
  failure: null,
  sentence: "Sealed: survived the pinned refuter at measured power 0.8; concordance is (1, 1) — unmeasured at k=1.",
  powerMin: 0.8, k: 1, agreeing: 1,
  residual: [["meets the operator's intent", "check_stage"]],
  trackRecords: null,
};

describe("admissibility terminal", () => {
  it("a sealed line shows the seal, its carried power, and its residual", () => {
    renderItem(withAdm(sealed));
    const terminal = screen.getByTestId("line-terminal");
    expect(terminal).toHaveTextContent("Sealed");
    expect(terminal).toHaveTextContent(/measured power 0.8/);
    expect(terminal).toHaveTextContent("concordance (1, 1)");
    expect(terminal).toHaveTextContent(/^((?!not admissible).)*admissible/);
    expect(terminal).toHaveTextContent("meets the operator's intent — reviewed at the check gate");
    expect(terminal.className).not.toContain("terminal--qualified");
    expect(screen.getByTestId("layer-chip")).toHaveAttribute("data-state", "sealed");
  });

  it("accepted without a seal is layer I with the reason — never 'Sealed'", () => {
    renderItem(withAdm({
      layer: "I", sealed: false, admissible: false, impeached: false, tainted: false,
      failure: "sample refused: bind key mismatch",
      sentence: "Identity gates only: sample refused: bind key mismatch",
    }));
    const terminal = screen.getByTestId("line-terminal");
    expect(terminal).toHaveTextContent("Accepted — layer I");
    expect(terminal).toHaveTextContent("Identity gates only: sample refused: bind key mismatch");
    expect(terminal).not.toHaveTextContent(/^Sealed/);
    expect(terminal.className).toContain("terminal--qualified");
    expect(screen.getByTestId("layer-chip")).toHaveAttribute("data-state", "unsealed-accepted");
  });

  it("an impeached line says so and is not admissible", () => {
    renderItem(withAdm({
      ...sealed, admissible: false, impeached: true,
      sentence: "Sealed, then impeached: a replayed escape stands against a sealed claim.",
    }));
    const terminal = screen.getByTestId("line-terminal");
    expect(terminal).toHaveTextContent("Impeached");
    expect(terminal).toHaveTextContent("not admissible");
    expect(terminal.className).toContain("terminal--qualified");
    expect(screen.getByTestId("layer-chip")).toHaveTextContent("IRC · impeached");
  });

  it("a tainted line says so", () => {
    renderItem(withAdm({
      ...sealed, admissible: false, tainted: true,
      sentence: "Sealed, then tainted: a refuter it relied on was refused after sealing.",
    }));
    expect(screen.getByTestId("line-terminal")).toHaveTextContent("Tainted");
    expect(screen.getByTestId("layer-chip")).toHaveTextContent("IRC · tainted");
  });

  it("a failed label over a sealed record renders the conflict, not 'nothing was written'", () => {
    renderItem({ ...withAdm(sealed), status: "failed" });
    const terminal = screen.getByTestId("line-terminal");
    expect(terminal).not.toHaveTextContent("Nothing was written");
    expect(terminal).toHaveTextContent("record disagrees");
    expect(terminal).toHaveTextContent(/Trust the record/);
  });

  it("a seal with no calibration stamp reads IR, never Sealed", () => {
    renderItem(withAdm({ ...sealed, layer: "IR", mediated: false, admissible: false,
      sentence: "Sealed under scrutiny, but not mediated by the calibration authority: no track-record stamp binds this seal, so it carries layer-R standing only." }));
    const terminal = screen.getByTestId("line-terminal");
    expect(terminal).toHaveTextContent("layer IR, not mediated");
    expect(terminal).not.toHaveTextContent(/^Sealed$/);
    expect(terminal).toHaveTextContent("not mediated by the calibration authority");
    expect(terminal.className).toContain("terminal--qualified");
    expect(screen.getByTestId("layer-chip")).toHaveAttribute("data-state", "unmediated");
  });

  it("a legacy state without the record keeps the honest fallback word: Accepted", () => {
    renderItem(withAdm(null));
    const terminal = screen.getByTestId("line-terminal");
    expect(terminal).toHaveTextContent("Accepted");
    expect(terminal).not.toHaveTextContent("Sealed");
  });
});
