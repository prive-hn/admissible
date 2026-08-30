/**
 * Properties the instrument must not lose to a later restyle.
 *
 * These are honesty tests, not pixel tests: what a fail-closed break does to
 * the gates under it, whether the approved contract is the enforced one,
 * whether a synthesized artifact can pass for a real one, and whether the
 * paper's vocabulary is readable without the paper.
 */
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { CenterStages } from "../src/components/CenterStages";
import { RightArtifact } from "../src/components/RightArtifact";
import { LegendPanel } from "../src/components/LegendPanel";
import { EvidenceList } from "../src/components/EvidenceList";
import { TopComposer } from "../src/components/TopComposer";
import { makeDemoState } from "../src/domain/demoState";
import { defaultSettings } from "../src/api/client";
import type { Contract, WorkItem } from "../src/domain/types";

vi.mock("../src/api/client", async () => {
  const actual = await vi.importActual<typeof import("../src/api/client")>("../src/api/client");
  return { ...actual, compileWorkItemContract: vi.fn(async () => { throw new Error("no stub"); }) };
});
const { compileWorkItemContract } = await import("../src/api/client");

/** A line that broke at its first gate, with a second gate that never ran. */
function brokenLine(): WorkItem {
  const item = structuredClone(makeDemoState().workItems[1]);
  item.status = "failed";
  item.stages[0] = { ...item.stages[0], pc: "Closed", sentence: "Stage sheared." };
  item.stages[1] = { ...item.stages[1], pc: "Open", failure: null, sentence: "Waiting to start." };
  return item;
}

const noop = () => {};

describe("the load path", () => {
  it("marks gates under a break as never run, not as queued", () => {
    render(
      <CenterStages
        item={brokenLine()}
        selectedNodeId={null}
        openNodeId={null}
        onSelectNode={noop}
        onToggleDrill={noop}
        onRecover={noop}
      />,
    );
    expect(screen.getByText("not reached")).toBeInTheDocument();
    expect(
      screen.getByText(/closed at an earlier gate, so this one never ran/i),
    ).toBeInTheDocument();
  });

  it("terminates a finished line with what actually happened to it", () => {
    const failed = brokenLine();
    render(
      <CenterStages item={failed} selectedNodeId={null} openNodeId={null}
        onSelectNode={noop} onToggleDrill={noop} onRecover={noop} />,
    );
    expect(screen.getByText("Closed")).toBeInTheDocument();
    expect(screen.getByText(/Nothing was written to the store/i)).toBeInTheDocument();
  });

  it("keeps the drilldown's own controls outside the gate's button", async () => {
    const user = userEvent.setup();
    const item = structuredClone(makeDemoState().workItems[1]);
    render(
      <CenterStages item={item} selectedNodeId="W2.1" openNodeId="W2.1"
        onSelectNode={noop} onToggleDrill={noop} onRecover={noop} />,
    );
    const summary = screen.getAllByRole("button", { name: /check/i })[0];
    expect(within(summary).queryByRole("button")).toBeNull();
    await user.click(summary); // still the control for the card
  });
});

describe("the visible contract", () => {
  const authoritative: Contract = {
    cls: "feature",
    title: "Add a CSV export",
    summary: "Add a CSV export",
    policyVersion: "cockpit-v2",
    requiredStages: [
      { kind: "write", name: "implement" },
      { kind: "check", name: "review" },
    ],
    allowSet: ["builder:implement", "reviewer:review"],
    acceptanceMode: "strict-match",
    dependsOn: [],
  };

  function composer(onSubmit = vi.fn()) {
    render(
      <TopComposer settings={defaultSettings} specialists={["builder:implement"]}
        connection="live" projectLoaded open onOpenChange={noop}
        onOpenSettings={noop} onOpenLegend={noop} onOpenRoutes={noop} onSubmit={onSubmit} />,
    );
    return onSubmit;
  }

  it("shows the terms the authority will enforce", async () => {
    const user = userEvent.setup();
    vi.mocked(compileWorkItemContract).mockResolvedValue(authoritative);
    composer();
    await user.type(screen.getByLabelText(/prompt composer/i), "Add a CSV export");
    await user.click(screen.getByRole("button", { name: /compile contract/i }));
    const card = await screen.findByTestId("contract-card");
    expect(within(card).getByText("class feature")).toBeInTheDocument();
    expect(within(card).getByText("write·implement")).toBeInTheDocument();
    expect(within(card).getByText(/these are the terms it will enforce/i)).toBeInTheDocument();
  });

  it("refuses to open a line on a shape compiled without the authority", async () => {
    const user = userEvent.setup();
    vi.mocked(compileWorkItemContract).mockImplementation(async () => {
      throw new Error("offline");
    });
    const onSubmit = composer();
    await user.type(screen.getByLabelText(/prompt composer/i), "Add a CSV export");
    await user.click(screen.getByRole("button", { name: /compile contract/i }));
    const card = await screen.findByTestId("contract-card");
    expect(within(card).getByText(/offline shape/i)).toBeInTheDocument();
    expect(within(card).getByRole("button", { name: /open line under this contract/i })).toBeDisabled();
    expect(onSubmit).not.toHaveBeenCalled();
  });
});

describe("artifact honesty", () => {
  it("labels a synthesized artifact as a fallback", () => {
    const item = makeDemoState().workItems[1];
    render(<RightArtifact item={item} />);
    expect(screen.getByText(/deterministic fallback/i)).toBeInTheDocument();
  });

  it("does not show a candidate in place of an accepted artifact", async () => {
    const user = userEvent.setup();
    const item = { ...makeDemoState().workItems[1], status: "failed" as const };
    render(<RightArtifact item={item} />);
    await user.click(screen.getByRole("button", { name: "Accepted" }));
    expect(screen.getByText(/not in the store/i)).toBeInTheDocument();
    expect(screen.queryByTestId("artifact-frame")).toBeNull();
  });
});

describe("vocabulary", () => {
  it("gives every machine term a plain reading and its formal source", async () => {
    const user = userEvent.setup();
    render(<LegendPanel onClose={noop} />);
    expect(screen.getByText(/the model that ran was not the model that was bound/i)).toBeInTheDocument();
    await user.type(screen.getByLabelText(/search the legend/i), "reachable");
    expect(screen.getByText(/it has not been seen/i)).toBeInTheDocument();
    expect(screen.queryByText(/the line starts/i)).toBeNull();
  });
});

describe("evidence", () => {
  it("keeps raw payloads folded until asked for", async () => {
    const user = userEvent.setup();
    render(
      <EvidenceList
        items={[{ id: "E1", kind: "decide", label: "Fail closed and published · F1",
                  detail: '{"fault":"F1"}', journalIndex: 14 }]}
        empty="none"
      />,
    );
    expect(screen.queryByText(/"fault"/)).toBeNull();
    await user.click(screen.getByRole("button", { name: /payload/i }));
    expect(screen.getByText(/"fault": "F1"/)).toBeInTheDocument();
  });
});
