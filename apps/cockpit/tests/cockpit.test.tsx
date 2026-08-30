import { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { makeDemoState } from "../src/domain/demoState";
import { LeftAtlas } from "../src/components/LeftAtlas";
import { CenterStages } from "../src/components/CenterStages";
import { RightArtifact } from "../src/components/RightArtifact";
import { BottomSteer } from "../src/components/BottomSteer";
import { QuestionModal } from "../src/components/QuestionModal";
import { FailureDetailView } from "../src/components/FailureDetailView";

const state = makeDemoState();

function ThreePaneFixture() {
  const [selected, setSelected] = useState("W2");
  const item = state.workItems.find((w) => w.id === selected)!;
  const [node, setNode] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  return (
    <div>
      <LeftAtlas outcome={state.atlas.outcome} capabilities={state.atlas.capabilities}
        selectedWorkItemId={selected} onSelectWorkItem={setSelected} />
      <CenterStages item={item} selectedNodeId={node} openNodeId={open}
        onSelectNode={setNode} onToggleDrill={(id) => setOpen(open === id ? null : id)}
        onRecover={() => {}} />
      <RightArtifact item={item} />
    </div>
  );
}

describe("three-pane cockpit", () => {
  it("keeps project atlas, live work item, and artifact visible together", () => {
    render(<ThreePaneFixture />);
    expect(screen.getByLabelText(/capability and outcome atlas/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/selected work line and its gates/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/artifact and evidence/i)).toBeInTheDocument();
  });

  it("opens exact node evidence without navigating away", async () => {
    const user = userEvent.setup();
    render(<ThreePaneFixture />);
    await user.click(screen.getByText(/check stage broke/i));
    expect(screen.getByText(/what happened/i)).toBeInTheDocument();
    expect(screen.getByText(/what remains safe/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/capability and outcome atlas/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/artifact and evidence/i)).toBeInTheDocument();
  });
});

describe("steering", () => {
  it("offers slash commands and accepts free steering text", async () => {
    const user = userEvent.setup();
    const onSteer = vi.fn();
    render(<BottomSteer node={state.workItems[1].stages[1]} workItemId="W2" onSteer={onSteer} />);
    const input = screen.getByLabelText(/steering input/i);
    await user.type(input, "/");
    expect(screen.getByTestId("slash-suggestion-impact")).toBeInTheDocument();
    await user.clear(input);
    await user.type(input, "Keep the API but redo the interface");
    await user.click(screen.getByRole("button", { name: "Steer" }));
    expect(onSteer).toHaveBeenCalledWith(
      expect.objectContaining({ cmd: "/steer", channel: "steer" }),
      "Keep the API but redo the interface",
      "W2.1",
    );
  });
});

describe("questions and failures", () => {
  it("answers a question in a focused modal", async () => {
    const user = userEvent.setup();
    const onAnswer = vi.fn();
    render(<QuestionModal question={state.questions[0]} onAnswer={onAnswer} onClose={() => {}} />);
    expect(screen.getByRole("dialog", { name: /open question/i })).toHaveAttribute("aria-modal", "false");
    await user.type(screen.getByLabelText(/or answer in your own words/i), "Retry with dave");
    await user.click(screen.getByRole("button", { name: /submit answer/i }));
    expect(onAnswer).toHaveBeenCalledWith(undefined, "Retry with dave");
  });

  it("separates observed, reachable, and unknown impact", () => {
    const failure = state.workItems[1].stages[1].failure!;
    render(<FailureDetailView failure={failure} onRecover={() => {}} />);
    expect(screen.getByText("Observed")).toBeInTheDocument();
    expect(screen.getByText("Reachable")).toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });
});
