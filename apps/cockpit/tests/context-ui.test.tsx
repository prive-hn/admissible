import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ProjectStrip } from "../src/components/ProjectStrip";
import { GateTray } from "../src/components/GateTray";
import { LeftAtlas } from "../src/components/LeftAtlas";
import { BottomSteer } from "../src/components/BottomSteer";
import { CenterStages } from "../src/components/CenterStages";
import { ImpactReviewTray } from "../src/components/ImpactReviewTray";
import { makeDemoState } from "../src/domain/demoState";
import * as client from "../src/api/client";
import type { GateConfig, GateEnvelope, ProjectSummary, SteeringTarget } from "../src/domain/types";

const project: ProjectSummary = {
  id: "fcd", name: "Fail Closed Dispatch", local_path: "/repo",
  github: "prive-hn/admissible", base_branch: "main",
  current_branch: "feat/context", verified: true, project_version: 18,
  memory_version: 12, policy_version: "p4", skin: "instrument",
};

/** A route whose adapter reported every check. Unreported readiness is not
 *  readiness, so a fixture that omits it is asserting the wrong thing. */
const READY = {
  executor_id: "demo", declared_executor_id: "demo", executor_connected: true,
  provider: "demo", model_api_id: "reviewer", installed: true, authenticated: true,
  model_resolves: true, project_access: true, tools_available: true, canary: true,
  receipt_available: true, death_observable: true, ready: true,
};

const config: GateConfig = {
  work_item_id: "W1", gate_id: "review", name: "Independent review",
  agent_id: "reviewer", executor_id: "demo", model_id: "review-model",
  context_mode: "fresh_blind", continuity: "fresh", editable: true,
  attempt_id: null, locked: false,
};

const envelope: GateEnvelope = {
  attempt_id: "W1/review/1/abc", work_item_id: "W1", gate_id: "review",
  attempt_counter: 1, state: "Passed", agent_id: "reviewer", specialist: "reviewer:review",
  executor_id: "demo", model_provider: "demo", model_api_id: "reviewer",
  context_mode: "fresh_blind", project_version: 18, memory_version: 12,
  locked: true, package_status: "ready", receipt_status: "valid",
  steering_sequence_acknowledged: true, executor_reuse_reported: false,
};

describe("project entry and navigation", () => {
  it("gates work behind a verified project and still accepts a hand-typed path", async () => {
    const user = userEvent.setup();
    vi.spyOn(client, "discoverProjects").mockResolvedValue({ roots: [], candidates: [] });
    const onLoad = vi.fn();
    render(<ProjectStrip current={null} projects={[]} counts={{ active: 0, questions: 0, drift: 0 }}
      onLoad={onLoad} onSelect={() => {}} onNavigate={() => {}} />);
    expect(screen.getByText(/load a project to start work/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /open project/i }));
    // Search is the default now; typing a path is the deliberate fallback.
    await user.click(await screen.findByRole("button", { name: /enter a path/i }));
    await user.type(screen.getByLabelText(/local path/i), "/repo");
    await user.type(screen.getByLabelText(/github repository/i), "prive-hn/admissible");
    await user.click(screen.getByRole("button", { name: /verify and load/i }));
    expect(onLoad).toHaveBeenCalledWith(expect.objectContaining({
      local_path: "/repo", github: "prive-hn/admissible", base_branch: "main",
    }));
  });

  it("loads a discovered repository without the operator typing a path", async () => {
    const user = userEvent.setup();
    vi.spyOn(client, "discoverProjects").mockResolvedValue({
      roots: ["/Users/me/repos"],
      candidates: [{
        local_path: "/Users/me/repos/widgets", name: "widgets",
        github: "acme/widgets", base_branch: "main", current_branch: "feat/x",
      }],
    });
    const onLoad = vi.fn();
    render(<ProjectStrip current={null} projects={[]} counts={{ active: 0, questions: 0, drift: 0 }}
      onLoad={onLoad} onSelect={() => {}} onNavigate={() => {}} />);
    await user.click(screen.getByRole("button", { name: /open project/i }));
    await user.type(await screen.findByLabelText(/find a repository/i), "widg");
    await user.click(await screen.findByRole("option", { name: /widgets/i }));
    // The identity comes from the repository's own remote, not from memory.
    expect(onLoad).toHaveBeenCalledWith(expect.objectContaining({
      local_path: "/Users/me/repos/widgets",
      github: "acme/widgets",
      base_branch: "main",
    }));
  });

  it("will not guess an identity for a repository with no origin remote", async () => {
    const user = userEvent.setup();
    vi.spyOn(client, "discoverProjects").mockResolvedValue({
      roots: ["/Users/me/repos"],
      candidates: [{
        local_path: "/Users/me/repos/local-only", name: "local-only",
        github: "", base_branch: "main", current_branch: "main",
      }],
    });
    const onLoad = vi.fn();
    render(<ProjectStrip current={null} projects={[]} counts={{ active: 0, questions: 0, drift: 0 }}
      onLoad={onLoad} onSelect={() => {}} onNavigate={() => {}} />);
    await user.click(screen.getByRole("button", { name: /open project/i }));
    await user.click(await screen.findByRole("option", { name: /local-only/i }));
    expect(onLoad).not.toHaveBeenCalled();
    expect(await screen.findByText(/no origin remote/i)).toBeInTheDocument();
  });

  it("shows pinned P/K and makes question/drift counts navigable", async () => {
    const user = userEvent.setup();
    const onNavigate = vi.fn();
    render(<ProjectStrip current={project} projects={[project]} counts={{ active: 3, questions: 2, drift: 1 }}
      onLoad={() => {}} onSelect={() => {}} onNavigate={onNavigate} />);
    // "P18 · K12" told an operator nothing; the rail spells the versions out.
    expect(screen.getByText(/project 18 · memory 12/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /2 questions/i }));
    await user.click(screen.getByRole("button", { name: /1 drift/i }));
    expect(onNavigate).toHaveBeenNthCalledWith(1, "questions");
    expect(onNavigate).toHaveBeenNthCalledWith(2, "drift");
  });
});

describe("work and gate surfaces", () => {
  it("lists every sibling line under a component instead of selecting only the first", async () => {
    const user = userEvent.setup();
    const state = makeDemoState();
    const cap = state.atlas.capabilities[0];
    cap.components[0].workItemIds = ["W1", "W2", "W3"];
    const onSelect = vi.fn();
    render(<LeftAtlas outcome={state.atlas.outcome} capabilities={[cap]} workItems={[
      ...state.workItems,
      { ...state.workItems[0], id: "W3", title: "Third line" },
    ]} drift={[]} selectedWorkItemId="W1" onSelectWorkItem={onSelect} />);
    expect(screen.getByRole("button", { name: /W1/i })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /W2/i }).length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: /W3/i }));
    expect(onSelect).toHaveBeenCalledWith("W3");
  });

  it("expands capabilities that arrive after the live state loads", () => {
    const state = makeDemoState();
    const { rerender } = render(<LeftAtlas outcome={state.atlas.outcome} capabilities={[]}
      workItems={state.workItems} drift={[]} selectedWorkItemId={null} onSelectWorkItem={() => {}} />);
    rerender(<LeftAtlas outcome={state.atlas.outcome} capabilities={[state.atlas.capabilities[0]]}
      workItems={state.workItems} drift={[]} selectedWorkItemId={null} onSelectWorkItem={() => {}} />);
    expect(screen.getAllByRole("button", { name: /W1/i }).length).toBeGreaterThan(0);
  });

  it("edits inherited gate choices before Admit", async () => {
    const user = userEvent.setup();
    const onConfigure = vi.fn();
    render(<GateTray config={{ ...config, readiness: READY }} envelope={null}
      agents={[{ id: "reviewer", revision: 1, name: "Reviewer", instructions: "Review independently; do not implement", default_model_id: "review-model", tools: [], authority: [] }]}
      models={[
        { id: "review-model", revision: 1, provider: "demo", api_id: "reviewer", display: "Reviewer", context_profile: "", reasoning: "high", readiness: READY },
        { id: "builder-model", revision: 1, provider: "demo", api_id: "builder", display: "Builder", context_profile: "", reasoning: "high", readiness: { ...READY, model_api_id: "builder" } },
      ]} onConfigure={onConfigure} />);
    expect(screen.getByText(/editable before Admit/i)).toBeInTheDocument();
    expect(screen.getByText(/Review independently; do not implement/i)).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText(/exact model/i), "builder-model");
    await user.click(screen.getByRole("button", { name: /save without running/i }));
    expect(onConfigure).toHaveBeenCalledWith(expect.objectContaining({ model_id: "builder-model" }));
  });

  it("shows model readiness and blocks an unavailable route", () => {
    render(<GateTray config={config} envelope={null}
      agents={[]}
      models={[{ id: "review-model", revision: 1, provider: "anthropic", api_id: "claude-review", display: "Review", context_profile: "1m", reasoning: "high",
        readiness: { executor_id: "demo", declared_executor_id: "demo", executor_connected: true, provider: "anthropic", model_api_id: "claude-review", installed: true, authenticated: true, model_resolves: false, project_access: true, tools_available: true, canary: false, receipt_available: true, death_observable: true, ready: false } }]}
      onConfigure={() => {}} />);
    expect(screen.getByText(/route not ready/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /save without running/i })).toBeDisabled();
  });

  it("locks admitted envelope and shows exact provider API identity and receipt", () => {
    render(<GateTray config={{ ...config, editable: false, locked: true, attempt_id: envelope.attempt_id }}
      envelope={envelope} agents={[]} models={[]} onConfigure={() => {}} />);
    expect(screen.getByText(/locked at Admit/i)).toBeInTheDocument();
    expect(screen.getByText("demo / reviewer")).toBeInTheDocument();
    expect(screen.getByText("valid")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /save without running/i })).not.toBeInTheDocument();
  });

  it("shows bounded drift evidence and explicit review actions", async () => {
    const user = userEvent.setup();
    const onReview = vi.fn(); const onAction = vi.fn();
    render(<ImpactReviewTray drift={{ work_item_id: "W2", pinned_head: [18, 12], current_head: [19, 13], status: "needs_review", classification: null, decision: null }}
      onReview={onReview} onAction={onAction} />);
    expect(screen.getByText("Observed")).toBeInTheDocument();
    expect(screen.getByText("Reachable")).toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /continue pinned/i }));
    await user.click(screen.getByRole("button", { name: /refresh.*rebase/i }));
    await user.click(screen.getByRole("button", { name: /discard/i }));
    expect(onReview).toHaveBeenNthCalledWith(1, "reachable", "continue_pinned");
    expect(onReview).toHaveBeenNthCalledWith(2, "reachable", "refresh");
    expect(onAction).toHaveBeenCalledWith("discard");
  });

  // The collapsed gate names the specialist that was admitted, then the model
  // phi binds it to — not an "agent" and a separately chosen model.
  it("shows the specialist, the model it binds and the context mode", () => {
    const item = structuredClone(makeDemoState().workItems[0]);
    item.stages[0].name = "review";
    render(<CenterStages item={item} selectedNodeId={null} openNodeId={null}
      gateConfigs={[config]} models={[{ id: "review-model", revision: 1, provider: "demo", api_id: "reviewer", display: "Reviewer", context_profile: "", reasoning: "high" }]}
      onSelectNode={() => {}} onToggleDrill={() => {}} onRecover={() => {}} />);
    expect(screen.getByText("reviewer:review")).toBeInTheDocument();
    expect(screen.getByText(/demo \/ reviewer/i)).toBeInTheDocument();
    expect(screen.getByText(/fresh_blind/i)).toBeInTheDocument();
  });

  // Corrected. `fcd.core.norm` strips a bracketed context suffix before
  // comparing, so these two are the SAME identity and the gate passes. The
  // previous expectation made the cockpit flag a mismatch on a gate the
  // authority had held, under a tooltip stating the rule it was breaking.
  it("treats a bracketed context suffix as the same model identity", () => {
    const item = structuredClone(makeDemoState().workItems[0]);
    item.stages[0].declaredModel = "demo:reviewer[1m]";
    item.stages[0].executedModel = "demo:reviewer";
    const { container } = render(<CenterStages item={item} selectedNodeId={null} openNodeId={null}
      onSelectNode={() => {}} onToggleDrill={() => {}} onRecover={() => {}} />);
    expect(container.querySelector(".stage-node__models .mismatch")).toBeNull();
    expect(container.querySelector(".stage-node__models .match")).toBeInTheDocument();
  });

  it("still flags a different vendor prefix as a mismatch", () => {
    const item = structuredClone(makeDemoState().workItems[0]);
    item.stages[0].declaredModel = "vendorA:gpt";
    item.stages[0].executedModel = "vendorB:gpt";
    const { container } = render(<CenterStages item={item} selectedNodeId={null} openNodeId={null}
      onSelectNode={() => {}} onToggleDrill={() => {}} onRecover={() => {}} />);
    expect(container.querySelector(".stage-node__models .mismatch")).toBeInTheDocument();
  });
});

describe("multi-scope steering", () => {
  it("shows and changes an explicit project→work→gate→stage→artifact target", async () => {
    const user = userEvent.setup();
    const state = makeDemoState();
    const targets: SteeringTarget[] = [
      { scope: "project", id: "fcd", label: "Project fcd" },
      { scope: "work", id: "W2", label: "Work W2" },
      { scope: "stage", id: "W2.1", label: "Stage Review" },
      { scope: "artifact", id: "W2", label: "Artifact W2" },
    ];
    const onTarget = vi.fn();
    render(<BottomSteer node={state.workItems[1].stages[1]} workItemId="W2"
      target={targets[2]} targets={targets} onTargetChange={onTarget} onSteer={() => {}} />);
    const scope = screen.getByLabelText(/steering scope/i);
    expect(scope).toHaveValue("stage:W2.1");
    await user.selectOptions(scope, "artifact:W2");
    expect(onTarget).toHaveBeenCalledWith(targets[3]);
  });
});
