import type { ReactNode } from "react";
import type {
  Contract,
  GateConfig,
  RecoveryOption,
  SteeringTarget,
  WorkItem,
} from "../domain/types";
import type { SlashCommand } from "../domain/slash";
import type { Skin } from "./skin";
import type { PaneLayout } from "../state/usePaneLayout";

/**
 * The skin surface: everything a representation of this machine is given, and
 * everything it is allowed to do.
 *
 * A skin that only wants to repaint answers the token contract and uses the
 * reference view. A skin that wants to *re-represent* — the same lines and
 * gates drawn as a city, a processor die, a room full of avatars — supplies a
 * `view` instead and owns the whole composition. Neither is more privileged
 * than the other, because both get exactly this and nothing else.
 *
 * `state` is deep-frozen before it gets here, and every intent is a request to
 * the authority — there is no local writer, so a view cannot decide that a gate
 * held. A city skin can draw a gate as a collapsing bridge; whether the bridge
 * held is `fcd`'s answer, not the skin's.
 *
 * Be clear about what this is NOT. A view is in-bundle code in the same realm
 * as the shell: it has ambient `fetch` and can import the API client. This
 * interface is a convenience surface, not a sandbox, and the enforcement that
 * matters is server-side. See `docs/SKIN_PROTOCOL.md`. Third-party skins need
 * a real frame boundary before they are safe to load.
 */
export interface CockpitSelection {
  readonly workItemId: string | null;
  readonly nodeId: string | null;
  /** Node whose drilldown is open, if the view has such a concept. */
  readonly openNodeId: string | null;
  readonly steeringTarget: SteeringTarget | null;
  /** Derived for convenience; a view may ignore all of it. */
  readonly item: WorkItem | null;
  readonly gateConfig: GateConfig | null;
  readonly steeringTargets: readonly SteeringTarget[];
}

/**
 * Every action the cockpit can take. A view calls these; it never reaches past
 * them. Adding a capability here is a deliberate widening of what a skin may
 * do, so the list is worth keeping short and readable.
 */
export interface CockpitIntents {
  // ---- selection: local, and safe for a view to drive freely -----------
  selectWorkItem(workItemId: string): void;
  selectNode(nodeId: string): void;
  toggleDrill(nodeId: string): void;
  setSteeringTarget(target: SteeringTarget): void;
  navigate(target: "active" | "questions" | "drift"): void;

  // ---- surfaces the shell owns ----------------------------------------
  // Note what is absent: there is no way to dismiss a published refusal. The
  // shell owns that, because a view that could clear it could hide a failure.
  openSettings(): void;
  openLegend(): void;
  openRoutes(): void;
  setComposerOpen(open: boolean): void;
  openQuestion(questionId: string): void;

  // ---- authority requests: all of these go to the server ---------------
  createWorkItem(prompt: string, contract: Contract): void;
  loadProject(definition: {
    id: string; name: string; local_path: string; github: string; base_branch: string;
  }): Promise<void>;
  selectProject(projectId: string): void;
  steer(command: SlashCommand, text: string, nodeId: string | null): void;
  recover(nodeId: string, option: RecoveryOption): void;
  answerQuestion(value: string | undefined, text: string | undefined): void;
  configureGate(gateId: string, changes: Partial<GateConfig>): void;
  /** Admit a specialist and run the gate. "run" if it has never run, else "retry". */
  runGate(nodeId: string, verb: "run" | "retry"): void;
  reviewImpact(
    classification: "reachable" | "unknown",
    decision: "continue_pinned" | "refresh" | "owner_override",
  ): void;
  driftAction(action: "retry" | "discard"): void;

  // ---- layout, for views that use panes --------------------------------
  resizePane(side: "left" | "right", width: number): void;
  nudgePane(side: "left" | "right", delta: number): void;
  resetPane(side: "left" | "right"): void;
  togglePane(side: "left" | "right"): void;
}

/** What the shell hands any view, reference or otherwise. */
export interface SkinViewProps {
  /** Canonical snapshot. Read-only by construction. */
  state: import("../domain/types").CockpitState;
  connection: "live" | "demo-disconnected";
  selection: CockpitSelection;
  intents: CockpitIntents;
  /** The active skin, for a view that wants its tokens or labels. */
  skin: Skin;
  /** Pane geometry, meaningless to a view that does not use panes. */
  panes: PaneLayout;
  /** The authority's last published refusal, if any. */
  refusal: string | null;
  /** Shell chrome the view decides whether to host. */
  composerOpen: boolean;
  activeQuestionId: string | null;
}

export type SkinView = (props: SkinViewProps) => ReactNode;
