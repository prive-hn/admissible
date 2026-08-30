import { useEffect, useMemo, useRef, useState } from "react";
import type {
  Contract,
  GateConfig,
  ProjectSettings,
  RecoveryOption,
  SteeringTarget,
  WorkItem,
} from "./domain/types";
import { SLASH_COMMANDS, FREE_STEER, type SlashCommand } from "./domain/slash";
import { useCockpitState } from "./state/useCockpitState";
import {
  actOnWorkItem,
  answerQuestion,
  configureGate,
  createWorkItem,
  defaultSettings,
  loadProject,
  refusalReason,
  saveSettings,
  reviewImpact,
  selectProject,
  steerWorkItem,
} from "./api/client";
import { applySkinTokens, instrumentSkin, type Skin } from "./skins/skin";
import { TopComposer } from "./components/TopComposer";
import { BottomSteer } from "./components/BottomSteer";
import { QuestionModal } from "./components/QuestionModal";
import { ReferenceView } from "./views/ReferenceView";
import type { CockpitIntents, CockpitSelection } from "./skins/view";
import { SettingsModal } from "./components/SettingsModal";
import { ProjectStrip } from "./components/ProjectStrip";
import { LegendPanel } from "./components/LegendPanel";
import { RefusalStrip } from "./components/RefusalStrip";
import { RoutesPanel } from "./components/RoutesPanel";
import { usePaneLayout } from "./state/usePaneLayout";
import {
  applyViewPrefs,
  readViewPrefs,
  writeViewPrefs,
  type ViewPrefs,
} from "./domain/viewPrefs";

export function App() {
  const { state, connected, refresh } = useCockpitState(1000);

  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [openNodeId, setOpenNodeId] = useState<string | null>(null);
  const [activeQuestionId, setActiveQuestionId] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [showLegend, setShowLegend] = useState(false);
  const [showRoutes, setShowRoutes] = useState(false);
  const [composerOpen, setComposerOpen] = useState(false);
  /** The authority's last published refusal. Cleared only by the operator. */
  const [refusal, setRefusal] = useState<string | null>(null);
  const { layout, resize, nudge, reset, toggle } = usePaneLayout();
  const [view, setView] = useState<ViewPrefs>(readViewPrefs);
  const [skin, setSkin] = useState<Skin>(instrumentSkin);
  const [steeringTarget, setSteeringTarget] = useState<SteeringTarget | null>(null);
  const selectedProjectRef = useRef<string | null | undefined>(undefined);
  // Settings are optimistic-local until the server echoes them back.
  const [settingsOverride, setSettingsOverride] = useState<ProjectSettings | null>(null);

  useEffect(() => {
    applySkinTokens(skin);
    applyViewPrefs(view);
  }, [skin, view]);

  useEffect(() => {
    writeViewPrefs(view);
  }, [view]);

  // Opening a line is rare and consequential, so it lives behind a shortcut and
  // a button rather than a text box holding the best real estate on screen.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setComposerOpen((v) => !v);
        return;
      }
      if (e.key === "Escape") {
        setComposerOpen(false);
        setShowLegend(false);
        setShowRoutes(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const settings = settingsOverride ?? (state.currentProject ? state.settings : defaultSettings);

  const specialists = useMemo(() => {
    const s = new Set<string>();
    for (const wi of state.workItems)
      for (const st of wi.stages) (st.allowSet ?? []).forEach((a) => s.add(a));
    return s.size ? [...s].sort() : ["alice", "carol", "dave"];
  }, [state.workItems]);

  // A project switch invalidates selection even when work IDs happen to overlap.
  useEffect(() => {
    const projectId = state.currentProject?.id ?? null;
    if (selectedProjectRef.current === projectId) return;
    selectedProjectRef.current = projectId;
    setSelectedItemId(null);
    setSelectedNodeId(null);
    setOpenNodeId(null);
    setSteeringTarget(null);
  }, [state.currentProject?.id]);

  // Default-select the first non-accepted line so the cockpit is never empty.
  //
  // Only when nothing is selected. It used to also fire whenever the selected
  // id was absent from the snapshot, which clobbered a just-opened line: the
  // commit selects W3 before the refresh carrying W3 has landed, so the effect
  // saw an unknown id and bounced the operator back to the previous line. A
  // project switch nulls the selection explicitly, which is the case this is
  // actually for.
  useEffect(() => {
    if (selectedItemId !== null) return;
    const first =
      state.workItems.find((w) => w.status !== "accepted") ?? state.workItems[0];
    if (first) setSelectedItemId(first.id);
  }, [state.workItems, selectedItemId]);

  const selectedItem: WorkItem | null =
    state.workItems.find((w) => w.id === selectedItemId) ?? null;

  // Land on the gate that needs a decision: the break if there is one, else
  // the first gate still to hold. An operator should never have to hunt for
  // the failure that closed the line.
  useEffect(() => {
    if (!selectedItem) return;
    if (selectedNodeId && selectedItem.stages.some((s) => s.id === selectedNodeId)) return;
    const focus =
      selectedItem.stages.find((s) => s.pc === "Closed" || s.pc === "Stopped") ??
      selectedItem.stages.find((s) => s.pc !== "Passed") ??
      selectedItem.stages[selectedItem.stages.length - 1];
    if (!focus) return;
    setSelectedNodeId(focus.id);
    if (focus.failure) setOpenNodeId(focus.id);
    setSteeringTarget({ scope: "stage", id: focus.id, label: `Stage ${focus.name}` });
  }, [selectedItem, selectedNodeId]);
  const selectedArtifact = state.artifacts?.find((a) => a.workItemId === selectedItemId);
  const selectedNode =
    selectedItem?.stages.find((s) => s.id === selectedNodeId) ?? null;
  const selectedGateConfig: GateConfig | null =
    state.gateConfigs?.find((g) => g.work_item_id === selectedItemId && g.gate_id === selectedNode?.name) ?? null;
  const steeringTargets = useMemo<SteeringTarget[]>(() => {
    const targets: SteeringTarget[] = [];
    if (state.currentProject) targets.push({ scope: "project", id: state.currentProject.id, label: `Project ${state.currentProject.name}` });
    if (selectedItem) targets.push({ scope: "work", id: selectedItem.id, label: `Work ${selectedItem.id}` });
    if (selectedGateConfig) targets.push({ scope: "gate", id: selectedGateConfig.gate_id, label: `Gate ${selectedGateConfig.name}` });
    if (selectedNode) {
      targets.push({ scope: "stage", id: selectedNode.id, label: `Stage ${selectedNode.name}` });
      for (const evidence of selectedNode.evidence ?? [])
        targets.push({ scope: "evidence", id: evidence.id, label: `Evidence ${evidence.id}` });
      if (selectedNode.failure) targets.push({ scope: "failure", id: selectedNode.id, label: `Failure ${selectedNode.id}` });
    }
    if (selectedArtifact) targets.push({ scope: "artifact", id: selectedArtifact.workItemId, label: `Artifact ${selectedArtifact.title}` });
    return targets;
  }, [state.currentProject, selectedItem, selectedGateConfig, selectedNode, selectedArtifact]);

  useEffect(() => {
    if (steeringTarget && steeringTargets.some((t) => t.scope === steeringTarget.scope && t.id === steeringTarget.id)) return;
    setSteeringTarget(steeringTargets.find((t) => t.scope === "stage") ?? steeringTargets.find((t) => t.scope === "work") ?? steeringTargets[0] ?? null);
  }, [steeringTargets, steeringTarget]);

  const connection = connected ? state.connection ?? "live" : "demo-disconnected";

  // ---- intent handlers (never mutate state locally) ------------------
  const afterIntent = () => {
    setRefusal(null);
    refresh();
  };
  const onRefused = (error: unknown) => setRefusal(refusalReason(error));

  const handleCreate = async (prompt: string, contract: Contract) => {
    try {
      const { id } = await createWorkItem({ prompt, contract });
      // Land on the line that was just opened. Staying put made a successful
      // commit look like nothing had happened.
      if (id) {
        setSelectedItemId(id);
        setSelectedNodeId(null);
        setOpenNodeId(null);
      }
      afterIntent();
    } catch (error) {
      onRefused(error);
    }
  };

  const handleSteer = async (
    command: SlashCommand,
    text: string,
    nodeId: string | null,
  ) => {
    if (!selectedItem) return;
    // Never trust the caller's object: a view can construct one. Resolve the
    // verb against the fixed set so a forged {cmd:"/discard", channel:"action"}
    // cannot turn an inquiry into a state change.
    const verb =
      SLASH_COMMANDS.find((c) => c.cmd === command.cmd) ??
      (command.cmd === FREE_STEER.cmd ? FREE_STEER : null);
    if (!verb) return;
    command = verb;
    // Inquiry commands open the local drilldown immediately; state intents
    // route to /action. Both also notify the server so it can narrate.
    if (command.channel === "steer") {
      if (nodeId) {
        setSelectedNodeId(nodeId);
        setOpenNodeId(nodeId);
      }
      try {
        await steerWorkItem(selectedItem.id, {
          nodeId: steeringTarget?.id ?? nodeId ?? undefined,
          scope: steeringTarget?.scope ?? "stage",
          command: command.cmd.slice(1),
          text,
        });
        afterIntent();
      } catch (error) {
        onRefused(error);
      }
      return;
    }
    if (command.cmd === "/pause") {
      try {
        await actOnWorkItem(selectedItem.id, { action: "pause", nodeId: nodeId ?? undefined });
        afterIntent();
      } catch (error) {
        onRefused(error);
      }
      return;
    }
    try {
      await actOnWorkItem(selectedItem.id, {
        action: command.cmd.slice(1),
        nodeId: nodeId ?? undefined,
      });
      afterIntent();
    } catch (error) {
      onRefused(error);
    }
  };

  const handleRecover = async (nodeId: string, option: RecoveryOption) => {
    if (!selectedItem) return;
    if (option.action === "pause") {
      try {
        await actOnWorkItem(selectedItem.id, { action: "pause", nodeId });
        afterIntent();
      } catch (error) {
        onRefused(error);
      }
      return;
    }
    try {
      await actOnWorkItem(selectedItem.id, {
        action: option.action,
        nodeId,
        specialist: option.specialist,
      });
      afterIntent();
    } catch (error) {
      onRefused(error);
    }
  };

  const handleAnswer = async (value: string | undefined, text: string | undefined) => {
    if (!activeQuestionId) return;
    try {
      await answerQuestion(activeQuestionId, { value, text });
      afterIntent();
      setActiveQuestionId(null);
    } catch (error) {
      onRefused(error);
    }
  };

  // Verification failures belong next to the fields that caused them, so this
  // rethrows for the loader to render inline as well as publishing it.
  const handleLoadProject = async (definition: { id: string; name: string; local_path: string; github: string; base_branch: string }) => {
    try {
      await loadProject(definition);
      setSelectedItemId(null);
      afterIntent();
    } catch (error) {
      onRefused(error);
      throw error;
    }
  };
  const handleSelectProject = async (id: string) => {
    try { await selectProject(id); setSelectedItemId(null); setSelectedNodeId(null); afterIntent(); }
    catch (error) { onRefused(error); }
  };
  const handleNavigate = (target: "active" | "questions" | "drift") => {
    if (target === "questions") {
      const q = state.questions[0];
      if (q) { setSelectedItemId(q.workItemId); setSelectedNodeId(q.stageId ?? null); setActiveQuestionId(q.id); }
      return;
    }
    if (target === "drift") {
      const d = state.contextAtlas?.drift.find((x) => x.status === "needs_review") ?? state.contextAtlas?.drift[0];
      if (d) { setSelectedItemId(d.work_item_id); setSelectedNodeId(null); }
      return;
    }
    const active = state.workItems.find((w) => w.status === "open");
    if (active) setSelectedItemId(active.id);
  };
  const handleRunGate = async (nodeId: string, verb: "run" | "retry") => {
    if (!selectedItem) return;
    try {
      await actOnWorkItem(selectedItem.id, { action: verb, nodeId });
      afterIntent();
    } catch (error) {
      onRefused(error);
    }
  };
  const handleConfigureGate = async (gateId: string, changes: Partial<Pick<GateConfig, "agent_id" | "executor_id" | "model_id" | "context_mode" | "continuity">>) => {
    if (!selectedItem) return;
    try { await configureGate(selectedItem.id, gateId, changes); afterIntent(); }
    catch (error) { onRefused(error); }
  };
  const handleImpactReview = async (classification: "reachable" | "unknown", decision: "continue_pinned" | "refresh" | "owner_override") => {
    if (!selectedItem) return;
    try { await reviewImpact(selectedItem.id, classification, decision); afterIntent(); }
    catch (error) { onRefused(error); }
  };
  const handleDriftAction = async (action: "retry" | "discard") => {
    if (!selectedItem) return;
    try { await actOnWorkItem(selectedItem.id, { action, nodeId: selectedNode?.id }); afterIntent(); }
    catch (error) { onRefused(error); }
  };

  // A live question badge: if the selected item has an open question, offer it.
  const openQuestion =
    state.questions.find((q) => q.id === activeQuestionId) ??
    (selectedItem?.openQuestionId
      ? state.questions.find((q) => q.id === selectedItem.openQuestionId)
      : undefined);

  // ---- the skin surface ------------------------------------------------
  // Everything a representation is given, and everything it may do. A skin
  // that supplies its own view gets exactly this and nothing else; there is no
  // local writer here, so however it draws the machine it still cannot Admit,
  // Bind, Pass or Accept.
  const selection: CockpitSelection = {
    workItemId: selectedItemId,
    nodeId: selectedNodeId,
    openNodeId,
    steeringTarget,
    item: selectedItem,
    gateConfig: selectedGateConfig,
    steeringTargets,
  };

  const intents: CockpitIntents = {
    selectWorkItem: (id) => {
      setSelectedItemId(id);
      setSelectedNodeId(null);
      setOpenNodeId(null);
      setSteeringTarget({ scope: "work", id, label: `Work ${id}` });
    },
    selectNode: (id) => {
      setSelectedNodeId(id);
      const stage = selectedItem?.stages.find((s) => s.id === id);
      setSteeringTarget({ scope: "stage", id, label: `Stage ${stage?.name ?? id}` });
    },
    toggleDrill: (id) => setOpenNodeId((cur) => (cur === id ? null : id)),
    setSteeringTarget,
    navigate: handleNavigate,
    openSettings: () => setShowSettings(true),
    openLegend: () => setShowLegend(true),
    openRoutes: () => setShowRoutes(true),
    setComposerOpen,
    openQuestion: setActiveQuestionId,
    createWorkItem: handleCreate,
    loadProject: handleLoadProject,
    selectProject: handleSelectProject,
    steer: handleSteer,
    recover: handleRecover,
    answerQuestion: handleAnswer,
    configureGate: handleConfigureGate,
    runGate: handleRunGate,
    reviewImpact: handleImpactReview,
    driftAction: handleDriftAction,
    resizePane: resize,
    nudgePane: nudge,
    resetPane: reset,
    togglePane: toggle,
  };

  // A skin may replace the main region entirely; the shell keeps the rail, the
  // refusal strip, the steering bar and the way back to settings, so no skin
  // can strand an operator or hide a published failure.
  const View = skin.view ?? ReferenceView;

  return (
    <div className="cockpit">
      {/* The rail's controls precede the work on every tab traversal, so
          reaching a gate by keyboard meant passing all of them first. */}
      <a className="skip-link" href="#cockpit-main">Skip to the work</a>
      <header className="rail">
        <ProjectStrip
          current={state.currentProject ?? null}
          projects={state.projects ?? []}
          counts={{ active: state.atlas.outcome.active, questions: state.atlas.outcome.question,
                    drift: state.contextAtlas?.counts.drift ?? 0 }}
          onLoad={handleLoadProject}
          onSelect={handleSelectProject}
          onNavigate={handleNavigate}
        />
        <TopComposer
          settings={settings}
          specialists={specialists}
          connection={connection}
          projectLoaded={Boolean(state.currentProject)}
          open={composerOpen}
          onOpenChange={setComposerOpen}
          onOpenSettings={() => setShowSettings(true)}
          onOpenLegend={() => setShowLegend(true)}
          onOpenRoutes={() => setShowRoutes(true)}
          onSubmit={handleCreate}
        />
      </header>

      <main id="cockpit-main" className="cockpit__main" tabIndex={-1}>
      <View
        state={state}
        connection={connection}
        selection={selection}
        intents={intents}
        skin={skin}
        panes={layout}
        refusal={refusal}
        composerOpen={composerOpen}
        activeQuestionId={activeQuestionId}
      />
      </main>

      {refusal && <RefusalStrip reason={refusal} onDismiss={() => setRefusal(null)} />}

      <BottomSteer
        node={selectedNode}
        workItemId={selectedItem?.id ?? null}
        target={steeringTarget}
        targets={steeringTargets}
        onTargetChange={setSteeringTarget}
        onSteer={handleSteer}
      />

      {openQuestion && activeQuestionId && (
        <QuestionModal
          question={openQuestion}
          onAnswer={handleAnswer}
          onClose={() => setActiveQuestionId(null)}
        />
      )}

      {showLegend && <LegendPanel onClose={() => setShowLegend(false)} />}

      {showRoutes && (
        <RoutesPanel
          models={state.models ?? []}
          agents={state.agents ?? []}
          gates={state.gatePolicies ?? []}
          adapter={state.adapter}
          onClose={() => setShowRoutes(false)}
        />
      )}

      {showSettings && (
        <SettingsModal
          settings={settings}
          view={view}
          onChangeView={setView}
          activeSkinId={skin.id}
          onChangeSkin={setSkin}
          onSave={(next) => {
            // Optimistic locally, then sent to the authority — these choices
            // govern what intake will refuse, so they have to be known there.
            setSettingsOverride(next);
            setShowSettings(false);
            void saveSettings({
              acceptanceMode: next.acceptanceMode,
              intakeMode: next.intakeMode,
              repairMode: next.repairMode,
            })
              .then(() => setSettingsOverride(null))
              .catch((error) => {
                setSettingsOverride(null);
                onRefused(error);
              });
          }}
          onClose={() => setShowSettings(false)}
        />
      )}
    </div>
  );
}
