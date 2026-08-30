import type { SkinViewProps } from "../skins/view";
import { LeftAtlas } from "../components/LeftAtlas";
import { CenterStages } from "../components/CenterStages";
import { RightArtifact } from "../components/RightArtifact";
import { GateTray } from "../components/GateTray";
import { ImpactReviewTray } from "../components/ImpactReviewTray";
import { PaneResizer } from "../components/PaneResizer";
import { PANE_LIMITS } from "../state/usePaneLayout";

/**
 * The reference representation: atlas, live line, artifact, side by side.
 *
 * This is one view among possible many, not the shape of the product. It is
 * the default because the three panes are the product's own claim — capability
 * context, the line taking form, and the result an owner can evaluate, all
 * reachable without navigating away — and because it is the one an operator
 * can read without learning a metaphor first.
 *
 * Its widths belong to the operator: the dividers are real controls, the
 * side panes collapse, and both survive a reload.
 */
export function ReferenceView({ state, selection, intents, skin, panes }: SkinViewProps) {
  const { item, nodeId, openNodeId, workItemId } = selection;
  const artifact = state.artifacts?.find((a) => a.workItemId === workItemId);
  const drift = state.contextAtlas?.drift.find((d) => d.work_item_id === workItemId) ?? null;

  return (
    <div
      className="panes"
      style={{
        "--pane-left": panes.leftCollapsed ? "0px" : `${panes.left}px`,
        "--pane-right": panes.rightCollapsed ? "0px" : `${panes.right}px`,
      } as React.CSSProperties}
      data-left-collapsed={panes.leftCollapsed || undefined}
      data-right-collapsed={panes.rightCollapsed || undefined}
    >
      {panes.leftCollapsed ? (
        <button
          className="pane-stub"
          onClick={() => intents.togglePane("left")}
          aria-expanded={false}
          title="Show the atlas"
        >
          Atlas
        </button>
      ) : (
        <LeftAtlas
          outcome={state.atlas.outcome}
          capabilities={state.atlas.capabilities}
          workItems={state.workItems}
          drift={state.contextAtlas?.drift ?? []}
          selectedWorkItemId={workItemId}
          onSelectWorkItem={intents.selectWorkItem}
          onCollapse={() => intents.togglePane("left")}
        />
      )}

      {!panes.leftCollapsed && (
        <PaneResizer
          side="left"
          width={panes.left}
          min={PANE_LIMITS.left.min}
          max={PANE_LIMITS.left.max}
          label="Resize the atlas"
          onResize={(w) => intents.resizePane("left", w)}
          onNudge={(d) => intents.nudgePane("left", d)}
          onReset={() => intents.resetPane("left")}
        />
      )}

      <CenterStages
        item={item}
        selectedNodeId={nodeId}
        openNodeId={openNodeId}
        skin={skin}
        onSelectNode={intents.selectNode}
        onToggleDrill={intents.toggleDrill}
        onRecover={intents.recover}
        gateConfigs={state.gateConfigs?.filter((g) => g.work_item_id === item?.id) ?? []}
        models={state.models ?? []}
        onAnswerQuestion={
          item?.openQuestionId ? () => intents.openQuestion(item.openQuestionId!) : undefined
        }
        banner={
          drift ? (
            <ImpactReviewTray
              drift={drift}
              onReview={intents.reviewImpact}
              onAction={intents.driftAction}
            />
          ) : null
        }
        // The envelope belongs to the gate it configures, so it renders under
        // that gate rather than in a separate tray fighting for the same
        // scroll space.
        renderGateSlot={(stage) => {
          const config =
            state.gateConfigs?.find(
              (g) => g.work_item_id === item?.id && g.gate_id === stage.name,
            ) ?? null;
          if (!config) return null;
          const envelope = config.attempt_id
            ? state.envelopes?.find((e) => e.attempt_id === config.attempt_id) ?? null
            : null;
          // Holding the last gate that has not yet held accepts the line, which
          // writes the store. The control has to say so before it is pressed.
          const sealsOnHold =
            (item?.stages ?? []).filter((g) => g.pc !== "Passed" && g.id !== stage.id).length === 0;
          return (
            <GateTray
              config={config}
              envelope={envelope}
              stage={stage}
              sealsOnHold={sealsOnHold}
              agents={state.agents ?? []}
              models={state.models ?? []}
              onConfigure={(changes) => intents.configureGate(config.gate_id, changes)}
              onRun={(verb) => intents.runGate(stage.id, verb)}
            />
          );
        }}
      />

      {!panes.rightCollapsed && (
        <PaneResizer
          side="right"
          width={panes.right}
          min={PANE_LIMITS.right.min}
          max={PANE_LIMITS.right.max}
          label="Resize the artifact pane"
          onResize={(w) => intents.resizePane("right", w)}
          onNudge={(d) => intents.nudgePane("right", d)}
          onReset={() => intents.resetPane("right")}
        />
      )}

      {panes.rightCollapsed ? (
        <button
          className="pane-stub"
          onClick={() => intents.togglePane("right")}
          aria-expanded={false}
          title="Show the artifact"
        >
          Artifact
        </button>
      ) : (
        <RightArtifact
          item={item}
          artifact={artifact}
          onCollapse={() => intents.togglePane("right")}
        />
      )}
    </div>
  );
}
