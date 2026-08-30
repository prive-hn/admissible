import type { SkinViewProps } from "../skins/view";
import { CenterStages } from "../components/CenterStages";
import { GateTray } from "../components/GateTray";
import { ImpactReviewTray } from "../components/ImpactReviewTray";
import { RightArtifact } from "../components/RightArtifact";

/**
 * One line at a time, in a single column.
 *
 * This exists to prove the seam is real: it is a different composition of the
 * same snapshot, not a repaint. It drops the panes entirely — no atlas, no
 * side-by-side artifact — and the instrument keeps working, because the shell
 * still owns the rail, the refusals, the steering bar and the way back to
 * settings. A skin that draws this machine as a city or a processor die
 * replaces exactly this much and inherits exactly those guarantees.
 *
 * It is also the quiet answer to "do we need three panes": when you are
 * working one line, you do not.
 */
export function FocusView({ state, selection, intents, skin }: SkinViewProps) {
  const { item, nodeId, openNodeId, workItemId } = selection;
  const artifact = state.artifacts?.find((a) => a.workItemId === workItemId);
  const drift = state.contextAtlas?.drift.find((d) => d.work_item_id === workItemId) ?? null;
  const lines = state.workItems;

  return (
    <div className="focus">
      <nav className="focus__lines" aria-label="Work lines">
        {lines.map((line) => (
          <button
            key={line.id}
            className="focus__line"
            data-status={line.status}
            aria-pressed={line.id === workItemId}
            onClick={() => intents.selectWorkItem(line.id)}
          >
            <span className="focus__line-id">{line.id}</span>
            <span className="focus__line-title">{line.title}</span>
            {line.openQuestionId && <span className="flag flag--question">?</span>}
          </button>
        ))}
        {lines.length === 0 && <span className="hint">No lines yet.</span>}
      </nav>

      <div className="focus__column">
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
          renderGateSlot={(stage) => {
            const config =
              state.gateConfigs?.find(
                (g) => g.work_item_id === item?.id && g.gate_id === stage.name,
              ) ?? null;
            if (!config) return null;
            const envelope = config.attempt_id
              ? state.envelopes?.find((e) => e.attempt_id === config.attempt_id) ?? null
              : null;
            return (
              <GateTray
                config={config}
                envelope={envelope}
                agents={state.agents ?? []}
                models={state.models ?? []}
                onConfigure={(changes) => intents.configureGate(config.gate_id, changes)}
              />
            );
          }}
        />

        {item && (
          <div className="focus__artifact">
            <RightArtifact item={item} artifact={artifact} />
          </div>
        )}
      </div>
    </div>
  );
}
