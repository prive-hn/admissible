import { useDialog } from "../domain/useDialog";
import { useState } from "react";
import type { ProjectSettings } from "../domain/types";
import { skins, type Skin } from "../skins/skin";
import { DENSITIES, TEXT_SIZES, type ViewPrefs } from "../domain/viewPrefs";

interface Props {
  settings: ProjectSettings;
  view: ViewPrefs;
  onChangeView: (view: ViewPrefs) => void;
  activeSkinId: string;
  onChangeSkin: (skin: Skin) => void;
  onSave: (next: ProjectSettings) => void;
  onClose: () => void;
}

/** Each mode gets the sentence an operator needs, not just its slug. */
const ACCEPTANCE: { value: ProjectSettings["acceptanceMode"]; note: string }[] = [
  { value: "strict-match", note: "A gate holds only when the model that ran matches the model that was bound." },
  { value: "quorum", note: "Acceptance needs more than one holding check gate." },
  { value: "manual-final", note: "Every gate holds, then a person accepts." },
];
const INTAKE: { value: ProjectSettings["intakeMode"]; note: string }[] = [
  { value: "class-inferred", note: "The class is read from the prompt." },
  { value: "explicit-class", note: "You name the class before a line opens." },
  { value: "guarded", note: "An unclear class blocks intake instead of guessing." },
];
const REPAIR: { value: ProjectSettings["repairMode"]; note: string }[] = [
  { value: "retry-in-allow-set", note: "A break offers another allowed specialist for the same gate." },
  { value: "ask-first", note: "A break asks you before anything is retried." },
  { value: "stop-on-break", note: "A break ends the line. Nothing retries." },
];

/**
 * Project settings. Saving bumps a versioned label — settings are an identity,
 * not a mutable slot, mirroring the machine's policy-version discipline — and a
 * change only ever affects lines opened after it.
 */
export function SettingsModal({
  settings,
  view,
  onChangeView,
  activeSkinId,
  onChangeSkin,
  onSave,
  onClose,
}: Props) {
  const dialog = useDialog<HTMLDivElement>(onClose);
  const [draft, setDraft] = useState<ProjectSettings>(settings);

  const nextVersionLabel = () => {
    const m = settings.versionLabel.match(/v(\d+)/);
    const n = m ? parseInt(m[1], 10) + 1 : 1;
    return `settings v${n}`;
  };

  const changed =
    draft.acceptanceMode !== settings.acceptanceMode ||
    draft.intakeMode !== settings.intakeMode ||
    draft.repairMode !== settings.repairMode;

  const save = () => {
    onSave({
      ...draft,
      versionLabel: changed ? nextVersionLabel() : settings.versionLabel,
    });
  };

  const note = <T extends string>(rows: { value: T; note: string }[], value: T) =>
    rows.find((r) => r.value === value)?.note;

  return (
    <div className="modal-scrim" onClick={onClose}>
      <div
        ref={dialog}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label="Project settings"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal__head">
          <div>
            <span className="modal__title">Project settings</span>
            <p className="modal__lead">
              A change here applies to lines opened afterwards. Lines already in flight finish
              under the settings they pinned.
            </p>
          </div>
          <span className="chip" data-testid="settings-version">{settings.versionLabel}</span>
        </div>

        <div className="modal__body">
          <div className="field">
            <label className="field__label" htmlFor="acceptance">Acceptance mode</label>
            <select
              id="acceptance"
              value={draft.acceptanceMode}
              onChange={(e) =>
                setDraft({ ...draft, acceptanceMode: e.target.value as ProjectSettings["acceptanceMode"] })
              }
            >
              {ACCEPTANCE.map((m) => <option key={m.value} value={m.value}>{m.value}</option>)}
            </select>
            <p className="field__note">{note(ACCEPTANCE, draft.acceptanceMode)}</p>
          </div>

          <div className="field">
            <label className="field__label" htmlFor="intake">Intake mode</label>
            <select
              id="intake"
              value={draft.intakeMode}
              onChange={(e) =>
                setDraft({ ...draft, intakeMode: e.target.value as ProjectSettings["intakeMode"] })
              }
            >
              {INTAKE.map((m) => <option key={m.value} value={m.value}>{m.value}</option>)}
            </select>
            <p className="field__note">{note(INTAKE, draft.intakeMode)}</p>
          </div>

          <div className="field">
            <label className="field__label" htmlFor="repair">Repair mode</label>
            <select
              id="repair"
              value={draft.repairMode}
              onChange={(e) =>
                setDraft({ ...draft, repairMode: e.target.value as ProjectSettings["repairMode"] })
              }
            >
              {REPAIR.map((m) => <option key={m.value} value={m.value}>{m.value}</option>)}
            </select>
            <p className="field__note">{note(REPAIR, draft.repairMode)}</p>
          </div>

          <div className="field field--row">
            <div>
              <label className="field__label" htmlFor="text-size">Text size</label>
              <select
                id="text-size"
                value={view.textSize}
                onChange={(e) => onChangeView({ ...view, textSize: e.target.value as ViewPrefs["textSize"] })}
              >
                {TEXT_SIZES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </div>
            <div>
              <label className="field__label" htmlFor="density">Density</label>
              <select
                id="density"
                value={view.density}
                onChange={(e) => onChangeView({ ...view, density: e.target.value as ViewPrefs["density"] })}
              >
                {DENSITIES.map((d) => <option key={d.value} value={d.value}>{d.label}</option>)}
              </select>
            </div>
            <p className="field__note">
              Text scales on its own: gaps, controls and radii keep their size, so a larger
              size does not stretch the layout. Both apply immediately and are remembered.
              Drag the dividers between panes to set their widths, or focus one and use the
              arrow keys.
            </p>
          </div>

          <div className="field field--split">
            <div>
              <label className="field__label" htmlFor="skin">Skin</label>
              <select
                id="skin"
                value={activeSkinId}
                onChange={(e) => {
                  const s = skins.find((k) => k.id === e.target.value);
                  if (s) onChangeSkin(s);
                }}
              >
                {skins.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
            </div>
            <p className="field__note">
              {skins.find((s) => s.id === activeSkinId)?.note}{" "}
              A skin answers every token in the presentation contract — colour, type,
              density, motion. It cannot change what anything means, collapse two certainty
              bands into one appearance, hide a failure, or write the store.
            </p>
          </div>
        </div>

        <div className="modal__foot">
          <span className="hint">
            {changed ? `Saving publishes ${nextVersionLabel()}.` : "No changes to publish."}
          </span>
          <button className="btn btn--ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn--primary" onClick={save}>Save settings</button>
        </div>
      </div>
    </div>
  );
}
