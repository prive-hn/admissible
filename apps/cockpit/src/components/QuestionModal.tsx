import { useDialog } from "../domain/useDialog";
import { useState } from "react";
import type { Question } from "../domain/types";

interface Props {
  question: Question;
  onAnswer: (value: string | undefined, text: string | undefined) => void;
  onClose: () => void;
}

/**
 * A question pauses exactly one line at exactly one node. The sheet is
 * deliberately non-modal: the rest of the instrument stays readable, because
 * the answer usually depends on what the other panes are showing. Answering
 * records an interaction event and resumes from the same checkpoint.
 */
export function QuestionModal({ question, onAnswer, onClose }: Props) {
  const dialog = useDialog<HTMLDivElement>(onClose);
  const [text, setText] = useState("");

  return (
    <div className="question-anchor">
      <div
        ref={dialog}
        className="modal question-sheet"
        role="dialog"
        aria-modal="false"
        aria-label="Open question"
        tabIndex={-1}
      >
        <div className="modal__head">
          <span className="modal__title" data-testid="question-title">
            Question
            <span className="modal__scope mono">
              {question.workItemId}
              {question.stageId ? ` · ${question.stageId}` : ""}
            </span>
          </span>
          <button className="icon-btn icon-btn--quiet" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        <div className="modal__body">
          <p className="question-sheet__prompt" data-testid="question-prompt">
            {question.prompt}
          </p>
          {question.context && <p className="question-sheet__context">{question.context}</p>}

          {question.options && question.options.length > 0 && (
            <div className="option-list" role="group" aria-label="Answer options">
              {question.options.map((opt) => (
                <button
                  key={opt.value}
                  className="option"
                  data-testid={`question-option-${opt.value}`}
                  onClick={() => onAnswer(opt.value, text.trim() || undefined)}
                >
                  <span className="option__label">{opt.label}</span>
                  {opt.hint && <span className="option__hint">{opt.hint}</span>}
                </button>
              ))}
            </div>
          )}

          {question.allowFreeText && (
            <div className="field">
              <label className="field__label" htmlFor="q-free">
                Or answer in your own words
              </label>
              <textarea
                id="q-free"
                rows={3}
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder="Your answer resumes this line from the same checkpoint."
              />
            </div>
          )}
        </div>

        <div className="modal__foot">
          <button className="btn btn--ghost" onClick={onClose}>Keep paused</button>
          {question.allowFreeText && (
            <button
              className="btn btn--primary"
              disabled={!text.trim()}
              onClick={() => onAnswer(undefined, text.trim())}
            >
              Submit answer &amp; resume
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
