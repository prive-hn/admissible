import { useMemo, useRef, useState } from "react";
import type { StageNode, SteeringTarget } from "../domain/types";
import { parseSteer, suggestSlash, type SlashCommand } from "../domain/slash";

interface Props {
  /** The node the steering is scoped to (center selection). */
  node: StageNode | null;
  workItemId: string | null;
  target?: SteeringTarget | null;
  targets?: SteeringTarget[];
  onTargetChange?: (target: SteeringTarget) => void;
  onSteer: (command: SlashCommand, text: string, nodeId: string | null) => void;
}

/**
 * The command bar. One row: what the words land on, the words, and the verb.
 *
 * Scope is chosen explicitly and shown next to the input rather than across the
 * width of the instrument, because "which thing am I steering" is the question
 * an operator has to answer before typing, not after. Plain text is free
 * steering evidence; a leading slash opens the fixed verb set.
 */
export function BottomSteer({ node, workItemId, target, targets = [], onTargetChange, onSteer }: Props) {
  const [value, setValue] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const suggestions = useMemo(() => suggestSlash(value), [value]);
  // Escape closes the list without clearing what has been typed; it reopens
  // as soon as the token changes.
  const [dismissed, setDismissed] = useState(false);
  const showSuggest = suggestions.length > 0 && !dismissed;
  const parsed = parseSteer(value);

  const complete = (cmd: SlashCommand) => {
    setValue(cmd.cmd + " ");
    setActive(0);
    inputRef.current?.focus();
  };

  const submit = () => {
    const next = parseSteer(value);
    if (!next.command) return;
    onSteer(next.command, next.text, node?.id ?? null);
    setValue("");
    setActive(0);
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (showSuggest) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setActive((a) => (a + 1) % suggestions.length);
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setActive((a) => (a - 1 + suggestions.length) % suggestions.length);
        return;
      }
      // Shift+Tab moves focus backwards and must keep doing so; completing on
      // it trapped the operator in the input whenever the list was open.
      if (e.key === "Tab" && !e.shiftKey) {
        e.preventDefault();
        complete(suggestions[active]);
        return;
      }
      if (e.key === "Escape") {
        e.preventDefault();
        setDismissed(true);
        return;
      }
    }
    if (e.key === "Enter") {
      e.preventDefault();
      // If the token is still a partial command, complete it first.
      if (!parseSteer(value).command && showSuggest) {
        complete(suggestions[active]);
      } else {
        submit();
      }
    }
  };

  const readout = parsed.command
    ? parsed.command.cmd === "/steer"
      ? "free steering — recorded as evidence, never a contract change"
      : parsed.command.desc
    : "Type to steer the selected scope. Start with / for the fixed verb set.";

  return (
    <div className="steer">
      {showSuggest && (
        <div className="autocomplete" role="listbox" id="steer-suggestions" aria-label="Slash commands">
          {suggestions.map((c, i) => (
            <button
              key={c.cmd}
              id={`steer-opt-${c.cmd.slice(1)}`}
              role="option"
              aria-selected={i === active}
              className={`autocomplete__item ${i === active ? "autocomplete__item--active" : ""}`}
              data-testid={`slash-suggestion-${c.cmd.slice(1)}`}
              // The list is driven from the input, so an option is not a tab
              // stop; it is reached with the arrow keys and taken with Enter
              // or Tab. `onMouseDown` alone made these pointer-only — Enter
              // and Space fire `click`, which nothing was listening for.
              tabIndex={-1}
              onMouseDown={(e) => {
                e.preventDefault();
                complete(c);
              }}
              onClick={() => complete(c)}
            >
              <span className="autocomplete__cmd">{c.cmd}</span>
              <span className="autocomplete__desc">{c.desc}</span>
              <span className={`autocomplete__channel autocomplete__channel--${c.channel}`}>
                {c.channel === "action" ? "changes state" : "asks"}
              </span>
            </button>
          ))}
        </div>
      )}

      <div className="steer__bar">
        <div className="steer__scope">
          <span className="steer__scope-label">Steering</span>
          {targets.length > 0 ? (
            <select
              aria-label="Steering scope"
              value={target ? `${target.scope}:${target.id}` : ""}
              onChange={(e) => {
                const next = targets.find((t) => `${t.scope}:${t.id}` === e.target.value);
                if (next) onTargetChange?.(next);
              }}
            >
              {targets.map((t) => (
                <option key={`${t.scope}:${t.id}`} value={`${t.scope}:${t.id}`}>
                  {t.label}
                </option>
              ))}
            </select>
          ) : (
            <span className="steer__crumb">
              {node ? `stage · ${node.name}` : workItemId ? `work · ${workItemId}` : "no target"}
            </span>
          )}
        </div>

        <input
          ref={inputRef}
          className="steer__input"
          aria-label="Steering input"
          role="combobox"
          aria-expanded={showSuggest}
          aria-controls="steer-suggestions"
          aria-autocomplete="list"
          aria-activedescendant={
            showSuggest && suggestions[active] ? `steer-opt-${suggestions[active].cmd.slice(1)}` : undefined
          }
          placeholder="/inspect  /why  /impact  /fix  /retry  /pause  /discard  /accept"
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setActive(0);
            setDismissed(false);
          }}
          onKeyDown={onKeyDown}
        />

        <button className="btn btn--primary" onClick={submit} disabled={!parsed.command}>
          Steer
        </button>
      </div>

      <div className={`steer__readout ${parsed.command?.channel === "action" ? "steer__readout--action" : ""}`}>
        {readout}
      </div>
    </div>
  );
}
