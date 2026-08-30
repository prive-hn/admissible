import { useEffect, useRef, useState } from "react";
import { discoverProjects, refusalReason, type ProjectCandidate } from "../api/client";

interface Props {
  onPick: (candidate: ProjectCandidate) => void;
  /** Fall back to typing a path by hand when discovery finds nothing. */
  onManual: () => void;
}

/**
 * Find a repository by name instead of recalling its path.
 *
 * Opening work used to mean typing an absolute path and a GitHub identity from
 * memory, and getting either wrong produced a verification refusal. The server
 * already runs git, so it reads each candidate's origin and base branch here —
 * which means picking a repository fills in an identity that came from the
 * repository itself rather than from the operator's recollection, and removes
 * the "local origin does not match GitHub definition" failure entirely.
 *
 * Search is confined to the server's roots. Those are shown, not hidden, so it
 * is obvious why something is missing and what to do about it.
 */
export function ProjectPicker({ onPick, onManual }: Props) {
  const [query, setQuery] = useState("");
  const [candidates, setCandidates] = useState<ProjectCandidate[]>([]);
  const [roots, setRoots] = useState<string[]>([]);
  const [active, setActive] = useState(0);
  const [problem, setProblem] = useState<string | null>(null);
  const [searching, setSearching] = useState(true);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // Debounced so a scan does not run on every keystroke, aborted so a slow
  // result cannot overwrite a newer one.
  useEffect(() => {
    const controller = new AbortController();
    setSearching(true);
    const timer = setTimeout(() => {
      discoverProjects(query, controller.signal)
        .then((found) => {
          setCandidates(found.candidates);
          setRoots(found.roots);
          setActive(0);
          setProblem(null);
        })
        .catch((error) => {
          if (controller.signal.aborted) return;
          setProblem(refusalReason(error));
        })
        .finally(() => {
          if (!controller.signal.aborted) setSearching(false);
        });
    }, 180);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [query]);

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (!candidates.length) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => (a + 1) % candidates.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => (a - 1 + candidates.length) % candidates.length);
    } else if (e.key === "Enter") {
      e.preventDefault();
      onPick(candidates[active]);
    }
  };

  return (
    <div className="picker">
      <label className="picker__field">
        Find a repository
        <input
          ref={inputRef}
          aria-label="Find a repository"
          placeholder="Start typing a repository name"
          // The arrow keys move a highlight while focus stays in the input, so
          // the input has to be the combobox that owns the list — otherwise
          // nothing is announced when the highlight moves.
          role="combobox"
          aria-expanded={candidates.length > 0}
          aria-controls="picker-results"
          aria-autocomplete="list"
          aria-activedescendant={
            candidates[active] ? `picker-opt-${active}` : undefined
          }
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
        />
      </label>

      {problem ? (
        <p className="picker__problem" role="alert">{problem}</p>
      ) : (
        <p className="picker__roots">
          {roots.length
            ? <>Searching {roots.map((r) => <code key={r}>{r}</code>)}</>
            : "No repository folders found."}{" "}
          <button className="picker__manual" onClick={onManual}>
            Somewhere else? Enter a path
          </button>
        </p>
      )}

      {/* A listbox owns its options directly; the <li> wrappers broke that
          relationship, so the options were not exposed as belonging to it. */}
      <div className="picker__results" role="listbox" id="picker-results" aria-label="Repositories">
        {candidates.map((c, i) => (
            <button
              key={c.local_path}
              id={`picker-opt-${i}`}
              role="option"
              aria-selected={i === active}
              tabIndex={-1}
              className={`picker__result ${i === active ? "picker__result--active" : ""}`}
              onClick={() => onPick(c)}
            >
              <span className="picker__name">{c.name}</span>
              <span className="picker__github">
                {c.github || <em>no origin remote</em>}
              </span>
              <span className="picker__meta">
                <span className="picker__path">{c.local_path}</span>
                <span className="picker__branch">
                  base {c.base_branch}
                  {c.current_branch && c.current_branch !== c.base_branch
                    ? ` · on ${c.current_branch}`
                    : ""}
                </span>
              </span>
            </button>
        ))}
      </div>

      {!searching && !problem && candidates.length === 0 && (
        <p className="picker__empty">
          {query
            ? `No repository matching "${query}" under the folders above.`
            : "No repositories found under those folders."}{" "}
          Set <code>FCD_PROJECT_ROOTS</code> to search elsewhere, or enter a path by hand.
        </p>
      )}
    </div>
  );
}
