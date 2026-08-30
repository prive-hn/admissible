import { useState } from "react";
import type { ProjectSummary } from "../domain/types";
import { Gloss } from "./Gloss";
import { refusalReason, type ProjectCandidate } from "../api/client";
import { ProjectPicker } from "./ProjectPicker";

interface Counts { active: number; questions: number; drift: number }
interface Props {
  current: ProjectSummary | null;
  projects: ProjectSummary[];
  counts: Counts;
  onLoad: (definition: { id: string; name: string; local_path: string; github: string; base_branch: string }) => void | Promise<void>;
  onSelect: (projectId: string) => void;
  onNavigate: (target: "active" | "questions" | "drift") => void;
}

/**
 * Left half of the command rail: which project is loaded, what it is pinned
 * to, and the three counts worth interrupting for. Work is gated behind a
 * verified project, so the unloaded state is an instruction, not an empty box.
 */
export function ProjectStrip({ current, projects, counts, onLoad, onSelect, onNavigate }: Props) {
  const [opening, setOpening] = useState(false);
  const [localPath, setLocalPath] = useState("");
  const [github, setGithub] = useState("");
  const [base, setBase] = useState("main");
  const [verifying, setVerifying] = useState(false);
  /** Search first; typing a path by hand is the fallback, not the default. */
  const [manual, setManual] = useState(false);
  /** Why verification refused, next to the fields that caused it. */
  const [problem, setProblem] = useState<string | null>(null);

  // A refused load keeps the form open with its reason attached. Closing the
  // panel on failure would leave an operator with a project that silently did
  // not load.
  const load = async (definition: {
    id: string; name: string; local_path: string; github: string; base_branch: string;
  }) => {
    setVerifying(true);
    setProblem(null);
    try {
      await onLoad(definition);
      setOpening(false);
      setManual(false);
    } catch (error) {
      setProblem(refusalReason(error));
      setManual(true);
    } finally {
      setVerifying(false);
    }
  };

  // Picking fills the identity from the repository itself, so the two fields
  // that used to be typed from memory are already correct.
  const pick = (c: ProjectCandidate) => {
    setLocalPath(c.local_path);
    setGithub(c.github);
    setBase(c.base_branch);
    if (!c.github) {
      setManual(true);
      setProblem("This repository has no origin remote. Enter the GitHub identity to load it.");
      return;
    }
    void load({
      id: c.name, name: c.name, local_path: c.local_path,
      github: c.github, base_branch: c.base_branch,
    });
  };

  const submit = async () => {
    if (!localPath.trim() || !github.trim() || verifying) return;
    const repo = github.trim().split("/").pop() || "project";
    await load({
      id: repo, name: repo, local_path: localPath.trim(),
      github: github.trim(), base_branch: base.trim() || "main",
    });
  };

  return (
    <section className="project-strip" aria-label="Project context">
      <div className="project-strip__identity">
        {current ? (
          <>
            <span className="project-picker">
              <select aria-label="Current project" value={current.id} onChange={(e) => onSelect(e.target.value)}>
                {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </span>
            <span className="project-strip__source" title={`${current.github} · ${current.current_branch}`}>
              <span className="project-strip__repo">{current.github}</span>
              <span className="project-strip__branch">{current.current_branch}</span>
            </span>
            <Gloss term="head" className="pin" focusable>
              project {current.project_version} · memory {current.memory_version}
            </Gloss>
          </>
        ) : (
          <strong className="project-strip__prompt">Load a project to start work</strong>
        )}
        <button className="btn btn--ghost btn--sm" onClick={() => setOpening((v) => !v)} aria-expanded={opening}>
          Open project…
        </button>
      </div>

      <div className="project-strip__counts" role="group" aria-label="Jump to work">
        <button onClick={() => onNavigate("active")} title="Jump to an open line">
          <b>{counts.active}</b> active
        </button>
        <button
          className={counts.questions ? "has-questions" : ""}
          onClick={() => onNavigate("questions")}
          title="Jump to a line waiting on your answer"
        >
          <b>{counts.questions}</b> questions
        </button>
        <button
          className={counts.drift ? "has-drift" : ""}
          onClick={() => onNavigate("drift")}
          title="Jump to a line whose pinned head fell behind"
        >
          <b>{counts.drift}</b> drift
        </button>
      </div>

      {opening && (
        <div className="project-loader">
          {!manual ? (
            <ProjectPicker onPick={pick} onManual={() => setManual(true)} />
          ) : (
          <>
          <p className="project-loader__note">
            The cockpit verifies the path and repository before loading anything.{" "}
            <button className="picker__manual" onClick={() => setManual(false)}>
              Search for a repository instead
            </button>
          </p>
          <div className="project-loader__fields">
            <label>Local path
              <input aria-label="Local path" placeholder="/Users/you/repos/project" value={localPath} onChange={(e) => setLocalPath(e.target.value)} />
            </label>
            <label>GitHub repository
              <input aria-label="GitHub repository" placeholder="owner/repo" value={github} onChange={(e) => setGithub(e.target.value)} />
            </label>
            <label>Base branch
              <input aria-label="Base branch" value={base} onChange={(e) => setBase(e.target.value)} />
            </label>
            <button
              className="btn btn--primary"
              disabled={!localPath.trim() || !github.trim() || verifying}
              onClick={() => void submit()}
            >
              {verifying ? "Verifying…" : "Verify and load"}
            </button>
          </div>
          </>
          )}
          {problem && (
            <p className="project-loader__problem" role="alert">
              <span>Not loaded</span>
              {problem}
            </p>
          )}
        </div>
      )}
    </section>
  );
}
