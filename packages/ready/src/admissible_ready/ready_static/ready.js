(() => {
  "use strict";

  const byId = (id) => document.getElementById(id);
  const elements = {
    connectionDot: byId("connection-dot"),
    connectionCopy: byId("connection-copy"),
    projectName: byId("project-name"),
    commitLabel: byId("commit-label"),
    statusOrbit: byId("status-orbit"),
    statusGlyph: byId("status-glyph"),
    statusKicker: byId("status-kicker"),
    statusTitle: byId("status-title"),
    statusSummary: byId("status-summary"),
    runCheck: byId("run-check"),
    checkLabel: byId("check-label"),
    nextHeading: byId("next-heading"),
    actionOwner: byId("action-owner"),
    actionDetail: byId("action-detail"),
    commandRow: byId("command-row"),
    actionCommand: byId("action-command"),
    reasonList: byId("reason-list"),
    agentList: byId("agent-list"),
    checksScore: byId("checks-score"),
    checkList: byId("check-list"),
    technicalState: byId("technical-state"),
    technicalReadiness: byId("technical-readiness"),
    technicalStanding: byId("technical-standing"),
    technicalRepository: byId("technical-repository"),
    technicalCommit: byId("technical-commit"),
    technicalTree: byId("technical-tree"),
    technicalPolicy: byId("technical-policy"),
    technicalAttempt: byId("technical-attempt"),
    dialog: byId("connect-dialog"),
    connectForm: byId("connect-form"),
    connectFields: byId("connect-fields"),
    setupResult: byId("setup-result"),
    setupTitle: byId("setup-title"),
    setupInstruction: byId("setup-instruction"),
    setupSnippet: byId("setup-snippet"),
    toast: byId("toast"),
  };

  const presentations = {
    checking: {
      glyph: "···",
      kicker: "Checking current state",
      title: "One clear answer about this commit.",
    },
    needs_attention: {
      glyph: "!",
      kicker: "Needs attention",
      title: "There is one useful next move.",
    },
    waiting_for_review: {
      glyph: "↗",
      kicker: "Waiting for review",
      title: "Your checks passed. Review is next.",
    },
    checks_complete: {
      glyph: "✓",
      kicker: "Checks complete",
      title: "This commit passed its checks.",
    },
    ready: {
      glyph: "✓",
      kicker: "Ready",
      title: "This exact commit is ready.",
    },
    unable_to_check: {
      glyph: "×",
      kicker: "Unable to check",
      title: "Admissible stopped safely.",
    },
  };

  const ownerLabels = {
    agent_or_human: "You or your agent",
    human: "You",
    reviewer: "Independent reviewer",
    trusted_infrastructure: "Secure confirmation",
  };

  let currentState = null;
  let checking = false;
  let toastTimer = null;

  async function api(path, options = {}) {
    const settings = {
      cache: "no-store",
      credentials: "same-origin",
      ...options,
      headers: {
        "Accept": "application/json",
        "X-Admissible-Ready": "1",
        ...(options.headers || {}),
      },
    };
    if (settings.body !== undefined) {
      settings.headers["Content-Type"] = "application/json";
    }
    const response = await fetch(path, settings);
    const text = await response.text();
    let payload;
    try {
      payload = JSON.parse(text);
    } catch (_error) {
      throw new Error(`Admissible returned an unreadable response (${response.status}).`);
    }
    if (!response.ok) {
      throw new Error(payload.message || `Request failed (${response.status}).`);
    }
    return payload;
  }

  function short(value, length = 9) {
    return typeof value === "string" && value ? value.slice(0, length) : "—";
  }

  function repositoryName(repository) {
    if (typeof repository !== "string" || !repository) return "Current repository";
    const pieces = repository.replace(/\.git$/, "").split("/");
    return pieces[pieces.length - 1] || repository;
  }

  function setConnection(state, copy) {
    elements.connectionDot.className = `connection-dot ${state}`.trim();
    elements.connectionCopy.textContent = copy;
  }

  function renderJourney(document) {
    const steps = [...window.document.querySelectorAll(".journey-step")];
    steps.forEach((step) => step.classList.remove("done", "active"));
    const identityKnown = Boolean(document.identity && document.identity.commit_sha);
    const checksDone = ["waiting_for_review", "checks_complete", "ready"].includes(document.status);
    const requiredReviews = Number(document.advanced?.required_independent_reviews || 0);
    const reviews = Number(document.advanced?.independent_reviews || 0);
    const reviewDone = requiredReviews === 0 || reviews >= requiredReviews;
    const named = Object.fromEntries(steps.map((step) => [step.dataset.step, step]));
    if (identityKnown) named.change.classList.add("done");
    if (!checksDone) named.checks.classList.add("active");
    else named.checks.classList.add("done");
    if (checksDone && !reviewDone) named.review.classList.add("active");
    if (checksDone && reviewDone) named.review.classList.add("done");
    if (document.status === "ready") named.ready.classList.add("done");
    else if (checksDone && reviewDone) named.ready.classList.add("active");
  }

  function renderReasons(reasons) {
    elements.reasonList.replaceChildren();
    (Array.isArray(reasons) ? reasons : []).slice(0, 6).forEach((reason) => {
      const row = document.createElement("div");
      row.className = "reason";
      const copy = document.createElement("span");
      copy.textContent = reason.detail || reason.subject || reason.code || "Requirement not met";
      row.append(copy);
      elements.reasonList.append(row);
    });
  }

  function renderChecks(checks, progress, advanced) {
    elements.checkList.replaceChildren();
    const rows = Array.isArray(checks) ? checks : [];
    const passed = Number(progress?.checks_passed || 0);
    const total = Number(progress?.checks_total || rows.length || 0);
    const unavailable = advanced?.check_evidence === "unavailable";
    const optionalFailed = rows.filter((check) => (
      check.required === false && check.status !== "passed"
    )).length;
    elements.checksScore.textContent = unavailable
      ? "Authenticated admission"
      : optionalFailed
        ? `Required checks complete · ${optionalFailed} optional check${optionalFailed === 1 ? "" : "s"} failed`
        : (total ? `${passed} / ${total} passed` : "Not checked");
    if (!rows.length) {
      const empty = document.createElement("div");
      empty.className = "check-empty";
      empty.textContent = unavailable
        ? "Detailed check evidence unavailable in this authenticated status process."
        : "Run a check to see exact results here.";
      elements.checkList.append(empty);
      return;
    }
    rows.forEach((check) => {
      const row = document.createElement("div");
      row.className = "check-row";
      const icon = document.createElement("span");
      const ok = check.status === "passed";
      icon.className = `check-icon${ok ? "" : " failed"}`;
      icon.textContent = ok ? "✓" : "!";
      const name = document.createElement("span");
      name.className = "check-name";
      name.textContent = check.check_id || "Configured check";
      const meta = document.createElement("span");
      meta.className = "check-meta";
      const duration = Number.isInteger(check.duration_ms) ? `${check.duration_ms} ms` : "recorded";
      meta.textContent = `${check.status || "unknown"} · ${duration}`;
      row.append(icon, name, meta);
      elements.checkList.append(row);
    });
  }

  function renderTechnical(document) {
    const identity = document.identity || {};
    const canonical = document.canonical || {};
    elements.technicalState.textContent = canonical.state || "—";
    elements.technicalReadiness.textContent = canonical.readiness || "—";
    elements.technicalStanding.textContent = canonical.standing || "—";
    elements.technicalRepository.textContent = identity.repository || "—";
    elements.technicalCommit.textContent = identity.commit_sha || "—";
    elements.technicalTree.textContent = identity.tree_sha || "—";
    elements.technicalPolicy.textContent = identity.policy_digest || "—";
    elements.technicalAttempt.textContent = identity.attempt_id || "—";
  }

  function renderState(document) {
    currentState = document;
    const status = presentations[document.status] ? document.status : "unable_to_check";
    const view = presentations[status];
    const identity = document.identity || {};
    const repository = identity.repository;
    elements.projectName.textContent = repositoryName(repository);
    if (identity.applies_to_current_commit === true && identity.commit_sha) {
      elements.commitLabel.textContent = `Result applies to ${short(identity.commit_sha)}`;
    } else if (identity.commit_sha) {
      const dirty = (document.reasons || []).some((reason) => reason.code === "dirty_worktree");
      elements.commitLabel.textContent = dirty
        ? `HEAD ${short(identity.commit_sha)} · uncommitted changes`
        : `HEAD ${short(identity.commit_sha)} · not checked`;
    } else {
      elements.commitLabel.textContent = "Commit identity unavailable";
    }
    elements.statusOrbit.dataset.status = status;
    elements.statusGlyph.textContent = view.glyph;
    elements.statusKicker.textContent = view.kicker;
    elements.statusTitle.textContent = view.title;
    elements.statusSummary.textContent = document.summary || "No readiness summary is available.";

    const action = Array.isArray(document.next_actions) ? document.next_actions[0] : null;
    if (action) {
      elements.nextHeading.textContent = action.title || "Review the next requirement";
      elements.actionOwner.textContent = ownerLabels[action.owner] || "Admissible";
      elements.actionDetail.textContent = action.detail || "Follow this step, then check again.";
      if (action.command) {
        elements.commandRow.hidden = false;
        elements.actionCommand.textContent = action.command;
      } else {
        elements.commandRow.hidden = true;
        elements.actionCommand.textContent = "";
      }
    } else {
      elements.nextHeading.textContent = "No next action recorded";
      elements.actionOwner.textContent = "Admissible";
      elements.actionDetail.textContent = "Refresh the state or run a check.";
      elements.commandRow.hidden = true;
    }
    renderReasons(document.reasons);
    renderChecks(document.checks, document.progress, document.advanced);
    renderTechnical(document);
    renderJourney(document);
    elements.checkLabel.textContent = status === "needs_attention" || status === "unable_to_check"
      ? "Check again" : "Check this commit";
  }

  function renderFailure(error) {
    renderState({
      schema: "admissible/v0.7/ready-state",
      status: "unable_to_check",
      summary: error.message || "Ready could not reach the local Admissible service.",
      identity: {},
      canonical: {state: "BLOCKED", readiness: "NOT_READY", standing: "UNKNOWN"},
      progress: {}, checks: [], reasons: [],
      next_actions: [{title: "Restore the local connection", detail: "Reload this page after the Ready service is available.", owner: "human", command: ""}],
      advanced: {},
    });
    setConnection("error", "Connection lost");
  }

  async function loadState() {
    try {
      const document = await api("/api/v1/state");
      renderState(document);
      setConnection("live", "Local service connected");
    } catch (error) {
      renderFailure(error);
    }
  }

  async function runCheck() {
    if (checking) return;
    checking = true;
    elements.runCheck.disabled = true;
    elements.checkLabel.textContent = "Checking…";
    elements.statusOrbit.dataset.status = "checking";
    elements.statusGlyph.textContent = "···";
    try {
      const document = await api("/api/v1/check", {
        method: "POST",
        body: JSON.stringify({}),
      });
      renderState(document);
      showToast("Check complete for this exact commit.");
    } catch (error) {
      renderFailure(error);
    } finally {
      checking = false;
      elements.runCheck.disabled = false;
    }
  }

  function renderAgents(agents) {
    elements.agentList.replaceChildren();
    if (!Array.isArray(agents) || !agents.length) {
      const empty = document.createElement("div");
      empty.className = "empty-agent";
      const mark = document.createElement("span");
      mark.className = "empty-agent-mark";
      mark.textContent = "+";
      const copy = document.createElement("p");
      copy.textContent = "No agent connected yet.";
      empty.append(mark, copy);
      elements.agentList.append(empty);
      return;
    }
    agents.forEach((agent) => {
      const row = document.createElement("div");
      row.className = "agent-row";
      const avatar = document.createElement("span");
      avatar.className = "agent-avatar";
      avatar.textContent = (agent.name || "A").slice(0, 1).toUpperCase();
      const copy = document.createElement("span");
      const name = document.createElement("strong");
      name.textContent = agent.name || "Connected agent";
      const meta = document.createElement("small");
      meta.textContent = `${agent.runtime || "custom"} · ${agent.purpose || "Ready workflow"}`;
      copy.append(name, meta);
      const live = document.createElement("span");
      live.className = "agent-live";
      live.title = "MCP session live";
      row.append(avatar, copy, live);
      elements.agentList.append(row);
    });
  }

  async function loadAgents() {
    try {
      const document = await api("/api/v1/agents");
      renderAgents(document.agents);
    } catch (_error) {
      renderAgents([]);
    }
  }

  function openConnect() {
    elements.connectFields.hidden = false;
    elements.setupResult.hidden = true;
    if (!elements.dialog.open) elements.dialog.showModal();
    window.setTimeout(() => elements.connectForm.elements.name.focus(), 20);
  }

  async function generateConnection(event) {
    event.preventDefault();
    const data = new FormData(elements.connectForm);
    const submit = elements.connectForm.querySelector('button[type="submit"]');
    submit.disabled = true;
    try {
      const document = await api("/api/v1/connect", {
        method: "POST",
        body: JSON.stringify({
          name: data.get("name"),
          purpose: data.get("purpose"),
          runtime: data.get("runtime"),
        }),
      });
      elements.connectFields.hidden = true;
      elements.setupResult.hidden = false;
      elements.setupTitle.textContent = `Add ${document.name} to ${runtimeLabel(document.runtime)}`;
      elements.setupInstruction.textContent = document.instructions;
      elements.setupSnippet.textContent = document.snippet;
    } catch (error) {
      showToast(error.message, true);
    } finally {
      submit.disabled = false;
    }
  }

  function runtimeLabel(runtime) {
    return ({
      "claude-code": "Claude Code",
      codex: "Codex",
      hermes: "Hermes",
      local: "your local agent",
      custom: "your MCP client",
    })[runtime] || "your agent";
  }

  async function copy(value, success) {
    try {
      await navigator.clipboard.writeText(value);
      showToast(success);
    } catch (_error) {
      showToast("Copy was blocked. Select the text and copy it manually.", true);
    }
  }

  function showToast(message, error = false) {
    window.clearTimeout(toastTimer);
    elements.toast.textContent = message;
    elements.toast.style.background = error ? "#6f1f1a" : "#171a18";
    elements.toast.hidden = false;
    toastTimer = window.setTimeout(() => { elements.toast.hidden = true; }, 2600);
  }

  byId("open-connect").addEventListener("click", openConnect);
  byId("panel-connect").addEventListener("click", openConnect);
  byId("run-check").addEventListener("click", runCheck);
  byId("refresh-agents").addEventListener("click", loadAgents);
  byId("copy-command").addEventListener("click", () => copy(elements.actionCommand.textContent, "Command copied."));
  byId("copy-setup").addEventListener("click", () => copy(elements.setupSnippet.textContent, "Connection setup copied."));
  byId("another-agent").addEventListener("click", () => {
    elements.connectForm.reset();
    elements.connectFields.hidden = false;
    elements.setupResult.hidden = true;
  });
  elements.connectForm.addEventListener("submit", generateConnection);
  elements.dialog.addEventListener("click", (event) => {
    if (event.target === elements.dialog) elements.dialog.close();
  });

  loadState();
  loadAgents();
  window.setInterval(loadAgents, 5000);
})();
