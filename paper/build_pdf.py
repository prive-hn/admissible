#!/usr/bin/env python3
"""Render the fail-closed class dispatch paper to PDF with structural figures."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

ROOT = Path(__file__).resolve().parent
FIG = ROOT / "figures"
FIG.mkdir(exist_ok=True)
OUT_PDF = ROOT / "fail-closed-class-dispatch.pdf"
PDF_CREATE = ROOT / "tools" / "pdf_create.py"


def _fig_base():
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 9,
            "axes.edgecolor": "#222",
            "text.color": "#111",
        }
    )


def fig_automaton():
    _fig_base()
    fig, ax = plt.subplots(figsize=(8.2, 4.4))
    ax.set_xlim(0, 10)
    ax.set_ylim(-0.35, 5.2)   # the Stopped node sits at y=0.15 with height 0.7
    ax.axis("off")
    ax.set_title("Figure 1. Stage automaton (Observe machine)", loc="left", fontsize=11, pad=8)

    nodes = {
        "Open": (1.2, 2.6),
        "Admitted": (3.4, 2.6),
        "Running": (5.6, 2.6),
        "Passed": (8.2, 4.0),
        "Closed": (8.2, 1.2),
        "Stopped": (8.2, 0.15),
    }
    colors = {
        "Open": "#e8eef5",
        "Admitted": "#e8eef5",
        "Running": "#f4ead4",
        "Passed": "#dcebd8",
        "Closed": "#f3d9d6",
        "Stopped": "#ececec",
    }
    for name, (x, y) in nodes.items():
        w, h = 1.7, 0.7
        box = FancyBboxPatch(
            (x - w / 2, y - h / 2),
            w,
            h,
            boxstyle="round,pad=0.04,rounding_size=0.12",
            facecolor=colors[name],
            edgecolor="#222",
            linewidth=1.1,
        )
        ax.add_patch(box)
        ax.text(x, y, name, ha="center", va="center", fontsize=9)

    def arrow(a, b, text, rad=0.0, color="#222", label_at=None):
        ax.annotate(
            "",
            xy=b,
            xytext=a,
            arrowprops=dict(arrowstyle="-|>", color=color, lw=1.1, connectionstyle=f"arc3,rad={rad}"),
        )
        mx, my = (a[0] + b[0]) / 2, (a[1] + b[1]) / 2 + rad * 0.8
        lx, ly = label_at if label_at is not None else (mx, my + 0.18)
        ax.text(lx, ly, text, ha="center", va="bottom", fontsize=7, color="#333",
                bbox=dict(facecolor="white", edgecolor="none", pad=0.5, alpha=0.9))

    arrow((2.05, 2.6), (2.55, 2.6), "Admit")
    arrow((4.25, 2.6), (4.75, 2.6), "Bind  u=1")
    arrow((6.45, 2.85), (7.35, 3.85), "Pass  exec=decl")
    arrow((6.45, 2.35), (7.35, 1.45), "PassRefuse / Close", label_at=(7.25, 2.18))
    arrow((4.25, 2.25), (7.35, 1.2), "BindFail", rad=0.18, label_at=(5.85, 1.35))
    arrow((8.2, 3.65), (8.2, 1.55), "")
    ax.text(8.95, 2.6, "not a hop", fontsize=7, color="#555", rotation=90, va="center")
    arrow((7.35, 1.2), (4.25, 2.35), "Retry (same c)", rad=0.25, label_at=(5.25, 2.05))
    arrow((8.2, 0.85), (8.2, 0.5), "Stop")
    ax.text(5.6, 3.35, "Observe writes m_exec", ha="center", fontsize=7, color="#6a4a00")
    ax.text(1.2, 0.35, "Accept is item-level: all required stages Passed → store S", fontsize=7.5)
    fig.tight_layout()
    p = FIG / "fig1_automaton.png"
    fig.savefig(p, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close()
    return p


def fig_writers():
    _fig_base()
    fig, ax = plt.subplots(figsize=(8.2, 3.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 4.2)
    ax.axis("off")
    ax.set_title("Figure 2. Why I1 is non-vacuous: two writers", loc="left", fontsize=11, pad=8)

    def panel(x, title, lines, face):
        box = FancyBboxPatch((x, 0.5), 4.4, 3.2, boxstyle="round,pad=0.05,rounding_size=0.1",
                             facecolor=face, edgecolor="#222", lw=1.1)
        ax.add_patch(box)
        ax.text(x + 2.2, 3.35, title, ha="center", fontsize=10, fontweight="bold")
        for i, line in enumerate(lines):
            ax.text(x + 0.25, 2.85 - i * 0.45, line, fontsize=8, va="top")

    panel(0.3, "Round 3 (vacuous)", [
        "Bind:  m_exec ← φ(a)",
        "Pass guard: m_exec = φ(a)",
        "Always true by construction",
        "PassRefuse = dead code",
        "I1 is a tautology",
    ], "#f3d9d6")
    panel(5.3, "This machine", [
        "Bind:  m_decl ← φ(a)",
        "Observe: m_exec ← provider report",
        "Pass iff norm(exec)=norm(decl)",
        "Mismatch → PassRefuse (F1 live)",
        "I1 is a real filter",
    ], "#dcebd8")
    fig.tight_layout()
    p = FIG / "fig2_writers.png"
    fig.savefig(p, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close()
    return p


def fig_theorems():
    _fig_base()
    fig, ax = plt.subplots(figsize=(8.2, 4.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 6)
    ax.axis("off")
    ax.set_title("Figure 3. Stage theorem map (I1–I9)", loc="left", fontsize=11, pad=8)

    proved = [
        ("I4 frozen c, body", 0.4, 4.6),
        ("I2 class admit", 0.4, 3.5),
        ("I1 bind integrity", 3.4, 3.5),
        ("I6 dual control", 0.4, 2.4),
        ("I9 retry preserves c", 0.4, 1.3),
        ("I7 bounded admits", 6.5, 4.6),
        ("I5 accept coverage", 6.5, 3.5),
        ("I8 store ⊆ accepted", 6.5, 2.4),
        ("I3 no unbound hop", 3.4, 2.4),
    ]
    for name, x, y in proved:
        box = FancyBboxPatch((x, y), 2.8, 0.7, boxstyle="round,pad=0.03,rounding_size=0.08",
                             facecolor="#dcebd8", edgecolor="#222", lw=1)
        ax.add_patch(box)
        ax.text(x + 1.4, y + 0.35, name, ha="center", va="center", fontsize=8)

    ax.annotate("", xy=(3.4, 3.85), xytext=(3.2, 3.85),
                arrowprops=dict(arrowstyle="-|>", color="#333"))
    ax.annotate("", xy=(3.4, 2.75), xytext=(1.8, 3.5),
                arrowprops=dict(arrowstyle="-|>", color="#333"))
    ax.annotate("", xy=(3.4, 2.75), xytext=(4.8, 3.5),
                arrowprops=dict(arrowstyle="-|>", color="#333"))
    ax.annotate("", xy=(6.5, 2.75), xytext=(7.9, 3.5),
                arrowprops=dict(arrowstyle="-|>", color="#333"))

    ax.text(0.4, 0.45, "Not stage theorems: quality, item liveness, provider physics, physical context isolation.",
            fontsize=8, color="#444")
    fig.tight_layout()
    p = FIG / "fig3_theorems.png"
    fig.savefig(p, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close()
    return p


def fig_rates():
    _fig_base()
    fig, ax = plt.subplots(figsize=(8.2, 3.8))
    ax.axis("off")
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 4.4)
    ax.set_title("Figure 4. Measurement sample spaces (empty of numbers)", loc="left", fontsize=11, pad=8)

    rows = [
        ("Misbind", "first Observe / stage", "norm(exec)≠norm(decl)", "with silent-fail"),
        ("Silent fail", "well-formed stages + orphan open", "no decide/accept in W", "fail-closed = published"),
        ("Bleed", "stages of class c", "a ∉ π*(c) as-of ts", "pair with silent-fail"),
        ("Time-to-stage", "well-formed stages", "survival to decide/accept", "not a mean"),
    ]
    ax.text(0.3, 3.7, "Rate", fontsize=8, fontweight="bold")
    ax.text(2.3, 3.7, "Sample space", fontsize=8, fontweight="bold")
    ax.text(5.4, 3.7, "Event", fontsize=8, fontweight="bold")
    ax.text(7.8, 3.7, "Pairing", fontsize=8, fontweight="bold")
    for i, (a, b, c, d) in enumerate(rows):
        y = 3.15 - i * 0.7
        face = "#eef3f8" if i % 2 == 0 else "#f7f7f7"
        ax.add_patch(FancyBboxPatch((0.2, y - 0.22), 9.6, 0.6, boxstyle="round,pad=0.02,rounding_size=0.06",
                                    facecolor=face, edgecolor="#ccc", lw=0.6))
        ax.text(0.3, y, a, fontsize=8)
        ax.text(2.3, y, b, fontsize=7.5)
        ax.text(5.4, y, c, fontsize=7.5)
        ax.text(7.8, y, d, fontsize=7.5)
    ax.text(0.3, 0.25, "No empirical bars. Zeros are proofs only under write-ahead + total call/decide.",
            fontsize=7.5, color="#444")
    fig.tight_layout()
    p = FIG / "fig4_rates.png"
    fig.savefig(p, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close()
    return p


def fig_efficiency():
    """Structural tradeoff: safety vs leftover-fallback throughput. No fake numbers."""
    _fig_base()
    fig, ax = plt.subplots(figsize=(8.2, 3.8))
    ax.set_xlim(-0.2, 1.2)
    ax.set_ylim(-0.2, 1.2)
    ax.set_xlabel("Class integrity (I1–I3 on a Passed stage)")
    ax.set_ylabel("Published-reply availability when allowed binds are down")
    ax.set_title("Figure 5. Efficiency is a different objective", loc="left", fontsize=11, pad=8)
    ax.scatter([1.0], [0.0], s=90, c="#2a6f3b", zorder=3)
    ax.annotate("this process\n(fail closed)", (1.0, 0.0), textcoords="offset points",
                xytext=(-70, 12), fontsize=8)
    ax.scatter([0.0], [1.0], s=90, c="#8b2e2e", zorder=3)
    ax.annotate("leftover-fallback\nreply maximizer", (0.0, 1.0), textcoords="offset points",
                xytext=(12, -18), fontsize=8)
    ax.scatter([0.5], [0.5], s=70, c="#888", zorder=3)
    ax.annotate("score/cost router\n(no deny set)", (0.5, 0.5), textcoords="offset points",
                xytext=(12, 8), fontsize=8)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["not guaranteed", "machine theorem"])
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["stop / ask", "hop to anyone up"])
    ax.grid(True, ls=":", alpha=0.5)
    fig.tight_layout()
    p = FIG / "fig5_objectives.png"
    fig.savefig(p, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close()
    return p


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def para(*parts: str, space_after: float = 6) -> dict:
    return {"type": "paragraph", "text": "".join(parts), "space_after": space_after}


def reference(text: str) -> dict:
    return para(text, space_after=2)


def h(text: str, level: int = 1) -> dict:
    return {"type": "heading", "text": text, "level": level}


def img(path: Path, width: float = 460) -> dict:
    return {"type": "image", "path": str(path), "width": width}


def table(rows: list[list[str]]) -> dict:
    return {"type": "table", "rows": rows, "header": True}


def build_spec(paths: dict[str, Path]) -> dict:
    return {
        "title": "Fail-closed class dispatch",
        "author": "Roque Briceño",
        "page_size": "letter",
        "page_numbers": True,
        "elements": [
            h("Fail-closed class dispatch"),
            para("<b>Class-admitted work, data-plane bind. This machine has no leftover-hop edge.</b>"),
            para("Roque Briceño · Version 0.8.0 · 30 August 2026 · CC BY 4.0 · Reference implementation 0.5.0."),
            h("Abstract", 2),
            para(
                "A specialized model fleet is a checkable claim only if a work item of class c "
                "cannot complete a stage on a specialist or model outside the policy for c. "
                "Fail-closed class dispatch is that check. A work item has a class and a frozen body. "
                "A policy gives each class an allow set π(c) and a deny set δ(c). Each specialist a "
                "is bound to one API model identity φ(a). A stage may run only after a well-formed "
                "admit of some a ∈ π(c)\\δ(c) and only with executed model recorded by Observe. "
                "If that bind cannot be served, the stage fails closed and the failure is published. "
                "Retry, if any, is the same item, same class, a specialist not yet tried."
            ),
            para(
                "This is Clark–Wilson integrity applied to LLM binds, not a new access-control algebra. "
                "Allow/deny, fail-safe defaults, and dual control are old. The added obligations are: "
                "φ is the identity Observe recorded from the inference client; leftover fallback is not "
                "an edge in this table; the event contract is the witness set. An accidental hop is in "
                "scope. An adversarial worker that forges Observe is not."
            ),
            para(
                "Safety invariants I1–I6, I8, I9 hold on the abstract stage machine under A0–A9. I7 bounds "
                "Admit count. Under A10–A13, I10–I17 prove FCD-owned work/envelope pinning, package and receipt "
                "binding, steering scope, attempt-local cache identity and accepted-only memory promotion. "
                "Item liveness and model quality are not proved."
            ),
            h("1. Problem", 2),
            para(
                "Routing, cascades, and mixture-of-agents optimize score or spend "
                "(Chen et al., 2023; Ong et al., 2024; Wang et al., 2024). Mixture-of-experts is a learned "
                "gate inside one network (Jacobs et al., 1991; Shazeer et al., 2017). Orchestration says "
                "who calls whom. None of them forbid a hop to an unbound model when the bound provider is "
                "down. None of them treat a model that refuses a class as illegal rather than low-scoring."
            ),
            para(
                "The sentence “we run specialists” is then unfalsifiable. The control plane can name one "
                "model while the data plane calls another. A 403 can look like work still in progress. "
                "A reviewer can be the author. The required property is class integrity: a pass record "
                "lies in π(c)\\δ(c) and uses φ(a)."
            ),
            h("2. Objects", 2),
            para(
                "A <b>work item</b> has class c, charge, frozen body hash, author set, required-stage list "
                "Required(c), and status open | failed | accepted. π(c) and δ(c) are disjoint. On a check "
                "stage the effective allow set is π_chk(c, authors) = π(c)\\authors. φ: A → M maps a "
                "specialist to an API identity. Display strings are compared after norm. u(m)=0 iff bind "
                "time returns 401, 403, 404, 429, exhausted, or not_found. tried is the set of specialists "
                "already admitted on this stage."
            ),
            para(
                "A stage is well-formed only if a control event names class, specialist, declared model, "
                "and body hash. Prose that mentions a name is not a stage. Fail closed means: publish a "
                "fail_closed decision; next is ask, retry in π(c)\\δ(c)\\tried, or stop. An <b>accepted "
                "artifact</b> exists only when every stage in Required(c) has passed. The store accepts "
                "only accepted artifacts."
            ),
            h("3. Process", 2),
            para("1. Open a well-formed work item."),
            para("2. Admit a ∈ π*(c)\\δ(c)\\tried. If none, fail closed."),
            para("3. Bind. Writes m_decl = φ(a). If u(φ(a))=0, fail closed. Does not write m_exec."),
            para("4. Observe. Copies m_exec from the provider call (A1)."),
            para("5. Pass only if norm(m_exec)=norm(m_decl); else PassRefuse (F1)."),
            para("6. When Required(c) is covered, Accept into the store."),
            para("A death watchdog outside the worker records death while Running (A2, A9). Close publishes."),
            img(paths["automaton"]),
            h("4. What holds", 2),
            para(
                "Bind writes declared only. Observe writes executed. I1 is then non-vacuous. Under A0–A9, "
                "I1–I6, I8, I9 are inductive. I7 bounds Admit count. Ask may idle. The leftover-hop picture "
                "is an illustration, not a corollary."
            ),
            img(paths["writers"]),
            img(paths["theorems"]),
            table(
                [
                    ["Id", "Claim", "Status"],
                    ["I1", "Passed ⇒ norm(exec)=norm(decl)=norm(φ(a))", "Theorem (Pass-time)"],
                    ["I2", "Running/Passed ⇒ a ∈ π*\\δ", "Theorem"],
                    ["I3", "No Pass with exec outside φ(π*\\δ)", "Theorem (via I1, I2)"],
                    ["I4", "c and body frozen after Open", "Theorem"],
                    ["I5", "accepted ⇒ every required stage Passed", "Theorem"],
                    ["I6", "check Admit ⇒ a ∉ authors", "Theorem"],
                    ["I7", "≤ |π*\\δ| Admits per stage", "Bound, not termination"],
                    ["I8", "id ∈ S ⇒ accepted", "Theorem"],
                    ["I9", "Retry does not write c", "Theorem"],
                ]
            ),
            h("4.1 Inductive proofs (condensed)", 3),
            para(
                "<b>I1.</b> Only Pass sets pc=Passed, and only when m_exec ≠ none and "
                "norm(m_exec)=norm(m_decl). Bind is the only writer of m_decl and writes φ(a). "
                "Observe may set a mismatch; then PassRefuse fires and Passed is unreachable. "
                "If Bind wrote m_exec, the guard would be tautological."
            ),
            para(
                "<b>I2.</b> a is written only by Admit, whose guard is a ∈ π*\\δ\\tried. "
                "Stages of one item are sequential (A4), so π* is the Admit-time snapshot."
            ),
            para("<b>I3.</b> I1 gives exec = φ(a). I2 gives a ∈ π*\\δ."),
            para("<b>I4.</b> No transition after Open writes c or body."),
            para("<b>I5.</b> Accept is the only writer of status=accepted and requires all required Passed."),
            para("<b>I6.</b> Check admit uses π_chk = π(c)\\authors (A6) on the Admit-time snapshot."),
            para(
                "<b>I7.</b> Each Admit adds a unused specialist to tried (A7). The allow set is finite (A0). "
                "Ask may idle; this is a bound on Admit count, not liveness."
            ),
            para("<b>I8.</b> Accept is the only writer of store S and sets accepted in the same step (A8)."),
            para("<b>I9.</b> Retry does not write c (I4)."),
            {"type": "pagebreak"},
            h("5. Context, memory and cache envelope", 2),
            para(
                "A work item pins accepted project P and memory K at Open. Each gate Admit creates a monotonic "
                "attempt counter, unpredictable nonce and immutable base envelope containing agent/profile, exact "
                "provider/API model, instruction hash, context policy, tool authority, FCD cache identity and "
                "pre-Admit steering hash. Live steering advances a separate ordered continuation chain."
            ),
            para(
                "FCD builds canonical package bytes from include minus exclude. The adapter independently hashes "
                "the bytes it submits. Pass requires current attempt/nonce, package, executor/run, latest steering "
                "and executed-model receipts. fresh_blind excludes author context and forbids executor continuity. "
                "Existing executor tools, sessions and provider caches remain external."
            ),
            table([
                ["Id", "Context-envelope claim"],
                ["I10", "Work P/K and base envelope are pinned"],
                ["I11", "Pass requires current package receipt"],
                ["I12", "fresh_blind manifest excludes author context"],
                ["I13", "Only serialized accepted CAS promotes memory"],
                ["I14", "No silent project/memory drift"],
                ["I15", "Steering stays in scope and latest ack is required"],
                ["I16", "FCD cache is full-identity attempt-local"],
                ["I17", "Prior-attempt receipts cannot authorize Pass"],
            ]),
            para(
                "Theorems cover FCD manifests, receipts and state transitions. Adapter honesty, physical prompt "
                "isolation, hidden session residue, provider cache neutrality, model quality and impact-review "
                "correctness remain explicit assumptions or limits."
            ),
            h("6. Faults", 2),
            para("Each fault is a forbidden transition, not a metaphor."),
            table(
                [
                    ["Id", "Forbidden step"],
                    ["F1", "Pass with norm(m_exec) ≠ norm(φ(a))"],
                    ["F2", "Two specialists, one runtime instance (needs instance field)"],
                    ["F3", "After u=0, another call without fail-closed, or outside unused allow"],
                    ["F4", "Running exit with no published close"],
                    ["F5", "φ(a) not an API identity"],
                    ["F6", "Pass with a ∈ δ(c)"],
                    ["F7", "Check admit with a ∈ authors"],
                    ["F8", "Run without a well-formed stage"],
                    ["F9", "Stop in chat with status not accepted"],
                    ["F10", "Same id, class changes; or retry of a ∈ tried"],
                ]
            ),
            para("Weight-sharing across specialists is extra config. It is not in I6."),
            h("7. Measurement", 2),
            para(
                "A named cut is [t0, t1]. W is class p95 of completed stage durations in the previous cut, "
                "or 12 minutes if n&lt;30. Exclude ts &gt; t1−W. Evaluate π, δ, φ as-of event ts."
            ),
            img(paths["rates"]),
            para(
                "Zeros on misbind, bleed, and silent-fail are a proof that those faults did not fire only if "
                "stage is write-ahead and call/decide are total. Otherwise they are estimates biased clean. "
                "No numbers in this paper."
            ),
            h("8. Reference implementation", 2),
            para(
                "The control plane is this machine, not a chat host or sessions sidebar. A verified project comes "
                "before intake. The operator may choose the gate agent, execution adapter, exact model and context "
                "policy before Admit. Agent instructions and exact-route readiness are visible; an unavailable route "
                "cannot start. Admit locks the envelope. Existing executors keep their mature tools and session stores; "
                "adapters return evidence and receipts but cannot Pass, Accept or promote memory."
            ),
            para(
                "The three-pane surface keeps project/capability atlas, selected work line plus bounded gate tray, "
                "and real artifact visible together. Questions stay anchored. Steering has explicit project, work, "
                "gate, stage, artifact and evidence scope. A pixel is trustworthy only when it projects an event or receipt."
            ),
            h("9. Related work", 2),
            para(
                "Clark and Wilson (1987) already have constrained data items, transformation procedures, "
                "a certification relation, integrity verification, and mandatory separation of duty. "
                "A work item is a CDI. A bound specialist is a TP. Accept is a validated write."
            ),
            para(
                "Saltzer and Schroeder (1975) name fail-safe defaults. Deny-override is standard MAC/RBAC. "
                "Thomas and Sandhu (1997) bind permission to a task instance. F1/F2/F5 are TOCTOU / "
                "control-plane versus data-plane divergence. F7 is also LLM-as-judge self-preference."
            ),
            para(
                "MoE, MoA, FrugalGPT, RouteLLM, and MoMA optimize a different objective. "
                "Orchestrator-worker (Anthropic, 2024) is a topology. Topology is not the process."
            ),
            h("10. Limits", 2),
            para(
                "No dataset. No quality theorem. No item liveness. I1 is the Pass-time report, not execution "
                "history. I1/I3 hold up to norm collision unless norm is injective. I10–I17 prove FCD-owned "
                "manifest, receipt, cache and promotion transitions. They do not prove adapter honesty, physical "
                "prompt isolation, hidden executor residue, provider cache neutrality or impact-review correctness."
            ),
            h("10.1 Efficiency without sacrificing the theorems", 2),
            para(
                "Efficiency (tokens, latency, cache hits, published-reply rate) is a different objective "
                "from class integrity. A leftover-fallback reply-maximizer improves availability exactly "
                "when every allowed bind is down — the same state where this process is already not live. "
                "That is not a free lunch. It is a hop."
            ),
            img(paths["objectives"]),
            para(
                "Safe efficiency: (1) FCD cache stays attempt-local and clears on Admit/Close; (2) mature executors "
                "may report provider prefix/session reuse, but it has no Pass authority; (3) parallelize only across "
                "distinct work items; (4) retry only in π*\\δ\\tried, bounded by I7; (5) use cheaper models only "
                "when they are explicitly selected in policy; (6) Ask instead of hopping when the remainder is empty. "
                "These choices preserve I1–I17 under the stated assumptions."
            ),
            para(
                "Unsafe efficiency: shared FCD runtime across specialists (F2), session restore that ignores the "
                "pinned envelope, cross-attempt FCD cache reuse, leftover fallback, or treating executor-reported "
                "cache telemetry as semantic context proof."
            ),
            h("11. Interactive evidence layer", 2),
            para(
                "The reference implementation keeps verified project/capability atlas, every sibling work line, a "
                "bounded editable/locked gate tray and real artifact visible together. Questions stay anchored. "
                "Drift review and explicit multi-scope steering remain inside the same cockpit."
            ),
            img(paths["cockpit"], width=470),
            para(
                "The cockpit does not widen the theorem: execution adapters preserve mature worker tools/sessions but "
                "cannot Pass, Accept or promote memory; skins are read-only projections; fcd remains the only writer "
                "of accepted state. The shown Chrome journey produced package/model receipts before acceptance."
            ),
            h("References", 2),
            reference("Chen, L., Zaharia, M., and Zou, J. FrugalGPT. arXiv:2305.05176, 2023."),
            reference("Clark, D. D., and Wilson, D. R. A comparison of commercial and military computer security policies. IEEE Symposium on Security and Privacy, 1987."),
            reference("Jacobs, R. A., Jordan, M. I., Nowlan, S. J., and Hinton, G. E. Adaptive mixtures of local experts. Neural Computation, 1991."),
            reference("Ong, I. et al. RouteLLM. 2024."),
            reference("Saltzer, J. H., and Schroeder, M. D. The protection of information in computer systems. Proceedings of the IEEE, 1975."),
            reference("Shazeer, N. et al. The sparsely-gated mixture-of-experts layer. ICLR, 2017."),
            reference("Thomas, R. K., and Sandhu, R. S. Task-based authorization controls (TBAC). 1997."),
            reference("Wang, J. et al. Mixture-of-Agents Enhances Large Language Model Capabilities. arXiv:2406.04692, 2024."),
            reference("Towards Generalized Routing: MoMA. arXiv:2509.07571, 2025."),
            reference("Anthropic. How we built our multi-agent research system. 2024."),
        ],
    }


def main() -> int:
    paths = {
        "automaton": fig_automaton(),
        "writers": fig_writers(),
        "theorems": fig_theorems(),
        "rates": fig_rates(),
        "objectives": fig_efficiency(),
        "cockpit": FIG / "context-cockpit-gate.png",
    }
    spec = build_spec(paths)
    with tempfile.TemporaryDirectory(prefix="fcd-paper-spec-") as td:
        spec_path = Path(td) / "spec.json"
        spec_path.write_text(json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8")
        command = [sys.executable, str(PDF_CREATE), str(spec_path), "-o", str(OUT_PDF)]
        result = subprocess.run(command, check=False)
    if result.returncode != 0:
        return result.returncode
    print(json.dumps({"pdf": str(OUT_PDF), "figures": [str(p) for p in paths.values()]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
