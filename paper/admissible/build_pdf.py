#!/usr/bin/env python3
"""Typeset paper/admissible/DRAFT.md to PDF with generated figures.

The PDF is a rendering of DRAFT.md — the canonical text — converted
block-by-block rather than paraphrased, so the two cannot drift apart.
Figures are generated here: the three-machine composition, the anatomy
of a seal, and the bench outcomes imported live from eval/bench (whose
determinism tests/test_bench.py proves). Uses the same spec/renderer
pipeline as ../build_pdf.py.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIG = ROOT / "paper" / "figures"
DRAFT = HERE / "DRAFT.md"
OUT_PDF = HERE / "admissible.pdf"
PDF_CREATE = HERE.parent / "tools" / "pdf_create.py"

sys.path.insert(0, str(ROOT / "eval" / "bench"))


# ------------------------------------------------------------- md -> spec ----

MATH = {
    r"\triangleq": ":=", r"\wedge": "∧", r"\neg": "¬", r"\in": "∈",
    r"\subseteq": "⊆", r"\setminus": "\\", r"\to": "→", r"\Rightarrow": "⇒",
    r"\longleftarrow": "←", r"\ge": "≥", r"\pi": "π", r"\delta": "δ",
    r"\phi": "φ", r"\theta": "θ", r"\varepsilon": "ε", r"\nu": "ν",
    r"\min": "min", r"\square": "QED", r"\|": "|", r"\,": " ", r"\;": " ",
    r"\neq": "≠", r"\mid": "|", r"\cup": "∪",
    r"\sigma": "σ",
}


# Literal Unicode the renderer's font does not carry, mapped to what its
# LaTeX macro would produce. Probed against the real renderer, not assumed:
# the notdef box EXTRACTS as the letter 'I', so a text scan of the output
# cannot find these — two subscripts shipped as black boxes until a review
# rendered the page and looked. tests/test_paper_build.py now probes the
# renderer itself when it is available.
UNSUPPORTED = {"\u2016": "|", "\u25a1": "QED",
               "\u1d62": "i", "\u2080": "0", "\u2081": "1", "\u2082": "2",
               "\u2099": "n", "\u2c7c": "j", "\u2096": "k",
               # Custody-paper glyphs the base font cannot draw, mapped to a
               # drawable, escape-safe (no <>&) substitute probed against the
               # real renderer. \u00b5 (U+00B5) and \u2206 (U+2206) are exact visual
               # stand-ins for \u03bc and \u0394; the guillemets \u2039 \u00ab are drawable angles.
               "\u0100": "A", "\u0144": "n", "\u0394": "\u2206", "\u03bc": "\u00b5",
               "\u03f1": "\u03c1", "\u2113": "l", "\u2115": "N",
               "\u21a6": "|->", "\u21c0": "\u2192", "\u2218": "\u00b7",
               "\u227a": "\u2039", "\u2291": "[=", "\u22a8": "|=", "\u22b3": "|>",
               "\u22c0": "\u2227", "\u22c2": "\u2229", "\u22c3": "\u222a",
               "\u25c1": "\u00ab", "\u27e6": "[[", "\u27e7": "]]",
               "\u27e8": "(", "\u27e9": ")",
               "\U0001d4ab": "P", "\U0001d50a": "G", "\U0001d51f": "b"}


def _glyphs(t: str) -> str:
    for bad, good in UNSUPPORTED.items():
        t = t.replace(bad, good)
    return t


def _demath(t: str) -> str:
    for macro in (r"\mathrm", r"\mathit", r"\mathcal", r"\text"):
        t = re.sub(re.escape(macro) + r"\{([^{}]*)\}", r"\1", t)
    for k, v in MATH.items():
        t = t.replace(k, v)
    t = re.sub(r"_\{([^{}]*)\}", r"_\1", t)
    t = re.sub(r"\^\{([^{}]*)\}", r"^\1", t)
    return _glyphs(t.strip())


def _inline(t: str) -> str:
    """Convert supported Markdown inline forms to ReportLab markup."""
    t = re.sub(r"!?\[([^\]]+)\]\([^)]+\)", r"\1", t)
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = re.sub(r"\$([^$]+)\$", lambda m: _demath(m.group(1)), t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t, flags=re.S)
    t = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", t)
    t = re.sub(r"`([^`]+)`", r"\1", t)
    return _glyphs(t)


def para(text: str) -> dict:
    return {"type": "paragraph", "text": text}


def h(text: str, level: int) -> dict:
    return {"type": "heading", "text": text, "level": level}


def img(path: Path, width: float = 460) -> dict:
    return {"type": "image", "path": str(path), "width": width}


# The renderer puts raw strings in table cells and reportlab does not wrap
# them, so a row wider than the frame is silently clipped at both edges —
# the reader loses text and nothing says so. Any table too wide to fit is
# therefore rendered as definition paragraphs instead: the same content,
# folded, with the first column as the term. Letter minus margins is about
# 95 characters of 10pt Helvetica.
def _split_row(line: str) -> list[str]:
    """Split a markdown table row on real column boundaries only.

    A `|` inside a code span is content — the transition tables are full of
    `|samples| = k` — and `\\|` is an escaped literal. Splitting blindly on
    every pipe silently re-columned eight rows: one bench table lost its
    power column, and a normative Seal guard was cut in half.
    """
    cells, buf, in_code, i = [], [], False, 0
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and body[i + 1] == "|":
            buf.append("|"); i += 2; continue
        if ch == "`":
            in_code = not in_code
        if ch == "|" and not in_code:
            cells.append("".join(buf)); buf = []
        else:
            buf.append(ch)
        i += 1
    cells.append("".join(buf))
    return cells


# The width bound is measured with the renderer's own font metrics, not
# guessed in characters: a character count is off by more than 2x between
# "iiii" and "WWWW", and the 95-character guess this replaced would have
# passed a row that renders ~49pt past the frame edge.
_FRAME_PT = 468.0          # letter minus one-inch margins
_CELL_PAD_PT = 12.0        # reportlab's default 6pt left + 6pt right
_TABLE_FONT = ("Helvetica", 10)

try:
    from reportlab.pdfbase.pdfmetrics import stringWidth as _string_width
except ImportError:        # pragma: no cover - the renderer owns reportlab
    def _string_width(text, font, size):
        return len(text) * size * 0.6


def _row_width_pt(rows: list[list[str]]) -> float:
    cols = max(len(r) for r in rows)
    return sum(
        max(_string_width(r[i] if i < len(r) else "", *_TABLE_FONT) for r in rows) + _CELL_PAD_PT
        for i in range(cols))


_TAG = re.compile(r"</?[a-z]+(?: [^>]*)?/?>")


def _plain(cell: str) -> str:
    """Table cells reach reportlab as raw strings and are never parsed, so a
    cell must not carry markup: <b>0.8182</b> printed verbatim in the bench
    tables until a review read the page. Entities are unescaped for the same
    reason — &gt; must render as >."""
    text = _TAG.sub("", cell)
    return (text.replace("&lt;", "<").replace("&gt;", ">")
                .replace("&amp;", "&").replace("&nbsp;", " "))


def _table_or_definitions(rows: list[list[str]]) -> list[dict]:
    cols = max(len(r) for r in rows)
    plain = [[_plain(r[i]) if i < len(r) else "" for i in range(cols)] for r in rows]
    if _row_width_pt(plain) <= _FRAME_PT:
        return [{"type": "table", "rows": plain, "header": True}]
    header, out = rows[0], []
    for r in rows[1:]:
        parts = []
        for i, cell in enumerate(r[1:], start=1):
            if not cell:
                continue
            label = header[i] if i < len(header) else ""
            parts.append(f"<i>{label}:</i> {cell}" if label and cols > 2 else cell)
        term = r[0] if r else ""
        out.append(para(f"<b>{term}</b> — " + " · ".join(parts) if parts else f"<b>{term}</b>"))
    return out


_FENCE_TOKEN = "\x00fence"


def _lift_fences(md: str) -> tuple[str, list[str]]:
    out, fences, buf, inside = [], [], [], False
    for line in md.splitlines():
        if line.lstrip().startswith("```"):
            if inside:
                fences.append("\n".join(buf))
                out.append(f"\n{_FENCE_TOKEN}{len(fences) - 1}\n")
                buf, inside = [], False
            else:
                inside = True
            continue
        (buf if inside else out).append(line)
    if inside:                      # unterminated fence: keep the text
        out.extend(buf)
    return "\n".join(out), fences


_HARD_BREAK = "\x00br\x00"


def _flow(text: str) -> str:
    """One markdown block as one paragraph: a hard line break (two trailing
    spaces, as the papers' bylines use) stays a break; every other newline
    is a fold. The <br/> goes in after _inline, which escapes markup."""
    text = re.sub(r"[ \t]{2,}\n", _HARD_BREAK, text)
    text = re.sub(r"\s*\n\s*", " ", text)
    return _inline(text).replace(_HARD_BREAK, "<br/>")


def _code_block(body: str) -> dict:
    """A fenced block, kept verbatim. The renderer has no code element, so
    it becomes a monospace paragraph with hard breaks — indentation and line
    structure preserved, because a runnable snippet reflowed into prose is
    no longer runnable."""
    esc = (body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
               .replace(" ", "&nbsp;"))
    return para('<font face="Courier" size="8">'
                + "<br/>".join(esc.splitlines()) + "</font>")


def md_to_elements(md: str) -> list[dict]:
    out: list[dict] = []
    # Fenced blocks are lifted out before paragraph splitting: a blank line
    # inside a fence must not become a block boundary.
    md, fences = _lift_fences(md)
    blocks = re.split(r"\n\s*\n", md)
    for b in blocks:
        b = b.strip()
        if not b:
            continue
        if b.startswith(_FENCE_TOKEN):
            out.append(_code_block(fences[int(b[len(_FENCE_TOKEN):])]))
            continue
        if b.startswith("$$"):
            out.append(para("<b>" + _demath(b.strip("$ \n")) + "</b>"))
            continue
        m = re.match(r"^(#{1,3})\s+(.*)$", b.splitlines()[0])
        if m:
            out.append(h(_inline(m.group(2)), len(m.group(1))))
            rest = "\n".join(b.splitlines()[1:]).strip()
            if rest:
                out.append(para(_flow(rest)))
            continue
        lines = b.splitlines()
        if all(ln.lstrip().startswith("|") for ln in lines) and len(lines) >= 2:
            rows = []
            for ln in lines:
                cells = [c.strip() for c in _split_row(ln)]
                if all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
                    continue
                rows.append([_inline(c) for c in cells])
            out.extend(_table_or_definitions(rows))
            continue
        if any(re.match(r"^\s*(-|\d+\.)\s", ln) for ln in lines):
            # Any block containing list items is rendered as items: requiring
            # EVERY line to start a bullet folded lead-in lines and wrapped
            # items into run-on prose ("So: - A-det … line. - Check 1 …").
            # Continuations attach to the item they belong to.
            items: list[tuple[str, list[str]]] = []
            for ln in lines:
                m = re.match(r"^\s*(-|\d+\.)\s+(.*)$", ln)
                if m:
                    mark = "•  " if m.group(1) == "-" else m.group(1) + "  "
                    items.append((mark, [m.group(2)]))
                elif items:
                    items[-1][1].append(ln.strip())
                else:
                    items.append(("", [ln.strip()]))
            for mark, body in items:
                out.append(para(mark + _flow(" ".join(body))))
            continue
        out.append(para(_flow(b)))
    return out


# ---------------------------------------------------------------- figures ----

def _fig_base():
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9,
                         "axes.edgecolor": "#222", "text.color": "#111"})


def _box(ax, x, y, w, hh, label, color, fontsize=9):
    ax.add_patch(FancyBboxPatch((x, y), w, hh, boxstyle="round,pad=0.06",
                                fc=color, ec="#333", lw=1.0))
    ax.text(x + w / 2, y + hh / 2, label, ha="center", va="center", fontsize=fontsize)


def fig_layers() -> Path:
    _fig_base()
    fig, ax = plt.subplots(figsize=(8.2, 4.6))
    ax.set_xlim(0, 10); ax.set_ylim(0, 5.6); ax.axis("off")
    ax.set_title("Figure 6. One machine, three layers, one predicate",
                 loc="left", fontsize=11, pad=8)
    ax.text(5.0, 5.15, "admissible(id)  ≜  sealed(id)  ∧  mediated(id)  ∧  ¬tainted(id)  ∧  ¬impeached(id)",
            ha="center", fontsize=10.5, family="DejaVu Sans", weight="bold")
    _box(ax, 0.4, 3.4, 2.9, 0.95, "Layer C — standing\nL — rga/calibration.py\nC1–C7 · faults E1–E9", "#efe3f2")
    _box(ax, 3.7, 3.4, 2.9, 0.95, "Layer R — scrutiny\nA — rga/core.py\nR1–R13 · faults V1–V15", "#dcebd8")
    _box(ax, 7.0, 3.4, 2.9, 0.95, "Layer I — identity\nF — fcd/core.py\nI1–I17 · faults F1–F10", "#e8eef5")
    for x0, x1, lab in [(3.3, 3.7, "drives only guarded\ntransitions (C7)"),
                        (6.6, 7.0, "reads; writes\nno field (R11)")]:
        ax.add_patch(FancyArrowPatch((x0, 3.87), (x1, 3.87), arrowstyle="->",
                                     mutation_scale=13, color="#333"))
        ax.text((x0 + x1) / 2, 4.55, lab, ha="center", fontsize=7.4, color="#333")
    conj = [("mediated / impeached / tainted\n(C1–C7)", 1.85), ("sealed: S_R ⊆ S\n(R1–R13)", 5.15),
            ("accepted: S\n(I1–I17)", 8.45)]
    for lab, x in conj:
        ax.add_patch(FancyArrowPatch((x, 4.35), (x if x != 1.85 else 2.6, 4.95),
                                     arrowstyle="-", color="#888", lw=0.8, linestyle=":"))
        ax.text(x, 2.85, lab, ha="center", fontsize=8, color="#333")
    for i, (lab, x) in enumerate([("cal journal", 1.85), ("rga journal", 5.15), ("fcd journal", 8.45)]):
        _box(ax, x - 1.15, 1.15, 2.3, 0.75,
             f"{lab}\nappend-only · write-ahead\nre-guarded replay", "#f6f2e8", 7.6)
        ax.add_patch(FancyArrowPatch((x, 3.35), (x, 1.98), arrowstyle="->",
                                     mutation_scale=11, color="#666"))
    ax.text(5.0, 0.45, "Each machine rebuilds from its journal re-checking every live guard; inconsistent "
                       "records are refused, while historical authenticity requires an external current head.",
            ha="center", fontsize=8, color="#333")
    out = FIG / "fig6_layers.png"
    fig.savefig(out, dpi=180, bbox_inches="tight"); plt.close(fig)
    return out


def fig_seal() -> Path:
    import textwrap as tw
    _fig_base()
    fig, ax = plt.subplots(figsize=(8.2, 5.9))
    ax.set_xlim(0, 10); ax.set_ylim(-0.55, 7.2); ax.axis("off")
    ax.set_title("Figure 7. Anatomy of a seal (write-once; nothing on it can be raised later)",
                 loc="left", fontsize=11, pad=8)
    rows = [
        ("identity\n(layer I, by citation)",
         "work item · class · frozen body hash · fcd policy version · generator · executed model", "#e8eef5"),
        ("artifact", "hash of the exact bytes accepted — the served bytes, byte-checked at Accept", "#e8eef5"),
        ("sampling", "k samples · designated sample = stage 0 · sampling config hash · post-artifact nonces", "#f6f2e8"),
        ("per claim", "claim id · spec hash (authored outside the generator) · pinned refuter versions", "#dcebd8"),
        ("per refuter", "mode (ledger | bounded) · power = kills/|D| against content-addressed D (author fixed "
                        "by first record), or 1−(1−ε)^N from declared (ε, N) · kills · |D|", "#dcebd8"),
        ("composite", "union over shared D, or labelled max — never a product · (agreeing, k) so k=1 is "
                      "visibly trivial", "#dcebd8"),
        ("residual", "every claim NOT attacked, with disposition: check_stage | unreviewed — the seal "
                     "names what it does not cover", "#f3d9d6"),
        ("standing\n(layer C, queries)", "mediated? impeached? tainted? — never stored on the seal; computed "
                                        "against the retained escape ledger, with authenticated current heads "
                                        "making deletion of an anchored prefix loud", "#efe3f2"),
    ]
    y = 6.35
    for label, body, color in rows:
        wrapped = "\n".join(tw.wrap(body, 74))
        hh = 0.42 + 0.22 * wrapped.count("\n")
        _box(ax, 0.3, y - hh, 2.05, hh, label, color, 7.6)
        _box(ax, 2.55, y - hh, 7.15, hh, wrapped, "#ffffff", 7.4)
        y -= hh + 0.16
    out = FIG / "fig7_seal.png"
    fig.savefig(out, dpi=180, bbox_inches="tight"); plt.close(fig)
    return out


def fig_bench() -> Path:
    """Where each generator condition lands, per line.

    Rewritten: the previous version drew one panel per target with raw counts
    on a shared axis, so three conditions with 8, 24 and 6 lines apiece were
    compared by bar height, and nothing on the figure said which outcome each
    condition was *supposed* to reach or which of them is true by construction.
    A reader could take the solid honest bar for a result. It is not one.
    """
    import textwrap as tw

    import bench
    results = bench.run()
    _fig_base()

    SEALED, REFUTED, DISCORD = "#2a78d6", "#eb6834", "#1baf7a"
    INK, INK2, MUTED, SURFACE, MISS = "#0b0b0b", "#52514e", "#898781", "#fcfcfb", "#d03b3b"
    scenarios = [
        ("honest", "every sample is the reference implementation",
         "should seal — and does, by construction"),
        ("sloppy", "every sample carries one mutant drawn from D",
         "should be refuted, or sealed then impeached"),
        ("unstable", "samples alternate between correct and mutant",
         "should close as refutation or discord"),
    ]
    targets = list(results["targets"])
    lines = results["lines"]

    fig, ax = plt.subplots(figsize=(8.2, 5.4))
    fig.patch.set_facecolor(SURFACE); ax.set_facecolor(SURFACE)
    y, yticks, ylabels, groups = 0.0, [], [], []
    GAP = 0.008                       # surface gap between segments
    for scen, what, expect in scenarios:
        top = y
        for t in targets:
            o = results["targets"][t]["outcomes"][scen]
            imp = results["targets"][t]["escapes"]["impeached_by_scenario"][scen]
            standing, total = o["sealed"] - imp, lines[scen]
            x = 0.0
            for val, color, hatch in ((standing, SEALED, None), (imp, SEALED, "////"),
                                      (o["V1"], REFUTED, None), (o["V2"], DISCORD, None)):
                if not val:
                    continue
                ax.barh(y, val / total - GAP, left=x, height=0.44, color=color,
                        edgecolor=SURFACE if hatch else "none", linewidth=0,
                        hatch=hatch)
                x += val / total
            ax.text(1.03, y, f"{o['sealed']}  {o['V1']}  {o['V2']}", va="center",
                    ha="left", fontsize=8, color=INK2, family="DejaVu Sans Mono")
            # A seal nothing later struck, in a condition that should not have
            # sealed at all, is the one genuine miss here. Unmarked it reads
            # exactly like the honest rows above it.
            if standing and scen != "honest":
                ax.text(1.20, y, f"← {standing} missed", va="center", ha="left",
                        fontsize=7.4, color=MISS)
            yticks.append(y); ylabels.append(t)
            y += 1.0
        groups.append((scen, what, expect, top))
        y += 0.95
    y -= 0.95

    ax.set_xlim(0, 1.0); ax.set_ylim(y - 0.35, -0.75)
    ax.set_yticks(yticks); ax.set_yticklabels(ylabels, fontsize=8.5, color=INK)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xticklabels(["0", "25%", "50%", "75%", "100% of lines"],
                       fontsize=8, color=MUTED)
    ax.tick_params(axis="y", length=0); ax.tick_params(axis="x", colors=MUTED, length=3)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(MUTED); ax.spines["bottom"].set_linewidth(0.6)
    ax.text(1.03, -0.75, "sealed  ref  dis", fontsize=7.4, color=MUTED,
            va="center", ha="left", family="DejaVu Sans Mono")
    for scen, what, expect, top in groups:
        ax.text(0.0, top - 0.72, f"{scen}  —  {what}", fontsize=8.6, color=INK,
                weight="bold", va="center")
        ax.text(1.0, top - 0.72, expect, fontsize=7.8, color=INK2, va="center",
                ha="right", style="italic")
    ax.set_title("Figure 8. Where each generator condition lands, per line "
                 "(eval/bench)", loc="left", fontsize=11, pad=26, color=INK)
    handles = [Patch(fc=SEALED, ec="none", label="sealed, standing"),
               Patch(fc=SEALED, ec=SURFACE, hatch="////", label="sealed, later impeached"),
               Patch(fc=REFUTED, ec="none", label="refuted at trial (V1)"),
               Patch(fc=DISCORD, ec="none", label="discord (V2)")]
    ax.legend(handles=handles, loc="lower left", bbox_to_anchor=(0.0, 1.005),
              ncol=4, frameon=False, fontsize=7.8, handlelength=1.4,
              columnspacing=1.2, handletextpad=0.5)
    impeached = sum(r["escapes"]["impeached_by_scenario"]["sloppy"]
                    for r in results["targets"].values())
    sloppy_sealed = sum(r["outcomes"]["sloppy"]["sealed"]
                        for r in results["targets"].values())
    standing_misses = sum(r["outcomes"]["unstable"]["sealed"]
                          for r in results["targets"].values())
    note = (
        f"Proportions, because the conditions have different line counts "
        f"(honest {lines['honest']}, sloppy {lines['sloppy']}, unstable "
        f"{lines['unstable']} per target); raw counts at the right. This "
        f"measures the machinery, not a generator: the honest sample IS the "
        f"reference implementation serving as the differential oracle, so "
        f"sealing there is true by construction — an honest line that failed to "
        f"seal would be an instrument fault, and once was — and the sloppy "
        f"mutant is drawn from the defect model D that power is measured "
        f"against, so refutation is a within-model result that says nothing "
        f"about a defect outside D. Every sloppy seal was impeached afterwards "
        f"({impeached} of {sloppy_sealed}). {standing_misses} unstable seals "
        f"were not, and stand as misses.")
    fig.text(0.0, -0.075, "\n".join(tw.wrap(note, 132)), fontsize=7.2,
             color=INK2, ha="left", va="top")
    out = FIG / "fig8_bench.png"
    fig.savefig(out, dpi=180, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)
    return out


def fig_realdefects() -> Path:
    """Where the 63 real defects went.

    Deliberately not a rate: the ratio this shape invites — separations over
    testable — is the one eval/LOG.md says not to quote, because the run's own
    artifact rule was measured afterwards and never fires. What the figure
    carries instead is which losses are corpus properties and which are faults
    of the instrument.
    """
    import textwrap as tw

    rows = json.loads((ROOT / "eval" / "realdefects" / "e8-results.json").read_text())
    counted = {k: sum(1 for r in rows if r["result"] == k)
               for k in ("separated", "not-separated", "no-input-strategy",
                         "no-attributes-named", "module-exec-failed")}
    total = len(rows)
    loaded = total - counted["module-exec-failed"]
    testable = counted["separated"] + counted["not-separated"]
    verified = 8                       # hand-adjudicated; see eval/LOG.md

    _fig_base()
    RAMP = ["#86b6ef", "#5598e7", "#2a78d6", "#1c5cab", "#104281"]
    INK, INK2, SURFACE, WARN = "#0b0b0b", "#52514e", "#fcfcfb", "#d03b3b"
    stages = [
        (total, "triaged candidates", "", None),
        (loaded, "module loaded at both commits",
         f"{counted['module-exec-failed']} would not execute under this "
         f"interpreter", None),
        (testable, "an input strategy was built",
         f"{counted['no-input-strategy']} refused outright · "
         f"{counted['no-attributes-named']} refused by a guard bug",
         f"{counted['no-attributes-named']} of these are a bug, not a corpus "
         f"property: a parameter the body never reads yields no attributes, so "
         f"the harness calls it unconstructable. They are exactly the gap to "
         f"the pre-registered threshold of 45."),
        (counted["separated"], "separated from the fix",
         f"{counted['not-separated']} not separated",
         "Of six sampled negatives, three were overturned by a hand-written "
         "input and one is separable only outside this harness. “Not "
         "separated” here mostly means “not reached”."),
        (verified, "verified by hand against the patch",
         f"{counted['separated'] - verified} were not the defect",
         "One pure stubbing artifact, one right cause with a stub-corrupted "
         "result."),
    ]

    fig, ax = plt.subplots(figsize=(8.2, 4.6))
    fig.patch.set_facecolor(SURFACE); ax.set_facecolor(SURFACE)
    y = 0.0
    for i, (kept, label, lost, note) in enumerate(stages):
        ax.barh(y, kept / total, height=0.5, color=RAMP[i], edgecolor="none")
        ax.text(-0.012, y, label, ha="right", va="center", fontsize=8.6, color=INK)
        # Inside the bar while it fits, outside once it does not: a count
        # clipped by its own bar is the commonest defect in a funnel.
        inside = kept / total > 0.16
        ax.text(kept / total + (-0.012 if inside else 0.012), y, str(kept),
                ha="right" if inside else "left", va="center", fontsize=10,
                weight="bold", color=SURFACE if i >= 2 and inside else INK)
        if lost:
            ax.text(kept / total + (0.014 if inside else 0.085), y, lost,
                    ha="left", va="center", fontsize=7.6, color=INK2)
        if note:
            wrapped = "\n".join(tw.wrap(note, 108))
            ax.text(0.0, y - 0.40, wrapped, ha="left", va="top", fontsize=7.2,
                    color=WARN, linespacing=1.5)
            y -= 1.30 + 0.34 * wrapped.count("\n")
        else:
            y -= 1.0

    ax.set_xlim(-0.30, 1.34); ax.set_ylim(y + 0.72, 0.95); ax.axis("off")
    ax.set_title("Figure 9. Where 63 real defects went (eval/realdefects)",
                 loc="left", fontsize=11, pad=14, x=-0.19, color=INK)
    ax.text(-0.30, 0.55, "Deliberately not a rate. The two largest losses are "
            "the harness failing to reach the code, not the two versions "
            "agreeing.", fontsize=8, color=INK2, ha="left", va="center")
    fig.text(0.0, -0.02,
             "The eight that survive are real defects from youtube-dl, scrapy "
             "and thefuck, each separated by a search with no knowledge of the "
             "bug and then checked\nby hand against the commit that fixed it. "
             "The ratio this figure would otherwise invite — 10 of 42, 23.8% — "
             "is reported in eval/LOG.md and should not be\nquoted: the run's "
             "own artifact rule was measured afterwards and never fires, so the "
             "run repeats an earlier measurement rather than improving on it.",
             fontsize=7.2, color=INK2, ha="left", va="top")
    out = FIG / "fig9_realdefects.png"
    fig.savefig(out, dpi=180, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)
    return out


# -------------------------------------------------------------------- main ----

def build_spec() -> dict:
    elements = md_to_elements(DRAFT.read_text())
    figs = {"layers": fig_layers(), "seal": fig_seal(), "bench": fig_bench(),
            "realdefects": fig_realdefects()}
    anchors = {"## 3.": img(figs["layers"]), "## 5.": img(figs["seal"]),
               "## 10.": [img(figs["bench"]), img(figs["realdefects"])]}
    placed: list[dict] = []
    raw = DRAFT.read_text()
    heads = {ln.split(" ", 1)[1]: pref for pref in anchors
             for ln in raw.splitlines() if ln.startswith(pref)}
    for el in elements:
        if el["type"] == "heading":
            for title, pref in heads.items():
                if el["text"].startswith(_inline(title).split(" ")[0]) and _inline(title) == el["text"]:
                    a = anchors[pref]
                    placed.extend(a if isinstance(a, list) else [a])
        placed.append(el)
    return {"title": "Admissible: a fail-closed admissibility kernel",
            "author": "Roque Briceño", "page_size": "letter", "page_numbers": True,
            "elements": placed}


def _render(spec: dict, out_pdf: Path) -> int:
    with tempfile.TemporaryDirectory(prefix="admissible-paper-spec-") as td:
        spec_path = Path(td) / "spec.json"
        spec_path.write_text(json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(PDF_CREATE), str(spec_path), "-o", str(out_pdf)],
            check=False,
        )
    if result.returncode == 0:
        print(json.dumps({"pdf": str(out_pdf)}))
    return result.returncode


def main() -> int:
    rc = _render(build_spec(), OUT_PDF)
    if rc != 0:
        return rc
    rga_draft = HERE.parent / "RGA" / "DRAFT.md"
    rga_spec = {"title": "Refutation-gated admission", "author": "Roque Briceño",
                "page_size": "letter", "page_numbers": True,
                "elements": md_to_elements(rga_draft.read_text())}
    rc = _render(rga_spec, HERE.parent / "RGA" / "refutation-gated-admission.pdf")
    if rc != 0:
        return rc
    custody_draft = HERE.parent / "custody" / "DRAFT.md"
    custody_spec = {"title": "Custody theory", "author": "Roque Briceño",
                    "page_size": "letter", "page_numbers": True,
                    "elements": md_to_elements(custody_draft.read_text())}
    return _render(custody_spec, HERE.parent / "custody" / "custody.pdf")


if __name__ == "__main__":
    raise SystemExit(main())
