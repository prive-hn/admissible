"""Journal instrument. Draws what the machine actually did.

Not a mood board. Every mark is an event in e.events.
Pixels without a journal event are a lie (F1).
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

from .core import Enforcer


COLORS = {
    "open": "#c8c8c8",
    "stage": "#6a8caf",
    "bind": "#c4a35a",
    "call": "#c4a35a",
    "pass": "#3d7a4a",
    "fail_closed": "#a33a32",
    "accept": "#1f4d2a",
}


def _kind(ev: dict) -> str:
    t = ev.get("type")
    if t == "decide":
        return "pass" if ev.get("result") == "pass" else "fail_closed"
    return t or "open"


def render(enforcer: Enforcer, out: Path, title: str = "fail-closed class dispatch — live journal") -> Path:
    """One PNG: lines (items) × time (events). Store column on the right."""
    events = list(enforcer.events)
    items = list(enforcer.items.keys())
    if not items:
        raise ValueError("no items")
    ymap = {iid: i for i, iid in enumerate(reversed(items))}
    fig, ax = plt.subplots(figsize=(11.2, 2.2 + 0.85 * len(items)))
    ax.set_xlim(-0.6, max(len(events) + 1.8, 6))
    ax.set_ylim(-0.7, len(items) - 0.15)
    ax.set_yticks([ymap[i] for i in items])
    ax.set_yticklabels(
        [
            f"{iid}  v={enforcer.items[iid].policy_version}"
            + (f"  ←{','.join(enforcer.items[iid].depends_on)}" if enforcer.items[iid].depends_on else "")
            for iid in items
        ]
    )
    ax.set_xlabel("journal index (real events, in order)")
    ax.set_title(title, loc="left", fontsize=11, pad=10)
    ax.axvline(len(events) + 0.35, color="#ddd", lw=0.8)
    ax.text(len(events) + 0.5, len(items) - 0.35, "STORE", fontsize=8, color="#1f4d2a")

    for n, ev in enumerate(events):
        iid = ev.get("work_item_id")
        if iid not in ymap:
            continue
        y = ymap[iid]
        k = _kind(ev)
        face = COLORS.get(k, "#888")
        ax.add_patch(
            FancyBboxPatch(
                (n - 0.38, y - 0.28),
                0.76,
                0.56,
                boxstyle="round,pad=0.02,rounding_size=0.08",
                facecolor=face,
                edgecolor="#222",
                lw=0.6,
            )
        )
        label = k if k != "fail_closed" else (ev.get("fault") or "fail")
        ax.text(n, y, label[:8], ha="center", va="center", fontsize=6.5, color="white")

    for iid, item in enforcer.items.items():
        y = ymap[iid]
        x = len(events) + 0.85
        if iid in enforcer.store:
            ax.add_patch(
                FancyBboxPatch(
                    (x, y - 0.28),
                    1.15,
                    0.56,
                    boxstyle="round,pad=0.02,rounding_size=0.08",
                    facecolor=COLORS["accept"],
                    edgecolor="#111",
                    lw=1.0,
                )
            )
            ax.text(x + 0.57, y, "accepted", ha="center", va="center", fontsize=7, color="white")
        else:
            ax.add_patch(
                plt.Rectangle((x, y - 0.28), 1.15, 0.56, fill=False, ls="--", ec="#888", lw=1.0)
            )
            ax.text(x + 0.57, y, item.status, ha="center", va="center", fontsize=7, color="#666")

    for iid, item in enforcer.items.items():
        for dep in item.depends_on:
            if dep in ymap:
                ax.add_patch(
                    FancyArrowPatch(
                        (len(events) + 0.85, ymap[dep]),
                        (-0.35, ymap[iid]),
                        arrowstyle="-|>",
                        mutation_scale=8,
                        lw=0.7,
                        color="#888",
                        connectionstyle="arc3,rad=0.12",
                    )
                )

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=140, facecolor="white")
    plt.close()
    return out
