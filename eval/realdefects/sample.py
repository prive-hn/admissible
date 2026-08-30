"""The pre-registered hand-adjudication draw, as code.

The E8 pre-registration specified "a stratified random sample -- seed
`20260830`, six candidates the harness calls `separated` and six it calls
`not-separated`". That draw was made in a scratch script that was never
committed, so a reviewer could not reproduce it and reasonably concluded the
sample had been substituted. It had not been; the two strata are drawn
SEQUENTIALLY from one generator, and re-seeding for the second stratum gives a
different set. This file exists so nobody has to guess again.
"""
from __future__ import annotations

import json
import pathlib
import random

ROOT = pathlib.Path(__file__).resolve().parent
SEED = 20260830


def draw(results_path: pathlib.Path = ROOT / "e8-results.json") -> dict:
    rows = json.loads(results_path.read_text())
    rng = random.Random(SEED)          # ONE generator, both draws, in this order
    out = {}
    for arm in ("separated", "not-separated"):
        pool = sorted((r for r in rows if r["result"] == arm),
                      key=lambda r: (r["project"], r["bug"]))
        out[arm] = [f"{r['project']}/{r['bug']}" for r in rng.sample(pool, 6)]
    return out


if __name__ == "__main__":
    for arm, keys in draw().items():
        print(f"{arm:>14}: {', '.join(keys)}")
