"""A document may not claim what the code does not do.

paper/RGA/PROOFS.md and paper/RGA/INVARIANTS.md cite the guard that enforces
each claim as `path:line:symbol`, e.g. `rga/core.py:412:_guard_seal_complete`.
This test opens the file and checks that the cited line contains the symbol.
A refactor that moves a guard without updating the proof goes red here, which
is the point: the proof is a claim about the code, and the code moved.

It also requires every theorem R1–R13 in PROOFS.md to carry at least one
citation into rga/core.py, so a proof cannot be written without pointing at
the line that makes it true.
"""
from __future__ import annotations

import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
CITATION = re.compile(r"`((?:rga|fcd)/core\.py|rga/calibration\.py):(\d+):([A-Za-z_][A-Za-z0-9_]*)`")
THEOREM = re.compile(r"^## ([RC]\d+) ", re.M)


def _lines(path: str) -> list[str]:
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read().splitlines()


class CitationTests(unittest.TestCase):
    docs = ("paper/RGA/PROOFS.md", "paper/RGA/INVARIANTS.md")

    def test_every_citation_points_at_its_symbol(self):
        sources: dict[str, list[str]] = {}
        checked = 0
        for doc in self.docs:
            text = "\n".join(_lines(doc))
            for path, line, symbol in CITATION.findall(text):
                src = sources.setdefault(path, _lines(path))
                n = int(line)
                self.assertTrue(1 <= n <= len(src), f"{doc}: {path}:{n} is past the end of the file")
                self.assertIn(symbol, src[n - 1],
                              f"{doc} cites {path}:{n}:{symbol} but line {n} is: {src[n - 1].strip()!r}")
                checked += 1
        self.assertGreater(checked, 0, "no citations found")

    def test_every_theorem_cites_the_kernel(self):
        text = "\n".join(_lines("paper/RGA/PROOFS.md"))
        sections = THEOREM.split(text)
        # sections = [preamble, 'R1', body1, 'R2', body2, ...]
        seen = {}
        for name, body in zip(sections[1::2], sections[2::2]):
            kernel = "rga/calibration.py" if name.startswith("C") else "rga/core.py"
            seen[name] = any(path == kernel for path, _, _ in CITATION.findall(body))
        for i in range(1, 14):
            self.assertIn(f"R{i}", seen, f"PROOFS.md has no section for R{i}")
            self.assertTrue(seen[f"R{i}"], f"PROOFS.md R{i} cites no line of rga/core.py")
        for i in range(1, 8):
            self.assertIn(f"C{i}", seen, f"PROOFS.md has no section for C{i}")
            self.assertTrue(seen[f"C{i}"], f"PROOFS.md C{i} cites no line of rga/calibration.py")


if __name__ == "__main__":
    unittest.main()
