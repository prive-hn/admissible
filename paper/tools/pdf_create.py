#!/usr/bin/env python3
# Vendored from the Hermes Agent PDF skill by Nous Research.
# Licensed under the MIT License:
#
# Copyright Nous Research
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Create a deterministic PDF from a JSON spec using ReportLab Platypus."""
from __future__ import annotations

import argparse
import json
import sys


def _reconfigure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            reconfigure = getattr(stream, "reconfigure", None)
            if reconfigure is not None:
                reconfigure(encoding="utf-8")
        except Exception:
            pass


def build_pdf(spec: dict, out_path: str) -> int:
    try:
        from reportlab import rl_config

        # Stable creation metadata and document IDs make a clean rebuild
        # byte-comparable to the committed artifact.
        rl_config.invariant = 1

        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Image,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        print("Missing dependency: install with 'python3 -m pip install reportlab'", file=sys.stderr)
        return 2

    page_size = letter if str(spec.get("page_size", "A4")).lower() == "letter" else A4
    styles = getSampleStyleSheet()
    story = []
    for element in spec.get("elements", []):
        element_type = element.get("type")
        if element_type == "heading":
            level = min(max(int(element.get("level", 1)), 1), 3)
            story.append(Paragraph(element.get("text", ""), styles[f"Heading{level}"]))
        elif element_type == "paragraph":
            story.append(Paragraph(element.get("text", ""), styles["BodyText"]))
            story.append(Spacer(1, float(element.get("space_after", 6))))
        elif element_type == "table":
            rows = element.get("rows", [])
            if not rows:
                continue
            table = Table(rows, repeatRows=1 if element.get("header", True) else 0)
            style = [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
            if element.get("header", True):
                style += [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ]
            table.setStyle(TableStyle(style))
            story.append(table)
            story.append(Spacer(1, 10))
        elif element_type == "image":
            kwargs = {}
            if element.get("width"):
                kwargs["width"] = float(element["width"])
            if element.get("height"):
                kwargs["height"] = float(element["height"])
            image = Image(element["path"], **kwargs)
            if "width" in kwargs and "height" not in kwargs:
                ratio = image.imageHeight / image.imageWidth
                image.drawWidth = kwargs["width"]
                image.drawHeight = kwargs["width"] * ratio
            story.append(image)
            story.append(Spacer(1, 10))
        elif element_type == "pagebreak":
            story.append(PageBreak())
        else:
            print(f"Warning: unknown element type {element_type!r}, skipped", file=sys.stderr)

    def draw_page_number(canvas, document):
        if spec.get("page_numbers", True):
            canvas.saveState()
            canvas.setFont("Helvetica", 9)
            canvas.drawCentredString(page_size[0] / 2.0, 0.5 * inch, f"Page {document.page}")
            canvas.restoreState()

    document = SimpleDocTemplate(
        out_path,
        pagesize=page_size,
        title=spec.get("title", ""),
        author=spec.get("author", ""),
    )
    document.build(story, onFirstPage=draw_page_number, onLaterPages=draw_page_number)
    print(json.dumps({"output": out_path, "elements": len(spec.get("elements", []))}))
    return 0


def main() -> int:
    _reconfigure_stdio()
    parser = argparse.ArgumentParser(description="Create a PDF from a UTF-8 JSON spec.")
    parser.add_argument("spec", help="Path to a UTF-8 JSON spec")
    parser.add_argument("-o", "--output", required=True, help="Output PDF path")
    args = parser.parse_args()
    with open(args.spec, encoding="utf-8") as handle:
        spec = json.load(handle)
    return build_pdf(spec, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
