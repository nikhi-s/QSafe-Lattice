"""
build_figure6_drawio.py

Generates the STARTER .drawio XML file for Figure 6 (Q-Safe decision logic
schematic) programmatically.

IMPORTANT -- READ BEFORE RUNNING:
The .drawio file is intended to be the single source of truth for Figure 6's
layout, edited VISUALLY in draw.io (app.diagrams.net), not regenerated from
this script. Re-running this script produces a fresh starter layout and
would DISCARD any manual positioning/sizing/routing adjustments made in
draw.io since the file was last generated. For that reason:

  - This script REFUSES to overwrite an existing output file unless you
    pass --force explicitly.
  - Run it only to (a) recreate a lost/corrupted file, or (b) start over
    deliberately after a major algorithm change where re-editing the old
    layout is more work than starting fresh.

The algorithm constants embedded in the diagram text (EMA alpha = 0.35,
security ratings 0.6 / 1.0, hybrid margin 0.08) must match
qsafe_simulation.py -- if you tune those in code, update them here AND in
your edited .drawio file (or regenerate with --force and redo layout).

Usage:
    python build_figure6_drawio.py                # writes if file absent
    python build_figure6_drawio.py --force        # overwrites existing
"""

import os
import sys
from xml.sax.saxutils import escape

from pqc_config import (
    FIGURE_DIR
)

OUTPUT_FILE = os.path.join(FIGURE_DIR, "Figure 6 - Q-Safe Decision Logic.drawio")

# --- Algorithm constants (keep in sync with qsafe_simulation.py) ---
EMA_ALPHA = 0.35
KYBER_SECURITY_RATING = 0.6
FRODO_SECURITY_RATING = 1.0
HYBRID_MARGIN = 0.08

# --- Colors (matching build_figure6.py / the matplotlib version) ---
THREAT_C = "#F1948A"
CAPAB_C = "#85C1E9"
ENERGY_C = "#82E0AA"
NEUTRAL_C = "#FCF3CF"
KYBER_C = "#D5F5E3"
FRODO_C = "#D6EAF8"
HYBRID_C = "#EBDEF0"
DECISION_C = "#F5EEF8"

BOX_STYLE = ("rounded=1;whiteSpace=wrap;html=1;fillColor={fill};"
             "strokeColor=#000000;strokeWidth=1.5;fontSize={fs};arcSize={arc};")
STAGE_STYLE = ("text;html=1;align=center;verticalAlign=middle;rotation=-90;"
               "fontSize=11;fontStyle=1;fontColor=#566573;")
NOTE_STYLE = ("text;html=1;align=center;verticalAlign=middle;fontSize=10;"
              "fontStyle=2;fontColor=#566573;")
EDGE_STYLE = ("edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeWidth=1.5;"
              "endArrow=block;endFill=1;")


def vertex(cell_id, value, style, x, y, w, h):
    return (f'        <mxCell id="{cell_id}" value="{escape(value)}" '
            f'style="{style}" vertex="1" parent="1">\n'
            f'          <mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry" />\n'
            f'        </mxCell>\n')


def edge(cell_id, source, target, extra_style="", value=""):
    value_attr = f'value="{escape(value)}" ' if value else ""
    return (f'        <mxCell id="{cell_id}" {value_attr}style="{EDGE_STYLE}{extra_style}" '
            f'edge="1" parent="1" source="{source}" target="{target}">\n'
            f'          <mxGeometry relative="1" as="geometry" />\n'
            f'        </mxCell>\n')


def build_xml() -> str:
    cells = []

    # Stage labels
    stages = [("stage1", "INPUTS", 60), ("stage2", "SMOOTHING", 230),
              ("stage3", "WEIGHTING", 400), ("stage4", "SCORING", 600),
              ("stage5", "DECISION", 840), ("stage6", "OUTCOME", 1080)]
    for sid, label, y in stages:
        cells.append(vertex(sid, label, STAGE_STYLE, 10, y, 80, 20))

    # Row 1: inputs
    cells.append(vertex("input_threat", "Quantum Threat\nLevel (0\u2013100)",
                          BOX_STYLE.format(fill=THREAT_C, fs=12, arc=20), 80, 40, 200, 70))
    cells.append(vertex("input_capability", "System Capability\n(0\u2013100)",
                          BOX_STYLE.format(fill=CAPAB_C, fs=12, arc=20), 330, 40, 200, 70))
    cells.append(vertex("input_energy", "Energy Availability\n(0\u2013100)",
                          BOX_STYLE.format(fill=ENERGY_C, fs=12, arc=20), 580, 40, 200, 70))

    # Row 2: smoothing
    cells.append(vertex("smoothing",
                          f"Exponential moving-average smoothing (\u03b1 = {EMA_ALPHA})\n"
                          "filters transient spikes; prevents rapid algorithm flapping",
                          BOX_STYLE.format(fill=NEUTRAL_C, fs=12, arc=20), 130, 200, 600, 70))

    # Row 3: weights
    cells.append(vertex("w_security", "w_security\n\u2191 as threat rises",
                          BOX_STYLE.format(fill=THREAT_C, fs=12, arc=20), 80, 360, 200, 80))
    cells.append(vertex("w_performance", "w_performance\n\u2191 as capability\nheadroom shrinks",
                          BOX_STYLE.format(fill=CAPAB_C, fs=12, arc=20), 330, 360, 200, 80))
    cells.append(vertex("w_efficiency", "w_efficiency\n\u2191 as energy shrinks",
                          BOX_STYLE.format(fill=ENERGY_C, fs=12, arc=20), 580, 360, 200, 80))
    cells.append(vertex("norm_note", "(the three weights are normalized to sum to 1)",
                          NOTE_STYLE, 280, 450, 300, 20))

    # Row 4: scores (HTML-formatted, so pass raw with escape handled inside)
    kyber_text = (f"<b>Kyber composite score</b><br><br>"
                   f"w_security \u00d7 {KYBER_SECURITY_RATING}&nbsp;&nbsp;\u25c0 lower security rating<br>"
                   f"+ w_performance \u00d7 perf_score&nbsp;&nbsp;(fast: wins)<br>"
                   f"+ w_efficiency \u00d7 eff_score&nbsp;&nbsp;(cheap: wins)")
    frodo_text = (f"<b>FrodoKEM composite score</b><br><br>"
                   f"w_security \u00d7 {FRODO_SECURITY_RATING}&nbsp;&nbsp;\u25c0 highest security rating<br>"
                   f"+ w_performance \u00d7 perf_score&nbsp;&nbsp;(slower)<br>"
                   f"+ w_efficiency \u00d7 eff_score&nbsp;&nbsp;(costlier)")
    cells.append(vertex("kyber_score", kyber_text,
                          BOX_STYLE.format(fill=KYBER_C, fs=11, arc=15), 80, 520, 330, 140))
    cells.append(vertex("frodo_score", frodo_text,
                          BOX_STYLE.format(fill=FRODO_C, fs=11, arc=15), 450, 520, 330, 140))

    # Row 5: decision diamond
    cells.append(vertex("decision",
                          f"scores within\nhybrid margin?\n|\u0394| \u2264 {HYBRID_MARGIN}",
                          f"rhombus;whiteSpace=wrap;html=1;fillColor={DECISION_C};"
                          f"strokeColor=#000000;strokeWidth=1.5;fontSize=11;",
                          310, 770, 240, 140))

    # Row 6: outcomes
    hybrid_text = ("<b>Hybrid mode</b><br>run BOTH KEMs, combine secrets<br><br>"
                    "security of the stronger<br>+ cost of both")
    select_text = ("<b>Select higher-scoring algorithm</b><br><br>"
                    "Kyber \u2192 speed &amp; efficiency<br>FrodoKEM \u2192 maximum security")
    cells.append(vertex("hybrid_outcome", hybrid_text,
                          BOX_STYLE.format(fill=HYBRID_C, fs=11, arc=15), 80, 1020, 300, 120))
    cells.append(vertex("select_outcome", select_text,
                          BOX_STYLE.format(fill=NEUTRAL_C, fs=11, arc=15), 480, 1020, 300, 120))

    # Arrows
    cells.append(edge("a1", "input_threat", "smoothing"))
    cells.append(edge("a2", "input_capability", "smoothing"))
    cells.append(edge("a3", "input_energy", "smoothing"))
    cells.append(edge("a4", "smoothing", "w_security", "exitX=0.25;exitY=1;exitDx=0;exitDy=0;"))
    cells.append(edge("a5", "smoothing", "w_performance", "exitX=0.5;exitY=1;exitDx=0;exitDy=0;"))
    cells.append(edge("a6", "smoothing", "w_efficiency", "exitX=0.75;exitY=1;exitDx=0;exitDy=0;"))
    cells.append(edge("a7", "w_security", "kyber_score"))
    cells.append(edge("a8", "w_performance", "kyber_score",
                       "exitX=0.25;exitY=1;exitDx=0;exitDy=0;entryX=0.75;entryY=0;entryDx=0;entryDy=0;"))
    cells.append(edge("a9", "w_performance", "frodo_score",
                       "exitX=0.75;exitY=1;exitDx=0;exitDy=0;entryX=0.25;entryY=0;entryDx=0;entryDy=0;"))
    cells.append(edge("a10", "w_efficiency", "frodo_score"))
    cells.append(edge("a11", "kyber_score", "decision", "entryX=0.25;entryY=0.25;entryDx=0;entryDy=0;"))
    cells.append(edge("a12", "frodo_score", "decision", "entryX=0.75;entryY=0.25;entryDx=0;entryDy=0;"))
    cells.append(edge("a13", "decision", "hybrid_outcome",
                       "exitX=0.25;exitY=0.75;exitDx=0;exitDy=0;fontSize=11;",
                       value="Yes\n(too close to call)"))
    cells.append(edge("a14", "decision", "select_outcome",
                       "exitX=0.75;exitY=0.75;exitDx=0;exitDy=0;fontSize=11;",
                       value="No\n(clear winner)"))

    body = "".join(cells)
    return f'''<mxfile host="app.diagrams.net" agent="build_figure6_drawio.py" version="24.0.0" type="device">
  <diagram name="Figure 6 - Q-Safe Decision Logic" id="qsafe-decision-logic">
    <mxGraphModel dx="1000" dy="1200" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="850" pageHeight="1400" math="0" shadow="0">
      <root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />
{body}      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
'''


def main():
    force = "--force" in sys.argv
    if os.path.exists(OUTPUT_FILE) and not force:
        print(f"REFUSING to overwrite existing '{OUTPUT_FILE}'.")
        print("That file may contain manual layout edits made in draw.io, which")
        print("regenerating would silently destroy. If you really want a fresh")
        print("starter layout, re-run with --force:")
        print(f"    python {os.path.basename(__file__)} --force")
        sys.exit(1)

    xml = build_xml()
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(xml)
    print(f"Wrote {OUTPUT_FILE}")
    print("Open it at app.diagrams.net (File -> Open) and edit visually from there.")
    print("Remember: after this point, the .drawio file is the source of truth,")
    print("not this script.")


if __name__ == "__main__":
    main()
