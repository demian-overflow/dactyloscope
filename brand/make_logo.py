"""Generate the Dactyloscope mark: a mirror-symmetric concentric-whorl fingerprint.

    python3 brand/make_logo.py            # writes brand/logo.svg and brand/favicon.svg
"""
from math import cos, pi, sin
from pathlib import Path

BG, RIDGE, ACCENT = "#0B1020", "#E6EDF5", "#38D9F5"
CX, CY = 256, 262          # optical centre sits slightly below the geometric one
ASPECT = 0.80              # rx / ry: slightly tall ovals, like a real print


def point(r: float, t: float) -> tuple[float, float]:
    """Ellipse point; t = 0 at the top, clockwise."""
    return CX + r * ASPECT * sin(t), CY - r * cos(t)


def arc(r: float, t0: float, t1: float) -> str:
    """SVG path for the ellipse arc from t0 to t1 (clockwise)."""
    (x0, y0), (x1, y1) = point(r, t0), point(r, t1)
    large = 1 if (t1 - t0) % (2 * pi) > pi else 0
    return f"M{x0:.2f} {y0:.2f}A{r * ASPECT:.2f} {r:.2f} 0 {large} 1 {x1:.2f} {y1:.2f}"


def ring(r: float, gaps: list[tuple[float, float]]) -> list[str]:
    """A ridge with gaps, each gap = (centre angle, gap length in px). Gaps sorted by angle."""
    cuts = sorted(((c - g / r / 2) % (2 * pi), (c + g / r / 2) % (2 * pi)) for c, g in gaps)
    segs = []
    for i, (_, end) in enumerate(cuts):
        nxt = cuts[(i + 1) % len(cuts)][0]
        if nxt <= end:
            nxt += 2 * pi
        segs.append(arc(r, end, nxt))
    return segs


def mirrored(angle: float, gap: float) -> list[tuple[float, float]]:
    return [(angle, gap), (2 * pi - angle, gap)]


def build(ridges: list[tuple[float, list, str]], stroke: float, core: float, size: int = 512, radius: int = 0) -> str:
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="{size}" height="{size}">',
           f'<rect width="512" height="512" rx="{radius}" fill="{BG}"/>',
           f'<g fill="none" stroke-width="{stroke}" stroke-linecap="round">']
    for r, gaps, colour in ridges:
        out.append(f'<path stroke="{colour}" d="{"".join(ring(r, gaps))}"/>')
    out += ["</g>", f'<circle cx="{CX}" cy="{CY}" r="{core}" fill="{ACCENT}"/>', "</svg>"]
    return "\n".join(out) + "\n"


BOTTOM, TOP = pi, 0.0
# Full mark: six ridges. Every ridge opens at the bottom (where a print's ridges flow out);
# the cyan accent ridge has the one break at the top, on the axis.
LOGO = [
    (46,  [(BOTTOM, 30)], RIDGE),
    (74,  [(BOTTOM, 36)], RIDGE),
    (102, [(TOP, 30), (BOTTOM, 42)], ACCENT),
    (130, mirrored(2.25, 26) + [(BOTTOM, 48)], RIDGE),
    (158, [(BOTTOM, 54)], RIDGE),
    (186, mirrored(1.15, 30) + [(BOTTOM, 108)], RIDGE),
]
# Favicon: fewer, thicker ridges so it survives 32 px.
FAVICON = [
    (66,  [(BOTTOM, 48)], RIDGE),
    (122, [(TOP, 52), (BOTTOM, 60)], ACCENT),
    (178, [(BOTTOM, 112)], RIDGE),
]

if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    (here / "logo.svg").write_text(build(LOGO, stroke=15, core=18))
    (here / "favicon.svg").write_text(build(FAVICON, stroke=34, core=30, size=32, radius=96))
    print("wrote", here / "logo.svg", here / "favicon.svg")
