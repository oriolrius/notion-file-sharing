"""Render docs/diagrams/*.puml to docs/images/*.svg.

Usage (from the repository root):
    uv run --no-project python docs/diagrams/render.py [path/to/plantuml.jar]

The SVG files are made self-contained, so they look the same on GitHub and offline:
- the Ubuntu fonts from assets/fonts/ are embedded as @font-face (base64 woff2);
- screenshots that PlantUML down-sampled (<img:...{scale=...}>) are replaced by the
  full-resolution PNG, at the same size on the page (sharp on HiDPI screens).
"""

import base64
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "docs" / "diagrams"
OUT = ROOT / "docs" / "images"
FONTS = ROOT / "assets" / "fonts"
JAR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / ".cache/plantuml/plantuml.jar"

FACES = [
    ("Ubuntu", 300, "ubuntu-latin-300-normal.woff2"),
    ("Ubuntu", 400, "ubuntu-latin-400-normal.woff2"),
    ("Ubuntu", 500, "ubuntu-latin-500-normal.woff2"),
    ("Ubuntu", 700, "ubuntu-latin-700-normal.woff2"),
    ("Ubuntu Mono", 400, "ubuntu-mono-latin-400-normal.woff2"),
]


def b64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode()


def font_style() -> str:
    rules = "".join(
        f"@font-face{{font-family:'{family}';font-weight:{weight};font-style:normal;"
        f"src:url(data:font/woff2;base64,{b64(FONTS / file)}) format('woff2');}}"
        for family, weight, file in FACES
    )
    return f"<defs><style>{rules}</style></defs>"


def screenshots(puml: Path) -> list[Path]:
    """Images in the order they appear in the diagram source."""
    return [
        (puml.parent / m).resolve()
        for m in re.findall(r"<img:([^>{]+)", puml.read_text(encoding="utf-8"))
    ]


def fix_svg(svg: Path, images: list[Path], style: str) -> None:
    text = svg.read_text(encoding="utf-8")
    it = iter(images)

    def swap(m: re.Match) -> str:
        src = next(it, None)
        if src is None:
            return m.group(0)
        return f'{m.group(1)}data:image/png;base64,{b64(src)}"'

    text = re.sub(r'(<image\b[^>]*?xlink:href=")data:image/png;base64,[^"]*"', swap, text)
    text = re.sub(r"(<svg\b[^>]*>)", lambda m: m.group(1) + style, text, count=1)
    svg.write_text(text, encoding="utf-8")


def main() -> None:
    sources = sorted(p for p in SRC.glob("[0-9]*.puml"))
    for fmt in ("-tsvg",):
        subprocess.run(
            ["java", "-Djava.awt.headless=true", "-jar", str(JAR), fmt, "-o", str(OUT)]
            + [str(p) for p in sources],
            check=True,
        )
    style = font_style()
    for puml in sources:
        svg = OUT / (puml.stem + ".svg")
        fix_svg(svg, screenshots(puml), style)
        print(f"{svg.relative_to(ROOT)}  {svg.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
