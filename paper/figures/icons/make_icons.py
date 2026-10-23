#!/usr/bin/env python3
"""Render the Font Awesome Free icons used by the hand-drawn manuscript figures as small PDFs.

    python3 make_icons.py /path/to/fontawesome-free/svgs/solid

Icons: Font Awesome Free 7.3.1 (https://fontawesome.com), CC BY 4.0 for the icon artwork; the
npm package @fortawesome/fontawesome-free carries the licence. Only the icons named below are
rendered in the colours below; the figures use one colour per icon, and unused files are pruned.
"""
import pathlib
import sys

import cairosvg

ICONS = ["arrows-rotate", "ban", "bell", "bolt", "chart-line", "circle-check", "circle-xmark", "cloud", "code", "coins", "comment-sms", "database", "dice", "file-contract", "flask", "gauge-high", "gears", "globe", "hand-holding-dollar", "laptop", "list-check", "mask", "mobile-screen-button", "paper-plane", "phone-volume", "robot", "route", "sack-dollar", "server", "shield-halved", "square-check", "stopwatch", "tower-broadcast", "tower-cell", "user", "user-secret", "users"]
COLOURS = {"white": "#ffffff", "dark": "#2b2d42", "red": "#d9480f", "indigo": "#3b3f8f", "teal": "#1c8e9e", "green": "#2e8b4a",
           "amber": "#b7791f", "slate": "#4a5568"}


def main(src):
    src = pathlib.Path(src)
    out = pathlib.Path(__file__).resolve().parent
    for name in ICONS:
        svg = (src / f"{name}.svg").read_text()
        for cname, hexcol in COLOURS.items():
            coloured = svg.replace("<svg ", f'<svg fill="{hexcol}" ', 1).replace('fill="currentColor"', f'fill="{hexcol}"')
            cairosvg.svg2pdf(bytestring=coloured.encode(), write_to=str(out / f"{name}-{cname}.pdf"))
    print(f"{len(ICONS)} icons x {len(COLOURS)} colours written to {out}")


if __name__ == "__main__":
    main(sys.argv[1])
