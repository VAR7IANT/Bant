"""The BANT block-letter logo, drawn in the same design language as Rout's ROUT logo.

Same "ANSI Shadow" letterforms (full blocks with box-drawing shadows), six rows, 35 columns wide, a
restrained top-to-bottom blue gradient from the xterm-256 palette, and the credit and version centred
beneath it. The logo is plain terminal text - no images, no alternate screen, no cursor movement - and
every coloured span ends with a reset so the terminal state is never left modified.

It is only shown to a person at a real UTF-8 terminal: piped/captured output, scripts, `--json`,
non-UTF-8 terminals and windows narrower than the logo get a compact one-line title instead.
"""

from __future__ import annotations

import os

from bant import __version__

#   B (8)    A (8)    N (10)      T (9)   = 35 columns, exactly like ROUT (8 + 9 + 9 + 9)
LOGO_LINES = [
    "██████╗  █████╗ ███╗   ██╗████████╗",
    "██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝",
    "██████╔╝███████║██╔██╗ ██║   ██║   ",
    "██╔══██╗██╔══██║██║╚██╗██║   ██║   ",
    "██████╔╝██║  ██║██║ ╚████║   ██║   ",
    "╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ",
]
LOGO_WIDTH = 35
CREDIT = "Support by VAR7IANT"
GRADIENT = [39, 38, 33, 32, 27, 26]  # Rout's palette: the two tools read as one family
COMPACT_BELOW_ROWS = 30  # short windows get the compact title so the first menu fits on one screen
RESET = "\033[0m"


def rich_color(env: dict[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return "256color" in env.get("TERM", "") or bool(env.get("COLORTERM"))


def compact_title(width: int, color: bool) -> str:
    """One line: 'BANT v0.1.2 · Support by VAR7IANT', shortened to fit `width`."""
    version = f"v{__version__}"
    for parts in ((f"BANT {version}", CREDIT), (f"BANT {version}", "VAR7IANT"), (f"BANT {version}",), ("BANT",)):
        line = " · ".join(parts)
        if len(line) <= width:
            break
    if not color:
        return line
    head, sep, tail = line.partition(" · ")
    head = head.replace("BANT", f"\033[1;34mBANT{RESET}", 1)
    return head + (f"\033[2m{sep}{tail}{RESET}" if sep else "")


def render(width: int, *, color: bool, rich: bool, unicode: bool = True, height: int = 0) -> str:
    """The banner for a terminal of `width` columns (and `height` rows, 0 = unknown)."""
    if not unicode or width < LOGO_WIDTH + 4 or (0 < height < COMPACT_BELOW_ROWS):
        return compact_title(width, color) + "\n"
    out = []
    for i, line in enumerate(LOGO_LINES):
        if color and rich:
            out.append(f"  \033[38;5;{GRADIENT[i]}m{line}{RESET}")
        elif color:
            out.append(f"  \033[34m{line}{RESET}")
        else:
            out.append(f"  {line}")
    for sub in (CREDIT, f"v{__version__}"):
        lead = 2 + max(0, (LOGO_WIDTH - len(sub)) // 2)
        out.append(" " * lead + (f"\033[2m{sub}{RESET}" if color else sub))
    return "\n".join(out) + "\n"
