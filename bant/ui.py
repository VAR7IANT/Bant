"""Terminal output primitives shared by the CLI and the interactive TUI.

Uses Rich when it is importable and colour is wanted; otherwise falls back to readable plain
text (NO_COLOR, non-tty, TERM=dumb and missing Rich all land here). All dynamic text is escaped
so server-provided strings can never inject markup.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Sequence
from typing import Any, TextIO

try:  # Rich is optional at runtime
    from rich import box
    from rich.console import Console
    from rich.markup import escape
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    HAVE_RICH = True
except ImportError:  # pragma: no cover - exercised via force_plain in tests
    HAVE_RICH = False

STYLES = {"ok": "green", "warn": "yellow", "bad": "bold red", "dim": "dim", "accent": "cyan", "title": "bold"}
SEV_STYLE = {"critical": "bad", "high": "bad", "medium": "warn", "low": "accent", "info": "dim"}


class Abort(Exception):
    """User cancelled (Ctrl+C / Ctrl+D / EOF) at a prompt."""


def wants_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


class UI:
    def __init__(self, stream: TextIO | None = None, *, color: bool | None = None, force_plain: bool = False,
                 assume_yes: bool = False, input_fn=input):
        self.stream = stream or sys.stdout
        self.color = wants_color(self.stream) if color is None else color
        self.rich = HAVE_RICH and not force_plain
        self.assume_yes = assume_yes
        self._input = input_fn
        if self.rich:
            self.console = Console(file=self.stream, no_color=not self.color, highlight=False,
                                   force_terminal=self.color or None, color_system="auto" if self.color else None)

    # ---- geometry ----------------------------------------------------------
    @property
    def width(self) -> int:
        cols = self.console.width if self.rich else _term_width()
        return max(40, min(cols, 78))

    # ---- basic output ------------------------------------------------------
    def text(self, message: str = "", style: str | None = None) -> None:
        if self.rich:
            self.console.print(Text(message, style=STYLES.get(style or "", "")) if style else Text(message))
        else:
            print(message, file=self.stream)

    def success(self, message: str) -> None:
        self.text(f"{self.glyph('ok')} {message}" if self.unicode else f"[OK] {message}", "ok")

    def warn(self, message: str) -> None:
        self.text(f"! {message}" if self.unicode else f"[WARN] {message}", "warn")

    def error(self, message: str) -> None:
        self.text(f"{self.glyph('bad')} {message}" if self.unicode else f"[ERROR] {message}", "bad")

    def info(self, message: str) -> None:
        self.text(message, "dim")

    def bullet(self, message: str, style: str | None = None) -> None:
        self.text(f"  • {message}" if self.unicode else f"  - {message}", style)

    def glyph(self, kind: str) -> str:
        """Status mark that degrades to ASCII on terminals without UTF-8."""
        uni = {"ok": "✔", "bad": "✘", "warn": "!", "skip": "·", "wait": "…", "dot": "•"}
        asc = {"ok": "OK", "bad": "X", "warn": "!", "skip": "-", "wait": "...", "dot": "-"}
        return (uni if self.unicode else asc).get(kind, "")

    @property
    def unicode(self) -> bool:
        enc = (getattr(self.stream, "encoding", "") or "").lower()
        return "utf" in enc and os.environ.get("TERM") != "linux"

    def rule(self) -> None:
        self.text(("─" if self.unicode else "-") * self.width, "dim")

    def heading(self, title: str, subtitle: str | None = None) -> None:
        if self.rich and self.unicode:
            body = Text(title, style="bold", justify="center")
            if subtitle:
                body.append("\n" + subtitle, style="dim")
            self.console.print(Panel(body, box=box.ROUNDED, width=self.width, border_style="cyan" if self.color else ""))
            return
        bar = "+" + "-" * (self.width - 2) + "+"
        self.text(bar)
        self.text("|" + title.center(self.width - 2) + "|")
        if subtitle:
            self.text("|" + subtitle.center(self.width - 2) + "|")
        self.text(bar)

    def section(self, title: str) -> None:
        self.text("")
        self.text(f" {title.upper()}", "title")
        self.rule()

    # ---- structured output -------------------------------------------------
    def kv(self, rows: Iterable[tuple[str, Any, str | None]], label_width: int = 24) -> None:
        for label, value, style in rows:
            line = f" {label:<{label_width}} {value}"
            self.text(line, style)

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[Any]], styles: Sequence[str | None] | None = None) -> None:
        if not rows:
            self.info("  (none)")
            return
        if self.rich:
            t = Table(box=box.SIMPLE_HEAD if self.unicode else box.ASCII, show_edge=False, pad_edge=False, expand=False)
            for h in headers:
                t.add_column(h, overflow="fold")
            for i, row in enumerate(rows):
                st = STYLES.get((styles[i] if styles else None) or "", "")
                t.add_row(*[Text(str(c), style=st) for c in row])
            self.console.print(t)
            return
        widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        self.text(fmt.format(*headers), "title")
        for r in rows:
            self.text(fmt.format(*[str(c) for c in r]))

    def menu(self, items: Sequence[tuple[str, str]]) -> None:
        for key, label in items:
            self.text(f" {key:>2}. {label}")

    # ---- input -------------------------------------------------------------
    def ask(self, prompt: str, default: str | None = None) -> str:
        suffix = f" [{default}]" if default else ""
        try:
            answer = self._input(f"{prompt}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            self.text("")
            raise Abort from None
        return answer or (default or "")

    def confirm(self, prompt: str, default: bool = False) -> bool:
        if self.assume_yes:
            return True
        hint = "Y/n" if default else "y/N"
        while True:
            answer = self.ask(f"{prompt} ({hint})").lower()
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            self.text("Please answer yes or no.", "warn")

    def pause(self) -> None:
        try:
            self._input("\nPress Enter to continue...")
        except (EOFError, KeyboardInterrupt):
            raise Abort from None

    def clear(self) -> None:
        if self.color and getattr(self.stream, "isatty", lambda: False)():
            self.stream.write("\033[2J\033[H")
            self.stream.flush()


def _term_width() -> int:
    import shutil

    return shutil.get_terminal_size((80, 24)).columns


def style_for_state(state: str) -> str:
    return {"verified": "ok", "running": "ok", "active": "ok", "healthy": "ok", "ok": "ok", "enabled": "ok",
            "misconfigured": "bad", "failed": "bad", "critical": "bad", "fail": "bad", "unavailable": "bad",
            "inactive": "warn", "attention": "warn", "warn": "warn", "pending": "warn",
            "not_installed": "dim", "unknown": "dim", "skip": "dim"}.get(state, "")


def esc(text: str) -> str:
    return escape(text) if HAVE_RICH else text
