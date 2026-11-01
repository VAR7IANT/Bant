"""Terminal output primitives shared by the CLI and the interactive TUI.

Uses Rich when it is importable and colour is wanted; otherwise falls back to readable plain
text (NO_COLOR, non-tty, TERM=dumb and missing Rich all land here). All dynamic text is escaped
so server-provided strings can never inject markup.
"""

from __future__ import annotations

import os
import re
import sys
import unicodedata
from collections.abc import Iterable, Sequence
from typing import Any, TextIO

from bant.i18n import tr

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


YES_WORDS = {"y", "yes", "是", "好", "確定", "确定", "確認", "确认"}
NO_WORDS = {"n", "no", "否", "不", "取消"}


def stream_shows_cjk(stream: TextIO) -> bool:
    """True when the stream looks like a UTF-8 terminal (Chinese would otherwise be garbled)."""
    enc = (getattr(stream, "encoding", "") or "").lower()
    return "utf" in enc and os.environ.get("TERM") != "linux"


def display_width(text: str) -> int:
    """Terminal cell width (East Asian wide/fullwidth characters take two cells)."""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else (0 if unicodedata.combining(ch) else 1) for ch in text)


def pad(text: str, width: int) -> str:
    return text + " " * max(0, width - display_width(text))


def center(text: str, width: int) -> str:
    gap = max(0, width - display_width(text))
    return " " * (gap // 2) + text + " " * (gap - gap // 2)


class Abort(Exception):
    """User cancelled (Ctrl+C / Ctrl+D / EOF) at a prompt."""


class Cancelled(Abort):
    """The user left a required value empty (Enter): cancel the current action and go back."""


BACK_WORDS = {"0", "b", "q", "back", "quit", "exit"}  # still accepted for muscle memory; the prompt advertises Enter


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
        self.menu_mode = False  # interactive menus: an empty answer always means "no / cancel / back"
        self.force_logo = False  # tests: draw the logo although the stream is not a terminal
        self.term_size: tuple[int, int] | None = None  # tests: (columns, rows) instead of the real window
        self._logo_shown = False
        if self.rich:
            self.console = Console(file=self.stream, no_color=not self.color, highlight=False,
                                   force_terminal=self.color or None, color_system="auto" if self.color else None)

    # ---- geometry ----------------------------------------------------------
    @property
    def width(self) -> int:
        cols = self.console.width if self.rich else _term_width()
        return max(30, min(cols, 72))  # phone SSH clients are often 40-50 columns wide

    @property
    def narrow(self) -> bool:
        return self.width < 50

    # ---- basic output ------------------------------------------------------
    def text(self, message: str = "", style: str | None = None, *, raw: bool = False, fold: bool = True) -> None:
        """Print a message (translated). raw=True prints data such as log lines untouched."""
        message = message if raw else tr(message)
        if fold and not self.rich and "\n" not in message and display_width(message) > self.width:
            message = "\n".join(wrap(message, self.width))
        if self.rich:
            self.console.print(Text(message, style=STYLES.get(style or "", "")) if style else Text(message))
        else:
            print(message, file=self.stream)

    def success(self, message: str) -> None:
        self.text(f"{self.glyph('ok')} {tr(message)}" if self.unicode else f"[OK] {tr(message)}", "ok", raw=True)

    def warn(self, message: str) -> None:
        self.text(f"! {tr(message)}" if self.unicode else f"[WARN] {tr(message)}", "warn", raw=True)

    def error(self, message: str) -> None:
        self.text(f"{self.glyph('bad')} {tr(message)}" if self.unicode else f"[ERROR] {tr(message)}", "bad", raw=True)

    def info(self, message: str) -> None:
        self.text(message, "dim")

    def bullet(self, message: str, style: str | None = None) -> None:
        self.text(f"  • {tr(message)}" if self.unicode else f"  - {tr(message)}", style, raw=True)

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
        title, subtitle = tr(title), (tr(subtitle) if subtitle else None)
        if self.narrow:  # no box on small screens: two plain lines
            self.text(f" {title}", "title", raw=True)
            if subtitle:
                self.text(f" {subtitle}", "dim", raw=True)
            self.rule()
            return
        if self.rich and self.unicode:
            body = Text(title, style="bold", justify="center")
            if subtitle:
                body.append("\n" + subtitle, style="dim")
            self.console.print(Panel(body, box=box.ROUNDED, width=self.width, border_style="cyan" if self.color else ""))
            return
        bar = "+" + "-" * (self.width - 2) + "+"
        self.text(bar)
        self.text("|" + center(title, self.width - 2) + "|", raw=True)
        if subtitle:
            self.text("|" + center(subtitle, self.width - 2) + "|", raw=True)
        self.text(bar)

    def section(self, title: str) -> None:
        self.text("")
        t = tr(title)
        self.text(f" {t if _CJK.search(t) else t.upper()}", "title", raw=True)
        self.rule()

    # ---- structured output -------------------------------------------------
    def kv(self, rows: Iterable[tuple[str, Any, str | None]], label_width: int = 24) -> None:
        if self.narrow:
            label_width = min(label_width, 14)
        for label, value, style in rows:
            shown = tr(value, record=False) if isinstance(value, str) else value  # values are mostly data; the static scan covers templates
            self.text(f" {pad(tr(label), label_width)} {shown}", style, raw=True)

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[Any]], styles: Sequence[str | None] | None = None) -> None:
        headers = [tr(h) for h in headers]
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
        widths = [max(display_width(str(h)), *(display_width(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
        self.text("  ".join(pad(str(h), w) for h, w in zip(headers, widths, strict=True)), "title", raw=True, fold=False)
        for r in rows:
            self.text("  ".join(pad(str(c), w) for c, w in zip(r, widths, strict=True)), raw=True, fold=False)

    def menu(self, items: Sequence[tuple[str, str]]) -> None:
        for key, label in items:
            self.text(f" {key:>2}. {tr(label)}", raw=True)

    # ---- input -------------------------------------------------------------
    def ask(self, prompt: str, default: str | None = None, *, translate: bool = True) -> str:
        suffix = f" [{default}]" if default else ""
        try:
            answer = self._input(f"{tr(prompt) if translate else prompt}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            self.text("")
            raise Abort from None
        return answer or (default or "")

    def ask_required(self, prompt: str, *, translate: bool = True) -> str:
        """A value the action cannot do without. Enter (empty) cancels the action instead of guessing a default."""
        answer = self.ask(f"{tr(prompt) if translate else prompt} ({tr('Enter to cancel')})", translate=False)
        if not answer:
            raise Cancelled
        return answer

    def confirm(self, prompt: str, default: bool = False) -> bool:
        """Yes/no question. In the interactive menus an empty answer is always "no", never consent."""
        if self.assume_yes:
            return True
        if self.menu_mode:
            default = False
        hint = "Y/n" if default else "y/N"
        while True:
            answer = self.ask(f"{tr(prompt)} ({hint})", translate=False).lower()
            if not answer:
                return default
            if answer in YES_WORDS:
                return True
            if answer in NO_WORDS:
                return False
            self.text("Please answer yes or no.", "warn")

    def select(self, keys: Iterable[str], *, top: bool = False) -> str | None:
        """The one menu prompt used by every menu.

        Returns the chosen key, or None for "go back" (Enter, 0/b/q, Ctrl+C or EOF; on the main menu: exit).
        An unknown answer is reported and asked again without redrawing the menu.
        """
        valid = {k.lower() for k in keys}
        prompt = "Select an option (Enter to exit)" if top else "Select an option (Enter to go back)"
        while True:
            try:
                answer = self.ask(prompt).strip().lower()
            except Abort:
                return None
            if not answer or answer in BACK_WORDS and answer not in valid:
                return None
            if answer in valid:
                return answer
            self.warn(f"Unknown option '{answer}'. Type a number from the list, or press Enter to go back."
                      if not top else f"Unknown option '{answer}'. Type a number from the list, or press Enter to exit.")

    # ---- logo --------------------------------------------------------------
    @property
    def interactive(self) -> bool:
        return bool(getattr(self.stream, "isatty", lambda: False)()) and sys.stdin.isatty()

    def logo(self, *, once: bool = True) -> None:
        """The BANT block-letter banner, for people at a terminal only (never in pipes, scripts or --json)."""
        from bant import logo

        if (once and self._logo_shown) or not (self.interactive or self.force_logo):
            return
        self._logo_shown = True
        import shutil

        cols, rows = self.term_size or tuple(shutil.get_terminal_size((80, 0)))
        art = logo.render(cols, color=self.color, rich=logo.rich_color() or self.force_logo, unicode=self.unicode, height=rows)
        self.stream.write("\n" + art)
        self.stream.flush()


_CJK = re.compile(r"[\u3000-\u9fff\uff00-\uffef]")


def wrap(text: str, width: int) -> list[str]:
    """Wrap by display width (CJK characters count double); continuation lines keep the leading indent."""
    indent = " " * (len(text) - len(text.lstrip(" ")) + (2 if text.lstrip().startswith(("!", "•", "-", "✔", "✘")) else 0))
    lines, cur = [], ""
    for token in re.findall(r"\S+\s*|\s+", text):
        if display_width(cur + token.rstrip()) <= width or not cur.strip():
            cur += token
            while display_width(cur.rstrip()) > width:  # a single long token (or CJK run): hard break
                cut = len(cur)
                while cut > 1 and display_width(cur[:cut]) > width:
                    cut -= 1
                lines.append(cur[:cut].rstrip())
                cur = indent + cur[cut:]
            continue
        lines.append(cur.rstrip())
        cur = indent + token
    if cur.strip():
        lines.append(cur.rstrip())
    return lines or [text]


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
