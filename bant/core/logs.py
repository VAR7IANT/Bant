"""Log access: Bant's own audit trail plus SSH and Fail2ban events (read on demand, never polled)."""

from __future__ import annotations

from bant.context import Context
from bant.errors import ValidationError
from bant.utils.fsutil import read_text
from bant.utils.logging import redact

SOURCES = ("audit", "ssh", "fail2ban")


def read_lines(ctx: Context, source: str, lines: int = 50, grep: str | None = None) -> list[str]:
    """Plain-text lines for the ssh/fail2ban sources (journal first, then log files)."""
    if source == "ssh":
        argv = ["journalctl", "--no-pager", "-q", "-o", "short-iso", "-n", str(max(lines * 6, 200)),
                "-u", "ssh.service", "-u", "sshd.service"]
        fallback = ctx.paths.auth_log
    elif source == "fail2ban":
        argv = ["journalctl", "--no-pager", "-q", "-o", "short-iso", "-n", str(max(lines * 6, 200)), "-u", "fail2ban.service"]
        fallback = ctx.paths.p("/var/log/fail2ban.log")
    else:
        raise ValidationError(f"Unknown log source {source!r}", hint="Use: " + ", ".join(SOURCES))
    res = ctx.run(argv, timeout=30)
    text = res.stdout if res.ok and res.stdout.strip() else read_text(fallback)
    out = [redact(line) for line in text.splitlines() if line.strip()]
    if grep:
        needle = grep.lower()
        out = [line for line in out if needle in line.lower()]
    return out[-lines:]
