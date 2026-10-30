"""Choosing the SSH port: one you specify, one already in use, or a random free one (the default).

Random ports are drawn from 10240-65535 but never from the kernel's ephemeral (outgoing connection)
range, never from a port something already listens on (TCP or UDP), and never from a short list of
ports that well-known applications like to use.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from bant.context import Context
from bant.core import netinfo, ssh
from bant.errors import OperationFailed
from bant.utils.fsutil import read_text
from bant.utils.validation import parse_port

RANDOM_MIN = 10240
DEFAULT_EPHEMERAL = (32768, 60999)
AVOID = frozenset({10000, 11211, 15672, 25565, 27017, 27018, 30000, 32400, 51820})


def ephemeral_range(ctx: Context) -> tuple[int, int]:
    parts = read_text(ctx.paths.proc / "sys/net/ipv4/ip_local_port_range").split()
    try:
        return int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return DEFAULT_EPHEMERAL


def in_use(ctx: Context) -> set[int]:
    return {lst.port for lst in netinfo.listeners(ctx)}


def _windows(ctx: Context) -> list[tuple[int, int]]:
    lo, hi = ephemeral_range(ctx)
    wins = [(RANDOM_MIN, min(lo - 1, 65535)), (max(hi + 1, RANDOM_MIN), 65535)]
    return [(a, b) for a, b in wins if b >= a]


def pick_random(ctx: Context, exclude: Iterable[int] = ()) -> int:
    """A free random port outside the ephemeral range."""
    busy = in_use(ctx) | set(exclude) | AVOID
    wins = _windows(ctx)
    total = sum(b - a + 1 for a, b in wins)
    for _ in range(1000):
        n = ctx.rng.randrange(total)
        for a, b in wins:
            size = b - a + 1
            if n < size:
                port = a + n
                break
            n -= size
        if port not in busy:
            return port
    raise OperationFailed("Could not find a free random port.", hint="Choose one yourself: `sudo bant ssh port <PORT>`.")


def in_ephemeral_range(ctx: Context, port: int) -> bool:
    lo, hi = ephemeral_range(ctx)
    return lo <= port <= hi


def resolve_target(ctx: Context, requested: str | int | None = None) -> tuple[int, str]:
    """Return (port, source). source is one of:

    requested   the user gave a number
    random      a new random port (user asked for 'random', or nothing was chosen before)
    config      the port stored in bant.toml from an earlier run
    existing    SSH already listens on a single non-default port; Bant keeps it
    remembered  the random port chosen by an earlier, unfinished run (so reruns are stable)
    """
    st = ssh.status(ctx)
    current = st.active_ports
    if requested is not None and str(requested).strip().lower() == "random":
        return pick_random(ctx, exclude=current), "random"
    if requested is not None:
        return parse_port(requested), "requested"
    if ctx.config.ssh_port:
        return ctx.config.ssh_port, "config"
    if len(current) == 1 and current[0] != 22:
        return current[0], "existing"
    remembered: Any = ctx.state.get("ssh", "planned_port")
    if isinstance(remembered, int) and remembered not in in_use(ctx):
        return remembered, "remembered"
    return pick_random(ctx, exclude=current), "random"


def remember(ctx: Context, port: int) -> None:
    """Persist the chosen port so that a re-run after an interrupted/rolled-back attempt reuses it."""
    if not ctx.dry_run:
        ctx.state.update(lambda d: d.setdefault("ssh", {}).__setitem__("planned_port", port))


DESCRIPTIONS = {
    "requested": "chosen by you",
    "random": "random",
    "config": "from your Bant configuration",
    "existing": "your existing non-default SSH port (kept)",
    "remembered": "random, chosen by an earlier run",
}
