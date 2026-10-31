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
PORT_MAX = 65535
DEFAULT_EPHEMERAL = (32768, 60999)
# Ports that well-known software likes to use (monitoring agents, databases, game servers, VPNs, ...).
AVOID = frozenset({10000, 10050, 10051, 11211, 15672, 19999, 25565, 27017, 27018, 27019, 30000, 32400, 50000, 51820})


class NoFreePort(OperationFailed):
    """No port passed the checks; the user has to pick one."""


def _read_range(ctx: Context) -> tuple[int, int] | None:
    parts = read_text(ctx.paths.proc / "sys/net/ipv4/ip_local_port_range").split()
    try:
        lo, hi = int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return None
    if not (1 <= lo <= hi <= PORT_MAX):
        return None
    return lo, hi


def ephemeral_range(ctx: Context) -> tuple[int, int]:
    """The kernel's range for outgoing connections. Missing or malformed values fall back to the Linux default."""
    return _read_range(ctx) or DEFAULT_EPHEMERAL


def reserved_ports(ctx: Context) -> set[int]:
    """net.ipv4.ip_local_reserved_ports: never handed out for outgoing connections, so safe to listen on."""
    out: set[int] = set()
    for part in read_text(ctx.paths.proc / "sys/net/ipv4/ip_local_reserved_ports").replace("\n", ",").split(","):
        part = part.strip()
        try:
            if "-" in part:
                a, b = (int(x) for x in part.split("-", 1))
            elif part:
                a = b = int(part)
            else:
                continue
        except ValueError:
            continue
        if 1 <= a <= b <= PORT_MAX and b - a < 70000:
            out.update(range(a, b + 1))
    return out


def in_use(ctx: Context) -> set[int]:
    """Ports with a listening TCP socket or a bound UDP socket."""
    return {lst.port for lst in netinfo.listeners(ctx)}


def _windows(ctx: Context) -> list[tuple[int, int]]:
    """Ranges >= RANDOM_MIN that lie outside the ephemeral range (may be empty, e.g. ephemeral = 1024-65535)."""
    lo, hi = ephemeral_range(ctx)
    wins = [(RANDOM_MIN, min(lo - 1, PORT_MAX)), (max(hi + 1, RANDOM_MIN), PORT_MAX)]
    return [(a, b) for a, b in wins if a <= b]


def candidates(ctx: Context, exclude: Iterable[int] = ()) -> tuple[list[int], str]:
    """Ports that may be chosen at random, and the strategy that produced them.

    preferred   outside the ephemeral range (or in ip_local_reserved_ports), not listening, not on the avoid list
    ephemeral   only used when the kernel's ephemeral range covers every preferred port: a port inside it that
                no socket at all uses right now (listening, connected or bound; TCP and UDP). Once sshd listens
                on it the kernel no longer hands it out for outgoing connections.
    """
    busy = in_use(ctx) | set(exclude) | AVOID
    reserved = {p for p in reserved_ports(ctx) if p >= RANDOM_MIN}
    pool: set[int] = set(reserved)
    for a, b in _windows(ctx):
        pool.update(range(a, b + 1))
    preferred = sorted(pool - busy)
    if preferred:
        return preferred, "preferred"
    lo, hi = ephemeral_range(ctx)
    used = busy | netinfo.local_ports_in_use(ctx)
    fallback = [p for p in range(max(lo, RANDOM_MIN), hi + 1) if p not in used]
    return fallback, "ephemeral"


def pick_random(ctx: Context, exclude: Iterable[int] = ()) -> int:
    """A free random port. Raises NoFreePort (a normal, explained error) when nothing qualifies."""
    pool, _strategy = candidates(ctx, exclude)
    if not pool:
        lo, hi = ephemeral_range(ctx)
        raise NoFreePort(f"No free port found for SSH between {RANDOM_MIN} and {PORT_MAX} (the kernel's outgoing-connection range is {lo}-{hi}).",
                         hint="Choose a port yourself, e.g. `sudo bant ssh port 667` or `sudo bant setup --ssh-port 667`.")
    return pool[ctx.rng.randrange(len(pool))]


def random_strategy(ctx: Context, port: int) -> str:
    return "ephemeral" if in_ephemeral_range(ctx, port) and port not in reserved_ports(ctx) else "preferred"


def in_ephemeral_range(ctx: Context, port: int) -> bool:
    lo, hi = ephemeral_range(ctx)
    return lo <= port <= hi and port not in reserved_ports(ctx)


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
