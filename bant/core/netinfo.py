"""Server-side network facts: listening sockets, SSH sessions and the admin's own connection.

Connection facts come from the kernel (/proc) rather than from client-supplied data such as
environment variables, so they can be used to verify that a *new* login really arrived on a
given listener.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path

from bant.context import Context
from bant.utils.fsutil import read_text

TCP_ESTABLISHED = "01"
TCP_LISTEN = "0A"
_SESSION_RE = re.compile(r"^sshd(?:-session)?: (\S+?)@(\S+)\s*$")


# ---------------------------------------------------------------------------
# /proc/net/tcp parsing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TcpEntry:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    inode: str


def _hex_ip(h: str) -> str:
    raw = bytes.fromhex(h)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    words = [raw[i:i + 4][::-1] for i in range(0, 16, 4)]
    addr = ipaddress.IPv6Address(b"".join(words))
    return str(addr.ipv4_mapped) if addr.ipv4_mapped else str(addr)


def parse_proc_net_tcp(text: str) -> list[TcpEntry]:
    out = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            lip, lport = parts[1].split(":")
            rip, rport = parts[2].split(":")
            out.append(TcpEntry(_hex_ip(lip), int(lport, 16), _hex_ip(rip), int(rport, 16), parts[3], parts[9]))
        except ValueError:
            continue
    return out


def tcp_table(ctx: Context) -> list[TcpEntry]:
    entries: list[TcpEntry] = []
    for name in ("tcp", "tcp6"):
        entries += parse_proc_net_tcp(read_text(ctx.paths.proc / "net" / name))
    return entries


def local_ports_in_use(ctx: Context) -> set[int]:
    """Local port of every TCP/UDP socket in any state (listening, connected, bound), IPv4 and IPv6."""
    out: set[int] = set()
    for name in ("tcp", "tcp6", "udp", "udp6"):
        out.update(e.local_port for e in parse_proc_net_tcp(read_text(ctx.paths.proc / "net" / name)))
    return out


# ---------------------------------------------------------------------------
# Listening sockets
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Listener:
    proto: str
    addr: str
    port: int
    process: str = ""

    @property
    def scope(self) -> str:
        a = self.addr.split("%")[0]
        if a in ("*", "0.0.0.0", "::", "[::]"):
            return "public"
        try:
            ip = ipaddress.ip_address(a.strip("[]"))
        except ValueError:
            return "public"
        return "loopback" if ip.is_loopback else "specific"


def _split_hostport(token: str) -> tuple[str, int] | None:
    host, sep, port = token.rpartition(":")
    if not sep or not port.isdigit():
        return None
    return host.strip("[]") or "*", int(port)


def parse_ss(text: str) -> list[Listener]:
    out: list[Listener] = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 5 or cols[0] not in ("tcp", "udp"):
            continue
        hp = _split_hostport(cols[4])
        if not hp:
            continue
        m = re.search(r'\(\("([^"]+)"', line)
        out.append(Listener(cols[0], hp[0], hp[1], m.group(1) if m else ""))
    return out


def listeners(ctx: Context) -> list[Listener]:
    """All listening TCP sockets and bound UDP sockets."""
    return ctx.memo("net.listeners", lambda: _listeners(ctx))


def _listeners(ctx: Context) -> list[Listener]:
    res = ctx.run(["ss", "-H", "-tulnp"], timeout=10)
    if res.ok and res.stdout.strip():
        return parse_ss(res.stdout)
    return [Listener("tcp", e.local_ip, e.local_port) for e in tcp_table(ctx) if e.state == TCP_LISTEN]


def tcp_listening(ctx: Context, port: int) -> bool:
    return any(lst.proto == "tcp" and lst.port == port for lst in listeners(ctx))


def tcp_listen_addresses(ctx: Context, port: int) -> list[str]:
    return sorted({lst.addr for lst in listeners(ctx) if lst.proto == "tcp" and lst.port == port})


def port_owner(ctx: Context, port: int) -> str | None:
    """Process name holding a TCP port, '' if listening but unknown, None if free."""
    for lst in listeners(ctx):
        if lst.proto == "tcp" and lst.port == port:
            return lst.process
    return None


# ---------------------------------------------------------------------------
# SSH sessions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SshSession:
    pid: int
    user: str
    tty: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    started: float  # epoch seconds

    @property
    def peer(self) -> str:
        return f"{self.remote_ip}:{self.remote_port}"


def _boot_time(ctx: Context) -> float:
    for line in read_text(ctx.paths.proc / "stat").splitlines():
        if line.startswith("btime "):
            return float(line.split()[1])
    return 0.0


def _proc_start(ctx: Context, pid_dir: Path, btime: float) -> float:
    stat = read_text(pid_dir / "stat")
    try:
        rest = stat[stat.rindex(")") + 2:].split()
        ticks = int(rest[19])  # field 22 overall; index 19 after pid/comm
        return btime + ticks / os.sysconf("SC_CLK_TCK")
    except (ValueError, IndexError):
        return 0.0


def _socket_inodes(pid_dir: Path) -> list[str]:
    inodes = []
    try:
        for fd in (pid_dir / "fd").iterdir():
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            m = re.match(r"^socket:\[(\d+)\]$", target)
            if m:
                inodes.append(m.group(1))
    except OSError:
        pass
    return inodes


def ssh_sessions(ctx: Context) -> list[SshSession]:
    """Authenticated sshd session processes with their socket endpoints (needs root to see all)."""
    table = {e.inode: e for e in tcp_table(ctx) if e.state == TCP_ESTABLISHED}
    btime = _boot_time(ctx)
    sessions: list[SshSession] = []
    try:
        entries = list(ctx.paths.proc.iterdir())
    except OSError:
        return []
    for pid_dir in entries:
        if not pid_dir.name.isdigit():
            continue
        cmd = read_text(pid_dir / "cmdline").replace("\x00", " ").strip()
        m = _SESSION_RE.match(cmd)
        if not m:
            continue
        for inode in _socket_inodes(pid_dir):
            entry = table.get(inode)
            if entry:
                sessions.append(SshSession(int(pid_dir.name), m.group(1), m.group(2), entry.local_ip,
                                           entry.local_port, entry.remote_ip, entry.remote_port,
                                           _proc_start(ctx, pid_dir, btime)))
                break
    return sessions


def _ppid(ctx: Context, pid: int) -> int:
    stat = read_text(ctx.paths.proc / str(pid) / "stat")
    try:
        return int(stat[stat.rindex(")") + 2:].split()[1])
    except (ValueError, IndexError):
        return 0


def current_session(ctx: Context, start_pid: int | None = None) -> SshSession | None:
    """The SSH session this process descends from, determined via the process tree."""
    by_pid = {s.pid: s for s in ssh_sessions(ctx)}
    pid = start_pid or os.getpid()
    for _ in range(64):
        if pid in by_pid:
            return by_pid[pid]
        pid = _ppid(ctx, pid)
        if pid <= 1:
            return None
    return None


def local_addresses(ctx: Context) -> set[str]:
    """Addresses configured on this host (to reject 'remote' peers that are really local)."""
    addrs = {"127.0.0.1", "::1"}
    res = ctx.run(["ip", "-o", "addr", "show"], timeout=5)
    for line in res.lines():
        m = re.search(r"\binet6? (\S+?)(?:/\d+)?\s", line + " ")
        if m:
            addrs.add(m.group(1))
    return addrs
