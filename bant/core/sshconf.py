"""sshd_config parsing, effective-configuration inspection and Bant drop-in rendering.

OpenSSH semantics that matter here (verified against OpenSSH 9.6):
  * For most keywords the FIRST obtained value wins; Port/ListenAddress/HostKey accumulate.
  * `Include` is spliced in place, files are processed in glob (lexical) order.
  * A `Match` block opened inside an included file ends with that file.
  * `Port` is ignored by sshd when the daemon is socket-activated (ssh.socket).
The parser here is only used for ownership/conflict reporting and as a non-root fallback;
authoritative values always come from `sshd -T`.
"""

from __future__ import annotations

import glob
import re
from dataclasses import dataclass
from pathlib import Path

from bant.context import Context
from bant.errors import OperationFailed
from bant.utils.fsutil import MANAGED_HEADER, read_text

CUMULATIVE = {"port", "listenaddress", "hostkey", "subsystem", "acceptenv", "setenv", "allowusers",
              "allowgroups", "denyusers", "denygroups", "include", "permitlisten", "permitopen"}

# Conservative defaults used only when `sshd -T` cannot run (non-root).
DEFAULTS = {
    "port": ["22"], "passwordauthentication": ["yes"], "kbdinteractiveauthentication": ["yes"],
    "pubkeyauthentication": ["yes"], "permitrootlogin": ["prohibit-password"], "maxauthtries": ["6"],
    "logingracetime": ["120"], "permitemptypasswords": ["no"], "usepam": ["no"],
    "authenticationmethods": ["any"], "allowtcpforwarding": ["yes"], "x11forwarding": ["no"],
}
AUTH_KEYS = ("passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication",
             "permitrootlogin", "authenticationmethods", "permitemptypasswords", "maxauthtries")

_LINE_RE = re.compile(r"^(\w+)\s*(?:=\s*|\s+)(.*)$")


@dataclass
class Directive:
    file: Path
    lineno: int
    keyword: str  # lower-case
    args: str
    raw: str
    match: str | None = None  # criteria of the enclosing Match block, None when global

    @property
    def is_global(self) -> bool:
        return self.match is None


class Effective:
    """Effective sshd configuration as a mapping of lower-case keyword -> list of values."""

    def __init__(self, values: dict[str, list[str]], source: str, note: str = ""):
        self.values = values
        self.source = source  # "sshd -T" or "parsed"
        self.note = note

    def all(self, key: str) -> list[str]:
        return self.values.get(key, [])

    def one(self, key: str, default: str = "") -> str:
        vals = self.values.get(key)
        return vals[0] if vals else default

    def flag(self, key: str, default: bool = False) -> bool:
        v = self.one(key, "yes" if default else "no").lower()
        return v in ("yes", "true", "on")

    @property
    def ports(self) -> list[int]:
        seen: list[int] = []
        for p in self.all("port"):
            if p.isdigit() and int(p) not in seen:
                seen.append(int(p))
        return seen


def _strip_comment(arg: str) -> str:
    out, quote = [], ""
    for i, ch in enumerate(arg):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or arg[i - 1].isspace()):
            break
        out.append(ch)
    return "".join(out).strip()


def parse_config(ctx: Context, main: Path | None = None) -> list[Directive]:
    """Parse sshd_config with Include expansion and Match tracking."""
    main = main or ctx.paths.sshd_config
    out: list[Directive] = []
    seen: set[Path] = set()

    def resolve(pattern: str) -> list[Path]:
        root = str(ctx.paths.root)
        if not pattern.startswith("/"):
            pat = str(ctx.paths.ssh_dir / pattern)
        elif root != "/" and not pattern.startswith(root):
            pat = str(ctx.paths.p(pattern))
        else:
            pat = pattern
        return [Path(p) for p in sorted(glob.glob(pat))]

    def walk(path: Path, depth: int, inherited_match: str | None) -> None:
        if depth > 16 or path in seen:
            return
        seen.add(path)
        match = inherited_match
        text = read_text(path)
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = _LINE_RE.match(line)
            if not m:
                continue
            kw, args = m.group(1).lower(), _strip_comment(m.group(2))
            if kw == "match":
                match = None if args.strip().lower() == "all" else args
                out.append(Directive(path, lineno, kw, args, raw, match))
                continue
            if kw == "include":
                out.append(Directive(path, lineno, kw, args, raw, match))
                for pattern in args.split():
                    for inc in resolve(pattern.strip("\"'")):
                        walk(inc, depth + 1, match)
                continue
            out.append(Directive(path, lineno, kw, args, raw, match))
        seen.discard(path)

    walk(main, 0, None)
    return out


def parsed_effective(directives: list[Directive]) -> Effective:
    values: dict[str, list[str]] = {}
    for d in directives:
        if not d.is_global or d.keyword in ("match", "include"):
            continue
        if d.keyword in CUMULATIVE:
            values.setdefault(d.keyword, []).append(d.args)
        elif d.keyword not in values:
            values[d.keyword] = [d.args.lower() if d.keyword.endswith(("authentication", "login")) else d.args]
    for k, v in DEFAULTS.items():
        values.setdefault(k, list(v))
    return Effective(values, "parsed", "Approximation from configuration files; run as root for sshd -T.")


def parse_sshd_T(text: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        key, _, val = line.partition(" ")
        values.setdefault(key.lower(), []).append(val.strip())
    return values


def effective(ctx: Context, *, user: str | None = None, addr: str | None = None, lport: int | None = None,
              laddr: str | None = None, config: Path | None = None) -> Effective:
    """Effective configuration, from `sshd -T` when possible. A connection context may be given."""
    cfg = str(config or ctx.paths.sshd_config)
    argv = ["sshd", "-T", "-f", cfg]
    if user or addr or lport:
        spec = [f"user={user or 'nobody'}", "host=bant-probe.invalid", f"addr={addr or '192.0.2.1'}"]
        if laddr or lport:
            spec += [f"laddr={laddr or '192.0.2.2'}", f"lport={lport or 22}"]
        argv += ["-C", ",".join(spec)]
    res = ctx.run(argv, timeout=15)
    if res.ok and res.stdout.strip():
        return Effective(parse_sshd_T(res.stdout), "sshd -T")
    if ctx.which("sshd") is None and not res.stdout:
        note = "OpenSSH server (sshd) is not installed."
    else:
        note = (res.stderr.strip().splitlines() or ["sshd -T failed"])[0]
    eff = parsed_effective(parse_config(ctx, config))
    eff.note = f"{note} Showing values parsed from configuration files."
    return eff


def validate(ctx: Context, config: Path | None = None) -> tuple[bool, str]:
    """`sshd -t` against the live (or given) configuration."""
    res = ctx.run(["sshd", "-t", "-f", str(config or ctx.paths.sshd_config)], timeout=15)
    return res.ok, res.output


def match_overrides(directives: list[Directive], keys=AUTH_KEYS) -> list[Directive]:
    """Directives inside Match blocks that override authentication-related keywords."""
    return [d for d in directives if d.match is not None and d.keyword in keys]


def explicit_ports(directives: list[Directive], exclude: Path | None = None) -> list[Directive]:
    return [d for d in directives if d.keyword == "port" and d.is_global and d.file != exclude]


def listen_addresses_with_ports(directives: list[Directive]) -> list[Directive]:
    """ListenAddress lines that pin a port (host:port, [v6]:port); incompatible with automatic port moves."""
    out = []
    for d in directives:
        if d.keyword != "listenaddress" or not d.is_global:
            continue
        a = d.args.split()[0] if d.args.split() else ""
        if re.search(r"\]:\d+$", a) or re.match(r"^[^:\[\]]+:\d+$", a):
            out.append(d)
    return out


# ---------------------------------------------------------------------------
# Managed drop-in
# ---------------------------------------------------------------------------

def render_dropin(ports: list[int], options: dict[str, str]) -> str:
    lines = [MANAGED_HEADER.rstrip("\n"),
             "# Loaded first (00-) so that OpenSSH's first-value-wins rule applies these settings.", ""]
    for port in ports:
        lines.append(f"Port {port}")
    for key in sorted(options):
        lines.append(f"{key} {options[key]}")
    return "\n".join(lines) + "\n"


def read_dropin(ctx: Context, path: Path | None = None) -> tuple[list[int], dict[str, str]]:
    ports: list[int] = []
    options: dict[str, str] = {}
    for raw in read_text(path or ctx.paths.ssh_dropin).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        if m.group(1).lower() == "port":
            if m.group(2).strip().isdigit():
                ports.append(int(m.group(2).strip()))
        else:
            options[m.group(1)] = m.group(2).strip()
    return ports, options


def comment_out_ports(ctx: Context, directives: list[Directive], ports: set[int], backup) -> list[Directive]:
    """Disable global `Port <n>` lines for the given ports outside the Bant drop-in.

    `backup(path)` must be called before a file is edited so the change is recoverable.
    Returns the directives that were disabled.
    """
    touched: dict[Path, list[Directive]] = {}
    for d in explicit_ports(directives, exclude=ctx.paths.ssh_dropin):
        if d.args.strip().isdigit() and int(d.args.strip()) in ports:
            touched.setdefault(d.file, []).append(d)
    changed: list[Directive] = []
    for path, items in touched.items():
        if path.is_symlink():
            raise OperationFailed(f"{path} is a symbolic link; refusing to edit it.",
                                  hint="Remove the Port line manually, then run `bant ssh port` again.")
        backup(path)
        lines = read_text(path).splitlines(keepends=True)
        for d in items:
            idx = d.lineno - 1
            if idx < len(lines) and lines[idx].rstrip("\n") == d.raw:
                lines[idx] = f"# bant-disabled: {d.raw.strip()}\n"
                changed.append(d)
        ctx.write_file(path, "".join(lines), mode=path.stat().st_mode & 0o777 if path.exists() else 0o644)
    return changed
