"""Fail2ban installation, policy management and operational verification.

Design points (all validated against fail2ban 1.0.2):
  * Bant only writes its own files: jail.d/zz-bant-sshd.local and filter.d/bant-sshd.conf.
  * Keys that an administrator already defined for [sshd] (or [DEFAULT]) are never overridden;
    they are reported as conflicts instead.
  * Effective configuration is read back with `fail2ban-client -d`, which merges every file
    exactly as the server would, so precedence assumptions are never relied upon.
  * "Running" is not "protecting": verify() checks config validity, jail liveness, port
    coverage, ban-action usability and that the log source actually yields sshd lines.
"""

from __future__ import annotations

import ast
import configparser
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bant.context import Context
from bant.core import firewall, sshconf
from bant.errors import OperationFailed, Unsupported, ValidationError
from bant.platform import unit_active, unit_state
from bant.utils.fsutil import MANAGED_HEADER, read_text
from bant.utils.validation import parse_duration, parse_int_range, parse_ip

JAIL = "sshd"
MANAGED_KEYS = ("enabled", "port", "maxretry", "findtime", "bantime", "backend", "banaction", "filter", "logpath", "ignoreip")
STOCK = {"maxretry": "5", "findtime": "10m", "bantime": "10m"}
# Config files shipped by distribution packages that carry no administrator intent.
DISTRO_FILES = {"jail.conf", "defaults-debian.conf", "paths-common.conf", "paths-debian.conf"}
SAMPLE_FAILURE = "Oct 30 05:00:00 bant-probe sshd[1234]: Failed password for invalid user probe from 192.0.2.77 port 4444 ssh2"
COMPAT_JOURNALMATCH = "_SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _COMM=sshd + _COMM=sshd-session"


@dataclass
class Check:
    name: str
    ok: bool | None  # None = could not determine
    detail: str = ""


@dataclass
class Overview:
    installed: bool = False
    version: str = ""
    service: str = "inactive"  # active / inactive / failed / ...
    enabled_on_boot: bool = False
    jail_enabled: bool = False
    jail_running: bool = False
    ports: list[int] = field(default_factory=list)
    maxretry: str = ""
    findtime: str = ""
    bantime: str = ""
    backend: str = ""
    banaction: str = ""
    currently_banned: int | None = None
    total_banned: int | None = None
    state: str = "not_installed"  # not_installed | inactive | running | misconfigured | verified
    problems: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Reading effective configuration
# ---------------------------------------------------------------------------

def installed(ctx: Context) -> tuple[bool, str]:
    res = ctx.run(["fail2ban-client", "--version"])
    if res.ok:
        m = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", res.stdout)
        return True, m.group(1) if m else res.stdout.strip()
    return False, ""


def parse_dump(text: str) -> list[list[Any]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            try:
                val = ast.literal_eval(line)
            except (ValueError, SyntaxError):
                continue
            if isinstance(val, list):
                out.append(val)
    return out


def dump_config(ctx: Context, config_dir: Path | None = None) -> list[list[Any]]:
    argv = ["fail2ban-client"]
    if config_dir:
        argv += ["-c", str(config_dir)]
    res = ctx.run(argv + ["-d"], timeout=30)
    return parse_dump(res.stdout) if res.ok else []


def jail_from_dump(commands: list[list[Any]], jail: str = JAIL) -> dict[str, Any]:
    info: dict[str, Any] = {"present": False, "ignoreip": [], "journalmatch": [], "logpath": [], "banaction": "", "port": ""}
    for cmd in commands:
        if len(cmd) < 3 or cmd[1] != jail:
            continue
        verb = cmd[0]
        if verb == "add":
            info["present"], info["backend"] = True, cmd[2]
        elif verb == "set":
            key = cmd[2]
            if key in ("maxretry", "findtime", "bantime"):
                info[key] = str(cmd[3])
            elif key == "addignoreip":
                info["ignoreip"] += [str(x) for x in cmd[3:]]
            elif key == "addjournalmatch":
                info["journalmatch"].append(" ".join(str(x) for x in cmd[3:]))
            elif key == "addlogpath":
                info["logpath"].append(str(cmd[3]))
            elif key == "addaction":
                info["banaction"] = str(cmd[3])
        elif verb == "multi-set" and cmd[2] == "action" and len(cmd) >= 5:
            for pair in cmd[4]:
                if pair[0] == "port":
                    info["port"] = str(pair[1])
    return info


def effective_jail(ctx: Context, jail: str = JAIL, config_dir: Path | None = None) -> dict[str, Any]:
    return jail_from_dump(dump_config(ctx, config_dir), jail)


def parse_ports(value: str) -> list[int]:
    ports = []
    for part in re.split(r"[,\s]+", value or ""):
        if part.isdigit():
            ports.append(int(part))
        elif part == "ssh":
            ports.append(22)
    return sorted(set(ports))


def parse_status(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"banned_ips": []}
    for line in text.splitlines():
        m = re.search(r"Currently banned:\s*(\d+)", line)
        if m:
            out["currently_banned"] = int(m.group(1))
        m = re.search(r"Total banned:\s*(\d+)", line)
        if m:
            out["total_banned"] = int(m.group(1))
        m = re.search(r"Total failed:\s*(\d+)", line)
        if m:
            out["total_failed"] = int(m.group(1))
        m = re.search(r"Banned IP list:\s*(.*)$", line)
        if m:
            out["banned_ips"] = m.group(1).split()
        m = re.search(r"Jail list:\s*(.*)$", line)
        if m:
            out["jails"] = [j.strip() for j in m.group(1).split(",") if j.strip()]
    return out


def server_status(ctx: Context) -> dict[str, Any]:
    res = ctx.run(["fail2ban-client", "status"])
    return parse_status(res.stdout) if res.ok else {}


def jail_status(ctx: Context, jail: str = JAIL) -> dict[str, Any] | None:
    res = ctx.run(["fail2ban-client", "status", jail])
    return parse_status(res.stdout) if res.ok else None


# ---------------------------------------------------------------------------
# Administrator-owned configuration (conflict detection)
# ---------------------------------------------------------------------------

def _is_bant_file(path: Path) -> bool:
    return "bant" in path.name or path.name.startswith("zz-sshd-protection")


def admin_files(ctx: Context) -> list[Path]:
    """Jail config files that may carry administrator intent (excludes Bant's and distro-shipped files)."""
    base = ctx.paths.f2b_dir
    cands = [base / "jail.local"]
    jd = base / "jail.d"
    if jd.is_dir():
        cands += sorted(p for p in jd.iterdir() if p.suffix in (".conf", ".local"))
    out = []
    for p in cands:
        if not p.is_file() or _is_bant_file(p) or p.name in DISTRO_FILES:
            continue
        out.append(p)
    return out


def admin_defined(ctx: Context) -> dict[str, tuple[Path, str, str]]:
    """key -> (file, section, value) for MANAGED_KEYS set by the administrator for [sshd] or [DEFAULT]."""
    found: dict[str, tuple[Path, str, str]] = {}
    for path in admin_files(ctx):
        cp = configparser.RawConfigParser(strict=False, interpolation=None)
        cp.optionxform = str  # type: ignore[assignment,method-assign]
        try:
            cp.read_string(read_text(path))
        except configparser.Error:
            continue
        sections = {"DEFAULT": dict(cp.defaults()), JAIL: dict(cp._sections.get(JAIL, {}))}  # type: ignore[attr-defined]
        for section, items in sections.items():
            for key, value in items.items():
                if key in MANAGED_KEYS:
                    found[key] = (path, section, str(value).strip())
    return found


# ---------------------------------------------------------------------------
# Choosing backend / action
# ---------------------------------------------------------------------------

ACTION_BINARIES = {"nftables": "nft", "iptables": "iptables", "ufw": "ufw", "firewallcmd": "firewall-cmd"}


def action_problem(ctx: Context, action: str, fw: firewall.FirewallInfo | None = None) -> str | None:
    """Why `action` cannot work on this host, or None when it looks usable."""
    if not action:
        return "no ban action configured"
    family = next((k for k in ACTION_BINARIES if action.startswith(k)), None)
    if family is None:
        return None  # custom action: cannot judge
    if ctx.which(ACTION_BINARIES[family]) is None:
        return f"action '{action}' needs `{ACTION_BINARIES[family]}`, which is not installed"
    fw = fw or firewall.detect(ctx)
    if family == "ufw" and fw.backend != "ufw":
        return "action 'ufw' requires an active UFW"
    if family == "firewallcmd" and fw.backend != "firewalld":
        return f"action '{action}' requires a running firewalld"
    return None


def choose_banaction(ctx: Context, current: str, fw: firewall.FirewallInfo) -> str | None:
    """Return a replacement banaction if the current effective one is unusable, else None."""
    if not action_problem(ctx, current, fw):
        return None
    if fw.backend == "firewalld":
        return "firewallcmd-rich-rules"
    if ctx.which("nft"):
        return "nftables"
    if ctx.which("iptables"):
        return "iptables-multiport"
    raise Unsupported("No usable firewall tool (nft/iptables) for Fail2ban ban actions.",
                      hint="Install nftables (apt install nftables) and run `bant repair`.")


def journal_has_sshd(ctx: Context) -> bool | None:
    res = ctx.run(["journalctl", "--no-pager", "-q", "-n", "3", "-o", "cat",
                   "_SYSTEMD_UNIT=ssh.service", "+", "_SYSTEMD_UNIT=sshd.service", "+", "_COMM=sshd", "+", "_COMM=sshd-session"],
                  timeout=20)
    if not res.ok and res.returncode == 127:
        return None
    return bool(res.stdout.strip()) if res.ok else None


def systemd_python_ok(ctx: Context) -> bool:
    return ctx.run(["/usr/bin/python3", "-c", "import systemd.journal"]).ok


def sshd_has_split_binary(ctx: Context) -> bool:
    return any(ctx.paths.p(p).exists() for p in ("/usr/lib/openssh/sshd-session", "/usr/libexec/sshd-session",
                                                  "/usr/lib/ssh/sshd-session"))


def choose_log_source(ctx: Context) -> dict[str, Any]:
    """Pick systemd journal or auth.log. Never configures a logpath that does not exist."""
    auth = ctx.paths.auth_log
    journal = journal_has_sshd(ctx)
    pysd = systemd_python_ok(ctx)
    if journal and pysd:
        return {"backend": "systemd", "reason": "sshd logs are in the systemd journal"}
    if auth.is_file() and auth.stat().st_size > 0:
        return {"backend": "auto", "logpath": "/var/log/auth.log", "reason": "using /var/log/auth.log"}
    if ctx.which("journalctl") and ctx.paths.p("/run/systemd/system").is_dir():
        note = "" if pysd else " (python3-systemd must be installed)"
        return {"backend": "systemd", "reason": "systemd journal is the log source" + note, "need_pysystemd": not pysd}
    raise Unsupported("No SSH authentication log source found (no systemd journal, no /var/log/auth.log).",
                      hint="Install rsyslog or enable journald, then run `bant repair`.")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_filter() -> str:
    return (
        MANAGED_HEADER
        + "# Reuses the stock sshd filter but matches the journal units/commands used on Debian and Ubuntu\n"
        "# (ssh.service) and on OpenSSH >= 9.8 (sshd-session).\n"
        "# journalmatch is set in both sections: the stock filter uses [Definition], and [Init] takes\n"
        "# precedence in the versions we tested; identical values make the result independent of that.\n"
        "[INCLUDES]\nbefore = sshd.conf\n\n"
        f"[Definition]\njournalmatch = {COMPAT_JOURNALMATCH}\n\n"
        f"[Init]\njournalmatch = {COMPAT_JOURNALMATCH}\n"
    )


def merged_ignoreip(base: list[str], trusted: list[str]) -> list[str]:
    out: list[str] = []
    for ip in ["127.0.0.1/8", "::1", *base, *trusted]:
        if ip not in out:
            out.append(ip)
    return out


def render_jail(settings: dict[str, str]) -> str:
    lines = [MANAGED_HEADER.rstrip("\n"),
             "# Keys an administrator defined elsewhere are intentionally omitted (see `bant doctor`).", "", f"[{JAIL}]"]
    for key in MANAGED_KEYS:
        if key in settings:
            lines.append(f"{key} = {settings[key]}")
    return "\n".join(lines) + "\n"


def desired_settings(ctx: Context, ports: list[int]) -> tuple[dict[str, str], list[str]]:
    """Compute the settings Bant writes, plus conflict notes for keys the administrator owns.

    Administrator values always win unless the user explicitly set that key through Bant
    (then only a [sshd]-section override still blocks it, and is reported as a conflict).
    """
    explicit = set(ctx.state.get("fail2ban", "explicit", default=[]) or [])
    cfg = ctx.config
    owned = admin_defined(ctx)
    conflicts: list[str] = []
    wanted = {
        "enabled": "true",
        "port": ",".join(str(p) for p in sorted(set(ports))),
        "maxretry": str(cfg.maxretry),
        "findtime": cfg.findtime,
        "bantime": cfg.bantime,
    }
    cur = effective_jail(ctx) if installed(ctx)[0] else {}
    src = choose_log_source(ctx)
    wanted["backend"] = src["backend"]
    if "logpath" in src:
        wanted["logpath"] = src["logpath"]
    if sshd_has_split_binary(ctx) or src["backend"] == "systemd":
        wanted["filter"] = "bant-sshd"
    fw = firewall.detect(ctx)
    repl = choose_banaction(ctx, cur.get("banaction", ""), fw) if cur.get("banaction") is not None else None
    if repl:
        wanted["banaction"] = repl
    trusted = ctx.config.trusted_ips
    if trusted or "ignoreip" in owned:
        previous = set(ctx.state.get("fail2ban", "trusted_applied", default=[]) or [])
        base = [i for i in cur.get("ignoreip", []) if i not in set(trusted) | previous]
        wanted["ignoreip"] = " ".join(merged_ignoreip(base, trusted))
    for key in list(wanted):
        if key in owned and owned[key][1] == JAIL and key != "ignoreip":
            path, _, value = owned[key]
            if value.replace(" ", "") != wanted[key].replace(" ", ""):
                conflicts.append(f"{path.name} sets {key} = {value} for [sshd]; Bant keeps it (wanted {wanted[key]})")
            del wanted[key]
        elif key in owned and owned[key][1] == "DEFAULT" and key in ("maxretry", "findtime", "bantime") and key not in explicit:
            del wanted[key]  # the administrator customised a global default and never asked Bant to change it
    return wanted, conflicts


# ---------------------------------------------------------------------------
# Applying
# ---------------------------------------------------------------------------

def install(ctx: Context) -> str:
    ctx.require_root("Installing Fail2ban")
    ok, ver = installed(ctx)
    if ok:
        return f"Fail2ban {ver} already installed"
    pkgs = ["fail2ban", "python3-systemd"]
    res = ctx.run_mut(["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-o", "DPkg::Lock::Timeout=120",
                       "-o", "Dpkg::Options::=--force-confold", *pkgs], timeout=900)
    if not res.ok:
        raise OperationFailed(f"Installing Fail2ban failed: {res.output[-400:]}",
                              hint="Check network/apt state (`apt-get -f install`) and retry.")
    ctx.audit("fail2ban.install", packages=pkgs)
    ok, ver = installed(ctx)
    if not ok and not ctx.dry_run:
        raise OperationFailed("Fail2ban was installed but fail2ban-client is not usable.")
    return f"Installed Fail2ban {ver}"


def ensure_pysystemd(ctx: Context) -> None:
    if systemd_python_ok(ctx):
        return
    res = ctx.run_mut(["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-o", "DPkg::Lock::Timeout=120", "python3-systemd"], timeout=600)
    if not res.ok:
        raise OperationFailed(f"Could not install python3-systemd: {res.output[-300:]}")


def _test_config(ctx: Context) -> tuple[bool, str]:
    res = ctx.run(["fail2ban-client", "-t"], timeout=60)
    return res.ok, res.output[-600:]


def apply_policy(ctx: Context, ports: list[int] | None = None, *, tx=None, txm=None) -> dict[str, Any]:
    """Write Bant's jail/filter files, validate, reload, and verify the jail is live on `ports`.

    On any failure the previous files are restored and Fail2ban reloaded.
    """
    ctx.require_root("Changing Fail2ban configuration")
    ok, _ = installed(ctx)
    if not ok:
        raise Unsupported("Fail2ban is not installed.", hint="Run `bant fail2ban enable` to install and configure it.")
    ports = ports or sshconf.effective(ctx).ports
    if not ports:
        raise OperationFailed("Could not determine the SSH port(s) to protect.")
    settings, conflicts = desired_settings(ctx, ports)
    if settings.get("backend") == "systemd":
        ensure_pysystemd(ctx)
    jail_path, filter_path = ctx.paths.f2b_jail, ctx.paths.f2b_filter
    targets = {jail_path: render_jail(settings)}
    if settings.get("filter") == "bant-sshd":
        targets[filter_path] = render_filter()
    if ctx.dry_run:
        for p in targets:
            ctx.planned.append(f"write {p}")
        return {"settings": settings, "conflicts": conflicts, "ports": ports}

    originals = {p: (p.read_bytes() if p.exists() else None) for p in (jail_path, filter_path)}
    if tx is not None:
        for p in (jail_path, filter_path):
            txm.backup_file(tx, p)
        txm.add_post(tx, ["fail2ban-client", "reload"])
    try:
        for path, content in targets.items():
            ctx.write_file(path, content, 0o644)
        good, out = _test_config(ctx)
        if not good:
            raise OperationFailed(f"Fail2ban rejected the new configuration: {out}")
        _reload(ctx)
        eff = effective_jail(ctx)
        got = parse_ports(eff.get("port", ""))
        if not eff.get("present"):
            raise OperationFailed("The sshd jail is not defined after applying the configuration.")
        if conflicts == [] and sorted(got) != sorted(set(ports)):
            raise OperationFailed(f"Effective jail ports {got} do not match the SSH ports {sorted(set(ports))}.")
    except Exception:
        for path, data in originals.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                ctx.write_file(path, data, 0o644)
        ctx.run_mut(["fail2ban-client", "reload"])
        raise
    applied = list(ctx.config.trusted_ips)
    ctx.state.update(lambda d: d.setdefault("fail2ban", {}).__setitem__("trusted_applied", applied))
    ctx.audit("fail2ban.policy", ports=ports, settings=settings, conflicts=conflicts)
    return {"settings": settings, "conflicts": conflicts, "ports": ports}


def _reload(ctx: Context) -> None:
    if not unit_active(ctx, "fail2ban.service"):
        res = ctx.run_mut(["systemctl", "enable", "--now", "fail2ban.service"])
        if not res.ok:
            raise OperationFailed(f"Could not start fail2ban: {res.output}")
        return
    st = jail_status(ctx)
    res = ctx.run_mut(["fail2ban-client", "reload", JAIL] if st is not None else ["fail2ban-client", "reload"], timeout=60)
    if not res.ok:
        raise OperationFailed(f"fail2ban reload failed: {res.output}")


def sync_if_managed(ctx: Context) -> bool:
    """Re-render Bant's jail after a Bant setting (e.g. trusted IPs) changed. No-op if Bant never configured it."""
    if not ctx.paths.f2b_jail.exists() or not ctx.is_root:
        return False
    apply_policy(ctx)
    return True


def set_option(ctx: Context, key: str, value: str) -> str:
    """Change maxretry / findtime / bantime and apply."""
    if key == "maxretry":
        value = str(parse_int_range(value, 1, 100, "maxretry"))
    elif key in ("findtime", "bantime"):
        secs = parse_duration(value)
        if key == "findtime" and secs < 0:
            raise ValidationError("findtime cannot be permanent.")
        value = str(value).strip().lower() if secs > 0 else "-1"
    else:
        raise ValidationError(f"Unknown setting {key!r}", hint="Use maxretry, findtime or bantime.")
    with ctx.lock():
        old = ctx.config.get("fail2ban", key)
        was_explicit = list(ctx.state.get("fail2ban", "explicit", default=[]) or [])
        ctx.config.set("fail2ban", key, int(value) if key == "maxretry" else value)
        if key not in was_explicit and not ctx.dry_run:
            ctx.state.update(lambda d: d.setdefault("fail2ban", {}).__setitem__("explicit", sorted({*was_explicit, key})))
        try:
            if not ctx.dry_run:
                ctx.config.save()
            res = apply_policy(ctx)
        except Exception:
            ctx.config.set("fail2ban", key, old)
            if not ctx.dry_run:
                ctx.config.save()
                ctx.state.update(lambda d: d.setdefault("fail2ban", {}).__setitem__("explicit", was_explicit))
            raise
        ctx.audit("fail2ban.set", key=key, value=value, previous=old)
    note = f" ({'; '.join(res['conflicts'])})" if res.get("conflicts") else ""
    return f"{key} = {value}{note}"


def set_enabled(ctx: Context, enable: bool) -> str:
    ctx.require_root("Changing Fail2ban")
    with ctx.lock():
        if enable:
            msg = install(ctx)
            apply_policy(ctx)
            res = ctx.run_mut(["systemctl", "enable", "--now", "fail2ban.service"])
            if not res.ok:
                raise OperationFailed(f"Could not enable fail2ban: {res.output}")
            ctx.audit("fail2ban.enable")
            return msg + "; Fail2ban enabled and SSH jail configured"
        if not installed(ctx)[0]:
            return "Fail2ban is not installed"
        res = ctx.run_mut(["systemctl", "disable", "--now", "fail2ban.service"])
        if not res.ok:
            raise OperationFailed(f"Could not disable fail2ban: {res.output}")
        ctx.audit("fail2ban.disable", level="warning")
        return "Fail2ban stopped and disabled (SSH brute-force protection is OFF)"


# ---------------------------------------------------------------------------
# Bans
# ---------------------------------------------------------------------------

_WITH_TIME_RE = re.compile(r"^(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s*\+\s*(-?\d+)\s*=\s*(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s*$")


def parse_banip_with_time(text: str) -> dict[str, str]:
    """ip -> unban time from `fail2ban-client get <jail> banip --with-time` ('permanent' for negative bantime)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _WITH_TIME_RE.match(line.strip())
        if m:
            out[m.group(1)] = "permanent" if int(m.group(3)) < 0 else m.group(4)
    return out


def banned(ctx: Context) -> list[dict[str, str]]:
    """Bans per jail with expiry when this Fail2ban version can report it (otherwise 'jail bantime')."""
    out = []
    for jail in server_status(ctx).get("jails", []):
        st = jail_status(ctx, jail) or {}
        timed = ctx.run(["fail2ban-client", "get", jail, "banip", "--with-time"])
        expiry = parse_banip_with_time(timed.stdout) if timed.ok else {}
        out += [{"ip": ip, "jail": jail, "source": "fail2ban", "expires": expiry.get(ip, "per jail bantime")}
                for ip in st.get("banned_ips", [])]
    return out


def ban(ctx: Context, ip: str, jail: str = JAIL) -> str:
    ctx.require_root("Banning an IP address")
    ip = parse_ip(ip, for_ban=True)
    if jail_status(ctx, jail) is None:
        raise Unsupported(f"Jail '{jail}' is not running.", hint="Check `bant fail2ban status`.")
    res = ctx.run_mut(["fail2ban-client", "set", jail, "banip", ip])
    if not res.ok:
        raise OperationFailed(f"Ban failed: {res.output}")
    ctx.audit("ban.add", ip=ip, source="fail2ban", jail=jail)
    return f"Banned {ip} in jail {jail} (expires after the jail's bantime)"


def unban(ctx: Context, ip: str) -> int:
    """Unban in every jail. Returns how many bans were actually removed (0 = it was not banned)."""
    ctx.require_root("Unbanning an IP address")
    ip = parse_ip(ip)
    res = ctx.run_mut(["fail2ban-client", "unban", ip])
    if not res.ok:
        raise OperationFailed(f"Unban failed: {res.output}")
    last = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else "0"
    removed = int(last) if last.isdigit() else (0 if ctx.dry_run else 1)
    if removed:
        ctx.audit("ban.remove", ip=ip, source="fail2ban", removed=removed)
    return removed


def ban_self_check(ctx: Context, ip: str) -> str | None:
    from bant.core import bans
    return bans.ban_risk(ctx, ip)


# ---------------------------------------------------------------------------
# Verification / overview
# ---------------------------------------------------------------------------

def verify(ctx: Context, ssh_ports: list[int] | None = None) -> list[Check]:
    checks: list[Check] = []
    ok, ver = installed(ctx)
    checks.append(Check("installed", ok, f"version {ver}" if ok else "fail2ban-client not found"))
    if not ok:
        return checks
    ping = ctx.run(["fail2ban-client", "ping"])
    checks.append(Check("server running", ping.ok and "pong" in ping.stdout.lower(), ping.output[:120]))
    good, out = _test_config(ctx)
    checks.append(Check("configuration valid", good, "" if good else out))
    eff = effective_jail(ctx)
    checks.append(Check("sshd jail enabled", bool(eff.get("present")), "" if eff.get("present") else "no [sshd] jail in effective configuration"))
    st = jail_status(ctx)
    checks.append(Check("sshd jail running", st is not None, "" if st is not None else "jail not loaded in the running server"))
    ports = parse_ports(eff.get("port", ""))
    ssh_ports = ssh_ports if ssh_ports is not None else sshconf.effective(ctx).ports
    missing = sorted(set(ssh_ports) - set(ports))
    checks.append(Check("jail covers SSH port(s)", not missing if eff.get("present") else None,
                        f"jail protects {ports}; SSH listens on {ssh_ports}" + (f" - UNPROTECTED: {missing}" if missing else "")))
    problem = action_problem(ctx, eff.get("banaction", ""))
    checks.append(Check("ban action usable", problem is None, problem or f"action {eff.get('banaction')}"))
    backend = eff.get("backend", "")
    if backend == "systemd":
        py = systemd_python_ok(ctx)
        checks.append(Check("python3-systemd available", py, "" if py else "backend=systemd needs python3-systemd"))
        has = journal_has_sshd(ctx)
        checks.append(Check("journal yields sshd lines", has, "journal match returns entries" if has else
                            "no sshd entries matched in the journal yet (cannot confirm detection)" if has is False else "journalctl unavailable"))
    elif eff.get("logpath"):
        missing_logs = [p for p in eff["logpath"] if not ctx.paths.p(p).exists()]
        checks.append(Check("log file exists", not missing_logs, ", ".join(eff["logpath"]) if not missing_logs else f"missing: {missing_logs}"))
    sample = ctx.run(["fail2ban-regex", SAMPLE_FAILURE, "sshd"], timeout=30)
    matched = re.search(r"(\d+) matched", sample.stdout)
    checks.append(Check("filter parses a sample failure", bool(matched and int(matched.group(1)) >= 1),
                        "sshd filter matched a synthetic failed-login line" if matched and int(matched.group(1)) else "filter did not match the sample line"))
    return checks


def overview(ctx: Context, ssh_ports: list[int] | None = None) -> Overview:
    return ctx.memo(f"f2b.overview.{ssh_ports}", lambda: _overview(ctx, ssh_ports))


def _overview(ctx: Context, ssh_ports: list[int] | None) -> Overview:
    ov = Overview()
    ov.installed, ov.version = installed(ctx)
    if not ov.installed:
        return ov
    stt = unit_state(ctx, "fail2ban.service")
    ov.service = stt["ActiveState"] or "unknown"
    ov.enabled_on_boot = stt["UnitFileState"] == "enabled"
    eff = effective_jail(ctx)
    ov.jail_enabled = bool(eff.get("present"))
    ov.ports = parse_ports(eff.get("port", ""))
    ov.maxretry, ov.findtime, ov.bantime = eff.get("maxretry", ""), eff.get("findtime", ""), eff.get("bantime", "")
    ov.backend, ov.banaction = eff.get("backend", ""), eff.get("banaction", "")
    st = jail_status(ctx)
    ov.jail_running = st is not None
    if st:
        ov.currently_banned, ov.total_banned = st.get("currently_banned"), st.get("total_banned")
    if ov.service != "active":
        ov.state = "inactive"
        ov.problems.append("fail2ban.service is not running")
        return ov
    ov.checks = verify(ctx, ssh_ports)
    failed = [c for c in ov.checks if c.ok is False]
    ov.problems += [f"{c.name}: {c.detail}" for c in failed]
    ov.state = "misconfigured" if failed else ("verified" if all(c.ok for c in ov.checks) else "running")
    admin = admin_defined(ctx)
    for key, (path, section, value) in admin.items():
        if section == JAIL and key in ("port", "enabled", "maxretry", "findtime", "bantime"):
            ov.conflicts.append(f"{path.name}: [sshd] {key} = {value}")
    return ov
