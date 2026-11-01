"""SSH status, authentication policy and the helpers shared with port migration.

Authentication changes that could reduce access (password off, restricting root, pubkey off) run
inside a rollback transaction and only become permanent after `bant ssh cf` has verified a NEW
authenticated session server-side. Safe changes are applied with an in-process revert on failure.
"""

from __future__ import annotations

import grp
import pwd
import re
from dataclasses import dataclass, field
from typing import Any

from bant.context import Context
from bant.core import netinfo, sshconf
from bant.core.rollback import Transaction, TxManager
from bant.errors import BantError, OperationFailed, RolledBack, Unsupported, ValidationError
from bant.platform import detect_ssh_units, has_systemd
from bant.utils.fsutil import read_text
from bant.utils.validation import parse_duration, parse_int_range

ACCEPTED_RE = re.compile(r"Accepted (publickey|password|keyboard-interactive/pam) for (\S+) from (\S+) port (\d+)")

ROOT_LABELS = {
    "yes": ("Root login permitted", "Root may log in with a password or a key."),
    "prohibit-password": ("Root login with public key only", "Root may log in only with a key; root password login is refused."),
    "without-password": ("Root login with public key only", "Root may log in only with a key; root password login is refused."),
    "forced-commands-only": ("Root login restricted to forced commands", "Root key logins may only run a pre-set command."),
    "no": ("Root login disabled", "Root cannot log in over SSH at all."),
}


@dataclass
class SshStatus:
    installed: bool = False
    service_unit: str | None = None
    socket_unit: str | None = None
    mode: str = "none"  # service | socket | none
    service_active: bool = False
    config_valid: bool | None = None
    config_error: str = ""
    config_ports: list[int] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)
    password_auth: bool = True
    kbd_interactive: bool = False
    pubkey_auth: bool = True
    root_login: str = "prohibit-password"
    root_label: str = ""
    root_detail: str = ""
    root_password_login: bool = False
    permit_empty: bool = False
    max_auth_tries: str = ""
    login_grace_time: str = ""
    authentication_methods: str = "any"
    forwarding: str = ""
    source: str = ""
    note: str = ""
    match_overrides: list[str] = field(default_factory=list)
    pending_tx: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def active_ports(self) -> list[int]:
        """Ports SSH actually uses: socket/listening state wins over the config file."""
        return self.listening_ports or self.config_ports


def root_policy(eff: sshconf.Effective) -> tuple[str, str, str, bool]:
    value = eff.one("permitrootlogin", "prohibit-password").lower()
    label, detail = ROOT_LABELS.get(value, (f"Root login: {value}", "Unrecognised value"))
    root_password = value == "yes" and eff.flag("passwordauthentication", True)
    return value, label, detail, root_password


def socket_ports(ctx: Context, unit: str) -> list[int]:
    res = ctx.run(["systemctl", "show", unit, "-p", "Listen"])
    ports = []
    for line in res.lines():
        m = re.match(r"^Listen=.*:(\d+) \(Stream\)", line)
        if m and int(m.group(1)) not in ports:
            ports.append(int(m.group(1)))
    return ports


def socket_hosts(ctx: Context, unit: str) -> list[str]:
    res = ctx.run(["systemctl", "show", unit, "-p", "Listen"])
    hosts = []
    for line in res.lines():
        m = re.match(r"^Listen=(.*):\d+ \(Stream\)", line)
        if m and m.group(1) not in hosts:
            hosts.append(m.group(1))
    return hosts or ["0.0.0.0", "[::]"]


def status(ctx: Context) -> SshStatus:
    return ctx.memo("ssh.status", lambda: _status(ctx))


def _status(ctx: Context) -> SshStatus:
    st = SshStatus()
    units = detect_ssh_units(ctx)
    st.service_unit, st.socket_unit = units["service"], units["socket"]
    st.installed = ctx.which("sshd") is not None or st.service_unit is not None
    if not st.installed:
        st.notes.append("OpenSSH server is not installed.")
        return st
    st.mode = "socket" if st.socket_unit else "service"
    if st.service_unit:
        st.service_active = ctx.run(["systemctl", "is-active", "--quiet", st.service_unit]).ok or bool(st.socket_unit)
    eff = sshconf.effective(ctx)
    st.source, st.note = eff.source, eff.note
    st.config_ports = eff.ports
    if eff.source == "sshd -T" or ctx.is_root:
        ok, msg = sshconf.validate(ctx)
        st.config_valid, st.config_error = ok, "" if ok else msg
    if st.socket_unit:
        st.listening_ports = socket_ports(ctx, st.socket_unit)
    else:
        st.listening_ports = sorted({lst.port for lst in netinfo.listeners(ctx)
                                     if lst.proto == "tcp" and lst.process in ("sshd", "sshd-session", "")
                                     and lst.port in set(eff.ports)})
    st.password_auth = eff.flag("passwordauthentication", True)
    st.kbd_interactive = eff.flag("kbdinteractiveauthentication", False)
    st.pubkey_auth = eff.flag("pubkeyauthentication", True)
    st.root_login, st.root_label, st.root_detail, st.root_password_login = root_policy(eff)
    st.permit_empty = eff.flag("permitemptypasswords", False)
    st.max_auth_tries = eff.one("maxauthtries")
    st.login_grace_time = eff.one("logingracetime")
    st.authentication_methods = eff.one("authenticationmethods", "any")
    st.forwarding = eff.one("allowtcpforwarding", "yes")
    directives = sshconf.parse_config(ctx)
    st.match_overrides = [f"{d.file.name}:{d.lineno} Match {d.match}: {d.keyword} {d.args}"
                          for d in sshconf.match_overrides(directives)]
    pend = TxManager(ctx).pending()
    st.pending_tx = pend[0].id if pend else None
    return st


# ---------------------------------------------------------------------------
# Admin / key evidence
# ---------------------------------------------------------------------------

def other_admin_exists(exclude: str = "root") -> list[str]:
    """Local non-root users in an admin group with a real login shell."""
    admins = set()
    for gname in ("sudo", "admin", "wheel"):
        try:
            admins.update(grp.getgrnam(gname).gr_mem)
        except KeyError:
            continue
    out = []
    for name in sorted(admins):
        try:
            pw = pwd.getpwnam(name)
        except KeyError:
            continue
        if name != exclude and pw.pw_uid >= 1000 and not pw.pw_shell.endswith(("nologin", "false")):
            out.append(name)
    return out


def authorized_key_count(ctx: Context, user: str) -> int:
    try:
        home = pwd.getpwnam(user).pw_dir
    except KeyError:
        return 0
    text = read_text(ctx.paths.p(home) / ".ssh" / "authorized_keys")
    return sum(1 for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))


def recent_accepted_logins(ctx: Context) -> list[tuple[str, str, str, int]]:
    """(method, user, ip, port) for recent successful SSH logins from the journal or auth.log."""
    text = ""
    res = ctx.run(["journalctl", "--no-pager", "-q", "-o", "cat", "--since", "-3d", "-g", "Accepted ",
                   "_SYSTEMD_UNIT=ssh.service", "+", "_SYSTEMD_UNIT=sshd.service", "+", "_COMM=sshd", "+", "_COMM=sshd-session"],
                  timeout=30)
    if res.ok and res.stdout.strip():
        text = res.stdout
    else:
        log = ctx.paths.auth_log
        try:
            with open(log, "rb") as fh:
                fh.seek(0, 2)
                fh.seek(max(0, fh.tell() - 2_000_000))
                text = fh.read().decode("utf-8", "replace")
        except OSError:
            text = ""
    return [(m.group(1), m.group(2), m.group(3), int(m.group(4))) for m in ACCEPTED_RE.finditer(text)]


def live_pubkey_sessions(ctx: Context, since: float | None = None) -> list[netinfo.SshSession]:
    """Currently established SSH sessions whose login was authenticated with a public key."""
    logins = {(u, ip, port) for method, u, ip, port in recent_accepted_logins(ctx) if method == "publickey"}
    return [s for s in netinfo.ssh_sessions(ctx)
            if (s.user, s.remote_ip, s.remote_port) in logins and (since is None or s.started >= since)]


def pubkey_precheck(ctx: Context, eff: sshconf.Effective) -> list[str]:
    """Reasons why disabling password authentication is unsafe right now (empty list = OK)."""
    problems: list[str] = []
    if not eff.flag("pubkeyauthentication", True):
        problems.append("PubkeyAuthentication is disabled; turning passwords off would leave no way to log in.")
    methods = eff.one("authenticationmethods", "any")
    if methods not in ("any", "") :
        alts = methods.split()
        usable = [a for a in alts if not any(part.split(":")[0] in ("password", "keyboard-interactive") for part in a.split(","))]
        if not usable:
            problems.append(f"AuthenticationMethods '{methods}' requires a password-based method in every alternative; "
                            "disabling passwords would lock out all users.")
    if not live_pubkey_sessions(ctx):
        problems.append("No verified public-key login found. Open a NEW SSH session that logs in with your key "
                        "(not a password), then run this command from it (or any session while the key session is open).")
    return problems


# ---------------------------------------------------------------------------
# Option changes
# ---------------------------------------------------------------------------

OPTION_SPECS: dict[str, dict[str, Any]] = {
    "root-login": {"keyword": "PermitRootLogin", "choices": ("yes", "prohibit-password", "forced-commands-only", "no")},
    "max-auth-tries": {"keyword": "MaxAuthTries", "int": (2, 10)},
    "login-grace-time": {"keyword": "LoginGraceTime", "duration": (10, 600)},
    "empty-passwords": {"keyword": "PermitEmptyPasswords", "choices": ("yes", "no")},
    "pubkey": {"keyword": "PubkeyAuthentication", "choices": ("yes", "no")},
}


def normalise_option(name: str, value: str) -> tuple[str, str]:
    spec = OPTION_SPECS.get(name)
    if not spec:
        raise ValidationError(f"Unknown SSH option '{name}'.", hint="Options: " + ", ".join(sorted(OPTION_SPECS)))
    value = str(value).strip().lower()
    if name == "root-login" and value in ("key-only", "key", "without-password"):
        value = "prohibit-password"
    if "choices" in spec:
        if value not in spec["choices"]:
            raise ValidationError(f"{name} must be one of: {', '.join(spec['choices'])}")
        return spec["keyword"], value
    if "int" in spec:
        return spec["keyword"], str(parse_int_range(value, *spec["int"], name))
    secs = parse_duration(value)
    lo, hi = spec["duration"]
    if not lo <= secs <= hi:
        raise ValidationError(f"{name} must be between {lo}s and {hi}s")
    return spec["keyword"], str(secs)


def _is_risky(keyword: str, value: str, eff: sshconf.Effective) -> bool:
    if keyword == "PasswordAuthentication":
        return value == "no" and eff.flag("passwordauthentication", True)
    if keyword == "PermitRootLogin":
        return value in ("no", "forced-commands-only", "prohibit-password") and eff.one("permitrootlogin") != value
    if keyword == "PubkeyAuthentication":
        return value == "no"
    return False


def _prechecks(ctx: Context, eff: sshconf.Effective, changes: dict[str, str]) -> list[str]:
    problems: list[str] = []
    pw = changes.get("PasswordAuthentication")
    if pw == "no" and eff.flag("passwordauthentication", True):
        problems += pubkey_precheck(ctx, eff)
    root = changes.get("PermitRootLogin")
    if root in ("no", "forced-commands-only"):
        me = netinfo.current_session(ctx)
        if not other_admin_exists() and not (me and me.user != "root"):
            problems.append("Root is the only administrator account; disabling root login would lock you out. "
                            "Create a sudo user first (adduser <name>; usermod -aG sudo <name>).")
    if root == "prohibit-password" and eff.one("permitrootlogin") == "yes" and not other_admin_exists() \
            and authorized_key_count(ctx, "root") == 0:
        problems.append("Root has no authorized SSH keys and no other admin user exists; switching root to key-only "
                        "would lock you out.")
    if changes.get("PubkeyAuthentication") == "no" and not eff.flag("passwordauthentication", True):
        problems.append("Password authentication is off; disabling public keys would leave no login method.")
    return problems


def _effective_matches(ctx: Context, expected: dict[str, str | None], eff: sshconf.Effective) -> list[str]:
    bad = []
    for kw, val in expected.items():
        if val is None:
            continue
        got = eff.one(kw.lower()).lower()
        if got != val.lower() and not (kw == "PermitRootLogin" and {got, val.lower()} <= {"without-password", "prohibit-password"}):
            bad.append(f"{kw}: wanted {val}, effective {got or 'unset'}")
    return bad


def _shadow_report(ctx: Context, keyword: str) -> str:
    me = ctx.paths.ssh_dropin
    for d in sshconf.parse_config(ctx):
        if d.keyword == keyword.lower() and d.is_global and d.file != me:
            return f"{d.file}:{d.lineno} ('{d.raw.strip()}') takes precedence"
    return "an earlier configuration directive takes precedence"


def reload_ssh(ctx: Context, st: SshStatus) -> None:
    unit = st.service_unit or "ssh.service"
    if st.socket_unit and not ctx.run(["systemctl", "is-active", "--quiet", unit]).ok:
        return  # socket-activated and idle: sshd reads the new configuration when it next starts
    res = ctx.run_mut(["systemctl", "reload", unit], timeout=30)
    if not res.ok:
        raise OperationFailed(f"systemctl reload {unit} failed: {res.output}")


def change_options(ctx: Context, changes: dict[str, str | None], *, label: str, verify_fn=None) -> dict[str, Any]:
    """Apply SSH directives through Bant's drop-in, validate, reload and verify the *effective* result.

    Risky changes open a rollback transaction and return {'pending': tx} - they become permanent only
    via confirm(). Everything else is applied immediately with automatic local revert on failure.
    """
    ctx.require_root("Changing SSH configuration")
    if not has_systemd(ctx) and not ctx.dry_run:
        raise Unsupported("systemd is required.")
    with ctx.lock():
        st = status(ctx)
        if not st.installed:
            raise Unsupported("OpenSSH server is not installed.")
        if st.pending_tx:
            raise OperationFailed(f"SSH transaction {st.pending_tx} is still pending.",
                                  hint="Run `bant ssh cf` (or `bant ssh rollback`) first.")
        if st.config_valid is False:
            raise OperationFailed(f"The current SSH configuration is invalid: {st.config_error}",
                                  hint="Fix it before changing settings (backup available via `bant restore`).")
        eff = sshconf.effective(ctx)
        problems = _prechecks(ctx, eff, changes)
        if problems:
            raise OperationFailed("Refusing unsafe change: " + " ".join(problems))
        ports, options = sshconf.read_dropin(ctx)
        new_options = {k: v for k, v in {**options, **changes}.items() if v is not None}
        if new_options == options and ctx.paths.ssh_dropin.exists():
            return {"changed": False, "message": f"{label}: already configured"}
        risky = any(_is_risky(kw, v, eff) for kw, v in changes.items())
        content = sshconf.render_dropin(ports, new_options)
        if ctx.dry_run:
            ctx.planned.append(f"write {ctx.paths.ssh_dropin}")
            ctx.planned.append(f"systemctl reload {st.service_unit}")
            return {"changed": True, "dry_run": True, "risky": risky, "message": label}

        txm = TxManager(ctx)
        tx: Transaction | None = None
        original = ctx.paths.ssh_dropin.read_bytes() if ctx.paths.ssh_dropin.exists() else None
        try:
            if risky:
                tx = txm.begin("ssh-auth", ctx.config.rollback_minutes,
                               {"changes": changes, "require": {"method": "publickey" if changes.get("PasswordAuthentication") == "no" else None,
                                                                "min_started": ctx.clock()}})
                txm.backup_file(tx, ctx.paths.ssh_dropin)
                txm.add_post(tx, ["systemctl", "reload", st.service_unit or "ssh.service"])
            ctx.write_file(ctx.paths.ssh_dropin, content, 0o644)
            ok, msg = sshconf.validate(ctx)
            if not ok:
                raise OperationFailed(f"sshd rejected the new configuration: {msg}")
            reload_ssh(ctx, st)
            new_eff = sshconf.effective(ctx)
            bad = _effective_matches(ctx, changes, new_eff)
            if bad:
                kw = next(k for k, v in changes.items() if v is not None)
                raise OperationFailed(f"The change did not take effect ({'; '.join(bad)}): {_shadow_report(ctx, kw)}")
            if not ctx.banner_probe("127.0.0.1", (st.active_ports or [22])[0]):
                raise OperationFailed("sshd does not answer on its port after reload.")
        except Exception as exc:
            if tx is not None:
                txm.rollback(tx, str(exc))
            else:
                if original is None:
                    ctx.paths.ssh_dropin.unlink(missing_ok=True)
                else:
                    ctx.write_file(ctx.paths.ssh_dropin, original, 0o644)
                if st.service_unit:
                    ctx.run_mut(["systemctl", "reload", st.service_unit])
            ctx.audit("ssh.option.failed", level="error", changes=changes, error=str(exc))
            if isinstance(exc, BantError):
                raise RolledBack(f"{exc.message} - previous SSH configuration restored.", hint=exc.hint) from exc
            raise
        extra = _match_warnings(ctx, changes)
        ctx.audit("ssh.option", changes=changes, risky=risky, tx=tx.id if tx else None)
        if tx is not None:
            txm.set_phase(tx, "awaiting_confirmation", f"{label} applied; awaiting verification of a new session")
            return {"changed": True, "pending": tx.id, "deadline": tx.deadline, "warnings": extra, "message": label}
        return {"changed": True, "warnings": extra, "message": label}


def _match_warnings(ctx: Context, changes: dict[str, str]) -> list[str]:
    out = []
    for d in sshconf.match_overrides(sshconf.parse_config(ctx), keys=tuple(k.lower() for k in changes)):
        out.append(f"{d.file.name}:{d.lineno} Match {d.match} sets {d.keyword} {d.args} and overrides this change for matching connections")
    return out


def set_password_auth(ctx: Context, enable: bool) -> dict[str, Any]:
    if enable:
        # Setting it explicitly makes the request effective even if another file said "no";
        # dropping our KbdInteractive override restores the administrator's original value.
        changes: dict[str, str | None] = {"PasswordAuthentication": "yes", "KbdInteractiveAuthentication": None}
    else:
        # KbdInteractive also carries PAM password prompts, so both must go for passwords to be off.
        changes = {"PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no"}
    result = change_options(ctx, changes, label=f"SSH password authentication {'enabled' if enable else 'disabled'}")
    if enable and result.get("changed"):
        result.setdefault("warnings", []).append(
            "Password logins are exposed to brute-force attempts; keep Fail2ban enabled and prefer strong passwords or keys.")
    return result


def set_option(ctx: Context, name: str, value: str) -> dict[str, Any]:
    keyword, val = normalise_option(name, value)
    return change_options(ctx, {keyword: val}, label=f"{keyword} set to {val}")


