"""Security audit: evidence-based findings, no composite "score".

Each finding states what was observed, why it matters, what to do, and whether Bant can fix it
safely. Severity reflects exposure, not a guarantee: an empty report means "nothing found by these
checks", never "secure".
"""

from __future__ import annotations

import re
import stat
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from bant.context import Context
from bant.core import backups, fail2ban, firewall, migration, netinfo, ssh, updates
from bant.core.rollback import TxManager
from bant.platform import has_systemd

SEVERITIES = ("critical", "high", "medium", "low", "info")
RISKY_PUBLIC_PORTS = {23: "telnet", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
                      9200: "Elasticsearch", 11211: "memcached", 2375: "Docker API (unencrypted)", 5900: "VNC"}


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    evidence: str
    impact: str
    recommendation: str
    fixable: bool = False
    fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


Check = Callable[[Context], list[Finding]]


def _ssh_checks(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    st = ssh.status(ctx)
    if not st.installed:
        return [Finding("SSH-000", "info", "OpenSSH server not installed", "sshd not found", "None - no SSH attack surface",
                        "No action needed unless you expect SSH access.")]
    if st.config_valid is False:
        out.append(Finding("SSH-001", "critical", "SSH configuration is invalid", st.config_error[:300],
                           "sshd may fail to start or reload; you could lose remote access",
                           "Fix the configuration or restore a backup (`sudo bant restore`).", True, "sudo bant restore"))
    if st.pending_tx:
        out.append(Finding("SSH-002", "high", "An SSH change is waiting for confirmation", f"transaction {st.pending_tx}",
                           "It will be rolled back automatically at its deadline; until then a temporary configuration is live",
                           "Open a new session and run `sudo bant ssh cf`, or `sudo bant ssh rollback`.", True, "sudo bant ssh cf"))
    ports = st.active_ports
    if ports == [22]:
        out.append(Finding("SSH-010", "low", "SSH is on the default port 22", "listening on 22",
                           "Default-port SSH receives the bulk of automated scanning and brute-force traffic",
                           "Move SSH to a random free port safely with `sudo bant ssh port random`, or pick your own: `sudo bant ssh port <PORT>`.",
                           True, "sudo bant ssh port random"))
    elif len(ports) > 1:
        out.append(Finding("SSH-011", "low", "SSH listens on multiple ports", f"ports {ports}",
                           "Extra listeners widen the attack surface", "Remove ports you no longer need.", False))
    if st.permit_empty:
        out.append(Finding("SSH-020", "critical", "Empty passwords are permitted", "PermitEmptyPasswords yes",
                           "Accounts with no password can log in remotely", "sudo bant ssh set empty-passwords no", True,
                           "sudo bant ssh set empty-passwords no"))
    if st.password_auth:
        sev = "medium"
        out.append(Finding("SSH-021", sev, "SSH password authentication is enabled", "PasswordAuthentication yes",
                           "Passwords can be guessed; Fail2ban only slows this down",
                           "Set up key login, verify it, then run `sudo bant ssh password off`.", True, "sudo bant ssh password off"))
    elif st.kbd_interactive:
        out.append(Finding("SSH-022", "high", "Passwords are still possible via keyboard-interactive",
                           "PasswordAuthentication no but KbdInteractiveAuthentication yes",
                           "With PAM this accepts password prompts, defeating 'password off'",
                           "Run `sudo bant ssh password off` which disables both.", True, "sudo bant ssh password off"))
    if not st.pubkey_auth:
        out.append(Finding("SSH-023", "medium", "Public-key authentication is disabled", "PubkeyAuthentication no",
                           "Forces password-based logins", "sudo bant ssh set pubkey yes", True, "sudo bant ssh set pubkey yes"))
    if st.root_login == "yes":
        sev = "high" if st.password_auth else "medium"
        out.append(Finding("SSH-030", sev, "Root login is permitted with password" if st.password_auth else "Root login is permitted",
                           f"PermitRootLogin yes (password auth {'on' if st.password_auth else 'off'})",
                           "The root account is the most targeted account on the internet",
                           "Create a sudo user, then `sudo bant ssh root key-only` (or `no`).", True, "sudo bant ssh root key-only"))
    try:
        if int(st.max_auth_tries or 0) > 6:
            out.append(Finding("SSH-040", "low", "MaxAuthTries is high", f"MaxAuthTries {st.max_auth_tries}",
                               "More guesses per connection", "sudo bant ssh set max-auth-tries 4", True,
                               "sudo bant ssh set max-auth-tries 4"))
        if int(st.login_grace_time or 0) > 120 or st.login_grace_time == "0":
            out.append(Finding("SSH-041", "low", "LoginGraceTime is long or unlimited", f"LoginGraceTime {st.login_grace_time}",
                               "Idle pre-auth connections tie up sshd slots", "sudo bant ssh set login-grace-time 60", True,
                               "sudo bant ssh set login-grace-time 60"))
    except ValueError:
        pass
    if st.match_overrides:
        out.append(Finding("SSH-050", "info", "Match blocks override authentication settings", "; ".join(st.match_overrides)[:300],
                           "Global settings shown by Bant may not apply to those users/addresses", "Review these blocks.", False))
    if st.forwarding == "yes":
        out.append(Finding("SSH-060", "info", "TCP forwarding is allowed", "AllowTcpForwarding yes",
                           "Normal for proxy/tunnel use; allows port-forwarding by any authenticated user",
                           "Leave as-is if you rely on tunnelling. Bant never changes forwarding automatically.", False))
    return out


def _fail2ban_checks(ctx: Context) -> list[Finding]:
    ov = fail2ban.overview(ctx)
    fix = "sudo bant fail2ban enable"
    if not ov.installed:
        return [Finding("F2B-001", "high", "Fail2ban is not installed", "fail2ban-client not found",
                        "Repeated SSH login attempts are not blocked", "Install and configure it with `sudo bant fail2ban enable`.", True, fix)]
    out: list[Finding] = []
    if ov.state == "inactive":
        out.append(Finding("F2B-002", "high", "Fail2ban is not running", f"fail2ban.service is {ov.service}",
                           "No automatic SSH brute-force blocking", "sudo bant fail2ban enable", True, fix))
    elif not ov.jail_enabled or not ov.jail_running:
        out.append(Finding("F2B-003", "high", "The sshd jail is not active", f"jail defined={ov.jail_enabled} running={ov.jail_running}",
                           "SSH is not protected even though Fail2ban is running", "sudo bant fail2ban enable", True, fix))
    elif ov.state == "misconfigured":
        sev = "high" if any("covers SSH" in p or "running" in p for p in ov.problems) else "medium"
        out.append(Finding("F2B-004", sev, "Fail2ban is running but not verified operational", "; ".join(ov.problems)[:400],
                           "Protection may silently not work", "Run `sudo bant repair`, then `bant doctor`.", True, "sudo bant repair"))
    if ov.conflicts:
        out.append(Finding("F2B-005", "medium", "Administrator settings override Bant's SSH jail policy", "; ".join(ov.conflicts)[:300],
                           "Bant intentionally did not overwrite them, so its desired policy is not fully in effect",
                           "Edit or remove those lines if you want Bant to manage them.", False))
    if ov.state == "verified":
        out.append(Finding("F2B-000", "info", "Fail2ban SSH protection verified",
                           f"ports {ov.ports}, maxretry {ov.maxretry}, findtime {ov.findtime}, bantime {ov.bantime}",
                           "None", "No action needed.", False))
    return out


def _firewall_checks(ctx: Context) -> list[Finding]:
    info = firewall.detect(ctx)
    out: list[Finding] = []
    public = [lst for lst in netinfo.listeners(ctx) if lst.scope == "public"]
    if info.mode == "observe":
        out.append(Finding("FW-001", "info", "Firewall is in observation-only mode", info.detail,
                           "Bant cannot add or verify firewall rules", "Run as root for full visibility.", False))
    elif info.backend == "none" and public:
        out.append(Finding("FW-002", "medium", "No host firewall is active",
                           f"{len(public)} publicly bound listener(s)", "Every listening service is reachable from the internet "
                           "unless your provider filters traffic", "Enable ufw/nftables with rules for the services you intend to expose. "
                           "Bant does not enable a firewall automatically because that can break running services.", False))
    elif info.backend in ("nftables", "iptables") and not info.restrictive:
        out.append(Finding("FW-003", "low", "Firewall present but inbound traffic is not filtered by default", info.detail,
                           "Services are reachable unless individually blocked", "Consider a default-deny input policy "
                           "(after allowing SSH and your services).", False))
    return out


def _listener_checks(ctx: Context) -> list[Finding]:
    ssh_ports = set(ssh.status(ctx).active_ports)
    out: list[Finding] = []
    public = [lst for lst in netinfo.listeners(ctx) if lst.scope == "public" and lst.port not in ssh_ports]
    risky = [lst for lst in public if lst.proto == "tcp" and lst.port in RISKY_PUBLIC_PORTS]
    for lst in risky:
        out.append(Finding(f"NET-{lst.port}", "high", f"{RISKY_PUBLIC_PORTS[lst.port]} is exposed publicly",
                           f"{lst.proto} {lst.addr}:{lst.port} ({lst.process or 'unknown process'})",
                           "Database/admin services should not be reachable from the internet",
                           "Bind it to 127.0.0.1 or restrict it with the firewall.", False))
    others = sorted({(lst.proto, lst.port, lst.process) for lst in public if lst not in risky})
    if others:
        listing = ", ".join(f"{p}/{n}{'(' + proc + ')' if proc else ''}" for p, n, proc in others[:25])
        out.append(Finding("NET-000", "info", f"{len(others)} other publicly bound service port(s)", listing,
                           "Informational: expected for proxy/web services; unexpected entries deserve a look",
                           "Verify each entry is something you run. Bant does not treat UDP traffic volume as suspicious.", False))
    return out


def _ipv6_checks(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    v6 = [lst for lst in netinfo.listeners(ctx) if lst.scope == "public" and lst.addr in ("::", "[::]", "*")]
    ufw_default = ctx.paths.p("/etc/default/ufw").read_text(errors="replace") if ctx.paths.p("/etc/default/ufw").exists() else ""
    info = firewall.detect(ctx)
    if info.backend == "ufw" and re.search(r"^IPV6=no", ufw_default, re.M) and v6:
        out.append(Finding("V6-001", "medium", "UFW is not filtering IPv6", "IPV6=no in /etc/default/ufw while services listen on [::]",
                           "IPv6 clients bypass your IPv4 firewall rules", "Set IPV6=yes in /etc/default/ufw and reload ufw "
                           "(Bant does not disable IPv6 and will not edit ufw's defaults).", False))
    elif info.backend == "iptables" and info.restrictive and ctx.which("ip6tables"):
        parsed = firewall.parse_iptables_input(ctx.run(["ip6tables", "-S", "INPUT"]).stdout)
        if not parsed["restrictive"] and v6:
            out.append(Finding("V6-002", "medium", "IPv4 is filtered but IPv6 is not", "ip6tables INPUT policy ACCEPT",
                               "IPv6 traffic bypasses the IPv4 rules", "Mirror your IPv4 rules with ip6tables.", False))
    return out


def _update_checks(ctx: Context) -> list[Finding]:
    st = updates.status(ctx)
    out: list[Finding] = []
    if st.pending_security:
        sev = "high" if len(st.pending_security) >= 10 else "medium"
        out.append(Finding("UPD-001", sev, f"{len(st.pending_security)} security update(s) pending",
                           ", ".join(st.pending_security[:10]) + (" ..." if len(st.pending_security) > 10 else ""),
                           "Known vulnerabilities remain unpatched", "apt-get upgrade (or enable automatic security updates).",
                           True, "sudo bant updates enable"))
    if not st.auto_enabled:
        out.append(Finding("UPD-002", "low", "Automatic security updates are not enabled",
                           "unattended-upgrades " + ("installed but disabled" if st.installed else "not installed"),
                           "New vulnerabilities depend on you remembering to patch", "sudo bant updates enable", True, "sudo bant updates enable"))
    if st.reboot_required:
        out.append(Finding("UPD-003", "low", "A reboot is required", "/var/run/reboot-required exists",
                           "Some updates (e.g. kernel) are not active until reboot", "Reboot at a convenient time. Bant never reboots for you.", False))
    if st.auto_reboot:
        out.append(Finding("UPD-004", "info", "unattended-upgrades is configured to reboot automatically", "Automatic-Reboot true",
                           "Services restart unexpectedly", "Configured by you, not Bant.", False))
    return out


def _auth_failure_checks(ctx: Context) -> list[Finding]:
    res = ctx.run(["journalctl", "--no-pager", "-q", "-o", "cat", "--since", "-24h", "-n", "5000", "-g",
                   "Failed password|Invalid user|authentication failure",
                   "_SYSTEMD_UNIT=ssh.service", "+", "_SYSTEMD_UNIT=sshd.service", "+", "_COMM=sshd", "+", "_COMM=sshd-session"], timeout=40)
    if not res.ok:
        return []
    count = len([ln for ln in res.lines() if ln.strip()])
    if count == 0:
        return []
    ov = fail2ban.overview(ctx)
    protected = ov.state == "verified"
    sev = "info" if protected or count < 50 else "high"
    shown = f"{count}+" if count >= 5000 else str(count)
    return [Finding("AUTH-001", sev, f"{shown} failed SSH login events in the last 24h", "journal sample",
                    "Normal background noise on public servers; a problem when nothing blocks it",
                    "Keep Fail2ban verified; consider key-only login." if protected else "Fail2ban is not verified - fix that first.",
                    False)]


def _service_checks(ctx: Context) -> list[Finding]:
    res = ctx.run(["systemctl", "--failed", "--no-legend", "--plain"])
    names = [ln.split()[0] for ln in res.lines() if ln.strip()]
    if not names:
        return []
    critical = [n for n in names if n.startswith(("ssh", "sshd", "fail2ban", "ufw", "firewalld", "nftables"))]
    return [Finding("SVC-001", "high" if critical else "low", f"{len(names)} failed systemd unit(s)", ", ".join(names[:12]),
                    "Failed security/network units may mean missing protection" if critical else "Something you run is not working",
                    "Inspect with `systemctl status <unit>` and `journalctl -u <unit>`.", False)]


def _permission_checks(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    p = ctx.paths
    watch = [p.sshd_config] + (sorted(p.sshd_config_d.glob("*")) if p.sshd_config_d.is_dir() else [])
    for path in watch:
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            out.append(Finding("PERM-001", "high", f"{path.name} is writable by non-root", f"mode {oct(mode & 0o777)}",
                               "A local user could change SSH settings", f"chmod go-w {path}", False))
    keys = sorted(p.ssh_dir.glob("ssh_host_*_key")) if p.ssh_dir.is_dir() else []
    for k in keys:
        if k.stat().st_mode & 0o077:
            out.append(Finding("PERM-002", "high", f"Host private key {k.name} is accessible to other users", f"mode {oct(k.stat().st_mode & 0o777)}",
                               "Allows server impersonation", f"chmod 600 {k}", False))
    for issue in backups.secure_perms(ctx):
        out.append(Finding("PERM-003", "medium", "Bant state is too permissive", issue, "Backups/state may expose configuration",
                           "chmod to the expected mode (see message) or run `sudo bant repair`.", True, "sudo bant repair"))
    return out


def _recovery_checks(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    if not has_systemd(ctx):
        out.append(Finding("REC-001", "medium", "systemd not detected", "no /run/systemd/system",
                           "Bant cannot arm automatic rollback, so it will refuse risky SSH changes", "Use a systemd-based host.", False))
    items = backups.list_backups(ctx)
    if not items:
        out.append(Finding("REC-002", "low", "No Bant configuration backup exists", "backup directory empty",
                           "Nothing to restore from", "sudo bant backup", True, "sudo bant backup"))
    else:
        _, bad = backups.verify_integrity(ctx)
        if bad:
            out.append(Finding("REC-003", "medium", f"{bad} backup(s) failed their integrity check", "checksum mismatch",
                               "Those backups cannot be restored", "Create a fresh backup.", True, "sudo bant backup"))
    stale = [t for t in TxManager(ctx).all() if t.status == "rollback_failed"]
    if stale:
        out.append(Finding("REC-004", "critical", "A rollback did not complete", f"transaction {stale[-1].id}",
                           "SSH or firewall may be in a partially changed state", "Run `sudo bant repair` and see docs/RECOVERY.md.", True, "sudo bant repair"))
    pend = migration.describe_pending(ctx)
    if pend and pend["seconds_left"] < 120:
        out.append(Finding("REC-005", "high", "Rollback deadline is very close", f"{pend['seconds_left']}s left",
                           "SSH will revert momentarily", "Confirm now if the new connection works.", True, "sudo bant ssh cf"))
    return out


CHECKS: list[tuple[str, Check, bool]] = [  # (name, fn, slow)
    ("ssh", _ssh_checks, False),
    ("fail2ban", _fail2ban_checks, False),
    ("firewall", _firewall_checks, False),
    ("listeners", _listener_checks, False),
    ("ipv6", _ipv6_checks, False),
    ("updates", _update_checks, True),
    ("auth-failures", _auth_failure_checks, True),
    ("services", _service_checks, False),
    ("permissions", _permission_checks, False),
    ("recovery", _recovery_checks, False),
]


def run(ctx: Context, *, quick: bool = False) -> list[Finding]:
    with ctx.cached():
        return _run(ctx, quick)


def _run(ctx: Context, quick: bool) -> list[Finding]:
    findings: list[Finding] = []
    for name, fn, slow in CHECKS:
        if quick and slow:
            continue
        try:
            findings += fn(ctx)
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the others
            findings.append(Finding(f"ERR-{name}", "info", f"Check '{name}' could not run", f"{type(exc).__name__}: {exc}",
                                    "This area was not assessed", "Run `bant doctor`.", False))
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.id))
    return findings


def summarize(findings: list[Finding]) -> dict[str, Any]:
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    if counts["critical"]:
        verdict = "CRITICAL issues found"
    elif counts["high"]:
        verdict = "High-severity issues found"
    elif counts["medium"]:
        verdict = "Medium-severity issues found"
    else:
        verdict = "No high-severity issues found by these checks"
    return {"counts": counts, "verdict": verdict,
            "disclaimer": "This is a configuration review of specific checks, not a guarantee of security or a numeric score."}
