"""`bant status` and `bant doctor`: component state, distinguishing installed/running/verified."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from bant import __version__
from bant.context import Context
from bant.core import backups, bans, fail2ban, firewall, migration, security_audit, ssh, updater, updates
from bant.core.rollback import TxManager
from bant.platform import detect_os, has_systemd, unit_state
from bant.utils.fsutil import mode_str


def collect(ctx: Context, *, deep: bool = False) -> dict[str, Any]:
    """Machine-readable system overview. `deep` adds slower checks (update simulation, log scans)."""
    with ctx.cached():
        return _collect(ctx, deep)


def _collect(ctx: Context, deep: bool) -> dict[str, Any]:
    osi = detect_os(ctx)
    st = ssh.status(ctx)
    f2b = fail2ban.overview(ctx, st.active_ports or None)
    fw = firewall.detect(ctx)
    findings = security_audit.run(ctx, quick=not deep)
    upd = updates.status(ctx) if deep else None
    cfg = ctx.config
    bant_blocks = len(bans.active_entries(ctx))
    pend = migration.describe_pending(ctx)
    crit = [f for f in findings if f.severity in ("critical", "high")]
    if not st.installed:
        health = "unknown"
    elif any(f.severity == "critical" for f in findings):
        health = "critical"
    elif crit or pend:
        health = "attention"
    else:
        health = "healthy"
    return {
        "bant_version": __version__,
        "os": {"name": osi.pretty, "supported": osi.supported, "kernel": osi.kernel},
        "privileged": ctx.is_root,
        "ssh": {
            "installed": st.installed, "mode": st.mode, "ports": st.active_ports, "configured_ports": st.config_ports,
            "target_port": cfg.ssh_port or None, "service_active": st.service_active, "config_valid": st.config_valid,
            "password_auth": st.password_auth, "kbd_interactive": st.kbd_interactive, "pubkey_auth": st.pubkey_auth,
            "root_login": st.root_login, "root_label": st.root_label, "max_auth_tries": st.max_auth_tries,
            "login_grace_time": st.login_grace_time, "source": st.source, "pending": pend,
        },
        "fail2ban": {
            "state": f2b.state, "installed": f2b.installed, "version": f2b.version, "service": f2b.service,
            "jail_running": f2b.jail_running, "ports": f2b.ports, "maxretry": f2b.maxretry, "findtime": f2b.findtime,
            "bantime": f2b.bantime, "backend": f2b.backend, "banaction": f2b.banaction,
            "currently_banned": f2b.currently_banned, "problems": f2b.problems, "conflicts": f2b.conflicts,
        },
        "firewall": {"backend": fw.backend, "active": fw.active, "mode": fw.mode, "restrictive": fw.restrictive,
                     "docker": fw.docker, "detail": fw.detail, "bant_rules": len(firewall.registry(ctx))},
        "bans": {"fail2ban": f2b.currently_banned or 0, "bant": bant_blocks},
        "updates": ({"auto_enabled": upd.auto_enabled, "pending_security": len(upd.pending_security),
                     "reboot_required": upd.reboot_required, "installed": upd.installed} if upd else None),
        "findings": {"summary": security_audit.summarize(findings)["counts"],
                     "critical_and_high": [f.to_dict() for f in crit]},
        "bant_update": {k: updater.cached(ctx).get(k) for k in ("latest", "available", "checked_at", "prerelease")},
        "health": health,
        "setup": _setup_state(ctx),
        "notes": list(ctx.config.problems) + ([ssh_note] if (ssh_note := st.note) and st.source != "sshd -T" else []),
    }


def _setup_state(ctx: Context) -> str:
    from bant.core import setup

    try:
        return setup.initialized(ctx)
    except Exception:  # noqa: BLE001 - status must always render
        return "unknown"


@dataclass
class DoctorCheck:
    area: str
    name: str
    status: str  # ok | warn | fail | skip
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def doctor(ctx: Context) -> list[DoctorCheck]:
    out: list[DoctorCheck] = []

    def add(area: str, name: str, ok: bool | None, detail: str = "", *, warn: bool = False) -> None:
        status = "skip" if ok is None else ("ok" if ok else ("warn" if warn else "fail"))
        out.append(DoctorCheck(area, name, status, detail))

    osi = detect_os(ctx)
    add("system", "supported distribution", osi.supported, osi.pretty, warn=True)
    add("system", "systemd present", has_systemd(ctx), "required for automatic rollback")
    add("system", "running as root", ctx.is_root, "some checks need root", warn=True)
    for problem in ctx.config.problems:
        add("config", "bant.toml", False, problem, warn=True)

    st = ssh.status(ctx)
    add("ssh", "OpenSSH server installed", st.installed, st.service_unit or "")
    if st.installed:
        add("ssh", "sshd configuration valid (sshd -t)", st.config_valid, st.config_error)
        add("ssh", "effective config source", st.source == "sshd -T", st.source + (f" - {st.note}" if st.note else ""), warn=True)
        add("ssh", "listening", bool(st.listening_ports), f"ports {st.listening_ports or 'none detected'} (mode: {st.mode})")
        add("ssh", "not on the default port 22", 22 not in st.active_ports, f"active ports {st.active_ports}", warn=True)
        for port in st.active_ports[:1]:
            add("ssh", "answers with an SSH banner", ctx.banner_probe("127.0.0.1", port) is not None, f"127.0.0.1:{port}")
        add("ssh", "no pending transaction", st.pending_tx is None, st.pending_tx or "", warn=True)

    txm = TxManager(ctx)
    for tx in txm.pending():
        svc, tmr = txm.unit_names(tx.id)
        state = unit_state(ctx, tmr)
        add("rollback", f"timer for {tx.id}", state["ActiveState"] == "active", f"{tmr}: {state['ActiveState'] or 'missing'}; "
            f"{tx.seconds_left(ctx.clock())}s left")
    failed = [t.id for t in txm.all() if t.status == "rollback_failed"]
    add("rollback", "no failed rollbacks", not failed, ", ".join(failed))

    ov = fail2ban.overview(ctx, st.active_ports or None)
    add("fail2ban", "installed", ov.installed, ov.version)
    if ov.installed:
        add("fail2ban", "service state", ov.state in ("verified", "running"), f"{ov.state} (service {ov.service})")
        for c in ov.checks:
            add("fail2ban", c.name, c.ok, c.detail, warn=c.ok is None)
        for c in ov.conflicts:
            add("fail2ban", "administrator setting differs", False, c + " - see `bant fail2ban conflicts`", warn=True)

    fw = firewall.detect(ctx)
    add("firewall", "backend", True, f"{fw.backend} ({fw.mode}): {fw.detail}")
    add("firewall", "Bant blocklist available (nft)", bans.available(ctx), "needed for permanent/manual blocks", warn=True)

    items = backups.list_backups(ctx)
    add("backup", "backups exist", bool(items), f"{len(items)} backup(s)", warn=True)
    if items:
        good, bad = backups.verify_integrity(ctx)
        add("backup", "backup integrity", bad == 0, f"{good} ok, {bad} corrupt")
    for issue in backups.secure_perms(ctx):
        add("permissions", "Bant state permissions", False, issue)
    add("permissions", "audit log", ctx.paths.audit_log.exists() and (ctx.paths.audit_log.stat().st_mode & 0o077) == 0
        if ctx.paths.audit_log.exists() else None, mode_str(ctx.paths.audit_log))
    return out
