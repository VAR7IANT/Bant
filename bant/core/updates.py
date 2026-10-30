"""Automatic security updates via the distribution's unattended-upgrades (Debian/Ubuntu).

Bant never edits distribution-owned files: it manages one drop-in (52bant-unattended-upgrades)
that turns the periodic security upgrade on. Removing that file returns the system to whatever
the administrator had configured. Bant never enables automatic reboots.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from bant.context import Context
from bant.errors import OperationFailed, Unsupported
from bant.utils.fsutil import MANAGED_HEADER

BANT_CONF = (
    MANAGED_HEADER
    + 'APT::Periodic::Update-Package-Lists "1";\n'
    'APT::Periodic::Unattended-Upgrade "1";\n'
)


@dataclass
class UpdateStatus:
    installed: bool = False
    auto_enabled: bool = False
    managed_by_bant: bool = False
    allowed_origins: list[str] = field(default_factory=list)
    security_origin_allowed: bool | None = None
    auto_reboot: bool | None = None
    reboot_required: bool = False
    pending_security: list[str] = field(default_factory=list)
    pending_total: int | None = None
    index_age_hours: float | None = None
    package_manager_busy: bool = False
    note: str = ""


def parse_apt_config(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = re.match(r'^(\S+?)(?:::\d+)?\s+"?(.*?)"?;$', line.strip())
        if m:
            out.setdefault(m.group(1), []).append(m.group(2))
    return out


def package_manager_busy(ctx: Context) -> bool:
    for lock in ("/var/lib/dpkg/lock-frontend", "/var/lib/apt/lists/lock"):
        if ctx.run(["fuser", ctx.paths.p(lock).as_posix()]).ok:
            return True
    return False


def parse_simulated_upgrade(text: str) -> tuple[list[str], int]:
    """Names of pending security updates and total pending, from `apt-get -s upgrade` output."""
    security, total = [], 0
    for line in text.splitlines():
        if line.startswith("Inst "):
            total += 1
            name = line.split()[1]
            if re.search(r"-security|\bESM\b|/[^ ]*security", line):
                security.append(name)
    return security, total


def status(ctx: Context) -> UpdateStatus:
    st = UpdateStatus()
    st.installed = ctx.run(["dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"]).stdout.endswith("installed")
    cfg = ctx.run(["apt-config", "dump"])
    values = parse_apt_config(cfg.stdout) if cfg.ok else {}
    st.auto_enabled = st.installed and (values.get("APT::Periodic::Unattended-Upgrade", ["0"])[-1] not in ("0", ""))
    st.managed_by_bant = ctx.paths.apt_bant_conf.exists()
    st.allowed_origins = values.get("Unattended-Upgrade::Allowed-Origins", [])
    if st.allowed_origins:
        st.security_origin_allowed = any("security" in o.lower() or "esm" in o.lower() for o in st.allowed_origins)
    rb = values.get("Unattended-Upgrade::Automatic-Reboot")
    st.auto_reboot = rb[-1].lower() == "true" if rb else False
    st.reboot_required = ctx.paths.reboot_required.exists()
    st.package_manager_busy = package_manager_busy(ctx)
    sim = ctx.run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=60)
    if sim.ok:
        st.pending_security, st.pending_total = parse_simulated_upgrade(sim.stdout)
    else:
        st.note = "Could not simulate an upgrade (apt unavailable?)."
    lists = ctx.paths.p("/var/lib/apt/periodic/update-success-stamp")
    try:
        st.index_age_hours = round((ctx.clock() - lists.stat().st_mtime) / 3600, 1)
    except OSError:
        pass
    return st


def enable(ctx: Context) -> str:
    ctx.require_root("Enabling automatic security updates")
    with ctx.lock():
        st = status(ctx)
        if st.package_manager_busy:
            raise OperationFailed("Another package manager (apt/dpkg) is running.", hint="Wait for it to finish and retry.")
        if ctx.which("apt-get") is None:
            raise Unsupported("Automatic updates are only supported on Debian/Ubuntu (apt).")
        if not st.installed:
            res = ctx.run_mut(["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y",
                               "-o", "DPkg::Lock::Timeout=120", "unattended-upgrades"], timeout=900)
            if not res.ok:
                raise OperationFailed(f"Installing unattended-upgrades failed: {res.output[-300:]}")
        ctx.write_file(ctx.paths.apt_bant_conf, BANT_CONF, 0o644)
        ctx.audit("updates.enable")
        after = status(ctx) if not ctx.dry_run else st
        extra = ""
        if after.security_origin_allowed is False:
            extra = " WARNING: the configured Allowed-Origins do not include a security origin."
        return "Automatic security updates enabled (reboots are NOT automatic)." + extra


def disable(ctx: Context) -> str:
    ctx.require_root("Disabling Bant's update settings")
    with ctx.lock():
        if not ctx.paths.apt_bant_conf.exists():
            return "Bant is not managing update settings; nothing to disable."
        ctx.remove_file(ctx.paths.apt_bant_conf)
        ctx.audit("updates.disable")
        return "Removed Bant's update settings; your own apt configuration applies again."


def as_dict(st: UpdateStatus) -> dict[str, Any]:
    return {k: getattr(st, k) for k in st.__dataclass_fields__}
