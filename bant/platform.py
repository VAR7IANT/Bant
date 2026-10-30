"""Platform detection: distribution, systemd, SSH service units, kernel."""

from __future__ import annotations

import os
import platform as _platform
import re
from dataclasses import dataclass, field

from bant.constants import SUPPORTED_OS
from bant.context import Context
from bant.utils.fsutil import read_text


@dataclass
class OSInfo:
    id: str = "unknown"
    version_id: str = ""
    pretty: str = "Unknown Linux"
    kernel: str = ""
    supported: bool = False
    notes: list[str] = field(default_factory=list)


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r'^([A-Z_]+)=(.*)$', line.strip())
        if m:
            out[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    return out


def detect_os(ctx: Context) -> OSInfo:
    data = parse_os_release(read_text(ctx.paths.os_release))
    info = OSInfo(
        id=data.get("ID", "unknown").lower(),
        version_id=data.get("VERSION_ID", ""),
        pretty=data.get("PRETTY_NAME", "Unknown Linux"),
        kernel=_platform.release(),
    )
    versions = SUPPORTED_OS.get(info.id)
    info.supported = bool(versions and info.version_id in versions)
    if not info.supported:
        like = data.get("ID_LIKE", "")
        info.notes.append(
            "Not an officially supported release (Debian 12/13, Ubuntu 22.04/24.04)."
            + (f" Derivative of: {like}." if like else "")
        )
    return info


def has_systemd(ctx: Context) -> bool:
    return ctx.paths.p("/run/systemd/system").is_dir()


def unit_state(ctx: Context, unit: str) -> dict[str, str]:
    """LoadState / ActiveState / UnitFileState for a unit, empty strings when unknown."""
    res = ctx.run(["systemctl", "show", unit, "-p", "LoadState,ActiveState,UnitFileState,SubState"])
    out = {"LoadState": "", "ActiveState": "", "UnitFileState": "", "SubState": ""}
    if res.ok:
        for line in res.lines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v.strip()
    return out


def unit_active(ctx: Context, unit: str) -> bool:
    return ctx.run(["systemctl", "is-active", "--quiet", unit]).ok


def unit_exists(ctx: Context, unit: str) -> bool:
    st = unit_state(ctx, unit)
    return st["LoadState"] not in ("", "not-found", "masked")


def detect_ssh_units(ctx: Context) -> dict[str, str | None]:
    """Find the OpenSSH service unit and (if any) an active socket unit."""
    service = next((u for u in ("ssh.service", "sshd.service") if unit_exists(ctx, u)), None)
    socket = next((u for u in ("ssh.socket", "sshd.socket") if unit_active(ctx, u)), None)
    return {"service": service, "socket": socket}


def sudo_user() -> str | None:
    user = os.environ.get("SUDO_USER")
    return user if user and user != "root" else None
