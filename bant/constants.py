"""Fixed identifiers and filesystem layout."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DEFAULT_SSH_PORT = 667
DEFAULT_ROLLBACK_MINUTES = 10
BANT_TAG = "bant"  # appears in comments of rules Bant adds; never the sole ownership proof

SUPPORTED_OS = {
    "debian": ("12", "13"),
    "ubuntu": ("22.04", "24.04"),
}


@dataclass(frozen=True)
class Paths:
    """All absolute paths Bant touches, resolved under an optional root (tests use a tmp dir)."""

    root: Path = Path("/")

    def p(self, absolute: str) -> Path:
        return self.root / absolute.lstrip("/")

    # --- Bant's own layout -------------------------------------------------
    @property
    def etc_bant(self) -> Path: return self.p("/etc/bant")
    @property
    def config_file(self) -> Path: return self.p("/etc/bant/bant.toml")
    @property
    def state_dir(self) -> Path: return self.p("/var/lib/bant")
    @property
    def state_file(self) -> Path: return self.p("/var/lib/bant/state.json")
    @property
    def lock_file(self) -> Path: return self.p("/var/lib/bant/lock")
    @property
    def tx_dir(self) -> Path: return self.p("/var/lib/bant/tx")
    @property
    def backup_dir(self) -> Path: return self.p("/var/lib/bant/backups")
    @property
    def blocklist_file(self) -> Path: return self.p("/var/lib/bant/blocklist.json")
    @property
    def log_dir(self) -> Path: return self.p("/var/log/bant")
    @property
    def audit_log(self) -> Path: return self.p("/var/log/bant/audit.jsonl")
    @property
    def install_dir(self) -> Path: return self.p("/opt/bant")
    @property
    def launcher(self) -> Path: return self.p("/usr/local/bin/bant")

    # --- SSH ---------------------------------------------------------------
    @property
    def ssh_dir(self) -> Path: return self.p("/etc/ssh")
    @property
    def sshd_config(self) -> Path: return self.p("/etc/ssh/sshd_config")
    @property
    def sshd_config_d(self) -> Path: return self.p("/etc/ssh/sshd_config.d")
    @property
    def ssh_dropin(self) -> Path: return self.p("/etc/ssh/sshd_config.d/00-bant.conf")
    @property
    def ssh_retained_dropin(self) -> Path: return self.p("/etc/ssh/sshd_config.d/00-ssh-hardening.conf")
    @property
    def systemd_system(self) -> Path: return self.p("/etc/systemd/system")

    def socket_dropin(self, unit: str) -> Path:
        return self.p(f"/etc/systemd/system/{unit}.d/bant-port.conf")

    def socket_retained_dropin(self, unit: str) -> Path:
        return self.p(f"/etc/systemd/system/{unit}.d/ssh-port.conf")

    # --- Fail2ban ----------------------------------------------------------
    @property
    def f2b_dir(self) -> Path: return self.p("/etc/fail2ban")
    @property
    def f2b_jail(self) -> Path: return self.p("/etc/fail2ban/jail.d/zz-bant-sshd.local")
    @property
    def f2b_retained_jail(self) -> Path: return self.p("/etc/fail2ban/jail.d/zz-sshd-protection.local")
    @property
    def f2b_filter(self) -> Path: return self.p("/etc/fail2ban/filter.d/bant-sshd.conf")

    # --- Misc --------------------------------------------------------------
    @property
    def apt_bant_conf(self) -> Path: return self.p("/etc/apt/apt.conf.d/52bant-unattended-upgrades")
    @property
    def reboot_required(self) -> Path: return self.p("/var/run/reboot-required")
    @property
    def os_release(self) -> Path: return self.p("/etc/os-release")
    @property
    def auth_log(self) -> Path: return self.p("/var/log/auth.log")
    @property
    def proc(self) -> Path: return self.p("/proc")
