"""Hybrid hosts: real `sshd` / `fail2ban-client` binaries, operating only on throwaway config trees.

Nothing here talks to the machine's real services: `sshd -t/-T` and `fail2ban-client -t/-d` are
read-only config inspectors, and every path points into a temporary directory. Anything that would
start, stop or reload a service is answered by the FakeHost.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from bant.utils.commands import CmdResult
from tests.fakes import FakeHost

HAVE_SSHD = shutil.which("sshd") is not None
HAVE_F2B = shutil.which("fail2ban-client") is not None


def ensure_privsep_dir() -> bool:
    if Path("/run/sshd").is_dir():
        return True
    if os.geteuid() == 0:
        os.makedirs("/run/sshd", exist_ok=True)
        return True
    return False


needs_sshd = pytest.mark.skipif(not (HAVE_SSHD and shutil.which("ssh-keygen")), reason="OpenSSH server not installed")
needs_f2b = pytest.mark.skipif(not HAVE_F2B, reason="fail2ban not installed")


class RealSshdHost(FakeHost):
    """sshd -t / -T are executed by the real binary against a config tree under tmp."""

    def __init__(self, root: Path, **kw):
        super().__init__(root, **kw)
        if not ensure_privsep_dir():
            pytest.skip("/run/sshd missing and not root")
        key = root / "etc/ssh/ssh_host_test_key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        # absolute Include so the real sshd reads the temporary tree, not /etc/ssh
        self.paths.sshd_config.write_text(
            f"Include {self.paths.sshd_config_d}/*.conf\nHostKey {key}\nKbdInteractiveAuthentication no\nUsePAM yes\n"
            "X11Forwarding yes\nPrintMotd no\n"
        )

    def _cmd_sshd(self, argv, _input):
        res = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return CmdResult(argv, res.returncode, res.stdout, res.stderr)

    def _apply_service_ports(self) -> None:
        out = self._cmd_sshd(["sshd", "-T", "-f", str(self.paths.sshd_config)], None).stdout
        ports = {int(line.split()[1]) for line in out.splitlines() if line.startswith("port ")}
        self.listening = {p: v for p, v in self.listening.items() if v != "sshd"}
        for p in ports:
            self.listening[p] = "sshd"


class RealFail2banHost(FakeHost):
    """fail2ban-client -t / -d run for real against a copy of the distribution config under tmp."""

    def __init__(self, root: Path, **kw):
        super().__init__(root, **kw)
        dst = self.paths.f2b_dir
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree("/etc/fail2ban", dst)
        for name in ("jail.local",):
            (dst / name).unlink(missing_ok=True)

    def _cmd_fail2ban_client(self, argv, _input):
        if argv[1:2] == ["-c"]:
            res = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            return CmdResult(argv, res.returncode, res.stdout, res.stderr)
        if argv[1:2] in (["-t"], ["-d"]):
            real = ["fail2ban-client", "-c", str(self.paths.f2b_dir), *argv[1:]]
            res = subprocess.run(real, capture_output=True, text=True, timeout=60)
            return CmdResult(argv, res.returncode, res.stdout, res.stderr)
        return super()._cmd_fail2ban_client(argv, _input)
