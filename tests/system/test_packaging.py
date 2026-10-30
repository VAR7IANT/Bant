"""System-level checks that need no privileges: installer layout, launcher, real pty TUI, shellcheck."""

import os
import pty
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from bant import __version__
from bant.core import migration
from bant.core.rollback import TxManager
from tests.fakes import FakeHost

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.integration


def install(dest: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, DESTDIR=str(dest))
    return subprocess.run(["bash", str(ROOT / "install.sh"), "--yes", *args], capture_output=True, text=True, env=env, timeout=120)


def test_installer_layout_and_launcher(tmp_path):
    res = install(tmp_path)
    assert res.returncode == 0, res.stderr
    lib = tmp_path / "opt/bant/lib"
    assert (lib / "bant/__init__.py").is_file()
    assert (tmp_path / "opt/bant/emergency-recovery.sh").stat().st_mode & 0o777 == 0o700
    launcher = tmp_path / "usr/local/bin/bant"
    text = launcher.read_text()
    assert launcher.stat().st_mode & 0o111 and "-I -c" in text and "/opt/bant/lib" in text
    assert (tmp_path / "etc/systemd/system/bant-firewall.service").is_file()
    assert (tmp_path / "var/lib/bant").stat().st_mode & 0o777 == 0o700
    out = subprocess.run([sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {str(lib)!r}); from bant.cli import main; sys.exit(main())", "version"],
                         capture_output=True, text=True, cwd="/")
    assert out.stdout.strip() == f"bant {__version__}"


def test_installer_is_idempotent_and_upgrades_in_place(tmp_path):
    assert install(tmp_path).returncode == 0
    (tmp_path / "etc/bant/bant.toml").write_text("[ssh]\nport = 2222\n")
    (tmp_path / "var/lib/bant/state.json").write_text("{}")
    res = install(tmp_path)
    assert res.returncode == 0 and "upgrading" in res.stdout
    assert (tmp_path / "etc/bant/bant.toml").read_text() == "[ssh]\nport = 2222\n", "configuration must survive reinstall"
    assert (tmp_path / "var/lib/bant/state.json").exists()
    assert not list((tmp_path / "opt/bant").glob("lib.*")), "no leftover staging directories"


def test_installer_rejects_unknown_option_and_wrong_directory(tmp_path):
    res = subprocess.run(["bash", str(ROOT / "install.sh"), "--bogus"], capture_output=True, text=True)
    assert res.returncode != 0 and "unknown option" in res.stderr
    shutil.copy(ROOT / "install.sh", tmp_path / "install.sh")
    res = subprocess.run(["bash", str(tmp_path / "install.sh"), "--dry-run"], capture_output=True, text=True)
    assert res.returncode != 0 and "checkout" in res.stderr


def test_installer_dry_run_changes_nothing(tmp_path):
    res = subprocess.run(["bash", str(ROOT / "install.sh"), "--dry-run", "--force-unsupported"], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert "would" in res.stdout


@pytest.mark.skipif(not shutil.which("shellcheck"), reason="shellcheck not installed")
def test_shellcheck_clean(tmp_path, host=None):
    for f, shell in (("install.sh", "bash"), ("scripts/emergency-recovery.sh", "sh")):
        res = subprocess.run(["shellcheck", "-x", "-s", shell, str(ROOT / f)], capture_output=True, text=True)
        assert res.returncode == 0, res.stdout
    fake = FakeHost(tmp_path / "r", ufw=True)
    ctx = fake.make_ctx()
    migration.begin(ctx, 667)
    tx = TxManager(ctx).pending()[0]
    script = TxManager(ctx).dir(tx.id) / "rollback.sh"
    res = subprocess.run(["shellcheck", "-s", "sh", str(script)], capture_output=True, text=True)
    assert res.returncode == 0, "generated rollback script has shellcheck findings:\n" + res.stdout


def test_emergency_script_usage_and_syntax():
    res = subprocess.run(["sh", "-n", str(ROOT / "scripts/emergency-recovery.sh")], capture_output=True, text=True)
    assert res.returncode == 0
    res = subprocess.run(["sh", str(ROOT / "scripts/emergency-recovery.sh"), "bogus"], capture_output=True, text=True)
    assert res.returncode == 2 and "usage" in res.stdout


def test_systemd_unit_has_no_ordering_cycle_risk():
    unit = (ROOT / "systemd/bant-firewall.service").read_text()
    assert "Before=network.target" not in unit.replace("# No Before=network.target", "")
    assert "ExecStart=/usr/local/bin/bant _fw-apply" in unit and "WantedBy=multi-user.target" in unit


def test_tui_in_a_real_pty_starts_navigates_and_exits():
    """Starts `python -m bant` on a real pseudo-terminal (read-only on this host: only views are opened)."""
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(ROOT)
        os.environ["TERM"] = "xterm"
        os.environ["BANT_LANG"] = "en"  # skip the first-run language prompt: it would persist a choice on this machine
        os.execv(sys.executable, [sys.executable, "-m", "bant"])
    buf = b""

    def pump(seconds=4.0, until=None):
        nonlocal buf
        end = time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    return
                if not chunk:
                    return
                buf += chunk
                if until and until in buf:
                    return

    try:
        pump(10, b"Select an option")
        assert b"SYSTEM OVERVIEW" in buf and b"SSH Port" in buf
        os.write(fd, b"11\n")      # system information
        pump(10, b"Run deep diagnostics")
        os.write(fd, b"n\n")
        pump(5, b"Press Enter")
        os.write(fd, b"\n")
        pump(5, b"Select an option")
        os.write(fd, b"0\n")
        pump(5, b"Goodbye")
        assert b"Goodbye" in buf
    finally:
        try:
            _, status = os.waitpid(pid, os.WNOHANG)
            if status == 0:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    assert b"\x1b[" in buf, "colour/cursor escapes expected on a real terminal"


def test_installer_help_documents_random_port_option():
    res = subprocess.run(["bash", str(ROOT / "install.sh"), "--help"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "--ssh-port PORT|random" in res.stdout and "--dry-run" in res.stdout and "-h, --help" in res.stdout
    assert "667" not in res.stdout
