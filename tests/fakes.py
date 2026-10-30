"""A fake host for testing Bant without touching the machine running the tests.

FakeHost owns a temporary root directory laid out like a Debian/Ubuntu server and acts as the
command Runner: it answers `sshd`, `systemctl`, `ss`, `ufw`, `fail2ban-client`, ... from that
tree. Changes made through the fake (e.g. `systemctl reload ssh`) are applied to a simulated set
of listening ports, so migrations can be exercised end-to-end.
"""

from __future__ import annotations

import os
import re
import shlex
import time
from pathlib import Path

from bant.config import Config
from bant.constants import Paths
from bant.context import Context
from bant.core import sshconf
from bant.utils.commands import CmdResult, Runner

DEBIAN_SSHD_CONFIG = """\
Include /etc/ssh/sshd_config.d/*.conf
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem\tsftp\t/usr/lib/openssh/sftp-server
"""


class FakeHost(Runner):
    def __init__(self, root: Path, *, os_id="debian", os_version="12", socket_mode=False, ufw=False,
                 firewalld=False, fail2ban=True, ssh_installed=True, euid=0):
        super().__init__()
        self.root = root
        self.paths = Paths(root)
        self.calls: list[list[str]] = []
        self.binaries = {"sshd", "systemctl", "ss", "ip", "journalctl", "apt-get", "dpkg-query", "apt-config", "nft", "fuser"}
        if not ssh_installed:
            self.binaries.discard("sshd")
        if ufw:
            self.binaries.add("ufw")
        if firewalld:
            self.binaries.add("firewall-cmd")
        if fail2ban:
            self.binaries |= {"fail2ban-client", "fail2ban-regex"}
        self.fail2ban_installed = fail2ban
        self.ssh_installed = ssh_installed
        self.ufw_active = ufw
        self.ufw_rules: list[str] = []
        self.firewalld_active = firewalld
        self.firewalld_ports: set[str] = set()
        self.socket_mode = socket_mode
        self.socket_active = socket_mode
        self.listening: dict[int, str] = {}  # tcp port -> process
        self.sshd_invalid = False
        self.reload_fails = False
        self.fail_commands: set[str] = set()
        self.units: dict[str, str] = {}  # unit -> active state for timers/services
        self.f2b_running = fail2ban
        self.f2b_banned: list[str] = []
        self.f2b_config_invalid = False
        self.journal_has_sshd = True
        self.sessions: list[dict] = []
        self.accepted_log = ""
        self.pysystemd = True
        self.apt_calls: list[list[str]] = []
        self._inode = 1000
        self.euid = euid
        self._layout(os_id, os_version)

    # ---- layout ----------------------------------------------------------
    def _layout(self, os_id: str, os_version: str) -> None:
        p = self.paths
        for d in ("/etc/ssh/sshd_config.d", "/etc/fail2ban/jail.d", "/etc/fail2ban/filter.d", "/etc/systemd/system",
                  "/run/systemd/system", "/var/lib", "/var/log", "/proc/net", "/etc/apt/apt.conf.d", "/usr/local/bin"):
            p.p(d).mkdir(parents=True, exist_ok=True)
        p.os_release.write_text(f'ID={os_id}\nVERSION_ID="{os_version}"\nPRETTY_NAME="{os_id.title()} {os_version}"\n')
        if self.ssh_installed:
            p.sshd_config.write_text(DEBIAN_SSHD_CONFIG)
            self.listening[22] = "sshd"
        (p.f2b_dir / "jail.d" / "defaults-debian.conf").write_text("[DEFAULT]\nbanaction = nftables\nbackend = systemd\n\n[sshd]\nenabled = true\n")
        if self.socket_mode:
            self.listening[22] = "systemd"
        if self.ufw_active:
            p.p("/etc/ufw").mkdir(parents=True, exist_ok=True)
            p.p("/etc/ufw/ufw.conf").write_text("ENABLED=yes\nLOGLEVEL=low\n")
        (p.proc / "stat").write_text("cpu 0\nbtime 1000\n")
        (p.proc / "net" / "tcp").write_text(self._tcp_header())
        (p.proc / "net" / "tcp6").write_text(self._tcp_header())

    @staticmethod
    def _tcp_header() -> str:
        return "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

    def make_ctx(self, **kw) -> Context:
        clock = kw.pop("clock", None) or (lambda: 2000.0)
        ctx = Context(self.paths, self, euid=self.euid, clock=clock, config=Config.load(self.paths.config_file),
                      sleep=lambda s: None, banner_probe=self.banner, mirror_syslog=False, **kw)
        return ctx

    def banner(self, host: str, port: int) -> str | None:
        return "SSH-2.0-OpenSSH_9.6" if self.listening.get(port) in ("sshd", "systemd") else None

    # ---- sessions (fake /proc) ---------------------------------------------
    def add_ssh_session(self, user: str, local_port: int, remote_ip: str, remote_port: int, started: float = 2500.0,
                        pid: int | None = None, v6: bool = False) -> int:
        pid = pid or (3000 + len(self.sessions))
        self._inode += 1
        d = self.paths.proc / str(pid)
        (d / "fd").mkdir(parents=True, exist_ok=True)
        (d / "cmdline").write_bytes(f"sshd: {user}@pts/0".encode() + b"\x00")
        ticks = int((started - 1000) * os.sysconf("SC_CLK_TCK"))
        fields = ["S", "1"] + ["0"] * 17 + [str(ticks)]
        (d / "stat").write_text(f"{pid} (sshd) " + " ".join(fields) + "\n")
        link = d / "fd" / "3"
        link.symlink_to(f"socket:[{self._inode}]")
        line = (f"   0: {self._hex_ip('10.0.0.5')}:{local_port:04X} {self._hex_ip(remote_ip)}:{remote_port:04X} 01 "
                f"00000000:00000000 00:00000000 00000000     0        0 {self._inode} 1 0 0 0 0\n")
        with open(self.paths.proc / "net" / "tcp", "a") as fh:
            fh.write(line)
        self.sessions.append({"pid": pid, "user": user, "remote_ip": remote_ip, "remote_port": remote_port, "local_port": local_port})
        return pid

    @staticmethod
    def _hex_ip(ip: str) -> str:
        return "".join(f"{int(o):02X}" for o in reversed(ip.split(".")))

    def log_accepted(self, method: str, user: str, ip: str, port: int) -> None:
        self.accepted_log += f"Accepted {method} for {user} from {ip} port {port} ssh2: ED25519 SHA256:abc\n"

    # ---- Runner interface --------------------------------------------------
    def which(self, name: str) -> str | None:
        return f"/usr/bin/{name}" if name in self.binaries else None

    def run(self, argv, *, timeout=None, input=None) -> CmdResult:  # noqa: A002
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        key = " ".join(argv)
        if any(key.startswith(f) for f in self.fail_commands):
            return CmdResult(argv, 1, "", f"simulated failure: {key}")
        handler = getattr(self, "_cmd_" + argv[0].replace("-", "_").replace("/", "_"), None)
        if handler is None:
            if argv[0] in self.binaries or argv[0] in ("env", "/bin/sh", "logger"):
                return CmdResult(argv, 0, "", "")
            return CmdResult(argv, 127, "", f"{argv[0]}: command not found")
        return handler(argv, input)

    def called(self, prefix: str) -> bool:
        return any(" ".join(c).startswith(prefix) for c in self.calls)

    # ---- sshd ------------------------------------------------------------
    def _cmd_sshd(self, argv, _input):
        if not self.ssh_installed:
            return CmdResult(argv, 127, "", "sshd: command not found")
        cfg = Path(argv[argv.index("-f") + 1]) if "-f" in argv else self.paths.sshd_config
        invalid = self.sshd_invalid or "BogusOption" in "".join(p.read_text() for p in self._all_cfg_files())
        if "-t" in argv:
            return CmdResult(argv, 255 if invalid else 0, "", "Bad configuration option" if invalid else "")
        if "-T" in argv:
            if invalid:
                return CmdResult(argv, 255, "", "Bad configuration option")
            directives = sshconf.parse_config(self.make_ctx(), cfg)
            eff = sshconf.parsed_effective(directives)
            lines = []
            ports = eff.values.get("port") or ["22"]
            for k, v in sorted(eff.values.items()):
                for item in (dict.fromkeys(v) if k == "port" else v):
                    lines.append(f"{k} {item}")
            lines += [f"listenaddress 0.0.0.0:{p}" for p in dict.fromkeys(ports)]
            return CmdResult(argv, 0, "\n".join(lines) + "\n", "")
        return CmdResult(argv, 0, "", "")

    def _all_cfg_files(self):
        out = [self.paths.sshd_config]
        out += sorted(self.paths.sshd_config_d.glob("*.conf"))
        return [p for p in out if p.exists()]

    # ---- systemd -----------------------------------------------------------
    def _cmd_systemctl(self, argv, _input):
        sub = argv[1]
        if sub == "show":
            unit = argv[2]
            props = argv[4] if len(argv) > 4 else ""
            if unit in ("ssh.service",) and self.ssh_installed:
                return CmdResult(argv, 0, "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\nSubState=running\n", "")
            if unit == "ssh.socket" and self.socket_mode:
                lines = "".join(f"Listen={h}:{p} (Stream)\n" for p in sorted(self._socket_ports()) for h in ("[::]", "0.0.0.0")) if "Listen" in props else \
                    "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\nSubState=running\n"
                return CmdResult(argv, 0, lines, "")
            if unit == "fail2ban.service" and self.fail2ban_installed:
                st = "active" if self.f2b_running else "inactive"
                return CmdResult(argv, 0, f"LoadState=loaded\nActiveState={st}\nUnitFileState=enabled\nSubState=running\n", "")
            if unit in self.units:
                return CmdResult(argv, 0, f"LoadState=loaded\nActiveState={self.units[unit]}\nUnitFileState=enabled\nSubState=waiting\n", "")
            return CmdResult(argv, 0, "LoadState=not-found\nActiveState=inactive\nUnitFileState=\nSubState=dead\n", "")
        if sub == "is-active":
            unit = argv[-1]
            active = {"ssh.service": self.ssh_installed, "ssh.socket": self.socket_mode and self.socket_active,
                      "ufw.service": self.ufw_active, "firewalld.service": self.firewalld_active,
                      "fail2ban.service": self.f2b_running}.get(unit, self.units.get(unit) == "active")
            return CmdResult(argv, 0 if active else 3, "active\n" if active else "inactive\n", "")
        if sub == "reload" and argv[2].startswith("ssh"):
            if self.reload_fails:
                return CmdResult(argv, 1, "", "Job for ssh.service failed")
            if self.sshd_invalid:
                return CmdResult(argv, 1, "", "invalid config")
            self._apply_service_ports()
            return CmdResult(argv, 0, "", "")
        if sub == "restart" and argv[2] == "ssh.socket":
            self.listening = {p: v for p, v in self.listening.items() if v != "systemd"}
            for p in self._socket_ports():
                self.listening[p] = "systemd"
            return CmdResult(argv, 0, "", "")
        if sub in ("enable", "restart") and (sub == "restart" or "--now" in argv):
            self.units[argv[-1]] = "active"
            if argv[-1] == "fail2ban.service":
                self.f2b_running = True
        elif sub == "disable":
            self.units.pop(argv[-1], None)
            if argv[-1] == "fail2ban.service":
                self.f2b_running = False
        elif sub == "--failed":
            return CmdResult(argv, 0, "", "")
        return CmdResult(argv, 0, "", "")

    def _apply_service_ports(self) -> None:
        eff = sshconf.parsed_effective(sshconf.parse_config(self.make_ctx()))
        ports = {int(p) for p in eff.values.get("port", ["22"])}
        self.listening = {p: v for p, v in self.listening.items() if v != "sshd"}
        for p in ports:
            self.listening[p] = "sshd"

    def _socket_ports(self) -> set[int]:
        d = self.paths.p("/etc/systemd/system/ssh.socket.d")
        ports: set[int] = set()
        base = {22}
        if d.is_dir():
            for f in sorted(d.glob("*.conf")):
                for line in f.read_text().splitlines():
                    if line.strip() == "ListenStream=":
                        base = set()
                    m = re.match(r"ListenStream=.*:(\d+)$", line.strip())
                    if m:
                        ports.add(int(m.group(1)))
        return ports | base if not ports else ports

    # ---- network ---------------------------------------------------------
    def _cmd_ss(self, argv, _input):
        out = "".join(f"tcp   LISTEN 0      128          0.0.0.0:{p}      0.0.0.0:*    users:((\"{proc}\",pid=1,fd=3))\n"
                      f"tcp   LISTEN 0      128             [::]:{p}         [::]:*    users:((\"{proc}\",pid=1,fd=4))\n"
                      for p, proc in sorted(self.listening.items()))
        return CmdResult(argv, 0, out, "")

    def _cmd_ip(self, argv, _input):
        return CmdResult(argv, 0, "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n", "")

    # ---- ufw / firewalld -------------------------------------------------
    def _cmd_ufw(self, argv, _input):
        if argv[1] == "status":
            body = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n"
            body += "".join(f"{r}                    ALLOW       Anywhere\n" for r in self.ufw_rules)
            return CmdResult(argv, 0, body, "")
        if argv[1] == "allow":
            self.ufw_rules.append(argv[2])
        elif argv[1] == "delete":
            spec = argv[3]
            if spec not in self.ufw_rules:
                return CmdResult(argv, 1, "", "Could not delete non-existent rule")
            self.ufw_rules.remove(spec)
        return CmdResult(argv, 0, "Rule added\n", "")

    def _cmd_firewall_cmd(self, argv, _input):
        if "--query-port" in argv:
            return CmdResult(argv, 0 if argv[-1] in self.firewalld_ports else 1, "", "")
        for i, a in enumerate(argv):
            if a == "--add-port":
                self.firewalld_ports.add(argv[i + 1])
            if a == "--remove-port":
                self.firewalld_ports.discard(argv[i + 1])
        return CmdResult(argv, 0, "success\n", "")

    def _cmd__bin_sh(self, argv, _input):
        """Run a generated rollback script for real, with stubbed system commands, then replay them on the fake."""
        script = Path(argv[1])
        stubs, log = self.root / "_stubs", self.root / "_stub.log"
        log.write_text("")
        make_stubs(stubs, ["systemctl", "ufw", "nft", "iptables", "ip6tables", "fail2ban-client", "sshd", "firewall-cmd"], log)
        rc, out = run_script(script, stubs, *argv[2:])
        for line in log.read_text().splitlines():
            self.calls.append(["(rollback)"] + line.split())
            handler = getattr(self, "_cmd_" + line.split()[0].replace("-", "_"), None)
            if handler:
                handler(line.split(), None)
        return CmdResult(argv, rc, out, "")

    def _cmd_nft(self, argv, _input):
        return CmdResult(argv, 0, "", "")

    # ---- fail2ban --------------------------------------------------------
    def _f2b_settings(self) -> dict[str, str]:
        s = {"maxretry": "5", "findtime": "10m", "bantime": "10m", "port": "ssh", "banaction": "nftables",
             "backend": "systemd", "enabled": "true", "ignoreip": ""}
        files = [self.paths.f2b_dir / "jail.local"] + sorted((self.paths.f2b_dir / "jail.d").glob("*.conf")) + \
            sorted((self.paths.f2b_dir / "jail.d").glob("*.local"))
        import configparser
        for f in files:
            if not f.is_file():
                continue
            cp = configparser.RawConfigParser(strict=False, interpolation=None)
            try:
                cp.read_string(f.read_text())
            except configparser.Error:
                continue
            for sec in ("DEFAULT", "sshd"):
                items = cp.defaults() if sec == "DEFAULT" else (dict(cp._sections.get("sshd", {})) if cp.has_section("sshd") else {})
                s.update({k: v for k, v in items.items() if k != "__name__"})
        return s

    def _cmd_fail2ban_client(self, argv, _input):
        if not self.fail2ban_installed:
            return CmdResult(argv, 127, "", "not found")
        args = [a for a in argv[1:]]
        if args[:1] == ["--version"]:
            return CmdResult(argv, 0, "Fail2Ban v1.0.2\n", "")
        if args[:1] == ["-t"]:
            bad = self.f2b_config_invalid or "INVALID" in (self.paths.f2b_jail.read_text() if self.paths.f2b_jail.exists() else "")
            return CmdResult(argv, 255 if bad else 0, "", "ERROR: test configuration failed" if bad else "OK: configuration test is successful\n")
        if args[:1] == ["-d"]:
            s = self._f2b_settings()
            if s["enabled"] != "true":
                return CmdResult(argv, 0, "", "")
            ports = s["port"].replace("ssh", "22")
            lines = ["['add', 'sshd', 'systemd']", f"['set', 'sshd', 'maxretry', {s['maxretry']}]",
                     f"['set', 'sshd', 'findtime', '{s['findtime']}']", f"['set', 'sshd', 'bantime', '{s['bantime']}']",
                     f"['set', 'sshd', 'addaction', '{s['banaction']}']",
                     f"['multi-set', 'sshd', 'action', '{s['banaction']}', [['port', '{ports}']]]"]
            for ip in s["ignoreip"].split():
                lines.append(f"['set', 'sshd', 'addignoreip', '{ip}']")
            if s["backend"] == "systemd":
                lines.append("['set', 'sshd', 'addjournalmatch', '_SYSTEMD_UNIT=sshd.service', '+', '_COMM=sshd']")
            return CmdResult(argv, 0, "\n".join(lines) + "\n", "")
        if args[:1] == ["ping"]:
            return CmdResult(argv, 0 if self.f2b_running else 255, "Server replied: pong\n" if self.f2b_running else "", "")
        if args[:1] == ["status"] and len(args) == 1:
            return CmdResult(argv, 0 if self.f2b_running else 255, "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n", "")
        if args[:2] == ["status", "sshd"]:
            if not self.f2b_running:
                return CmdResult(argv, 255, "", "")
            body = (f"Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n|  `- Total failed:\t3\n`- Actions\n"
                    f"   |- Currently banned:\t{len(self.f2b_banned)}\n   |- Total banned:\t{len(self.f2b_banned)}\n"
                    f"   `- Banned IP list:\t{' '.join(self.f2b_banned)}\n")
            return CmdResult(argv, 0, body, "")
        if args[:3] == ["set", "sshd", "banip"]:
            self.f2b_banned.append(args[3])
            return CmdResult(argv, 0, "1\n", "")
        if args[:1] == ["unban"]:
            n = 1 if args[1] in self.f2b_banned else 0
            if n:
                self.f2b_banned.remove(args[1])
            return CmdResult(argv, 0, f"{n}\n", "")
        if args[:1] == ["reload"]:
            return CmdResult(argv, 255 if self.f2b_config_invalid else 0, "OK\n", "")
        return CmdResult(argv, 0, "", "")

    def _cmd_fail2ban_regex(self, argv, _input):
        return CmdResult(argv, 0, "Lines: 1 lines, 0 ignored, 1 matched, 0 missed\n", "")

    def _cmd_journalctl(self, argv, _input):
        if "Accepted " in argv:
            return CmdResult(argv, 0, self.accepted_log, "")
        return CmdResult(argv, 0, "line\n" if self.journal_has_sshd else "", "")

    # ---- apt -------------------------------------------------------------
    def _cmd_env(self, argv, _input):
        self.apt_calls.append(argv)
        if "fail2ban" in argv:
            self.fail2ban_installed = True
            self.binaries |= {"fail2ban-client", "fail2ban-regex"}
            self.f2b_running = True
        return CmdResult(argv, 0, "", "")

    def _cmd_apt_get(self, argv, _input):
        return CmdResult(argv, 0, "", "")

    def _cmd_dpkg_query(self, argv, _input):
        return CmdResult(argv, 1, "", "")

    def _cmd_apt_config(self, argv, _input):
        return CmdResult(argv, 0, "", "")

    def _cmd_fuser(self, argv, _input):
        return CmdResult(argv, 1, "", "")

    def _cmd__usr_bin_python3(self, argv, _input):
        return CmdResult(argv, 0 if self.pysystemd else 1, "", "")


def run_script(script: Path, stub_dir: Path, *extra: str) -> tuple[int, str]:
    """Execute a generated rollback script with stubbed system commands on PATH."""
    import subprocess

    text = script.read_text()
    text = re.sub(r"^PATH=.*$", f"PATH={shlex.quote(str(stub_dir))}:/usr/bin:/bin", text, flags=re.M)
    patched = script.with_name(script.name + ".test")
    patched.write_text(text)
    res = subprocess.run(["/bin/sh", str(patched), *extra], capture_output=True, text=True, timeout=60)
    return res.returncode, res.stdout + res.stderr


def make_stubs(stub_dir: Path, names: list[str], log: Path) -> None:
    stub_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        f = stub_dir / name
        f.write_text(f'#!/bin/sh\necho "{name} $*" >> {shlex.quote(str(log))}\nexit 0\n')
        f.chmod(0o755)


def now() -> float:
    return time.time()
