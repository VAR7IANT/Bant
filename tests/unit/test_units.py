"""Pure-function and small-module tests: validation, parsing, config, fsutil, logging, updates, audit."""

import json
import os
import socket
import stat
import struct

import pytest

from bant.config import CONFIG_VERSION, Config
from bant.core import netinfo, security_audit, sshconf, updates
from bant.errors import OperationFailed, ValidationError
from bant.platform import detect_os, parse_os_release
from bant.utils import fsutil, tomlio
from bant.utils.logging import AuditLog, redact
from bant.utils.validation import (
    format_duration,
    humanize_duration,
    parse_duration,
    parse_int_range,
    parse_ip,
    parse_onoff,
    parse_port,
    parse_proto,
    sanitize_comment,
)
from tests.fakes import FakeHost

# ---- validation ----------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [("667", 667), (22, 22), (" 65535 ", 65535)])
def test_port_ok(value, expected):
    assert parse_port(value) == expected


@pytest.mark.parametrize("value", ["0", "65536", "-1", "abc", "", "22; rm", "1e3", None, "0x16"])
def test_port_rejected(value):
    with pytest.raises(ValidationError):
        parse_port(value)


@pytest.mark.parametrize("value,secs", [("30s", 30), ("10m", 600), ("1h", 3600), ("2d", 172800), ("1w", 604800), ("90", 90), ("permanent", -1), ("-1", -1)])
def test_duration(value, secs):
    assert parse_duration(value) == secs


@pytest.mark.parametrize("value", ["", "0", "0h", "1y", "h", "1 hour", "-5m", "1.5h"])
def test_duration_rejected(value):
    with pytest.raises(ValidationError):
        parse_duration(value)


def test_duration_formatting():
    assert format_duration(3600) == "1h" and format_duration(600) == "10m" and format_duration(90) == "90s"
    assert format_duration(-1) == "permanent" and humanize_duration(3661) == "1 hour 1 min 1 sec"


def test_ip_normalisation_and_rejection():
    assert parse_ip("2001:DB8::0001") == "2001:db8::1"
    assert parse_ip("203.0.113.0/24", allow_network=True) == "203.0.113.0/24"
    assert parse_ip("203.0.113.5/24", allow_network=True) == "203.0.113.0/24"
    for bad in ("1.2.3", "1.2.3.4.5", "::g", "1.2.3.4 5.6.7.8", "1.2.3.4/33", "a" * 100, "$(whoami)", "-h", "1.2.3.4;ls"):
        with pytest.raises(ValidationError):
            parse_ip(bad, allow_network=True)
    with pytest.raises(ValidationError):
        parse_ip("10.0.0.0/8")  # network without allow_network


def test_ban_validation_blocks_special_ranges():
    for bad in ("127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "0.0.0.0/0", "::/0", "2000::/3"):
        with pytest.raises(ValidationError):
            parse_ip(bad, allow_network=True, for_ban=True)
    assert parse_ip("203.0.113.0/24", allow_network=True, for_ban=True)


def test_misc_validators():
    assert parse_onoff("ON") is True and parse_onoff("Disabled") is False
    with pytest.raises(ValidationError):
        parse_onoff("maybe")
    assert parse_proto("TCP") == "tcp"
    with pytest.raises(ValidationError):
        parse_proto("icmp")
    assert parse_int_range("5", 1, 10, "x") == 5
    with pytest.raises(ValidationError):
        parse_int_range("11", 1, 10, "x")
    assert sanitize_comment("ok\"; drop table;") == "ok drop table"


# ---- /proc parsing ----------------------------------------------------------------

def _hex4(ip):
    return struct.pack("<I", struct.unpack("!I", socket.inet_aton(ip))[0]).hex().upper()


def test_proc_net_tcp_parsing_v4_and_v6():
    v4 = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
          f"   0: {_hex4('10.0.0.5')}:029B {_hex4('203.0.113.7')}:C350 01 00000000:00000000 00:00000000 00000000     0        0 4242 1 0\n"
          f"   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4243 1 0\n")
    e = netinfo.parse_proc_net_tcp(v4)
    assert (e[0].local_port, e[0].remote_ip, e[0].remote_port, e[0].state, e[0].inode) == (667, "203.0.113.7", 50000, "01", "4242")
    assert e[1].state == netinfo.TCP_LISTEN and e[1].local_port == 22
    import ipaddress
    def v6hex(addr):  # /proc/net/tcp6 prints each 32-bit word of the address little-endian
        raw = ipaddress.IPv6Address(addr).packed
        return "".join(raw[i:i + 4][::-1].hex().upper() for i in range(0, 16, 4))
    v6 = f"  sl\n   0: {v6hex('::1')}:0016 {v6hex('::ffff:198.51.100.9')}:1F90 01 0:0 0:0 0 0 0 99 1\n"
    e6 = netinfo.parse_proc_net_tcp(v6)
    assert e6[0].local_ip == "::1" and e6[0].remote_ip == "198.51.100.9" and e6[0].remote_port == 8080


def test_proc_parser_survives_real_host_and_garbage():
    real = open("/proc/net/tcp").read() if os.path.exists("/proc/net/tcp") else ""
    netinfo.parse_proc_net_tcp(real)
    assert netinfo.parse_proc_net_tcp("garbage\nnot a line\n") == []


def test_ss_parsing():
    out = ('tcp   LISTEN 0 128 0.0.0.0:22  0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
           'tcp   LISTEN 0 128 [::]:667   [::]:*    users:(("sshd",pid=1,fd=4))\n'
           'udp   UNCONN 0 0   127.0.0.53%lo:53 0.0.0.0:*\n'
           'tcp   LISTEN 0 4096 *:443 *:* users:(("caddy",pid=9,fd=7))\n')
    ls = netinfo.parse_ss(out)
    assert [(x.proto, x.port, x.scope, x.process) for x in ls] == [
        ("tcp", 22, "public", "sshd"), ("tcp", 667, "public", "sshd"), ("udp", 53, "loopback", ""), ("tcp", 443, "public", "caddy")]


def test_ssh_session_discovery_ignores_non_session_processes(host, ctx):
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    priv = host.paths.proc / "4000"
    priv.mkdir()
    (priv / "cmdline").write_bytes(b"sshd: alice [priv]\x00")
    (priv / "stat").write_text("4000 (sshd) S 1 " + " ".join(["0"] * 20) + "\n")
    pre = host.paths.proc / "4001"
    pre.mkdir()
    (pre / "cmdline").write_bytes(b"sshd: [accepted]\x00")
    sessions = netinfo.ssh_sessions(ctx)
    assert [s.user for s in sessions] == ["alice"] and sessions[0].local_port == 667 and sessions[0].remote_ip == "203.0.113.7"


def test_current_session_walks_process_tree(host, ctx):
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001, pid=5000)
    bash = host.paths.proc / "5100"
    bash.mkdir()
    (bash / "stat").write_text("5100 (bash) S 5000 " + " ".join(["0"] * 20) + "\n")
    (bash / "cmdline").write_bytes(b"-bash\x00")
    sudo = host.paths.proc / "5200"
    sudo.mkdir()
    (sudo / "stat").write_text("5200 (sudo) S 5100 " + " ".join(["0"] * 20) + "\n")
    s = netinfo.current_session(ctx, start_pid=5200)
    assert s and s.pid == 5000 and s.local_port == 667
    assert netinfo.current_session(ctx, start_pid=1) is None


# ---- sshd_config parsing ----------------------------------------------------------

def test_parser_include_order_match_scope_and_comments(host, ctx):
    d = ctx.paths.sshd_config_d
    (d / "10-a.conf").write_text("# comment\nPort 2222 # trailing\nMatch User bob\n  PasswordAuthentication yes\n")
    (d / "20-b.conf").write_text('Banner "/etc/issue # not a comment"\n')
    ds = sshconf.parse_config(ctx)
    kws = [(x.file.name, x.keyword, x.match) for x in ds if x.keyword in ("port", "passwordauthentication", "banner", "kbdinteractiveauthentication")]
    assert kws[0] == ("10-a.conf", "port", None)
    assert ("10-a.conf", "passwordauthentication", "User bob") in kws
    assert ("20-b.conf", "banner", None) in kws and ("sshd_config", "kbdinteractiveauthentication", None) in kws
    assert [x.args for x in ds if x.keyword == "port"] == ["2222"]
    assert [x.args for x in ds if x.keyword == "banner"] == ['"/etc/issue # not a comment"']


def test_parser_handles_equals_syntax_cycles_and_missing_includes(host, ctx):
    cfg = ctx.paths.sshd_config
    cfg.write_text(f"Include {cfg}\nInclude /nonexistent/*.conf\nPort=2200\nport   2201\n")
    ds = sshconf.parse_config(ctx)
    assert [x.args for x in ds if x.keyword == "port"] == ["2200", "2201"]


def test_dropin_render_and_read_roundtrip(host, ctx):
    text = sshconf.render_dropin([22, 667], {"PasswordAuthentication": "no", "MaxAuthTries": "3"})
    assert text.startswith("# Managed by Bant")
    ctx.paths.ssh_dropin.write_text(text)
    assert sshconf.read_dropin(ctx) == ([22, 667], {"MaxAuthTries": "3", "PasswordAuthentication": "no"})


def test_comment_out_ports_only_touches_requested_ports_and_backs_up(host, ctx):
    d = ctx.paths.sshd_config_d
    (d / "10-a.conf").write_text("Port 2222\nPort 3333\n")
    saved = []
    changed = sshconf.comment_out_ports(ctx, sshconf.parse_config(ctx), {2222}, saved.append)
    assert [c.args for c in changed] == ["2222"] and saved == [d / "10-a.conf"]
    assert (d / "10-a.conf").read_text() == "# bant-disabled: Port 2222\nPort 3333\n"


def test_comment_out_refuses_symlinked_file(host, ctx):
    real = host.root / "real.conf"
    real.write_text("Port 2222\n")
    (ctx.paths.sshd_config_d / "10-link.conf").symlink_to(real)
    with pytest.raises(OperationFailed, match="symbolic link"):
        sshconf.comment_out_ports(ctx, sshconf.parse_config(ctx), {2222}, lambda p: None)
    assert real.read_text() == "Port 2222\n"


def test_parse_sshd_T_multi_values():
    v = sshconf.parse_sshd_T("port 22\nport 667\nlistenaddress 0.0.0.0:22\npasswordauthentication no\n")
    assert v["port"] == ["22", "667"]
    assert sshconf.Effective(v, "x").ports == [22, 667] and not sshconf.Effective(v, "x").flag("passwordauthentication")


# ---- platform / config / files ----------------------------------------------------

def test_os_detection(tmp_path):
    assert parse_os_release('ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n')["VERSION_ID"] == "12"
    for osid, ver, ok in (("debian", "12", True), ("debian", "13", True), ("ubuntu", "22.04", True), ("ubuntu", "24.04", True),
                          ("ubuntu", "20.04", False), ("debian", "11", False), ("centos", "9", False)):
        ctx = FakeHost(tmp_path / f"{osid}{ver}", os_id=osid, os_version=ver).make_ctx()
        assert detect_os(ctx).supported is ok, (osid, ver)


def test_config_defaults_roundtrip_and_validation(tmp_path):
    path = tmp_path / "bant.toml"
    cfg = Config(path=path)
    assert (cfg.ssh_port, cfg.rollback_minutes, cfg.maxretry, cfg.findtime, cfg.bantime) == (0, 10, 5, "10m", "1h")  # 0 = random, chosen on first setup
    cfg.set("trust", "ips", ["203.0.113.5"])
    cfg.save()
    again = Config.load(path)
    assert again.trusted_ips == ["203.0.113.5"] and again.data["general"]["config_version"] == CONFIG_VERSION
    assert path.stat().st_mode & 0o777 == 0o640


def test_config_bad_values_fall_back_with_problems_reported(tmp_path):
    path = tmp_path / "bant.toml"
    path.write_text('[ssh]\nport = 99999\n[fail2ban]\nmaxretry = "many"\nbantime = "forever-ish"\n[trust]\nips = ["1.2.3.4", "junk"]\n')
    cfg = Config.load(path)
    assert cfg.ssh_port == 0 and cfg.maxretry == 5 and cfg.bantime == "1h" and cfg.trusted_ips == ["1.2.3.4"]
    assert len(cfg.problems) == 4


def test_config_unparseable_file_uses_defaults(tmp_path):
    path = tmp_path / "bant.toml"
    path.write_text("this is = not [valid toml")
    cfg = Config.load(path)
    assert cfg.ssh_port == 0 and cfg.problems


def test_config_from_newer_version_is_rejected(tmp_path):
    path = tmp_path / "bant.toml"
    path.write_text("[general]\nconfig_version = 99\n")
    with pytest.raises(ValidationError, match="newer"):
        Config.load(path)


def test_toml_writer_escapes():
    text = tomlio.dumps({"a": {"s": 'x"y\\z', "n": 3, "b": True, "l": ["1", "2"]}})
    assert tomlio.loads(text) == {"a": {"s": 'x"y\\z', "n": 3, "b": True, "l": ["1", "2"]}}


def test_atomic_write_semantics(tmp_path):
    target = tmp_path / "f.conf"
    fsutil.atomic_write(target, "one", 0o640)
    assert target.read_text() == "one" and stat.S_IMODE(target.stat().st_mode) == 0o640
    fsutil.atomic_write(target, b"two")
    assert target.read_text() == "two"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")], "no temp files left behind"


def test_atomic_write_refuses_symlink_and_leaves_target_alone(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("precious")
    link = tmp_path / "link"
    link.symlink_to(victim)
    with pytest.raises(OperationFailed, match="symbolic link"):
        fsutil.atomic_write(link, "evil")
    assert victim.read_text() == "precious"


def test_atomic_write_failure_cleans_temp(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "replace", lambda a, b: (_ for _ in ()).throw(OSError("boom")))
    with pytest.raises(OSError):
        fsutil.atomic_write(tmp_path / "x", "data")
    assert list(tmp_path.iterdir()) == []


# ---- audit log ----------------------------------------------------------------------

def test_redaction():
    assert "hunter2" not in redact("login password=hunter2 ok") and "token=[REDACTED]" in redact("token: abc")
    assert "SECRET" not in redact("-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET\n-----END OPENSSH PRIVATE KEY-----")


def test_audit_log_rotation_is_bounded(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", mirror_syslog=False)
    import bant.utils.logging as lg
    lg.MAX_BYTES = 2000
    try:
        for i in range(400):
            log.write("evt", i=i, blob="x" * 40)
    finally:
        lg.MAX_BYTES = 1_000_000
    files = sorted(p.name for p in tmp_path.iterdir())
    assert len(files) <= lg.KEEP_FILES + 1 and "audit.jsonl" in files
    assert all((tmp_path / f).stat().st_mode & 0o777 == 0o600 for f in files)
    assert log.read(3)[-1]["detail"]["i"] == 399


def test_audit_log_survives_unwritable_location(tmp_path):
    log = AuditLog(tmp_path / "nope" / "deeper" / "a.jsonl", mirror_syslog=False)
    (tmp_path / "nope").write_text("a file, not a directory")
    assert log.write("evt") is False
    assert json.dumps(log.read()) == "[]"


# ---- updates / audit ------------------------------------------------------------------

def test_updates_parsing():
    sec, total = updates.parse_simulated_upgrade(
        "Inst libssl3 [3.0.1] (3.0.2 Ubuntu:22.04/jammy-security [amd64])\nInst vim [1] (2 Ubuntu:22.04/jammy-updates [amd64])\n"
        "Inst openssh-server [1] (2 Debian-Security:12/bookworm-security [amd64])\nConf foo\n")
    assert sec == ["libssl3", "openssh-server"] and total == 3
    cfg = updates.parse_apt_config('APT::Periodic::Unattended-Upgrade "1";\nUnattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";\n')
    assert cfg["APT::Periodic::Unattended-Upgrade"] == ["1"]


def test_updates_enable_writes_only_its_own_file_and_never_reboots(host, ctx):
    msg = updates.enable(ctx)
    text = ctx.paths.apt_bant_conf.read_text()
    assert "NOT automatic" in msg and "Automatic-Reboot" not in text
    assert 'APT::Periodic::Unattended-Upgrade "1"' in text
    assert any("unattended-upgrades" in c for c in host.apt_calls), "package installed when missing"
    assert "Removed" in updates.disable(ctx) and not ctx.paths.apt_bant_conf.exists()
    assert "nothing to disable" in updates.disable(ctx)


def test_updates_refuse_when_package_manager_busy(host, ctx):
    from bant.utils.commands import CmdResult
    original = host._cmd_fuser
    host._cmd_fuser = lambda argv, i: CmdResult(argv, 0, "123", "")
    with pytest.raises(OperationFailed, match="running"):
        updates.enable(ctx)
    host._cmd_fuser = original


def test_audit_flags_dangerous_ssh_settings(host, ctx):
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "PermitEmptyPasswords yes\nPermitRootLogin yes\nMaxAuthTries 10\nLoginGraceTime 0\n")
    ids = {f.id: f for f in security_audit.run(ctx)}
    assert ids["SSH-020"].severity == "critical" and ids["SSH-030"].severity == "high"
    assert ids["SSH-040"].fixable and "bant ssh set max-auth-tries" in ids["SSH-040"].fix
    assert "SSH-010" in ids and ids["SSH-010"].fix == "sudo bant ssh port random"


def test_audit_detects_password_still_possible_via_kbdinteractive(host, ctx):
    (ctx.paths.sshd_config_d / "00-x.conf").write_text("PasswordAuthentication no\nKbdInteractiveAuthentication yes\n")
    assert "SSH-022" in {f.id for f in security_audit.run(ctx)}


def test_audit_flags_exposed_database_but_not_proxy_ports(host, ctx):
    host.listening.update({6379: "redis-server", 8443: "sing-box", 443: "caddy"})
    ids = {f.id: f for f in security_audit.run(ctx)}
    assert ids["NET-6379"].severity == "high"
    assert "NET-8443" not in ids and "NET-443" not in ids
    assert "8443" in ids["NET-000"].evidence and ids["NET-000"].severity == "info"


def test_audit_summary_has_no_score_and_has_disclaimer(host, ctx):
    summary = security_audit.summarize(security_audit.run(ctx))
    assert set(summary) == {"counts", "verdict", "disclaimer"} and "guarantee" in summary["disclaimer"]


def test_audit_check_failure_is_contained(host, ctx, monkeypatch):
    def boom(c):
        raise RuntimeError("kaput")
    monkeypatch.setattr(security_audit, "CHECKS", [("bad", boom, False)] + [c for c in security_audit.CHECKS if c[0] == "ssh"])
    f = security_audit.run(ctx)
    assert any(x.id == "ERR-bad" for x in f) and any(x.id.startswith("SSH") for x in f)
