"""Integration: Bant's config handling validated by the REAL sshd and fail2ban-client (throwaway trees)."""

import pytest

from bant.core import fail2ban, migration, ssh, sshconf
from tests.real import RealFail2banHost, RealSshdHost, needs_f2b, needs_sshd

pytestmark = pytest.mark.integration


def real_ports(host):
    out = host._cmd_sshd(["sshd", "-T", "-f", str(host.paths.sshd_config)], None).stdout
    return sorted({int(line.split()[1]) for line in out.splitlines() if line.startswith("port ")})


# ---------------------------------------------------------------- sshd ------

@needs_sshd
def test_parser_agrees_with_real_sshd_on_precedence(tmp_path):
    host = RealSshdHost(tmp_path / "r")
    ctx = host.make_ctx()
    d = ctx.paths.sshd_config_d
    (d / "10-a.conf").write_text("PasswordAuthentication no\nMaxAuthTries 3\nMatch User bob\n  PasswordAuthentication yes\n")
    (d / "50-b.conf").write_text("PasswordAuthentication yes\nMaxAuthTries 9\nPort 2222\n")
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "Port 2200\nMaxAuthTries 1\n")
    mine = sshconf.parsed_effective(sshconf.parse_config(ctx))
    real = sshconf.effective(ctx)
    assert real.source == "sshd -T"
    assert real.one("passwordauthentication") == mine.one("passwordauthentication") == "no"
    assert real.one("maxauthtries") == mine.one("maxauthtries") == "3"
    assert sorted(real.ports) == sorted(mine.ports) == [2200, 2222]


@needs_sshd
def test_match_block_ends_at_end_of_included_file(tmp_path):
    host = RealSshdHost(tmp_path / "r")
    ctx = host.make_ctx()
    (ctx.paths.sshd_config_d / "10-m.conf").write_text("Match User bob\n  PasswordAuthentication no\n")
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "MaxAuthTries 2\n")
    directives = sshconf.parse_config(ctx)
    tries = next(d for d in directives if d.keyword == "maxauthtries")
    assert tries.is_global, "a Match inside an included file must not leak into the parent file"
    assert sshconf.effective(ctx, user="alice").one("maxauthtries") == "2"


@needs_sshd
def test_bant_dropin_is_accepted_and_wins_over_cloud_init(tmp_path):
    host = RealSshdHost(tmp_path / "r")
    ctx = host.make_ctx()
    (ctx.paths.sshd_config_d / "50-cloud-init.conf").write_text("PasswordAuthentication yes\n")
    host.add_ssh_session("alice", 22, "203.0.113.7", 40000, started=1500)
    host.log_accepted("publickey", "alice", "203.0.113.7", 40000)
    res = ssh.set_password_auth(ctx, False)
    assert res["pending"]
    out = host._cmd_sshd(["sshd", "-T", "-f", str(ctx.paths.sshd_config)], None).stdout
    assert "passwordauthentication no" in out and "kbdinteractiveauthentication no" in out
    ok, _ = sshconf.validate(ctx)
    assert ok


@needs_sshd
def test_real_sshd_rejects_bad_config_and_bant_rolls_back(tmp_path):
    host = RealSshdHost(tmp_path / "r")
    ctx = host.make_ctx()
    (ctx.paths.sshd_config_d / "99-bad.conf").write_text("BogusOption yes\n")
    ok, msg = sshconf.validate(ctx)
    assert not ok and "Bogus" in msg
    from bant.errors import OperationFailed
    with pytest.raises(OperationFailed, match="invalid"):
        migration.begin(ctx, 667)


@needs_sshd
def test_migration_against_real_sshd_dual_then_final(tmp_path):
    host = RealSshdHost(tmp_path / "r")
    ctx = host.make_ctx()
    host.listening = {22: "sshd"}
    migration.begin(ctx, 667)
    assert real_ports(host) == [22, 667], "real sshd must see both listeners (and each port exactly once)"
    out = host._cmd_sshd(["sshd", "-T", "-f", str(ctx.paths.sshd_config)], None).stdout
    assert out.count("listenaddress 0.0.0.0:667") == 1
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    migration.confirm(ctx)
    assert real_ports(host) == [667]


@needs_sshd
def test_migration_with_explicit_port_line_against_real_sshd(tmp_path):
    host = RealSshdHost(tmp_path / "r")
    ctx = host.make_ctx()
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "Port 2222\n")
    host.listening = {2222: "sshd"}
    migration.begin(ctx, 667)
    assert real_ports(host) == [667, 2222]
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    migration.confirm(ctx)
    assert real_ports(host) == [667]
    assert "# bant-disabled: Port 2222" in cfg.read_text()


@needs_sshd
def test_listenaddress_with_port_detected_by_parser(tmp_path):
    host = RealSshdHost(tmp_path / "r")
    ctx = host.make_ctx()
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "ListenAddress 0.0.0.0:22\nListenAddress [::]:22\nListenAddress 10.0.0.1\n")
    pinned = sshconf.listen_addresses_with_ports(sshconf.parse_config(ctx))
    assert [d.args for d in pinned] == ["0.0.0.0:22", "[::]:22"]


# ----------------------------------------------------------- fail2ban -------

@needs_f2b
def test_generated_jail_is_valid_for_real_fail2ban(tmp_path):
    host = RealFail2banHost(tmp_path / "r")
    ctx = host.make_ctx()
    ctx.config.set("trust", "ips", ["203.0.113.5"])
    res = fail2ban.apply_policy(ctx, [22, 667])
    assert res["conflicts"] == []
    t = host.run(["fail2ban-client", "-t"])
    assert t.ok, t.output
    eff = fail2ban.effective_jail(ctx, config_dir=ctx.paths.f2b_dir)
    assert fail2ban.parse_ports(eff["port"]) == [22, 667]
    assert eff["maxretry"] == "5" and eff["findtime"] == "10m" and eff["bantime"] == "1h"
    assert "203.0.113.5" in eff["ignoreip"] and "127.0.0.1/8" in eff["ignoreip"] and "::1" in eff["ignoreip"]
    joined = " ".join(eff["journalmatch"])
    assert "ssh.service" in joined and "sshd-session" in joined, "journal match must cover Debian's unit name and sshd-session"
    assert eff["backend"] == "systemd"


@needs_f2b
def test_admin_override_precedence_matches_real_fail2ban(tmp_path):
    host = RealFail2banHost(tmp_path / "r")
    ctx = host.make_ctx()
    (ctx.paths.f2b_dir / "jail.d" / "mine.local").write_text("[sshd]\nmaxretry = 2\n")
    fail2ban.apply_policy(ctx, [667])
    eff = fail2ban.effective_jail(ctx, config_dir=ctx.paths.f2b_dir)
    assert eff["maxretry"] == "2", "administrator's value must survive Bant's policy"
    assert eff["bantime"] == "1h"


@needs_f2b
def test_retained_jail_after_uninstall_still_valid(tmp_path):
    from bant.core import uninstall
    host = RealFail2banHost(tmp_path / "r")
    ctx = host.make_ctx()
    fail2ban.apply_policy(ctx, [667])
    ctx.paths.sshd_config.write_text("Port 667\n")
    host.listening = {667: "sshd"}
    ctx.paths.launcher.parent.mkdir(parents=True, exist_ok=True)
    uninstall.run(ctx)
    assert host.run(["fail2ban-client", "-t"]).ok
    assert fail2ban.parse_ports(fail2ban.effective_jail(ctx, config_dir=ctx.paths.f2b_dir)["port"]) == [667]


@needs_f2b
def test_compat_filter_overrides_journalmatch_for_real_fail2ban(tmp_path):
    host = RealFail2banHost(tmp_path / "r")
    ctx = host.make_ctx()
    fail2ban.apply_policy(ctx, [667])
    text = ctx.paths.f2b_filter.read_text()
    assert "[Definition]" in text and "[Init]" in text
    eff = fail2ban.effective_jail(ctx, config_dir=ctx.paths.f2b_dir)
    assert eff["journalmatch"] == ["_SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _COMM=sshd + _COMM=sshd-session"]
