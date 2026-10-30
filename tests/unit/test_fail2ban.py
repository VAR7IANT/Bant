import pytest

from bant.core import fail2ban, migration
from bant.errors import OperationFailed, RolledBack, Unsupported, ValidationError
from tests.fakes import FakeHost


def test_apply_policy_writes_only_bant_files(host, ctx):
    admin = ctx.paths.f2b_dir / "jail.d" / "custom.local"
    admin.write_text("[nginx-http-auth]\nenabled = true\n")
    res = fail2ban.apply_policy(ctx, [667])
    assert ctx.paths.f2b_jail.exists()
    assert admin.read_text() == "[nginx-http-auth]\nenabled = true\n"
    s = ctx.paths.f2b_jail.read_text()
    assert "port = 667" in s and "maxretry = 5" in s and "findtime = 10m" in s and "bantime = 1h" in s
    assert "Managed by Bant" in s
    assert res["conflicts"] == []


def test_effective_config_verified_after_apply(host, ctx):
    fail2ban.apply_policy(ctx, [22, 667])
    eff = fail2ban.effective_jail(ctx)
    assert fail2ban.parse_ports(eff["port"]) == [22, 667]
    assert eff["bantime"] == "1h"


def test_admin_defined_sshd_values_are_not_overridden_and_are_reported(host, ctx):
    (ctx.paths.f2b_dir / "jail.local").write_text("[sshd]\nmaxretry = 2\nbantime = 1d\n")
    res = fail2ban.apply_policy(ctx, [667])
    text = ctx.paths.f2b_jail.read_text()
    assert "maxretry" not in text and "bantime" not in text
    assert any("maxretry" in c for c in res["conflicts"])
    ov = fail2ban.overview(ctx)
    assert ov.maxretry == "2" and ov.bantime == "1d"
    assert ov.conflicts, "the overview must surface the administrator override"


def test_admin_global_default_respected_until_user_overrides_via_bant(host, ctx):
    (ctx.paths.f2b_dir / "jail.local").write_text("[DEFAULT]\nbantime = 1w\n")
    fail2ban.apply_policy(ctx, [22])
    fail2ban.apply_policy(ctx, [22, 667])  # a later run (e.g. migration) must not override it either
    assert "bantime" not in ctx.paths.f2b_jail.read_text()
    fail2ban.set_option(ctx, "bantime", "2d")  # explicit request through Bant
    assert "bantime = 2d" in ctx.paths.f2b_jail.read_text()


def test_admin_port_override_reported_as_unprotected(host, ctx):
    (ctx.paths.f2b_dir / "jail.d" / "mine.local").write_text("[sshd]\nport = 22\n")
    fail2ban.apply_policy(ctx, [667])
    ov = fail2ban.overview(ctx, [667])
    assert ov.state == "misconfigured"
    assert any("UNPROTECTED" in p for p in ov.problems)


def test_invalid_config_is_reverted(host, ctx):
    fail2ban.apply_policy(ctx, [22])
    before = ctx.paths.f2b_jail.read_text()
    host.f2b_config_invalid = True
    with pytest.raises(OperationFailed, match="rejected"):
        fail2ban.apply_policy(ctx, [667])
    assert ctx.paths.f2b_jail.read_text() == before


def test_not_installed_raises_unsupported(tmp_path):
    host = FakeHost(tmp_path / "r", fail2ban=False)
    ctx = host.make_ctx()
    with pytest.raises(Unsupported):
        fail2ban.apply_policy(ctx, [22])
    assert fail2ban.overview(ctx).state == "not_installed"


def test_enable_installs_package_then_configures(tmp_path):
    host = FakeHost(tmp_path / "r", fail2ban=False)
    ctx = host.make_ctx()
    msg = fail2ban.set_enabled(ctx, True)
    assert "Installed" in msg
    assert any("fail2ban" in c for c in host.apt_calls)
    assert ctx.paths.f2b_jail.exists()


def test_unusable_banaction_is_replaced(host, ctx):
    (ctx.paths.f2b_dir / "jail.d" / "defaults-debian.conf").write_text("[DEFAULT]\nbanaction = iptables-multiport\n[sshd]\nenabled = true\n")
    host.binaries.discard("iptables")
    res = fail2ban.apply_policy(ctx, [22])
    assert res["settings"].get("banaction") == "nftables"
    assert "banaction = nftables" in ctx.paths.f2b_jail.read_text()


def test_no_firewall_tool_at_all_is_reported(host, ctx):
    (ctx.paths.f2b_dir / "jail.d" / "defaults-debian.conf").write_text("[DEFAULT]\nbanaction = iptables-multiport\n[sshd]\nenabled = true\n")
    host.binaries -= {"iptables", "nft"}
    with pytest.raises(Unsupported, match="usable firewall tool"):
        fail2ban.apply_policy(ctx, [22])


def test_ufw_action_without_ufw_is_detected(host, ctx):
    assert fail2ban.action_problem(ctx, "ufw") is not None
    assert fail2ban.action_problem(ctx, "nftables") is None
    assert fail2ban.action_problem(ctx, "some-custom-action") is None


def test_missing_log_source_does_not_write_bad_logpath(host, ctx):
    host.journal_has_sshd = False
    host.pysystemd = False
    src = fail2ban.choose_log_source(ctx)
    assert src["backend"] == "systemd" and src.get("need_pysystemd") is True
    assert "logpath" not in src


def test_auth_log_used_only_when_it_exists(tmp_path):
    host = FakeHost(tmp_path / "r")
    host.journal_has_sshd = False
    ctx = host.make_ctx()
    (ctx.paths.auth_log).write_text("Oct 30 sshd[1]: something\n")
    src = fail2ban.choose_log_source(ctx)
    assert src == {"backend": "auto", "logpath": "/var/log/auth.log", "reason": "using /var/log/auth.log"}


def test_trusted_ips_merged_without_dropping_loopback(host, ctx):
    ctx.config.set("trust", "ips", ["203.0.113.5", "2001:db8::/48"])
    fail2ban.apply_policy(ctx, [22])
    line = [ln for ln in ctx.paths.f2b_jail.read_text().splitlines() if ln.startswith("ignoreip")][0]
    assert "127.0.0.1/8" in line and "::1" in line and "203.0.113.5" in line and "2001:db8::/48" in line
    ctx.config.set("trust", "ips", [])
    fail2ban.apply_policy(ctx, [22])
    assert "203.0.113.5" not in ctx.paths.f2b_jail.read_text()


def test_set_option_validates_and_persists(host, ctx):
    fail2ban.set_option(ctx, "maxretry", "3")
    assert ctx.config.maxretry == 3 and "maxretry = 3" in ctx.paths.f2b_jail.read_text()
    fail2ban.set_option(ctx, "bantime", "12h")
    assert "bantime = 12h" in ctx.paths.f2b_jail.read_text()
    with pytest.raises(ValidationError):
        fail2ban.set_option(ctx, "maxretry", "0")
    with pytest.raises(ValidationError):
        fail2ban.set_option(ctx, "bantime", "banana")
    assert ctx.config.maxretry == 3


def test_set_option_rolls_back_config_on_failure(host, ctx):
    fail2ban.apply_policy(ctx, [22])
    host.f2b_config_invalid = True
    with pytest.raises(OperationFailed):
        fail2ban.set_option(ctx, "maxretry", "9")
    assert ctx.config.maxretry == 5


def test_ban_and_unban(host, ctx):
    assert "Banned 203.0.113.50" in fail2ban.ban(ctx, "203.0.113.50")
    assert host.f2b_banned == ["203.0.113.50"]
    assert fail2ban.banned(ctx) == [{"ip": "203.0.113.50", "jail": "sshd", "source": "fail2ban", "expires": "per jail bantime"}]
    assert fail2ban.unban(ctx, "203.0.113.50") == 1
    assert host.f2b_banned == []
    assert fail2ban.unban(ctx, "203.0.113.50") == 0


def test_ipv6_ban_accepted_and_garbage_rejected(host, ctx):
    fail2ban.ban(ctx, "2001:db8::1")
    assert "2001:db8::1" in host.f2b_banned
    for bad in ("999.1.1.1", "1.2.3.4; reboot", "$(id)", "", "127.0.0.1", "0.0.0.0", "::1"):
        with pytest.raises(ValidationError):
            fail2ban.ban(ctx, bad)


def test_verify_flags_unprotected_new_port(host, ctx):
    fail2ban.apply_policy(ctx, [22])
    checks = {c.name: c for c in fail2ban.verify(ctx, [22, 667])}
    assert checks["jail covers SSH port(s)"].ok is False


def test_state_verified_only_when_all_checks_pass(host, ctx):
    fail2ban.apply_policy(ctx, [22])
    assert fail2ban.overview(ctx, [22]).state == "verified"
    host.f2b_running = False
    assert fail2ban.overview(ctx, [22]).state == "inactive"


def test_migration_updates_jail_for_both_ports_then_final(host, ctx):
    fail2ban.apply_policy(ctx, [22])
    migration.begin(ctx, 667)
    assert fail2ban.parse_ports(fail2ban.effective_jail(ctx)["port"]) == [22, 667]
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    migration.confirm(ctx)
    assert fail2ban.parse_ports(fail2ban.effective_jail(ctx)["port"]) == [667]


def test_failed_migration_restores_jail(host, ctx):
    fail2ban.apply_policy(ctx, [22])
    before = ctx.paths.f2b_jail.read_text()
    host.reload_fails = True
    with pytest.raises(RolledBack):
        migration.begin(ctx, 667)
    assert ctx.paths.f2b_jail.read_text() == before


def test_existing_ban_history_is_preserved_across_reapply(host, ctx):
    fail2ban.apply_policy(ctx, [22])
    fail2ban.ban(ctx, "203.0.113.60")
    fail2ban.apply_policy(ctx, [22, 667])
    assert "203.0.113.60" in host.f2b_banned
    assert not host.called("fail2ban-client unban")


def test_banip_with_time_parsing():
    out = fail2ban.parse_banip_with_time(
        "203.0.113.5 \t2026-10-30 05:00:00 + 3600 = 2026-10-30 06:00:00\n"
        "2001:db8::1 \t2026-10-30 05:00:00 + -1 = 2026-10-30 05:00:00\nnoise line\n")
    assert out == {"203.0.113.5": "2026-10-30 06:00:00", "2001:db8::1": "permanent"}


def test_banned_falls_back_when_expiry_unavailable(host, ctx):
    host.f2b_banned.append("203.0.113.5")
    assert fail2ban.banned(ctx)[0]["expires"] == "per jail bantime"
