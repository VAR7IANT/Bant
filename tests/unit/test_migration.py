"""SSH port migration: lifecycle, failure handling and rollback, against the fake host."""

import pytest

from bant.core import migration, ssh, sshconf
from bant.core.rollback import TxManager
from bant.errors import OperationFailed, RolledBack
from bant.utils.commands import CmdResult
from tests.fakes import FakeHost, make_stubs, run_script


def test_begin_creates_dual_listener_and_arms_rollback(host, ctx):
    result = migration.begin(ctx, 667)
    assert result["target"] == 667 and result["old_ports"] == [22]
    assert set(host.listening) == {22, 667}
    dropin = ctx.paths.ssh_dropin.read_text()
    assert "Port 22" in dropin and "Port 667" in dropin
    tx = TxManager(ctx).pending()[0]
    assert tx.phase == "dual"
    # the persistent timer was armed before any change
    assert host.units[f"bant-rollback-{tx.id}.timer"] == "active"
    assert (ctx.paths.systemd_system / f"bant-rollback-{tx.id}.timer").exists()
    assert "Persistent=true" in (ctx.paths.systemd_system / f"bant-rollback-{tx.id}.timer").read_text()


def test_confirm_without_new_session_is_refused(host, ctx):
    migration.begin(ctx, 667)
    # the admin is still connected on the OLD port: that must not confirm anything
    host.add_ssh_session("alice", 22, "203.0.113.7", 50000, started=2500)
    with pytest.raises(OperationFailed, match="No authenticated SSH session"):
        migration.confirm(ctx)
    assert TxManager(ctx).pending(), "transaction must stay open"
    assert 22 in host.listening and 667 in host.listening


def test_confirm_rejects_session_that_predates_the_change(host, ctx):
    migration.begin(ctx, 667)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001, started=1500)  # older than tx.created (2000)
    with pytest.raises(OperationFailed):
        migration.confirm(ctx)


def test_confirm_rejects_local_peer(host, ctx):
    migration.begin(ctx, 667)
    host.add_ssh_session("alice", 667, "10.0.0.5", 50002)  # our own address: not a real remote login
    with pytest.raises(OperationFailed):
        migration.confirm(ctx)


def test_confirm_finalizes_and_removes_old_listener(host, ctx):
    migration.begin(ctx, 667)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50003)
    out = migration.confirm(ctx)
    assert out["port"] == 667 and out["removed_ports"] == [22]
    assert set(host.listening) == {667}
    assert sshconf.read_dropin(ctx)[0] == [667]
    assert not TxManager(ctx).pending()
    assert ctx.config.ssh_port == 667
    assert ctx.state.get("migration", "status") == "done"
    # timer disarmed
    assert not any(k.endswith(".timer") and v == "active" for k, v in host.units.items())


def test_explicit_port_line_in_sshd_config_is_disabled_on_finalize(host, ctx):
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "Port 2222\n")
    host.listening = {2222: "sshd"}
    migration.begin(ctx, 667)
    assert set(host.listening) == {2222, 667}
    host.add_ssh_session("alice", 667, "203.0.113.7", 50004)
    migration.confirm(ctx)
    assert "# bant-disabled: Port 2222" in cfg.read_text()
    assert set(host.listening) == {667}


def test_port_in_use_is_a_blocker(host, ctx):
    host.listening[667] = "nginx"
    p = migration.plan(ctx, 667)
    assert any("already in use by nginx" in b for b in p.blockers)
    with pytest.raises(OperationFailed, match="nginx"):
        migration.begin(ctx, 667)
    assert not TxManager(ctx).pending() and not ctx.paths.ssh_dropin.exists()


def test_already_on_target_port_is_idempotent(host, ctx):
    ctx.paths.sshd_config.write_text(ctx.paths.sshd_config.read_text() + "Port 667\n")
    host.listening = {667: "sshd"}
    out = migration.begin(ctx, 667)
    assert out["already_done"]
    assert not TxManager(ctx).pending()


def test_reload_failure_triggers_automatic_rollback(host, ctx):
    original = ctx.paths.sshd_config.read_text()
    host.reload_fails = True
    stubs = host.root / "stubs"
    with pytest.raises(RolledBack):
        migration.begin(ctx, 667)
    # the in-process rollback runs the real shell script with the system PATH; nothing but our files was touched
    assert not ctx.paths.ssh_dropin.exists()
    assert ctx.paths.sshd_config.read_text() == original
    assert stubs is not None


def test_invalid_config_aborts_before_any_change(host, ctx):
    host.sshd_invalid = True
    with pytest.raises(OperationFailed, match="invalid"):
        migration.begin(ctx, 667)
    assert not ctx.paths.ssh_dropin.exists()


def test_firewall_failure_rolls_back(host):
    host = FakeHost(host.root.parent / "ufwroot", ufw=True)
    ctx = host.make_ctx()
    host.fail_commands.add("ufw allow")
    with pytest.raises(RolledBack):
        migration.begin(ctx, 667)
    assert not ctx.paths.ssh_dropin.exists()


def test_ufw_rule_added_and_committed_on_confirm(tmp_path):
    host = FakeHost(tmp_path / "r", ufw=True)
    ctx = host.make_ctx()
    migration.begin(ctx, 667)
    assert "667/tcp" in host.ufw_rules
    host.add_ssh_session("alice", 667, "203.0.113.7", 50005)
    migration.confirm(ctx)
    reg = ctx.state.get("firewall", "rules")
    assert [r["port"] for r in reg] == [667]
    assert reg[0]["backend"] == "ufw"


def test_preexisting_ufw_rule_is_not_claimed(tmp_path):
    host = FakeHost(tmp_path / "r", ufw=True)
    host.ufw_rules.append("667/tcp")
    ctx = host.make_ctx()
    migration.begin(ctx, 667)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50006)
    migration.confirm(ctx)
    assert ctx.state.get("firewall", "rules", default=[]) == []
    assert host.ufw_rules.count("667/tcp") == 1


def test_socket_activation_mode(tmp_path):
    host = FakeHost(tmp_path / "r", os_id="ubuntu", os_version="24.04", socket_mode=True)
    ctx = host.make_ctx()
    migration.begin(ctx, 667)
    sock = ctx.paths.socket_dropin("ssh.socket")
    text = sock.read_text()
    assert "ListenStream=\n" in text and "0.0.0.0:667" in text and "[::]:667" in text and "0.0.0.0:22" in text
    assert host.called("systemctl restart ssh.socket")
    assert set(host.listening) == {22, 667}
    host.add_ssh_session("alice", 667, "203.0.113.7", 50007)
    migration.confirm(ctx)
    final = sock.read_text()
    assert ":667" in final and ":22\n" not in final
    assert set(host.listening) == {667}


def test_listenaddress_with_port_blocks_automation(host, ctx):
    ctx.paths.sshd_config.write_text(ctx.paths.sshd_config.read_text() + "ListenAddress 0.0.0.0:22\n")
    assert any("ListenAddress" in b for b in migration.plan(ctx, 667).blockers)


def test_pending_transaction_blocks_new_change(host, ctx):
    migration.begin(ctx, 667)
    with pytest.raises(OperationFailed, match="pending"):
        migration.begin(ctx, 2200)


def test_abort_runs_rollback_script_and_restores(host, ctx):
    original = ctx.paths.sshd_config.read_text()
    migration.begin(ctx, 667)
    assert ctx.paths.ssh_dropin.exists()
    # rollback script executes for real with stubbed system commands
    tx = TxManager(ctx).pending()[0]
    stubs = host.root / "stubs"
    log = host.root / "stub.log"
    make_stubs(stubs, ["systemctl", "ufw", "nft", "iptables", "fail2ban-client", "sshd"], log)
    rc, out = run_script(TxManager(ctx).dir(tx.id) / "rollback.sh", stubs)
    assert rc == 0, out
    assert not ctx.paths.ssh_dropin.exists(), "Bant drop-in did not exist originally, so it must be removed"
    assert ctx.paths.sshd_config.read_text() == original
    assert (TxManager(ctx).dir(tx.id) / "rolled_back").exists()
    assert "systemctl reload ssh.service" in log.read_text()
    # idempotent: second run does nothing
    rc2, _ = run_script(TxManager(ctx).dir(tx.id) / "rollback.sh", stubs)
    assert rc2 == 0
    assert TxManager(ctx).load(tx.id).status == "rolled_back"


def test_rollback_script_is_skipped_once_confirmed(host, ctx):
    migration.begin(ctx, 667)
    tx = TxManager(ctx).pending()[0]
    host.add_ssh_session("alice", 667, "203.0.113.7", 50008)
    migration.confirm(ctx)
    stubs = host.root / "stubs"
    make_stubs(stubs, ["systemctl", "sshd"], host.root / "stub.log")
    rc, _ = run_script(TxManager(ctx).dir(tx.id) / "rollback.sh", stubs)
    assert rc == 0
    assert sshconf.read_dropin(ctx)[0] == [667], "a late timer must not undo a confirmed migration"


def test_rollback_restores_modified_admin_file(host, ctx):
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "Port 2222\n")
    original = cfg.read_text()
    host.listening = {2222: "sshd"}
    migration.begin(ctx, 667)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50009)
    # make finalize fail at the last verification step: old port never stops listening
    host.reload_fails = False
    real = host._apply_service_ports

    def sticky():
        real()
        host.listening[2222] = "sshd"
    host._apply_service_ports = sticky
    with pytest.raises(RolledBack):
        migration.confirm(ctx)
    assert cfg.read_text() == original
    assert not ctx.paths.ssh_dropin.exists()


def test_extend_pushes_deadline(host, ctx):
    migration.begin(ctx, 667)
    before = migration.describe_pending(ctx)["deadline"]
    migration.extend(ctx, 5)
    assert migration.describe_pending(ctx)["deadline"] == before + 300


def test_status_reflects_ports(host, ctx):
    st = ssh.status(ctx)
    assert st.installed and st.active_ports == [22] and st.password_auth is True


def test_fail2ban_trouble_at_finalize_does_not_undo_a_verified_migration(host, ctx):
    from bant.core import fail2ban
    fail2ban.apply_policy(ctx, [22])
    migration.begin(ctx, 667)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    real = fail2ban.apply_policy

    def broken(*a, **kw):
        raise OperationFailed("fail2ban said no")
    fail2ban.apply_policy = broken
    try:
        out = migration.confirm(ctx)
    finally:
        fail2ban.apply_policy = real
    assert out["port"] == 667 and set(host.listening) == {667}
    assert any("still protects the new port" in n for n in out["notes"])


def test_socket_activated_idle_service_does_not_break_option_changes(tmp_path):
    host = FakeHost(tmp_path / "r", os_id="ubuntu", os_version="24.04", socket_mode=True)
    ctx = host.make_ctx()
    real = host._cmd_systemctl

    def idle(argv, inp):
        if argv[1] == "is-active" and argv[-1] == "ssh.service":
            return CmdResult(argv, 3, "inactive\n", "")
        if argv[1] == "reload":
            return CmdResult(argv, 1, "", "Unit ssh.service is not active")
        return real(argv, inp)
    host._cmd_systemctl = idle
    res = ssh.set_option(ctx, "max-auth-tries", "4")
    assert res["changed"] and "MaxAuthTries 4" in ctx.paths.ssh_dropin.read_text()


def test_confirm_after_deadline_rollback_explains_what_happened(host, ctx):
    migration.begin(ctx, 667)
    tx = TxManager(ctx).pending()[0]
    TxManager(ctx).rollback(tx, "deadline reached")
    with pytest.raises(OperationFailed, match="already rolled back"):
        migration.confirm(ctx)
