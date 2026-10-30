"""setup / backup / restore / repair / uninstall."""

import pytest

from bant.core import backups, fail2ban, firewall, migration, ports, repair, setup, sshconf, uninstall
from bant.core.rollback import TxManager
from bant.errors import OperationFailed, PermissionDenied
from tests.fakes import FakeHost


def test_setup_fresh_server_leaves_pending_confirmation(host, ctx):
    rep = setup.run(ctx, port=667)
    steps = {s["step"]: s for s in rep["steps"]}
    assert steps["baseline"]["status"] == "done" and steps["fail2ban"]["status"] == "done"
    assert steps["ssh-migration"]["status"] == "pending"
    assert rep["outcome"] == "pending_confirmation"
    assert rep["pending"]["target"] == 667
    assert any("ssh -p 667" in n for n in rep["next_steps"])
    assert set(host.listening) == {22, 667}
    assert fail2ban.parse_ports(fail2ban.effective_jail(ctx)["port"]) == [22, 667]
    assert (ctx.paths.config_file).exists()


def test_setup_is_idempotent_while_pending(host, ctx):
    setup.run(ctx, port=667)
    jail = ctx.paths.f2b_jail.read_text()
    dropin = ctx.paths.ssh_dropin.read_text()
    tx_before = [t.id for t in TxManager(ctx).pending()]
    rep = setup.run(ctx)
    assert [t.id for t in TxManager(ctx).pending()] == tx_before
    assert ctx.paths.f2b_jail.read_text() == jail and ctx.paths.ssh_dropin.read_text() == dropin
    assert rep["outcome"] == "pending_confirmation"
    assert sum(1 for k in host.units if k.endswith(".timer")) == 1


def test_setup_complete_after_confirm_then_rerun_changes_nothing(host, ctx):
    setup.run(ctx, port=667)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    migration.confirm(ctx)
    snapshot = (ctx.paths.ssh_dropin.read_text(), ctx.paths.f2b_jail.read_text())
    rep = setup.run(ctx)
    assert rep["outcome"] == "complete"
    assert (ctx.paths.ssh_dropin.read_text(), ctx.paths.f2b_jail.read_text()) == snapshot
    assert not TxManager(ctx).pending()


def test_setup_port_conflict_is_reported_not_forced(host, ctx):
    host.listening[667] = "caddy"
    rep = setup.run(ctx, port=667)
    mig = next(s for s in rep["steps"] if s["step"] == "ssh-migration")
    assert mig["status"] == "skipped" and "caddy" in mig["detail"]
    assert rep["outcome"] == "incomplete"
    assert not ctx.paths.ssh_dropin.exists() and host.listening[22] == "sshd"


def test_setup_preserves_password_and_root_policy(host, ctx):
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "PasswordAuthentication yes\nPermitRootLogin yes\n")
    setup.run(ctx, port=667)
    eff = sshconf.effective(ctx)
    assert eff.flag("passwordauthentication") and eff.one("permitrootlogin") == "yes"


def test_setup_requires_root(tmp_path):
    ctx = FakeHost(tmp_path / "r", euid=1000).make_ctx()
    with pytest.raises(PermissionDenied):
        setup.run(ctx)


def test_setup_without_openssh_skips_ssh(tmp_path):
    host = FakeHost(tmp_path / "r", ssh_installed=False)
    ctx = host.make_ctx()
    rep = setup.run(ctx)
    assert next(s for s in rep["steps"] if s["step"] == "ssh")["status"] == "skipped"


def test_setup_runs_with_firewall_ufw(tmp_path):
    host = FakeHost(tmp_path / "r", ufw=True)
    ctx = host.make_ctx()
    setup.run(ctx, port=667)
    assert "667/tcp" in host.ufw_rules and "22/tcp" not in host.ufw_rules  # old port rule untouched/not invented


# ---- backups ----------------------------------------------------------------

def test_backup_contents_permissions_and_exclusions(host, ctx):
    (ctx.paths.ssh_dir / "ssh_host_ed25519_key").write_text("PRIVATE")
    (ctx.paths.sshd_config_d / "99-extra.conf").write_text("X11Forwarding no\n")
    b = backups.create(ctx, "t")
    root = ctx.paths.backup_dir / b["id"]
    assert root.stat().st_mode & 0o777 == 0o700
    stored = {p.name.split("-", 1)[1] for p in (root / "files").iterdir()}
    assert "sshd_config" in stored and "99-extra.conf" in stored
    assert not any("host_key" in n or "ssh_host" in n for n in stored)
    assert all((p.stat().st_mode & 0o777) == 0o600 for p in (root / "files").iterdir())


def test_restore_roundtrip_removes_bant_files_that_did_not_exist(host, ctx):
    original = ctx.paths.sshd_config.read_text()
    b = backups.create(ctx, "baseline")
    migration.begin(ctx, 667)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    migration.confirm(ctx)
    ctx.paths.sshd_config.write_text(original + "# admin edit\n")
    host.listening = {667: "sshd"}
    host.add_ssh_session("bob", 667, "203.0.113.8", 50002)
    res = backups.restore(ctx, b["id"])
    assert ctx.paths.sshd_config.read_text() == original
    assert not ctx.paths.ssh_dropin.exists()
    assert res["safety_backup"] and backups.resolve(ctx, res["safety_backup"])


def test_restore_aborts_and_undoes_if_session_port_would_vanish(host, ctx, monkeypatch):
    from bant.core import netinfo
    b = backups.create(ctx, "baseline")  # SSH on 22
    ctx.paths.sshd_config.write_text(ctx.paths.sshd_config.read_text() + "Port 2200\n")
    host.listening = {2200: "sshd"}
    host.add_ssh_session("alice", 2200, "203.0.113.7", 50001)
    monkeypatch.setattr(netinfo, "current_session", lambda c, start_pid=None: netinfo.ssh_sessions(c)[0])
    edited = ctx.paths.sshd_config.read_text()
    with pytest.raises(OperationFailed, match="undone"):
        backups.restore(ctx, b["id"])
    assert ctx.paths.sshd_config.read_text() == edited


def test_restore_detects_corrupt_backup_before_changing_anything(host, ctx):
    b = backups.create(ctx, "x")
    victim = next((ctx.paths.backup_dir / b["id"] / "files").iterdir())
    victim.write_text("tampered")
    ctx.paths.sshd_config.write_text("# changed\n" + ctx.paths.sshd_config.read_text())
    changed = ctx.paths.sshd_config.read_text()
    with pytest.raises(OperationFailed):
        backups.restore(ctx, b["id"])
    assert ctx.paths.sshd_config.read_text() == changed
    assert backups.verify_integrity(ctx)[1] >= 1


def test_restore_refused_while_transaction_pending(host, ctx):
    backups.create(ctx, "x")
    migration.begin(ctx, 667)
    with pytest.raises(OperationFailed, match="pending"):
        backups.restore(ctx, "latest")


def test_backup_requires_root_and_validates_id(tmp_path):
    host = FakeHost(tmp_path / "r", euid=1000)
    with pytest.raises(PermissionDenied):
        backups.create(host.make_ctx())
    ctx = FakeHost(tmp_path / "r2").make_ctx()
    backups.create(ctx)
    from bant.errors import ValidationError
    with pytest.raises(ValidationError):
        backups.resolve(ctx, "../../etc")


# ---- repair ----------------------------------------------------------------

def test_repair_rolls_back_overdue_transaction(host, ctx):
    migration.begin(ctx, 667)
    later = host.make_ctx(clock=lambda: 2000.0 + 3600)
    actions = repair.run(later)
    assert any("overdue transaction" in a["action"] and a["result"] == "ok" for a in actions)
    assert not ctx.paths.ssh_dropin.exists() and not TxManager(ctx).pending()


def test_repair_tightens_permissions(host, ctx):
    backups.create(ctx)
    ctx.paths.backup_dir.chmod(0o755)
    actions = repair.run(ctx)
    assert any("tightened" in a["action"] for a in actions)
    assert ctx.paths.backup_dir.stat().st_mode & 0o777 == 0o700


def test_repair_nothing_to_do(host, ctx):
    assert repair.run(ctx) == [{"action": "nothing to repair", "result": "ok"}]


# ---- uninstall -----------------------------------------------------------------

def _installed_and_confirmed(host, ctx):
    setup.run(ctx, port=667)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    migration.confirm(ctx)
    ctx.paths.launcher.write_text("#!/bin/sh\n")
    (ctx.paths.install_dir).mkdir(parents=True, exist_ok=True)


def test_uninstall_keeps_ssh_port_and_fail2ban_protection(host, ctx):
    _installed_and_confirmed(host, ctx)
    res = uninstall.run(ctx)
    assert set(host.listening) == {667}, "the working SSH listener must remain"
    assert sshconf.effective(ctx).ports == [667], "SSH must not revert to 22"
    assert not ctx.paths.ssh_dropin.exists() and ctx.paths.ssh_retained_dropin.exists()
    assert "Originally configured by Bant" in ctx.paths.ssh_retained_dropin.read_text()
    assert ctx.paths.f2b_retained_jail.exists() and not ctx.paths.f2b_jail.exists()
    assert fail2ban.parse_ports(fail2ban.effective_jail(ctx)["port"]) == [667]
    assert not ctx.paths.launcher.exists() and not ctx.paths.install_dir.exists()
    assert ctx.paths.backup_dir.exists(), "backups are kept unless --purge"
    assert any("not reverted" in res["final"]["note"] for _ in [0])
    assert not host.called("apt-get remove") and not any("purge" in " ".join(c) for c in host.calls if c[0] == "apt-get")


def test_uninstall_removes_only_registry_firewall_rules(tmp_path):
    host = FakeHost(tmp_path / "r", ufw=True)
    host.ufw_rules.append("443/tcp")
    ctx = host.make_ctx()
    _installed_and_confirmed(host, ctx)
    assert "667/tcp" in host.ufw_rules
    uninstall.run(ctx)
    assert "667/tcp" not in host.ufw_rules and "443/tcp" in host.ufw_rules
    assert firewall.registry(ctx) == []


def test_uninstall_refused_with_pending_transaction(host, ctx):
    setup.run(ctx, port=667)
    with pytest.raises(OperationFailed, match="pending"):
        uninstall.run(ctx)


def test_uninstall_refused_when_sshd_config_invalid(host, ctx):
    host.sshd_invalid = True
    with pytest.raises(OperationFailed, match="invalid"):
        uninstall.run(ctx)


def test_uninstall_purge_removes_data(host, ctx):
    _installed_and_confirmed(host, ctx)
    uninstall.run(ctx, purge=True)
    assert not ctx.paths.state_dir.exists() and not ctx.paths.etc_bant.exists()


def test_uninstall_dry_run_changes_nothing(host, ctx):
    _installed_and_confirmed(host, ctx)
    ctx.dry_run = True
    out = uninstall.run(ctx)
    assert out["dry_run"] and ctx.paths.ssh_dropin.exists() and ctx.paths.launcher.exists()


# ---- default: random port, user-overridable ------------------------------------------------

def test_setup_default_is_a_random_free_port_not_22_not_667(host, ctx):
    rep = setup.run(ctx)
    port = rep["ssh_port"]
    assert rep["port_source"] == "random" and rep["outcome"] == "pending_confirmation"
    assert 10240 <= port <= 65535 and port not in (22, 667)
    assert not ports.in_ephemeral_range(ctx, port), "must stay clear of the kernel's outgoing-connection range"
    assert set(host.listening) == {22, port}
    assert rep["pending"]["target"] == port
    assert any(f"allow inbound TCP {port}" in n for n in rep["next_steps"]), "provider-firewall reminder names the actual port"
    assert any(f"ssh -p {port}" in n for n in rep["next_steps"])


def test_setup_rerun_after_rollback_reuses_the_same_random_port(host, ctx):
    first = setup.run(ctx)["ssh_port"]
    from bant.core import repair
    later = host.make_ctx(clock=lambda: 2000.0 + 3600)
    repair.run(later)                     # deadline passed -> automatic rollback
    assert not TxManager(ctx).pending() and set(host.listening) == {22}
    again = setup.run(ctx)
    assert again["ssh_port"] == first and again["port_source"] == "remembered"


def test_user_can_choose_the_port(host, ctx):
    rep = setup.run(ctx, port=2222)
    assert rep["ssh_port"] == 2222 and rep["port_source"] == "requested"
    assert set(host.listening) == {22, 2222}


def test_user_can_ask_for_a_new_random_port_explicitly(host, ctx):
    port, source = ports.resolve_target(ctx, "random")
    assert source == "random" and port not in (22, 667)
    other, _ = ports.resolve_target(ctx, "random")
    assert 10240 <= other <= 65535


def test_existing_custom_ssh_port_is_kept_not_randomised(host, ctx):
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "Port 2222\n")
    host.listening = {2222: "sshd"}
    rep = setup.run(ctx)
    assert rep["ssh_port"] == 2222 and rep["port_source"] == "existing"
    assert next(s for s in rep["steps"] if s["step"] == "ssh-migration")["status"] == "done"
    assert not TxManager(ctx).pending() and ctx.config.ssh_port == 2222
    assert set(host.listening) == {2222}


def test_config_port_is_authoritative_on_later_runs(host, ctx):
    ctx.config.set("ssh", "port", 40123)
    port, source = ports.resolve_target(ctx, None)
    assert (port, source) == (40123, "config")


def test_random_choice_avoids_busy_ports_and_ephemeral_range(host, ctx):
    import random as _r
    host.listening.update({p: "x" for p in range(10240, 10300)})
    lo, hi = ports.ephemeral_range(ctx)
    for seed in range(200):
        c = host.make_ctx(rng=_r.Random(seed))
        p = ports.pick_random(c)
        assert 10240 <= p <= 65535 and not (lo <= p <= hi) and p not in host.listening and p not in ports.AVOID


def test_random_choice_reads_the_real_ephemeral_range(host, ctx):
    (host.paths.proc / "sys/net/ipv4").mkdir(parents=True)
    (host.paths.proc / "sys/net/ipv4/ip_local_port_range").write_text("15000\t30000\n")
    assert ports.ephemeral_range(ctx) == (15000, 30000)
    import random as _r
    for seed in range(100):
        p = ports.pick_random(host.make_ctx(rng=_r.Random(seed)))
        assert not 15000 <= p <= 30000


def test_plan_warns_about_ephemeral_range_for_user_chosen_port(host, ctx):
    plan = migration.plan(ctx, 40000)
    assert any("ephemeral" in w for w in plan.warnings)
    assert not any("ephemeral" in w for w in migration.plan(ctx, 20000).warnings)


def test_requested_port_that_is_busy_is_still_a_blocker(host, ctx):
    host.listening[2222] = "caddy"
    assert any("caddy" in b for b in migration.plan(ctx, 2222).blockers)
    port, _ = ports.resolve_target(ctx, "random")
    assert port != 2222
