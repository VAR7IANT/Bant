"""setup / backup / restore / repair / uninstall."""

import pytest

from bant.core import backups, fail2ban, firewall, migration, repair, setup, sshconf, uninstall
from bant.core.rollback import TxManager
from bant.errors import OperationFailed, PermissionDenied
from tests.fakes import FakeHost


def test_setup_fresh_server_leaves_pending_confirmation(host, ctx):
    rep = setup.run(ctx)
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
    setup.run(ctx)
    jail = ctx.paths.f2b_jail.read_text()
    dropin = ctx.paths.ssh_dropin.read_text()
    tx_before = [t.id for t in TxManager(ctx).pending()]
    rep = setup.run(ctx)
    assert [t.id for t in TxManager(ctx).pending()] == tx_before
    assert ctx.paths.f2b_jail.read_text() == jail and ctx.paths.ssh_dropin.read_text() == dropin
    assert rep["outcome"] == "pending_confirmation"
    assert sum(1 for k in host.units if k.endswith(".timer")) == 1


def test_setup_complete_after_confirm_then_rerun_changes_nothing(host, ctx):
    setup.run(ctx)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    migration.confirm(ctx)
    snapshot = (ctx.paths.ssh_dropin.read_text(), ctx.paths.f2b_jail.read_text())
    rep = setup.run(ctx)
    assert rep["outcome"] == "complete"
    assert (ctx.paths.ssh_dropin.read_text(), ctx.paths.f2b_jail.read_text()) == snapshot
    assert not TxManager(ctx).pending()


def test_setup_port_conflict_is_reported_not_forced(host, ctx):
    host.listening[667] = "caddy"
    rep = setup.run(ctx)
    mig = next(s for s in rep["steps"] if s["step"] == "ssh-migration")
    assert mig["status"] == "skipped" and "caddy" in mig["detail"]
    assert rep["outcome"] == "incomplete"
    assert not ctx.paths.ssh_dropin.exists() and host.listening[22] == "sshd"


def test_setup_preserves_password_and_root_policy(host, ctx):
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "PasswordAuthentication yes\nPermitRootLogin yes\n")
    setup.run(ctx)
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
    setup.run(ctx)
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
    setup.run(ctx)
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
    setup.run(ctx)
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
