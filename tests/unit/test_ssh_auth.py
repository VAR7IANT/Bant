"""Password/root/limits changes: safety prechecks, effective-config verification, confirmation."""

import pytest

from bant.core import migration, ssh, sshconf
from bant.core.rollback import TxManager
from bant.errors import OperationFailed, RolledBack, ValidationError


def key_session(host, user="alice", rport=40000):
    host.add_ssh_session(user, 22, "203.0.113.7", rport, started=1500)
    host.log_accepted("publickey", user, "203.0.113.7", rport)


def test_password_off_refused_without_verified_key_login(host, ctx):
    host.add_ssh_session("alice", 22, "203.0.113.7", 40000)
    host.log_accepted("password", "alice", "203.0.113.7", 40000)  # current session used a PASSWORD
    with pytest.raises(OperationFailed, match="No verified public-key login"):
        ssh.set_password_auth(ctx, False)
    assert not ctx.paths.ssh_dropin.exists()


def test_password_off_refused_when_no_log_evidence(host, ctx):
    host.add_ssh_session("alice", 22, "203.0.113.7", 40000)
    with pytest.raises(OperationFailed, match="public-key"):
        ssh.set_password_auth(ctx, False)


def test_password_off_applies_with_rollback_transaction(host, ctx):
    key_session(host)
    res = ssh.set_password_auth(ctx, False)
    assert res["pending"]
    eff = sshconf.effective(ctx)
    assert not eff.flag("passwordauthentication") and not eff.flag("kbdinteractiveauthentication")
    tx = TxManager(ctx).pending()[0]
    assert tx.kind == "ssh-auth" and tx.meta["require"]["method"] == "publickey"
    assert host.units[f"bant-rollback-{tx.id}.timer"] == "active"


def test_password_off_needs_a_new_key_session_to_confirm(host, ctx):
    key_session(host, rport=40000)
    ssh.set_password_auth(ctx, False)
    # the pre-existing session must NOT satisfy confirmation
    with pytest.raises(OperationFailed, match="No authenticated SSH session"):
        migration.confirm(ctx)
    # a new session that logged in with a PASSWORD (impossible now, but logs say so) does not count either
    host.add_ssh_session("alice", 22, "203.0.113.8", 40001, started=2600)
    host.log_accepted("password", "alice", "203.0.113.8", 40001)
    with pytest.raises(OperationFailed):
        migration.confirm(ctx)
    # a new key session does
    host.add_ssh_session("alice", 22, "203.0.113.9", 40002, started=2700)
    host.log_accepted("publickey", "alice", "203.0.113.9", 40002)
    out = migration.confirm(ctx)
    assert out["kind"] == "ssh-auth"
    assert not TxManager(ctx).pending()


def test_unconfirmed_password_off_is_rolled_back(host, ctx):
    key_session(host)
    ssh.set_password_auth(ctx, False)
    tx = TxManager(ctx).pending()[0]
    assert TxManager(ctx).rollback(tx, "deadline")
    assert not ctx.paths.ssh_dropin.exists()
    assert sshconf.effective(ctx).flag("passwordauthentication")


def test_password_off_rejected_when_every_auth_method_needs_password(host, ctx):
    key_session(host)
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "AuthenticationMethods publickey,password\n")
    with pytest.raises(OperationFailed, match="AuthenticationMethods"):
        ssh.set_password_auth(ctx, False)


def test_password_off_rejected_when_pubkey_disabled(host, ctx):
    key_session(host)
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "PubkeyAuthentication no\n")
    with pytest.raises(OperationFailed, match="PubkeyAuthentication"):
        ssh.set_password_auth(ctx, False)


def test_shadowed_setting_is_detected_and_reverted(host, ctx):
    """An earlier directive wins in OpenSSH; the change must not be reported as successful."""
    key_session(host)
    cfg = ctx.paths.sshd_config
    # Include moved BELOW a global directive: our drop-in can no longer take precedence
    cfg.write_text("PasswordAuthentication yes\n" + cfg.read_text())
    with pytest.raises(RolledBack, match="did not take effect"):
        ssh.set_password_auth(ctx, False)
    assert not ctx.paths.ssh_dropin.exists()
    assert not TxManager(ctx).pending() or TxManager(ctx).pending()[0].status != "open"


def test_password_on_is_effective_even_if_other_file_said_no(host, ctx):
    d = ctx.paths.sshd_config_d
    (d / "50-cloud-init.conf").write_text("PasswordAuthentication no\n")
    assert not sshconf.effective(ctx).flag("passwordauthentication")
    res = ssh.set_password_auth(ctx, True)
    assert res["changed"] and "pending" not in res
    assert sshconf.effective(ctx).flag("passwordauthentication")
    assert any("brute-force" in w for w in res["warnings"])


def test_password_on_preserves_root_policy(host, ctx):
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "PermitRootLogin no\n")
    ssh.set_password_auth(ctx, True)
    assert sshconf.effective(ctx).one("permitrootlogin") == "no"


def test_idempotent_reapply(host, ctx):
    ssh.set_password_auth(ctx, True)
    again = ssh.set_password_auth(ctx, True)
    assert again["changed"] is False


def test_invalid_config_after_change_restores_previous(host, ctx):
    ssh.set_option(ctx, "max-auth-tries", "4")
    before = ctx.paths.ssh_dropin.read_text()
    host.reload_fails = True
    with pytest.raises(RolledBack):
        ssh.set_option(ctx, "max-auth-tries", "3")
    assert ctx.paths.ssh_dropin.read_text() == before


def test_root_login_no_requires_another_admin(host, ctx, monkeypatch):
    monkeypatch.setattr(ssh, "other_admin_exists", lambda exclude="root": [])
    host.add_ssh_session("root", 22, "203.0.113.7", 40000)
    with pytest.raises(OperationFailed, match="only administrator"):
        ssh.set_option(ctx, "root-login", "no")


def test_root_login_no_allowed_from_non_root_session(host, ctx, monkeypatch):
    monkeypatch.setattr(ssh, "other_admin_exists", lambda exclude="root": ["alice"])
    host.add_ssh_session("alice", 22, "203.0.113.7", 40000)
    res = ssh.set_option(ctx, "root-login", "no")
    assert res["pending"], "restricting root is risky and must be transactional"


def test_option_validation(host, ctx):
    with pytest.raises(ValidationError):
        ssh.set_option(ctx, "max-auth-tries", "99")
    with pytest.raises(ValidationError):
        ssh.set_option(ctx, "nonsense", "1")
    with pytest.raises(ValidationError):
        ssh.set_option(ctx, "login-grace-time", "5")


def test_match_block_override_is_reported_not_hidden(host, ctx):
    cfg = ctx.paths.sshd_config
    cfg.write_text(cfg.read_text() + "Match User deploy\n  PasswordAuthentication yes\n")
    st = ssh.status(ctx)
    assert any("deploy" in m for m in st.match_overrides)
    res = ssh.set_password_auth(ctx, True)
    assert res["changed"] in (True, False)


def test_status_root_labels(host, ctx):
    st = ssh.status(ctx)
    assert st.root_login == "prohibit-password" and "public key only" in st.root_label
    assert st.root_password_login is False
    ctx.paths.sshd_config.write_text(ctx.paths.sshd_config.read_text() + "PermitRootLogin yes\n")
    st = ssh.status(ctx)
    assert st.root_password_login is True
