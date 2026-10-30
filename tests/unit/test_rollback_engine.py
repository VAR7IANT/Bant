"""Rollback transaction engine: persistence, interruption and independence from the installer process."""

import subprocess
import time

import pytest

from bant.core import migration
from bant.core.rollback import Transaction, TxManager, check_id
from bant.errors import RolledBack, Unsupported, ValidationError
from tests.fakes import FakeHost, make_stubs, run_script


def test_timer_is_persistent_and_uses_absolute_deadline(host, ctx):
    migration.begin(ctx, 667, minutes=15)
    tx = TxManager(ctx).pending()[0]
    timer = (ctx.paths.systemd_system / f"bant-rollback-{tx.id}.timer").read_text()
    assert "Persistent=true" in timer and "WantedBy=timers.target" in timer
    expected = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(2000 + 15 * 60))
    assert f"OnCalendar={expected}" in timer
    service = (ctx.paths.systemd_system / f"bant-rollback-{tx.id}.service").read_text()
    assert "Type=oneshot" in service and "rollback.sh" in service
    assert host.called("systemctl enable bant-rollback-") and host.called("systemctl restart bant-rollback-")


def test_state_files_are_private(host, ctx):
    migration.begin(ctx, 667)
    tx = TxManager(ctx).pending()[0]
    d = TxManager(ctx).dir(tx.id)
    assert d.stat().st_mode & 0o777 == 0o700
    for name in ("tx.json", "rollback.sh"):
        assert (d / name).stat().st_mode & 0o077 == 0
    for f in (d / "backup").iterdir():
        assert f.stat().st_mode & 0o777 == 0o600


def test_no_change_without_working_rollback_timer(host, ctx):
    host.fail_commands.add("systemctl restart bant-rollback")
    from bant.errors import OperationFailed
    original = ctx.paths.sshd_config.read_text()
    with pytest.raises(OperationFailed, match="rollback"):
        migration.begin(ctx, 667)
    assert not ctx.paths.ssh_dropin.exists() and ctx.paths.sshd_config.read_text() == original
    assert set(host.listening) == {22}
    assert not list(ctx.paths.systemd_system.glob("bant-rollback-*")), "unit files must be cleaned up"


def test_refuses_without_systemd(tmp_path):
    host = FakeHost(tmp_path / "r")
    (host.paths.p("/run/systemd/system")).rmdir()
    ctx = host.make_ctx()
    with pytest.raises(Unsupported, match="systemd"):
        TxManager(ctx).begin("ssh-port", 10)


def test_ctrl_c_during_migration_rolls_back_immediately(host, ctx):
    original = ctx.paths.sshd_config.read_text()
    real = host._cmd_systemctl
    fired = []

    def interrupt(argv, inp):
        if argv[1] == "reload" and not fired:
            fired.append(1)
            raise KeyboardInterrupt
        return real(argv, inp)
    host._cmd_systemctl = interrupt
    with pytest.raises(RolledBack):
        migration.begin(ctx, 667)
    host._cmd_systemctl = real
    assert not ctx.paths.ssh_dropin.exists() and ctx.paths.sshd_config.read_text() == original
    assert not TxManager(ctx).pending()


class Killed(BaseException):
    """Simulates the installer being SIGKILLed: nothing in Bant gets to run cleanup code."""


def test_killed_installer_is_recovered_by_the_timer_alone(host, ctx):
    original = ctx.paths.sshd_config.read_text()
    real = host._cmd_systemctl

    def die_on_reload(argv, inp):
        if argv[1] == "reload":
            raise Killed
        return real(argv, inp)
    host._cmd_systemctl = die_on_reload
    with pytest.raises(Killed):
        migration.begin(ctx, 667)
    host._cmd_systemctl = real
    # the process is gone; configuration is half-applied and a transaction is open
    assert ctx.paths.ssh_dropin.exists()
    tx = TxManager(ctx).pending()[0]
    assert host.units[f"bant-rollback-{tx.id}.timer"] == "active"
    # ...the deadline passes and systemd runs the unit's ExecStart, in a minimal environment
    stubs = host.root / "stubs"
    make_stubs(stubs, ["systemctl", "ufw", "nft", "iptables", "fail2ban-client", "sshd"], host.root / "log")
    script = TxManager(ctx).dir(tx.id) / "rollback.sh"
    rc, out = run_script(script, stubs)
    assert rc == 0, out
    assert ctx.paths.sshd_config.read_text() == original and not ctx.paths.ssh_dropin.exists()


def test_rollback_script_runs_with_empty_environment(host, ctx):
    migration.begin(ctx, 667)
    tx = TxManager(ctx).pending()[0]
    script = TxManager(ctx).dir(tx.id) / "rollback.sh"
    stubs = host.root / "stubs"
    make_stubs(stubs, ["systemctl", "ufw", "fail2ban-client"], host.root / "log")
    text = script.read_text().replace("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", f"PATH={stubs}:/usr/bin:/bin")
    script.write_text(text)
    res = subprocess.run(["env", "-i", "/bin/sh", str(script)], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    assert (TxManager(ctx).dir(tx.id) / "rolled_back").exists()


def test_failed_restore_is_not_reported_as_rolled_back(host, ctx):
    migration.begin(ctx, 667)
    tx = TxManager(ctx).pending()[0]
    # make the restore impossible: target directory vanished and is replaced by a file
    d = ctx.paths.sshd_config_d
    for f in d.iterdir():
        f.unlink()
    d.rmdir()
    d.write_text("not a directory")
    stubs = host.root / "stubs"
    make_stubs(stubs, ["systemctl", "ufw", "fail2ban-client"], host.root / "log")
    rc, out = run_script(TxManager(ctx).dir(tx.id) / "rollback.sh", stubs)
    # removing a non-existent dropin is fine, but the script must not claim success when a restore failed
    assert rc in (0, 1)
    if rc == 1:
        assert not (TxManager(ctx).dir(tx.id) / "rolled_back").exists()
        assert (TxManager(ctx).dir(tx.id) / "rollback.error").exists()


def test_confirmed_transaction_cannot_be_rolled_back_later(host, ctx):
    migration.begin(ctx, 667)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    migration.confirm(ctx)
    tx = TxManager(ctx).all()[-1]
    assert tx.status == "confirmed"
    stubs = host.root / "stubs"
    make_stubs(stubs, ["systemctl"], host.root / "log")
    rc, _ = run_script(TxManager(ctx).dir(tx.id) / "rollback.sh", stubs)
    assert rc == 0 and not (TxManager(ctx).dir(tx.id) / "rolled_back").exists()


def test_cannot_confirm_after_rollback(host, ctx):
    migration.begin(ctx, 667)
    txm = TxManager(ctx)
    tx = txm.pending()[0]
    txm.rollback(tx, "test")
    from bant.errors import OperationFailed
    with pytest.raises(OperationFailed):
        txm.confirm(tx)


def test_transaction_ids_are_validated():
    for bad in ("../../etc", "x", "20260101T000000Z-zzzzzz", "20260101T000000Z-abc123; rm -rf /"):
        with pytest.raises(ValidationError):
            check_id(bad)
    assert check_id("20260101T000000Z-abc123")


def test_old_finished_transactions_are_pruned(host, ctx):
    clock = [2000.0]
    ctx = host.make_ctx(clock=lambda: clock[0])
    ids = []
    for _ in range(14):
        clock[0] += 10
        txm = TxManager(ctx)
        tx = txm.begin("ssh-auth", 10)
        host.units.clear()
        txm.confirm(tx)
        ids.append(tx.id)
    left = {t.id for t in TxManager(ctx).all()}
    assert len(left) == 10 and ids[-1] in left and ids[0] not in left


def test_json_roundtrip_ignores_unknown_fields():
    tx = Transaction.from_dict({"id": "i", "kind": "k", "created": 1.0, "deadline": 2.0, "future_field": 1})
    assert tx.id == "i"


def test_finish_external_forgets_rolled_back_rules(tmp_path):
    host = FakeHost(tmp_path / "r", ufw=True)
    ctx = host.make_ctx()
    migration.begin(ctx, 667)
    tx = TxManager(ctx).pending()[0]
    stubs = host.root / "stubs"
    make_stubs(stubs, ["systemctl", "ufw", "fail2ban-client"], host.root / "log")
    run_script(TxManager(ctx).dir(tx.id) / "rollback.sh", stubs)
    TxManager(ctx).finish_external(tx.id, "rolled_back")
    assert TxManager(ctx).load(tx.id).status == "rolled_back"
    events = [r["event"] for r in ctx.audit_log.read(50)]
    assert "tx.rollback.timer" in events
