"""Regressions from real-VPS reports against 0.1.1, and the 0.1.2 uninstall / setup guarantees.

* AS3 VPS: `sudo bant setup` -> ValueError: empty range for randrange() (ephemeral range covered every candidate)
* AS3 VPS: `sudo bant uninstall` -> AttributeError: 'Namespace' object has no attribute 'dry_run'
"""

import io
import json
import random
import shutil
import subprocess

import pytest

from bant.cli import build_parser, main, normalize_args
from bant.core import fail2ban, migration, ports, setup, sshconf, uninstall
from bant.core.rollback import TxManager
from bant.errors import OperationFailed, RolledBack
from bant.ui import UI
from tests.fakes import FakeHost


def run(host, *argv, stdin=None):
    out = io.StringIO()
    feed = list(stdin or [])
    ui = UI(stream=out, color=False, force_plain=True, input_fn=lambda p="": feed.pop(0) if feed else "")
    rc = main(list(argv), ctx=host.make_ctx(), ui=ui)
    return rc, out.getvalue()


def set_range(host, text):
    d = host.paths.proc / "sys/net/ipv4"
    d.mkdir(parents=True, exist_ok=True)
    (d / "ip_local_port_range").write_text(text)


# ---------------------------------------------------------------------------
# Bug 1: random SSH port
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("os_id,ver", [("ubuntu", "22.04"), ("ubuntu", "24.04"), ("debian", "12"), ("debian", "13")])
def test_normal_range_on_every_supported_release(tmp_path, os_id, ver):
    host = FakeHost(tmp_path / "r", os_id=os_id, os_version=ver)
    set_range(host, "32768\t60999\n")
    ctx = host.make_ctx()
    pool, strategy = ports.candidates(ctx)
    assert strategy == "preferred" and pool
    p = ports.pick_random(ctx)
    assert p >= ports.RANDOM_MIN and not 32768 <= p <= 60999


@pytest.mark.parametrize("text", ["1024\t65535\n", "1024 65000\n", "10000 65535\n", "5000 65535\n"])
def test_range_covering_every_preferred_port_uses_a_verified_fallback(host, text):
    """The AS3 crash: no window left outside the ephemeral range -> must not call randrange(0)."""
    set_range(host, text)
    host.listening.update({p: "x" for p in range(20000, 20100)})
    # a connected (not listening) socket uses 30001 as its local port
    with open(host.paths.proc / "net" / "tcp", "a") as fh:
        fh.write(f"   9: 0500000A:{30001:04X} 0100007F:01BB 01 00000000:00000000 00:00000000 00000000     0        0 77 1 0 0 0 0\n")
    ctx = host.make_ctx()
    pool, strategy = ports.candidates(ctx)
    assert pool and strategy in ("ephemeral", "preferred")
    for seed in range(100):
        p = ports.pick_random(host.make_ctx(rng=random.Random(seed)))
        assert ports.RANDOM_MIN <= p <= 65535 and p not in host.listening and p not in ports.AVOID and p != 30001


def test_reserved_ports_are_preferred_when_the_range_is_full(host):
    set_range(host, "1024 65535\n")
    (host.paths.proc / "sys/net/ipv4/ip_local_reserved_ports").write_text("40000-40009,50123\n")
    pool, strategy = ports.candidates(host.make_ctx())
    assert strategy == "preferred" and set(pool) == set(range(40000, 40010)) | {50123}


@pytest.mark.parametrize("text", ["", "garbage\n", "70000 80000\n", "60000 1024\n", "0 0\n", "-5 10\n", "32768\n"])
def test_illegal_range_falls_back_to_the_linux_default(host, text):
    set_range(host, text)
    ctx = host.make_ctx()
    assert ports.ephemeral_range(ctx) == ports.DEFAULT_EPHEMERAL
    p = ports.pick_random(ctx)
    assert not 32768 <= p <= 60999


def test_no_free_port_is_a_clear_error_not_a_crash(host, monkeypatch):
    set_range(host, "1024 65535\n")
    monkeypatch.setattr(ports.netinfo, "local_ports_in_use", lambda ctx: set(range(1, 65536)))
    with pytest.raises(ports.NoFreePort) as e:
        ports.pick_random(host.make_ctx())
    assert "667" in (e.value.hint or "")


def test_setup_continues_when_no_random_port_exists(host, monkeypatch):
    """Fail2ban, backup and firewall steps still run; the migration step reports why and how to continue."""
    set_range(host, "1024 65535\n")
    monkeypatch.setattr(ports.netinfo, "local_ports_in_use", lambda ctx: set(range(1, 65536)))
    rep = setup.run(host.make_ctx())
    steps = {s["step"]: s for s in rep["steps"]}
    assert steps["fail2ban"]["status"] == "done" and steps["backup"]["status"] == "done"
    assert steps["ssh-migration"]["status"] == "failed" and "No free port" in steps["ssh-migration"]["detail"]
    assert rep["outcome"] == "incomplete" and any("ssh port 667" in n for n in rep["next_steps"])
    assert set(host.listening) == {22}, "SSH untouched"
    rep2 = setup.run(host.make_ctx(), port=667)  # the user picks a port and simply runs setup again
    assert rep2["outcome"] == "pending_confirmation" and 667 in host.listening


def test_cli_setup_without_random_port_shows_no_traceback(host, monkeypatch):
    set_range(host, "1024 65535\n")
    monkeypatch.setattr(ports.netinfo, "local_ports_in_use", lambda ctx: set(range(1, 65536)))
    rc, out = run(host, "setup", "--yes")
    assert "Traceback" not in out and "ValueError" not in out and "Unexpected" not in out
    assert "No free port" in out and rc == 1


def test_interactive_setup_asks_for_a_port_when_none_is_free(host, monkeypatch):
    set_range(host, "1024 65535\n")
    monkeypatch.setattr(ports.netinfo, "local_ports_in_use", lambda ctx: set(range(1, 65536)))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    rc, out = run(host, "setup", stdin=["abc", "667"])
    assert "Traceback" not in out and migration.describe_pending(host.make_ctx())["target"] == 667


def test_port_667_busy_is_a_blocker_and_free_667_works(host):
    host.listening[667] = "nginx"
    rep = setup.run(host.make_ctx(), port=667)
    mig = next(s for s in rep["steps"] if s["step"] == "ssh-migration")
    assert mig["status"] == "failed" and "nginx" in mig["detail"] and rep["outcome"] == "incomplete"
    assert set(host.listening) == {22, 667}, "nothing forced"
    del host.listening[667]
    assert setup.run(host.make_ctx(), port=667)["outcome"] == "pending_confirmation"


def test_invalid_ssh_port_is_rejected_before_anything_changes(host):
    rc, out = run(host, "setup", "--ssh-port", "99999", "--yes")
    assert rc != 0 and not host.paths.f2b_jail.exists() and not host.paths.ssh_dropin.exists()


def test_repeated_setup_is_idempotent(host):
    ctx = host.make_ctx()
    setup.run(ctx, port=667)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    migration.confirm(ctx)
    jail, dropin, rules = host.paths.f2b_jail.read_text(), host.paths.ssh_dropin.read_text(), list(host.ufw_rules)
    n_backups = len(list(host.paths.backup_dir.iterdir()))
    rep = setup.run(host.make_ctx())
    assert rep["outcome"] == "complete" and rep["ssh_port"] == 667
    assert host.paths.f2b_jail.read_text() == jail and host.paths.ssh_dropin.read_text() == dropin and host.ufw_rules == rules
    assert len(list(host.paths.backup_dir.iterdir())) == n_backups
    assert not TxManager(host.make_ctx()).pending()


# ---------------------------------------------------------------------------
# Bug 2: argparse SUPPRESS defaults
# ---------------------------------------------------------------------------

def _all_command_paths():
    parser = build_parser()
    out = []

    def walk(p, prefix):
        for action in p._actions:
            if action.__class__.__name__ == "_SubParsersAction":
                for name, sp in action.choices.items():
                    if name.startswith("_"):
                        continue
                    out.append(prefix + [name])
                    walk(sp, prefix + [name])
    walk(parser, [])
    return out


def test_every_command_namespace_has_all_global_options():
    parser = build_parser()
    for path in _all_command_paths():
        try:
            ns = parser.parse_args(path)
        except SystemExit:
            continue  # needs positional arguments
        normalize_args(ns)
        for name in ("json", "dry_run", "yes", "no_color", "lang"):
            assert hasattr(ns, name), (path, name)


@pytest.mark.parametrize("argv", [
    ["uninstall"], ["uninstall", "--dry-run"], ["uninstall", "--purge"], ["uninstall", "--yes"], ["uninstall", "--json"],
    ["--json", "uninstall", "--dry-run"], ["uninstall", "--dry-run", "--json"], ["--yes", "uninstall"], ["uninstall", "--purge", "--yes"],
])
def test_uninstall_argument_combinations_never_crash(tmp_path, argv):
    host = FakeHost(tmp_path / "r")
    rc, out = run(host, *argv)
    assert "AttributeError" not in out and "Unexpected" not in out and "Traceback" not in out, out
    if "--json" in argv:
        json.loads(out)
    if "--dry-run" in argv:
        assert rc == 0 and host.paths.sshd_config.exists()


def test_uninstall_without_yes_and_without_terminal_asks_for_yes(host):
    rc, out = run(host, "uninstall")
    assert rc == 2 and "--yes" in out


@pytest.mark.parametrize("argv", [
    ["status"], ["doctor"], ["audit"], ["ssh"], ["ssh", "status"], ["fail2ban"], ["firewall"], ["updates"], ["backup", "--list"],
    ["logs"], ["version"], ["lang"], ["self-update", "status"], ["repair", "--dry-run"], ["setup", "--dry-run"],
    ["ssh", "port", "667", "--dry-run"], ["ssh", "password", "off", "--dry-run"], ["fail2ban", "conflicts"],
    ["fail2ban", "ban", "203.0.113.9", "--dry-run"], ["firewall", "allow", "8080", "--dry-run"], ["restore", "--list"],
])
@pytest.mark.parametrize("flags", [[], ["--json"]])
def test_commands_without_optional_flags_do_not_crash(tmp_path, argv, flags):
    host = FakeHost(tmp_path / "r")
    rc, out = run(host, *(flags + argv))
    assert "AttributeError" not in out and "Unexpected" not in out and "Traceback" not in out, (argv, out)
    if flags:
        json.loads(out)


def test_dry_run_changes_nothing_on_disk(host):
    before = sorted(str(p) for p in host.root.rglob("*") if "/proc" not in str(p))
    for argv in (["setup", "--dry-run"], ["uninstall", "--dry-run"], ["ssh", "port", "2222", "--dry-run"]):
        run(host, *argv)
    after = sorted(str(p) for p in host.root.rglob("*") if "/proc" not in str(p) and "/var/log/bant" not in str(p))
    assert [p for p in after if p not in before] == []


def test_unexpected_errors_are_logged_not_shown(host, monkeypatch):
    from bant.core import status
    monkeypatch.setattr(status, "collect", lambda *a, **k: 1 / 0)
    host.paths.log_dir.mkdir(parents=True, exist_ok=True)
    rc, out = run(host, "status")
    assert rc == 1 and "Traceback" not in out and "ZeroDivisionError" in out
    assert "Traceback" in (host.paths.log_dir / "debug.log").read_text()


# ---------------------------------------------------------------------------
# Safe uninstall
# ---------------------------------------------------------------------------

def _program(host):
    host.paths.install_dir.mkdir(parents=True, exist_ok=True)
    (host.paths.install_dir / "lib").mkdir(exist_ok=True)
    host.paths.launcher.write_text("#!/bin/sh\n")
    for u in uninstall.BANT_UNITS:
        (host.paths.systemd_system / u).write_text("[Unit]\n")


def _confirmed(host, port=667, **kw):
    ctx = host.make_ctx()
    setup.run(ctx, port=port, **kw)
    host.add_ssh_session("alice", port, "203.0.113.7", 50001)
    migration.confirm(ctx)
    _program(host)
    return host.make_ctx()


def _assert_gone(host):
    assert not host.paths.install_dir.exists() and not host.paths.launcher.exists()
    assert not any((host.paths.systemd_system / u).exists() for u in uninstall.BANT_UNITS)


def test_standard_uninstall_keeps_ssh_fail2ban_firewall_and_backups(tmp_path):
    host = FakeHost(tmp_path / "r", ufw=True)
    ctx = _confirmed(host)
    res = uninstall.run(ctx)
    _assert_gone(host)
    assert set(host.listening) == {667} and sshconf.effective(ctx).ports == [667]
    assert "667/tcp" in host.ufw_rules
    assert fail2ban.parse_ports(fail2ban.effective_jail(ctx)["port"]) == [667] and host.f2b_running
    assert host.paths.backup_dir.exists() and host.paths.config_file.exists()
    assert res["final"]["ssh_valid"] is True and "running" in res["final"]["fail2ban"]
    assert not host.called("systemctl stop fail2ban") and not host.called("systemctl disable --now fail2ban")
    assert not host.called("apt-get remove") and not host.called("apt-get purge")
    assert not host.called("nft flush") and not host.called("iptables -F")


def test_purge_deletes_bant_data_but_not_protection(tmp_path):
    host = FakeHost(tmp_path / "r", ufw=True)
    ctx = _confirmed(host)
    uninstall.run(ctx, purge=True)
    _assert_gone(host)
    assert not host.paths.state_dir.exists() and not host.paths.etc_bant.exists() and not host.paths.log_dir.exists()
    assert set(host.listening) == {667} and "667/tcp" in host.ufw_rules and host.paths.f2b_retained_jail.exists()


def test_uninstall_after_program_only_install(host):
    _program(host)  # install.sh --no-setup: no SSH/Fail2ban changes by Bant
    res = uninstall.run(host.make_ctx())
    _assert_gone(host)
    assert set(host.listening) == {22} and not host.paths.ssh_retained_dropin.exists()
    assert any("backup" in d for d in res["done"])


def test_uninstall_after_failed_setup_rolled_back(host):
    ctx = host.make_ctx()
    setup.run(ctx, port=667)
    tx = TxManager(ctx).pending()[-1]
    TxManager(ctx).rollback(tx, "test")  # the timer fired: the migration was undone
    _program(host)
    uninstall.run(host.make_ctx())
    _assert_gone(host)
    assert set(host.listening) == {22}


def test_uninstall_after_partial_setup_without_fail2ban(tmp_path):
    host = FakeHost(tmp_path / "r", fail2ban=False)
    ctx = _confirmed(host, with_fail2ban=False)
    res = uninstall.run(ctx)
    _assert_gone(host)
    assert set(host.listening) == {667} and res["final"]["fail2ban"] == "not installed"


def test_uninstall_with_socket_activation_keeps_listener(tmp_path):
    host = FakeHost(tmp_path / "r", socket_mode=True, os_id="ubuntu", os_version="24.04")
    ctx = _confirmed(host)
    uninstall.run(ctx)
    assert 667 in host.listening and host.paths.socket_retained_dropin("ssh.socket").exists()


def test_uninstall_refuses_pending_migration_and_changes_nothing(host):
    setup.run(host.make_ctx(), port=667)
    _program(host)
    dropin = host.paths.ssh_dropin.read_text()
    with pytest.raises(OperationFailed, match="ssh cf"):
        uninstall.run(host.make_ctx())
    assert host.paths.ssh_dropin.read_text() == dropin and host.paths.launcher.exists()
    assert TxManager(host.make_ctx()).pending(), "the pending migration is neither completed nor destroyed"


def test_uninstall_refuses_when_backup_cannot_be_created(host, monkeypatch):
    ctx = _confirmed(host)
    from bant.core import backups

    def boom(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(backups, "create", boom)
    with pytest.raises(OperationFailed, match="Nothing was changed"):
        uninstall.run(ctx)
    assert host.paths.ssh_dropin.exists() and host.paths.launcher.exists()


def test_uninstall_refuses_when_ssh_cannot_be_verified(host):
    ctx = _confirmed(host)
    host.listening.clear()
    with pytest.raises(OperationFailed, match="listening"):
        uninstall.run(ctx)
    assert host.paths.ssh_dropin.exists() and host.paths.launcher.exists()


def test_uninstall_restores_files_when_fail2ban_rejects_the_change(host):
    ctx = _confirmed(host)
    jail = host.paths.f2b_jail.read_text()
    host.fail_commands.add("fail2ban-client -t")
    with pytest.raises(RolledBack, match="restored"):
        uninstall.run(ctx)
    assert host.paths.f2b_jail.read_text() == jail and not host.paths.f2b_retained_jail.exists()
    assert host.paths.ssh_dropin.exists() and not host.paths.ssh_retained_dropin.exists()
    assert host.paths.launcher.exists() and host.paths.backup_dir.exists(), "rollback data kept"


def test_uninstall_restores_files_when_ssh_stops_listening(host, monkeypatch):
    ctx = _confirmed(host)
    real = host._cmd_systemctl

    def systemctl(argv, inp):
        if argv[1] == "reload" and argv[2].startswith("ssh"):
            host.listening.pop(667, None)
            return real(["systemctl", "show", "x"], inp)
        return real(argv, inp)
    monkeypatch.setattr(host, "_cmd_systemctl", systemctl)
    with pytest.raises(RolledBack):
        uninstall.run(ctx)
    assert host.paths.ssh_dropin.exists() and host.paths.launcher.exists()


def test_interrupted_uninstall_can_be_repeated(host, monkeypatch):
    ctx = _confirmed(host)

    def interrupted(c, s):
        raise KeyboardInterrupt  # Ctrl+C / SIGTERM after the files were renamed
    monkeypatch.setattr(uninstall, "_reload_ssh", interrupted)
    with pytest.raises(KeyboardInterrupt):
        uninstall.run(ctx)
    monkeypatch.undo()
    assert host.paths.launcher.exists(), "the program is removed last, so it is still there to retry with"
    uninstall.run(host.make_ctx())
    _assert_gone(host)
    assert set(host.listening) == {667} and sshconf.effective(host.make_ctx()).ports == [667]
    assert host.paths.ssh_retained_dropin.exists() and not host.paths.ssh_dropin.exists()


def test_repeated_uninstall_is_harmless(host):
    ctx = _confirmed(host)
    uninstall.run(ctx)
    res = uninstall.run(host.make_ctx())  # e.g. run again from a checkout with `python3 -m bant uninstall`
    assert set(host.listening) == {667} and res["final"]["ssh_valid"]
    assert host.paths.ssh_retained_dropin.exists() and host.paths.f2b_retained_jail.exists()


def test_preview_lists_everything_and_changes_nothing(tmp_path):
    host = FakeHost(tmp_path / "r", ufw=True)
    ctx = _confirmed(host)
    ctx.dry_run = True
    out = uninstall.run(ctx, purge=True)
    actions = {i["item"]: i["action"] for i in out["plan"]}
    assert any("unchanged" in a for k, a in actions.items() if "SSH port" in k)
    assert any("keep (still needed)" in a for a in actions.values())
    assert host.paths.ssh_dropin.exists() and host.paths.launcher.exists() and host.paths.state_dir.exists()


def test_cli_uninstall_reports_kept_ssh_port(host):
    _confirmed(host)
    rc, out = run(host, "uninstall", "--yes")
    assert rc == 0, out
    assert "not reverted" in out and "667" in out
    _assert_gone(host)


def test_native_firewall_allowances_survive_reboot_after_uninstall(host):
    rules = [{"backend": "nftables", "port": 667, "proto": "tcp", "chain": {"family": "inet", "table": "filter", "chain": "input"}},
             {"backend": "iptables", "port": 667, "proto": "tcp", "binary": "ip6tables"},
             {"backend": "nftables", "port": 1, "proto": "tcp", "chain": {"family": "inet", "table": "x; rm -rf /", "chain": "input"}}]
    script = uninstall._retained_fw_script(rules)
    assert "nft_allow inet filter input tcp 667" in script and "ipt_allow ip6tables tcp 667" in script
    assert "rm -rf" not in script, "chain names are validated before they reach the shell"
    path = host.root / "s.sh"
    path.write_text(script)
    assert subprocess.run(["sh", "-n", str(path)]).returncode == 0
    if shutil.which("shellcheck"):
        assert subprocess.run(["shellcheck", "-s", "sh", str(path)], capture_output=True).returncode == 0


# ---------------------------------------------------------------------------
# Fail2ban: administrator jail overlapping with Bant's (VMISS9929: 5 doctor warnings)
# ---------------------------------------------------------------------------

ADMIN_99 = """[sshd]
enabled = true
port = 667
backend = systemd
banaction = nftables
maxretry = 5
findtime = 10m
bantime = 1h
"""


def _vmiss(host, body=ADMIN_99):
    _confirmed(host)
    (host.paths.f2b_dir / "jail.d" / "99-sshd.local").write_text(body)
    fail2ban.apply_policy(host.make_ctx())
    return host.make_ctx()


def test_identical_admin_values_are_duplicates_not_warnings(host):
    from bant.core import f2b_conflicts, status
    ctx = _vmiss(host)
    items = f2b_conflicts.analyze(ctx)
    assert {i["key"] for i in items} >= {"enabled", "port", "backend", "maxretry", "findtime", "bantime"}
    assert all(i["status"] in ("duplicate", "admin-only") for i in items), items
    assert fail2ban.overview(ctx).conflicts == []
    doc = status.doctor(host.make_ctx())
    assert "differs" not in repr(doc) and "override" not in repr(doc), doc


def test_different_admin_value_is_a_conflict_with_source_and_precedence(host):
    from bant.core import f2b_conflicts
    ctx = _vmiss(host, ADMIN_99.replace("maxretry = 5", "maxretry = 3"))
    items = {i["key"]: i for i in f2b_conflicts.analyze(ctx)}
    m = items["maxretry"]
    assert m["status"] == "conflict" and m["value"] == "3" and m["bant"] == "5" and m["effective"] == "3"
    assert m["file"] == "99-sshd.local" and m["winner"] == "99-sshd.local" and "read last" in m["precedence"]
    assert any("maxretry" in c for c in fail2ban.overview(ctx).conflicts)


def test_keep_records_the_choice_without_touching_files(host):
    from bant.core import f2b_conflicts
    ctx = _vmiss(host, ADMIN_99.replace("maxretry = 5", "maxretry = 3"))
    admin = (host.paths.f2b_dir / "jail.d" / "99-sshd.local").read_text()
    f2b_conflicts.resolve(ctx, "keep")
    assert (host.paths.f2b_dir / "jail.d" / "99-sshd.local").read_text() == admin
    assert fail2ban.overview(host.make_ctx()).conflicts == []
    # if the administrator changes the file again, the warning comes back
    (host.paths.f2b_dir / "jail.d" / "99-sshd.local").write_text(ADMIN_99.replace("maxretry = 5", "maxretry = 2"))
    assert fail2ban.overview(host.make_ctx()).conflicts


def test_adopt_preview_changes_nothing(host):
    from bant.core import f2b_conflicts
    ctx = _vmiss(host, ADMIN_99.replace("maxretry = 5", "maxretry = 3"))
    before = (host.paths.f2b_dir / "jail.d" / "99-sshd.local").read_text(), host.paths.f2b_jail.read_text()
    ctx.dry_run = True
    res = f2b_conflicts.resolve(ctx, "adopt")
    assert res["dry_run"] and any(p["key"] == "maxretry" and p["after"] == "3" for p in res["plan"])
    assert ((host.paths.f2b_dir / "jail.d" / "99-sshd.local").read_text(), host.paths.f2b_jail.read_text()) == before


def test_adopt_moves_settings_to_bant_and_keeps_protection_identical(host):
    from bant.core import f2b_conflicts
    other = "[nginx-http-auth]\nenabled = true\nmaxretry = 9\n"
    ctx = _vmiss(host, ADMIN_99.replace("maxretry = 5", "maxretry = 3") + "\n" + other)
    eff_before = fail2ban.effective_jail(ctx)
    res = f2b_conflicts.resolve(ctx, "adopt")
    assert res["changed"]
    admin = (host.paths.f2b_dir / "jail.d" / "99-sshd.local").read_text()
    assert "# maxretry = 3" in admin and "[sshd]" in admin, "commented out, never deleted"
    assert other.strip() in admin, "other jails are untouched"
    eff = fail2ban.effective_jail(host.make_ctx())
    assert eff["maxretry"] == "3" and fail2ban.parse_ports(eff["port"]) == [667] and eff["banaction"] == eff_before["banaction"]
    assert "maxretry = 3" in host.paths.f2b_jail.read_text()
    assert f2b_conflicts.analyze(host.make_ctx()) == [] and fail2ban.overview(host.make_ctx()).conflicts == []
    assert set(host.listening) == {667} and host.f2b_running
    assert any(b.name for b in host.paths.backup_dir.iterdir()), "backup taken first"


def test_adopt_rolls_back_when_fail2ban_rejects_it(host):
    from bant.core import f2b_conflicts
    ctx = _vmiss(host, ADMIN_99.replace("maxretry = 5", "maxretry = 3"))
    admin = (host.paths.f2b_dir / "jail.d" / "99-sshd.local").read_text()
    jail = host.paths.f2b_jail.read_text()
    host.fail_commands.add("fail2ban-client -t")
    with pytest.raises(RolledBack, match="restored"):
        f2b_conflicts.resolve(ctx, "adopt")
    assert (host.paths.f2b_dir / "jail.d" / "99-sshd.local").read_text() == admin and host.paths.f2b_jail.read_text() == jail
    assert host.make_ctx().config.maxretry == 5


def test_conflicts_cli(host):
    _vmiss(host, ADMIN_99.replace("bantime = 1h", "bantime = 2h"))
    rc, out = run(host, "fail2ban", "conflicts")
    assert rc == 0 and "bantime" in out and "99-sshd.local" in out
    rc, out = run(host, "--json", "fail2ban", "conflicts")
    assert json.loads(out)["summary"]["unresolved"] == 1
    rc, out = run(host, "fail2ban", "conflicts", "--resolve", "adopt", "--yes")
    assert rc == 0, out
    assert "bantime = 2h" in host.paths.f2b_jail.read_text()


# ---------------------------------------------------------------------------
# Setup: failures, interruption, resume
# ---------------------------------------------------------------------------

def test_failed_dependency_install_is_reported_and_other_steps_run(tmp_path):
    host = FakeHost(tmp_path / "r", fail2ban=False)
    host.fail_commands.add("env DEBIAN_FRONTEND=noninteractive apt-get install")
    rep = setup.run(host.make_ctx(), port=667)
    steps = {s["step"]: s for s in rep["steps"]}
    assert steps["fail2ban"]["status"] == "failed" and "Installing Fail2ban failed" in steps["fail2ban"]["detail"]
    assert steps["backup"]["status"] == "done" and steps["ssh-migration"]["status"] == "pending"
    assert rep["summary"]["failed"][0]["step"] == "fail2ban"
    assert any("fail2ban enable" in n for n in rep["next_steps"])


def test_setup_report_lists_completed_failed_remaining_and_rollback(host):
    host.listening[667] = "nginx"
    rep = setup.run(host.make_ctx(), port=667)
    s = rep["summary"]
    assert "backup" in s["completed"] and "fail2ban" in s["completed"]
    assert s["failed"] and s["failed"][0]["step"] == "ssh-migration" and "nginx" in s["failed"][0]["reason"]
    assert s["rolled_back"] is False
    rc, out = run(host, "setup", "--ssh-port", "667", "--yes")
    assert "SETUP REPORT" in out and "Completed" in out and "Run `sudo bant setup` again" in out


def test_interrupted_setup_resumes(host, monkeypatch):
    real = fail2ban.apply_policy

    def interrupted(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(fail2ban, "apply_policy", interrupted)
    with pytest.raises(KeyboardInterrupt):
        setup.run(host.make_ctx(), port=667)
    monkeypatch.setattr(fail2ban, "apply_policy", real)
    assert setup.initialized(host.make_ctx()) == "never"
    rep = setup.run(host.make_ctx(), port=667)
    assert rep["outcome"] == "pending_confirmation"
    assert next(s for s in rep["steps"] if s["step"] == "backup")["status"] == "already", "original backup not overwritten"


def test_setup_state_for_the_installer(host):
    assert run(host, "_setup-state")[1].strip() == "never"
    setup.run(host.make_ctx(), port=667)
    assert run(host, "_setup-state")[1].strip() == "pending_confirmation"
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    migration.confirm(host.make_ctx())
    setup.run(host.make_ctx())
    assert run(host, "_setup-state")[1].strip() == "complete"


def test_rerun_never_reenables_password_login_or_changes_port(host):
    ctx = host.make_ctx()
    setup.run(ctx, port=667)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    host.log_accepted("publickey", "alice", "203.0.113.7", 50001)
    migration.confirm(ctx)
    from bant.core import ssh
    ssh.set_password_auth(host.make_ctx(), False)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50002)
    host.log_accepted("publickey", "alice", "203.0.113.7", 50002)
    migration.confirm(host.make_ctx())
    rep = setup.run(host.make_ctx())
    assert rep["ssh_port"] == 667 and sshconf.effective(host.make_ctx()).one("passwordauthentication") == "no"


def test_setup_dry_run_previews_without_writing(host):
    rc, out = run(host, "setup", "--dry-run", "--ssh-port", "667")
    assert rc in (0, 1) and "DRY RUN" in out and "667" in out
    assert not host.paths.state_dir.exists() and not host.paths.etc_bant.exists()


def test_main_menu_uninstall_entry_uses_the_same_core(host):
    from bant.tui.app import run_tui
    _confirmed(host)
    answers = iter(["7", "1", "y"])  # main 7 = Safe uninstall, 1 = standard, y = explicit consent
    out = io.StringIO()
    ui = UI(stream=out, color=False, force_plain=True, input_fn=lambda p="": next(answers, "0"))
    assert run_tui(host.make_ctx(), ui) == 0
    text = out.getvalue()
    assert "Bant has been removed" in text and "Unexpected" not in text
    _assert_gone(host)
    assert set(host.listening) == {667}


def test_tui_survives_garbage_input_everywhere(host):
    from bant.tui.app import run_tui
    junk = iter(["", "abc", "-1", "999", "3", "x", "", "8", "zz", "", "0", "0", "4", "8", "4", "q", "0", "0", "\x1b[A", "", "0"])
    out = io.StringIO()
    ui = UI(stream=out, color=False, force_plain=True, input_fn=lambda p="": next(junk, "0"))
    assert run_tui(host.make_ctx(), ui) == 0
    assert "Traceback" not in out.getvalue() and "Unexpected internal error" not in out.getvalue()


def test_narrow_terminal_layout(host, monkeypatch):
    from bant.tui import dashboard
    out = io.StringIO()
    ui = UI(stream=out, color=False, force_plain=True)
    monkeypatch.setattr("bant.ui._term_width", lambda: 40)
    dashboard.draw(host.make_ctx(), ui)
    lines = out.getvalue().splitlines()
    assert ui.narrow and max(len(x) for x in lines) <= 40, lines
    assert "+---" not in out.getvalue(), "no box drawing on narrow screens"
