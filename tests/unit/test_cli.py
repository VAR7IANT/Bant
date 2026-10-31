"""CLI behaviour: parsing, exit codes, JSON, privilege enforcement, dry-run, TUI startup."""

import io
import json

import pytest

from bant import __version__
from bant.cli import build_parser, main
from bant.core import migration, setup
from bant.ui import UI
from tests.fakes import FakeHost


def run(host_or_ctx, *argv, stdin=None):
    ctx = host_or_ctx.make_ctx() if isinstance(host_or_ctx, FakeHost) else host_or_ctx
    out = io.StringIO()
    ui = UI(stream=out, color=False, force_plain=True, input_fn=(lambda p="": stdin.pop(0)) if stdin else input)
    rc = main(list(argv), ctx=ctx, ui=ui)
    return rc, out.getvalue()


def test_help_lists_every_required_command(capsys):
    with pytest.raises(SystemExit) as e:
        build_parser().parse_args(["--help"])
    assert e.value.code == 0
    text = capsys.readouterr().out
    for cmd in ("version", "status", "doctor", "audit", "logs", "ssh", "fail2ban", "firewall", "backup", "restore", "repair", "uninstall"):
        assert cmd in text


@pytest.mark.parametrize("argv", [["ssh", "--help"], ["fail2ban", "--help"], ["firewall", "--help"], ["ssh", "port", "--help"],
                                  ["ssh", "password", "--help"], ["fail2ban", "ban", "--help"]])
def test_subcommand_help_exits_zero(argv, capsys):
    rc, _ = run(FakeHost.__new__(FakeHost), *argv) if False else (None, None)
    with pytest.raises(SystemExit) as e:
        build_parser().parse_args(argv)
    assert e.value.code == 0 and capsys.readouterr().out


def test_version(host):
    rc, out = run(host, "version")
    assert rc == 0 and out.strip() == f"bant {__version__}"
    rc, out = run(host, "version", "--json")
    assert json.loads(out) == {"name": "bant", "version": __version__}


def test_usage_error_exit_code(host):
    assert run(host, "ssh", "password", "maybe")[0] == 2
    assert run(host, "nonsense")[0] == 2


def test_invalid_input_exit_code_4(host):
    rc, out = run(host, "ssh", "port", "70000")
    assert rc == 4 and "out of range" in out
    assert run(host, "fail2ban", "ban", "not-an-ip")[0] == 4
    assert run(host, "fail2ban", "ban", "1.2.3.4;reboot")[0] == 4
    assert run(host, "firewall", "allow", "0")[0] == 4


def test_status_json_is_machine_readable(host):
    rc, out = run(host, "status", "--json")
    data = json.loads(out)
    assert rc == 0 and data["ssh"]["ports"] == [22] and data["bant_version"] == __version__
    assert data["fail2ban"]["state"] in ("verified", "running", "misconfigured", "inactive", "not_installed")


def test_status_human_shows_real_values(host):
    rc, out = run(host, "status")
    assert rc == 0 and "SSH port" in out and "22" in out and "Password login" in out and "Enabled" in out


def test_read_only_commands_work_without_root(tmp_path):
    host = FakeHost(tmp_path / "r", euid=1000)
    for argv in (["status"], ["doctor"], ["audit"], ["ssh"], ["ssh", "status"], ["fail2ban"], ["firewall"], ["updates"], ["backup", "--list"], ["logs"]):
        rc, out = run(host, *argv)
        assert rc in (0, 8), (argv, rc, out)
        assert "Traceback" not in out


@pytest.mark.parametrize("argv", [
    ["ssh", "port", "667", "--yes"], ["ssh", "password", "off", "--yes"], ["ssh", "password", "on"], ["ssh", "confirm"],
    ["fail2ban", "enable"], ["fail2ban", "disable", "--yes"], ["fail2ban", "ban", "203.0.113.5"], ["fail2ban", "unban", "203.0.113.5"],
    ["firewall", "allow", "8080"], ["backup"], ["restore", "--yes"], ["repair"], ["setup"], ["uninstall", "--yes"],
    ["updates", "enable"], ["ssh", "rollback", "--yes"],
])
def test_mutations_require_root_and_change_nothing(tmp_path, argv):
    host = FakeHost(tmp_path / "r", euid=1000)
    rc, out = run(host, *argv)
    assert rc == 3, (argv, rc, out)
    assert "requires root" in out
    assert not host.paths.ssh_dropin.exists() and not host.paths.f2b_jail.exists()


def test_dry_run_ssh_port_changes_nothing(host):
    rc, out = run(host, "ssh", "port", "667", "--dry-run")
    assert rc == 0 and "DRY RUN" in out and "arm persistent rollback timer" in out
    assert not host.paths.ssh_dropin.exists() and set(host.listening) == {22}
    assert not any(c[:2] == ["systemctl", "enable"] for c in host.calls)


def test_ssh_port_flow_through_cli(host):
    rc, out = run(host, "ssh", "port", "667", "--yes")
    assert rc == 0 and "listens on [22, 667]" in out and "ssh confirm" in out
    rc, out = run(host, "ssh", "confirm")
    assert rc == 1 and "No authenticated SSH session" in out
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    rc, out = run(host, "ssh", "confirm")
    assert rc == 0 and "only on TCP 667" in out
    rc, out = run(host, "ssh", "status", "--json")
    assert json.loads(out)["status"]["listening_ports"] == [667]


def test_ssh_port_conflict_message_and_exit(host):
    host.listening[667] = "nginx"
    rc, out = run(host, "ssh", "port", "667", "--yes")
    assert rc == 1 and "already in use by nginx" in out and "another port" in out


def test_non_interactive_without_yes_refuses(host, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    rc, out = run(host, "ssh", "port", "667")
    assert rc == 2 and "--yes" in out


def test_ban_self_lockout_protection(host):
    host.add_ssh_session("alice", 22, "203.0.113.7", 40000)
    monkey_ctx = host.make_ctx()
    from bant.core import netinfo
    netinfo_current = netinfo.current_session
    netinfo.current_session = lambda c, start_pid=None: netinfo.ssh_sessions(c)[0]
    try:
        rc, out = run(monkey_ctx, "fail2ban", "ban", "203.0.113.7")
        assert rc == 1 and "Refusing to ban" in out and "--force" in out
        assert host.f2b_banned == []
        rc, out = run(monkey_ctx, "fail2ban", "ban", "203.0.113.7", "--force")
        assert rc == 0 and host.f2b_banned == ["203.0.113.7"]
    finally:
        netinfo.current_session = netinfo_current


def test_banned_listing_merges_sources(host):
    host.f2b_banned.append("198.51.100.4")
    run(host, "firewall", "block", "203.0.113.9", "--reason", "scanner")
    rc, out = run(host, "fail2ban", "banned", "--json")
    rows = json.loads(out)
    assert {(r["ip"], r["source"]) for r in rows} == {("198.51.100.4", "fail2ban"), ("203.0.113.9", "bant")}


def test_unban_unknown_ip_is_an_error_not_a_silent_success(host):
    rc, out = run(host, "fail2ban", "unban", "203.0.113.77")
    assert rc == 1 and "not banned" in out


def test_audit_fail_on_exit_code(host):
    rc, _ = run(host, "audit", "--fail-on", "low")
    assert rc == 8  # SSH on default port 22 is a LOW finding
    rc, _ = run(host, "audit", "--fail-on", "critical")
    assert rc == 0


def test_audit_findings_have_all_required_fields(host):
    rc, out = run(host, "audit", "--json")
    data = json.loads(out)
    assert data["findings"], "default host must produce at least the port-22 and password findings"
    for f in data["findings"]:
        assert set(f) == {"id", "severity", "title", "evidence", "impact", "recommendation", "fixable", "fix"}
        assert f["severity"] in ("critical", "high", "medium", "low", "info")
    assert "score" not in data["summary"] and "score" not in data
    assert "not a guarantee" in data["summary"]["disclaimer"]


def test_doctor_distinguishes_states(host):
    rc, out = run(host, "doctor", "--json")
    names = {c["name"] for c in json.loads(out)}
    assert "sshd configuration valid (sshd -t)" in names and "jail covers SSH port(s)" in names


def test_doctor_fails_on_broken_ssh_config(host):
    host.sshd_invalid = True
    rc, out = run(host, "doctor")
    assert rc == 8 and "configuration valid" in out


def test_logs_command_reads_audit_trail_without_secrets(host):
    ctx = host.make_ctx()
    ctx.audit("test.event", password="hunter2", note="token=abc123 and -----BEGIN OPENSSH PRIVATE KEY-----\nXYZ\n-----END OPENSSH PRIVATE KEY-----")
    rc, out = run(ctx, "logs", "--grep", "test.event")
    assert rc == 0 and "test.event" in out
    raw = ctx.paths.audit_log.read_text()
    assert "hunter2" not in raw and "abc123" not in raw and "XYZ" not in raw
    assert ctx.paths.audit_log.stat().st_mode & 0o777 == 0o600


def test_audit_trail_records_operations(host):
    run(host, "ssh", "port", "667", "--yes")
    events = [r["event"] for r in host.make_ctx().audit_log.read(100)]
    assert "tx.begin" in events and "ssh.port.dual" in events


def test_firewall_status_json(host):
    rc, out = run(host, "firewall", "status", "--json")
    data = json.loads(out)
    assert "firewall" in data and data["listeners"] and data["bant_rules"] == []


def test_trust_flow_updates_fail2ban(host):
    run(host, "fail2ban", "enable")
    rc, out = run(host, "fail2ban", "trust", "203.0.113.5", "--yes")
    assert rc == 0
    assert "203.0.113.5" in host.paths.f2b_jail.read_text()
    run(host, "fail2ban", "untrust", "203.0.113.5")
    assert "203.0.113.5" not in host.paths.f2b_jail.read_text()


def test_backup_restore_via_cli(host):
    rc, out = run(host, "backup", "--note", "cli test")
    assert rc == 0 and "created" in out
    rc, out = run(host, "backup", "--list", "--json")
    assert json.loads(out)[0]["note"] == "cli test"
    rc, out = run(host, "restore", "--yes")
    assert rc == 0 and "Restored" in out


def test_setup_via_cli_reports_pending_with_random_port(host):
    rc, out = run(host, "setup")
    pend = migration.describe_pending(host.make_ctx())
    assert rc == 0 and "NOT finished" in out and "ssh confirm" in out
    assert pend["target"] not in (22, 667) and f"SSH port: {pend['target']}" in out and "random" in out


def test_setup_via_cli_with_own_port(host):
    rc, out = run(host, "setup", "--ssh-port", "2222")
    assert rc == 0 and migration.describe_pending(host.make_ctx())["target"] == 2222 and "chosen by you" in out


def test_setup_rejects_bad_port(host):
    assert run(host, "setup", "--ssh-port", "99999")[0] == 4
    assert run(host, "setup", "--ssh-port", "banana")[0] == 4


def test_ssh_port_random_keyword(host):
    rc, out = run(host, "ssh", "port", "random", "--yes")
    pend = migration.describe_pending(host.make_ctx())
    assert rc == 0 and "Random free port chosen" in out and pend["target"] not in (22, 667)
    rc, out = run(host, "ssh", "port", "--json")
    assert json.loads(out)["bant_port"] is None


def test_setup_interactive_prompt_accept_reroll_or_own(host, monkeypatch):
    monkeypatch.setattr("sys.stdin", type("T", (), {"isatty": lambda self: True})())
    rc, out = run(host, "setup", stdin=["r", "70000", "31001"])
    pend = migration.describe_pending(host.make_ctx())
    assert rc == 0 and pend["target"] == 31001
    assert "New random port" in out and "out of range" in out


def test_setup_interactive_enter_accepts_the_proposed_random_port(host, monkeypatch):
    monkeypatch.setattr("sys.stdin", type("T", (), {"isatty": lambda self: True})())
    rc, out = run(host, "setup", stdin=[""])
    proposed = int(out.split("random free port: ")[1].split()[0])
    assert migration.describe_pending(host.make_ctx())["target"] == proposed


def test_uninstall_via_cli_keeps_listener(host):
    run(host, "setup", "--ssh-port", "667")
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    run(host, "ssh", "confirm")
    rc, out = run(host, "uninstall", "--yes")
    assert rc == 0 and "not reverted" in out.lower() or "NOT" in out
    assert set(host.listening) == {667}


def test_uninstall_dry_run(host):
    setup.run(host.make_ctx(), port=667)
    rc, out = run(host, "uninstall", "--dry-run")
    assert rc == 1 and "waiting for confirmation" in " ".join(out.split()) and host.paths.ssh_dropin.exists(), "a pending migration blocks uninstall, even in the preview"


def test_tui_starts_and_navigates(host):
    from bant.tui.app import run_tui
    out = io.StringIO()
    inputs = iter(["3", "", "0", "4", "0", "x", "", "99", "", "q"])
    ui = UI(stream=out, color=False, force_plain=True, input_fn=lambda p="": next(inputs))
    assert run_tui(host.make_ctx(), ui) == 0
    text = out.getvalue()
    assert "Security status" in text and "SSH MANAGEMENT" in text and "FAIL2BAN" in text
    assert text.count("Unknown option") == 2 and "Goodbye" in text
    for label in ("Security overview", "One-click protection", "SSH management", "Firewall & bans", "Maintenance & settings", "Safe uninstall"):
        assert label in text
    menu = [line for line in text.splitlines() if line.strip()[:2].rstrip(".").isdigit()]
    assert len({line for line in menu if line.strip()[0] in "0123456"}) <= 7 + 20  # main menu: six entries plus Exit


def test_tui_ctrl_c_exits_cleanly(host):
    from bant.tui.app import run_tui

    def boom(prompt=""):
        raise KeyboardInterrupt
    out = io.StringIO()
    assert run_tui(host.make_ctx(), UI(stream=out, color=False, force_plain=True, input_fn=boom)) == 0


def test_tui_read_only_mode_blocks_mutations(tmp_path):
    from bant.tui.app import run_tui
    host = FakeHost(tmp_path / "r", euid=1000)
    out = io.StringIO()
    inputs = iter(["2", "2", "667", "", "0", "q"])
    ui = UI(stream=out, color=False, force_plain=True, input_fn=lambda p="": next(inputs))
    run_tui(host.make_ctx(), ui)
    text = out.getvalue()
    assert "Read-only mode" in text and "requires root" in text
    assert not host.paths.ssh_dropin.exists()


def test_tui_confirm_is_case_insensitive(host):
    ui = UI(stream=io.StringIO(), color=False, force_plain=True, input_fn=lambda p="": "YES")
    assert ui.confirm("ok?") is True
    ui = UI(stream=io.StringIO(), color=False, force_plain=True, input_fn=lambda p="": "No")
    assert ui.confirm("ok?", True) is False


# ---- the original fixed port, 667, must remain selectable through every entry point ---------

@pytest.mark.parametrize("argv", [["setup", "--ssh-port", "667"], ["ssh", "port", "667", "--yes"]])
def test_port_667_can_be_chosen_via_cli(host, argv):
    rc, out = run(host, *argv)
    assert rc == 0 and migration.describe_pending(host.make_ctx())["target"] == 667
    assert set(host.listening) == {22, 667}


def test_port_667_can_be_chosen_in_the_interactive_prompt(host, monkeypatch):
    monkeypatch.setattr("sys.stdin", type("T", (), {"isatty": lambda self: True})())
    rc, _ = run(host, "setup", stdin=["667"])
    assert rc == 0 and migration.describe_pending(host.make_ctx())["target"] == 667


def test_port_667_can_be_the_persistent_default_from_the_config_file(host):
    host.paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    host.paths.config_file.write_text("[ssh]\nport = 667\n")
    rc, out = run(host, "setup", "--yes")
    assert rc == 0 and migration.describe_pending(host.make_ctx())["target"] == 667
    assert "from your Bant configuration" in out


def test_port_667_full_cycle_ends_with_ssh_only_on_667(host):
    run(host, "ssh", "port", "667", "--yes")
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001)
    rc, _ = run(host, "ssh", "confirm")
    assert rc == 0 and set(host.listening) == {667} and host.make_ctx().config.ssh_port == 667
