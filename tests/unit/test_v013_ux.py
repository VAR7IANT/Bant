"""0.1.3 interaction redesign: in-place output, Enter = back, `bant ssh cf`, the BANT logo.

Each test names the requirement it guards. The SSH tests run the real migration code against the fake host;
"this session" is simulated by pointing the process-tree walk (netinfo.self_pid) at a fake sshd session.
"""

import io
import re
from pathlib import Path

import pytest

from bant import __version__, logo
from bant.cli import main
from bant.core import migration, netinfo
from bant.core.rollback import TxManager
from bant.errors import OperationFailed
from bant.tui.app import run_tui
from bant.ui import UI
from tests.fakes import FakeHost, make_stubs, run_script

ROOT = Path(__file__).resolve().parents[2]
NEW_SESSION_START = 2100.0  # migration.begin() runs at fake time 2000; sessions opened after it count as "new"


class TTY(io.StringIO):
    encoding = "utf-8"

    def isatty(self):
        return True


def scripted(answers, stream=None):
    """A UI fed with `answers`; prompts are echoed into the output like input() does. Runs out -> Ctrl+D."""
    out = stream or io.StringIO()
    it = iter(answers)
    prompts = []

    def answer(prompt=""):
        prompts.append(prompt)
        out.write(prompt + "\n")
        try:
            return next(it)
        except StopIteration:
            raise EOFError from None
    return UI(stream=out, color=False, force_plain=True, input_fn=answer), out, prompts


def flat(text):
    return " ".join(text.split())  # output is folded to the terminal width; compare word sequences


def cli(host, *argv, answers=None):
    ui, out, _ = scripted(answers or [])
    return main(list(argv), ctx=host.make_ctx(), ui=ui), flat(out.getvalue())


def in_session(monkeypatch, host, port, *, started=NEW_SESSION_START, remote="203.0.113.7", user="alice"):
    """Make the running command look like it was started from an SSH session on `port`."""
    pid = host.add_ssh_session(user, port, remote, 50000 + len(host.sessions), started=started)
    monkeypatch.setattr(netinfo, "self_pid", lambda: pid)
    return pid


# ---------------------------------------------------------------------------
# 1. No alternate screen, no clearing
# ---------------------------------------------------------------------------

ESCAPES = ("\033[?1049", "\033[?47", "\033[2J", "\033[3J", "\033c", "\033[H")


def test_menus_never_switch_screens_or_clear(host):
    ui, out, _ = scripted(["1", "1", "", "3", "1", "", "4", "3", "", "5", "6", "", "6", "", ""])
    ui.color = True  # colour on: escape codes would be allowed, screen switching still is not
    assert run_tui(host.make_ctx(), ui) == 0
    text = out.getvalue()
    assert not any(e in text for e in ESCAPES)
    assert not hasattr(ui, "clear") and not hasattr(ui, "pause"), "no screen clearing / 'press Enter' pauses"


def test_source_contains_no_screen_switching_or_clear_calls():
    offenders = []
    for path in (ROOT / "bant").rglob("*.py"):
        src = path.read_text(encoding="utf-8")
        for pat in (r"\\033\[\?1049", r"\\x1b\[\?1049", r"\\033\[2J", r"\\033c", r"os\.system\(.(clear|cls)", r"\.clear\(\)\s*$"):
            for m in re.finditer(pat, src, re.M):
                line = src[: m.start()].count("\n") + 1
                if "_cache.clear()" not in src.splitlines()[line - 1]:
                    offenders.append(f"{path.relative_to(ROOT)}:{line}")
    assert not offenders, offenders


def test_errors_stay_in_the_output_and_the_menu_comes_back(tmp_path):
    host = FakeHost(tmp_path / "r", euid=1000)          # read-only: every change is refused with an error
    ui, out, _ = scripted(["3", "2", "", ""])
    run_tui(host.make_ctx(), ui)
    text = out.getvalue()
    err = text.index("requires root")
    assert "SSH MANAGEMENT" in text[err:] and "Goodbye" in text[err:], "error printed, then the menu again, nothing wiped"


# ---------------------------------------------------------------------------
# 3. Enter = back everywhere, Enter on the main menu = exit
# ---------------------------------------------------------------------------

def test_main_menu_enter_exits(host):
    ui, out, prompts = scripted([""])
    assert run_tui(host.make_ctx(), ui) == 0
    assert "Goodbye" in out.getvalue() and prompts == ["Select an option (Enter to exit): "]


def test_enter_in_a_submenu_returns_to_the_main_menu_without_repeating(host, monkeypatch):
    from bant.tui import menus
    calls = []
    monkeypatch.setattr(menus, "ssh_view", lambda c, u: calls.append("view"))
    monkeypatch.setitem(menus.ssh_menu.__globals__, "ssh_view", lambda c, u: calls.append("view"))
    ui, out, prompts = scripted(["3", "1", "", ""])        # SSH -> View status -> Enter (back) -> Enter (exit)
    assert run_tui(host.make_ctx(), ui) == 0
    assert calls == ["view"], "going back must not run the previous action again"
    assert prompts == ["Select an option (Enter to exit): ", "Select an option (Enter to go back): ",
                       "Select an option (Enter to go back): ", "Select an option (Enter to exit): "]
    assert "MAIN MENU" in out.getvalue()


def test_deeper_menus_go_back_one_level(host):
    # 4 Firewall & bans -> 7 Firewall rules -> Enter (back to Firewall & bans) -> Enter (main) -> Enter (exit)
    ui, out, prompts = scripted(["4", "7", "", "", ""])
    assert run_tui(host.make_ctx(), ui) == 0
    text = out.getvalue()
    assert text.index("FIREWALL") < text.rindex("FIREWALL & BANS") < text.rindex("MAIN MENU") < text.index("Goodbye")
    assert prompts[-1] == "Select an option (Enter to exit): " and len(prompts) == 5


def test_invalid_choices_are_reported_and_asked_again(host):
    ui, out, prompts = scripted(["9", "abc", "3", "42", "", ""])
    assert run_tui(host.make_ctx(), ui) == 0
    text = out.getvalue()
    assert text.count("Unknown option") == 3 and "Goodbye" in text
    assert text.count(" 1. Security overview") == 2, "an invalid answer does not reprint the menu"


def test_zero_and_q_still_work_as_back(host):
    ui, out, _ = scripted(["3", "0", "q"])
    assert run_tui(host.make_ctx(), ui) == 0 and "Goodbye" in out.getvalue()


@pytest.mark.parametrize("exc", [KeyboardInterrupt, EOFError])
def test_ctrl_c_and_eof_inside_an_action_are_safe(host, exc):
    seq = iter(["3", "2"])

    def answer(prompt=""):
        try:
            return next(seq)
        except StopIteration:
            raise exc from None
    out = io.StringIO()
    assert run_tui(host.make_ctx(), UI(stream=out, color=False, force_plain=True, input_fn=answer)) == 0
    assert "Traceback" not in out.getvalue() and "Goodbye" in out.getvalue()
    assert not host.paths.ssh_dropin.exists()


def test_enter_in_a_value_prompt_cancels_instead_of_using_a_default(host):
    # SSH -> Change port -> Enter: previously Enter meant "random"; now it cancels and nothing changes
    ui, out, prompts = scripted(["3", "2", "", "", ""])
    run_tui(host.make_ctx(), ui)
    assert "Cancelled." in out.getvalue() and "(Enter to cancel)" in "".join(prompts)
    assert not host.paths.ssh_dropin.exists() and not TxManager(host.make_ctx()).pending()


@pytest.fixture
def no_uninstall(monkeypatch):
    from bant.core import uninstall
    calls = []
    monkeypatch.setattr(uninstall, "run", lambda *a, **k: calls.append(1) or pytest.fail("uninstall ran"))
    return calls


@pytest.mark.parametrize("walk,check", [
    (["7", "1", ""], lambda h: True),                                                       # uninstall: Enter != yes
    (["4", "2", ""], lambda h: h.f2b_running),                                              # disable Fail2ban
    (["3", "2", "2222", ""], lambda h: not h.paths.ssh_dropin.exists()),                    # start port migration
    (["4", "7", "3", "8080", ""], lambda h: True),                                          # remove firewall allowance
])
def test_enter_never_confirms_a_risky_action(host, walk, check, no_uninstall):
    from bant.core import fail2ban
    fail2ban.set_enabled(host.make_ctx(), True)
    ui, out, prompts = scripted(walk + ["", "", ""])
    run_tui(host.make_ctx(), ui)
    assert any("(y/N)" in p for p in prompts), "risky questions default to no"
    assert not any("(Y/n)" in p for p in prompts)
    assert check(host) and "Cancelled." in out.getvalue() and not no_uninstall


def test_purge_needs_the_typed_word(host, no_uninstall):
    ui, out, _ = scripted(["7", "2", "y", "", "", ""])
    run_tui(host.make_ctx(), ui)
    assert "Cancelled." in out.getvalue() and not no_uninstall


def test_enter_rule_is_the_same_in_every_language(tmp_path):
    for code, exit_prompt, back_prompt in (("zh-CN", "请选择操作（Enter 退出）", "请选择操作（Enter 返回）"),
                                           ("zh-TW", "請選擇操作（Enter 退出）", "請選擇操作（Enter 返回）"),
                                           ("en", "Select an option (Enter to exit)", "Select an option (Enter to go back)")):
        host = FakeHost(tmp_path / code, language=code)
        from bant import i18n
        i18n.set_language(code)
        ui, out, prompts = scripted(["3", "", ""], stream=TTY())
        ui.stream = out
        assert run_tui(host.make_ctx(), ui) == 0
        assert prompts[0].startswith(exit_prompt) and prompts[1].startswith(back_prompt) and prompts[2].startswith(exit_prompt)
        i18n.set_language("en")


# ---------------------------------------------------------------------------
# 7-13. `bant ssh cf`
# ---------------------------------------------------------------------------

def test_port_change_output_is_short_and_points_to_ssh_cf(host):
    rc, out = cli(host, "ssh", "port", "667", "--yes")
    assert rc == 0
    tail = out[out.index("New SSH port: 667"):]  # (already flattened)
    for needle in ("New port is listening", "Firewall:", "Old SSH port kept open for now: 22",
                   "Reconnect to the server through the new port:", "ssh -p 667", "sudo bant ssh cf", "rolled back automatically"):
        assert needle in tail, needle
    assert "Transaction" not in tail and "ssh confirm" not in tail, "no transaction id or long command to copy"


def test_ssh_cf_confirms_from_the_new_session(host, monkeypatch):
    assert cli(host, "ssh", "port", "667", "--yes")[0] == 0
    assert set(host.listening) == {22, 667}, "old port stays available until confirmed"
    in_session(monkeypatch, host, 667)
    rc, out = cli(host, "ssh", "cf")
    assert rc == 0 and "(this session)" in out and "only on TCP 667" in out
    assert set(host.listening) == {667}, "old listener removed after confirmation"
    assert "port = 667\n" in host.paths.f2b_jail.read_text(), "Fail2ban narrowed to the new port"
    assert not TxManager(host.make_ctx()).pending()
    assert host.make_ctx().config.ssh_port == 667


def test_ssh_cf_with_nothing_pending_refuses(host, monkeypatch):
    in_session(monkeypatch, host, 22)
    rc, out = cli(host, "ssh", "cf")
    assert rc == 1 and "No SSH change is waiting for confirmation" in out
    assert set(host.listening) == {22}


def test_ssh_cf_after_the_deadline_refuses(host, monkeypatch):
    migration.begin(host.make_ctx(), 667)
    in_session(monkeypatch, host, 667)
    late = host.make_ctx(clock=lambda: 2000.0 + 11 * 60)
    with pytest.raises(OperationFailed, match="expired") as e:
        migration.confirm(late, "current")
    assert "ssh rollback" in e.value.hint
    assert set(host.listening) == {22, 667} and TxManager(late).pending(), "nothing finalised"


def test_ssh_cf_refuses_conflicting_pending_changes(host, monkeypatch):
    ctx = host.make_ctx()
    migration.begin(ctx, 667)
    txm = TxManager(ctx)
    txm.begin("ssh-auth", 10, {"require": {"port": None, "method": "publickey"}})  # a second, conflicting change
    in_session(monkeypatch, host, 667)
    with pytest.raises(OperationFailed, match="pending at the same time") as e:
        migration.confirm(host.make_ctx(), "current")
    assert "repair" in e.value.hint and set(host.listening) == {22, 667}


def test_ssh_cf_from_the_old_session_is_refused(host, monkeypatch):
    migration.begin(host.make_ctx(), 667)
    host.add_ssh_session("bob", 667, "198.51.100.4", 41000, started=NEW_SESSION_START)  # someone else on the new port
    in_session(monkeypatch, host, 22)                                                  # but THIS terminal is on 22
    rc, out = cli(host, "ssh", "cf")
    assert rc == 1 and "not the new port 667" in out and "ssh -p 667" in out
    assert set(host.listening) == {22, 667}


def test_ssh_cf_from_a_session_older_than_the_change_is_refused(host, monkeypatch):
    migration.begin(host.make_ctx(), 667)
    in_session(monkeypatch, host, 667, started=1500.0)
    rc, out = cli(host, "ssh", "cf")
    assert rc == 1 and "opened before the change" in out and set(host.listening) == {22, 667}


def test_ssh_cf_from_the_server_itself_is_refused(host, monkeypatch):
    migration.begin(host.make_ctx(), 667)
    in_session(monkeypatch, host, 667, remote="127.0.0.1")
    rc, out = cli(host, "ssh", "cf")
    assert rc == 1 and "from the server itself" in out and set(host.listening) == {22, 667}


def test_ssh_cf_ignores_spoofed_environment(host, monkeypatch):
    migration.begin(host.make_ctx(), 667)
    monkeypatch.setenv("SSH_CONNECTION", "203.0.113.7 50000 10.0.0.5 667")
    monkeypatch.setattr(netinfo, "self_pid", lambda: 99999)   # not under any sshd session
    rc, out = cli(host, "ssh", "cf")
    assert rc == 1 and "cannot prove that the new connection works" in out and "--other-session" in out
    assert set(host.listening) == {22, 667}


def test_console_alternative_needs_a_real_new_session_and_explicit_consent(host, monkeypatch):
    migration.begin(host.make_ctx(), 667)
    monkeypatch.setattr(netinfo, "self_pid", lambda: 99999)   # provider console
    rc, out = cli(host, "ssh", "cf", "--other-session", "--yes")
    assert rc == 1 and "No authenticated SSH session" in out, "no new session anywhere -> still refused"
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001, started=NEW_SESSION_START)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    rc, out = cli(host, "ssh", "cf", "--other-session")
    assert rc == 2 and "--yes" in out, "non-interactive without --yes never bypasses"
    monkeypatch.setattr("sys.stdin", TTY())
    rc, out = cli(host, "ssh", "cf", "--other-session", answers=[""])
    assert rc == 1 and "Cancelled" in out and set(host.listening) == {22, 667}, "Enter is not consent"
    rc, out = cli(host, "ssh", "cf", "--other-session", answers=["y"])
    assert rc == 0 and "another session" in out and set(host.listening) == {667}


def test_menu_confirm_uses_the_same_rules(host, monkeypatch):
    migration.begin(host.make_ctx(), 667)
    in_session(monkeypatch, host, 22)
    ui, out, _ = scripted(["3", "6", "", ""])
    run_tui(host.make_ctx(), ui)
    assert "not the new port 667" in flat(out.getvalue()) and set(host.listening) == {22, 667}
    in_session(monkeypatch, host, 667)
    ui, out, _ = scripted(["3", "6", "", ""])
    run_tui(host.make_ctx(), ui)
    assert "(this session)" in flat(out.getvalue()) and set(host.listening) == {667}


def test_password_off_confirmation_via_ssh_cf_requires_a_key_session(host, monkeypatch):
    from bant.core import ssh
    host.add_ssh_session("alice", 22, "203.0.113.7", 40000, started=1500)
    host.log_accepted("publickey", "alice", "203.0.113.7", 40000)
    ssh.set_password_auth(host.make_ctx(), False)
    pid = in_session(monkeypatch, host, 22)
    host.log_accepted("password", "alice", "203.0.113.7", 50000 + len(host.sessions) - 1)
    rc, out = cli(host, "ssh", "cf")
    assert rc == 1 and "did not log in with an SSH key" in out
    pid = host.add_ssh_session("alice", 22, "203.0.113.9", 40002, started=NEW_SESSION_START + 10, pid=4242)
    host.log_accepted("publickey", "alice", "203.0.113.9", 40002)
    monkeypatch.setattr(netinfo, "self_pid", lambda: pid)
    rc, out = cli(host, "ssh", "cf")
    assert rc == 0 and "permanent" in out


def test_unconfirmed_port_change_is_rolled_back_by_the_timer(host, monkeypatch):
    ctx = host.make_ctx()
    original = ctx.paths.sshd_config.read_text()
    migration.begin(ctx, 667)
    tx = TxManager(ctx).pending()[0]
    assert host.units[f"bant-rollback-{tx.id}.timer"] == "active"
    timer = (ctx.paths.systemd_system / f"bant-rollback-{tx.id}.timer").read_text()
    assert "OnCalendar=1970-01-01 00:43:20 UTC" in timer and "Persistent=true" in timer   # 2000 s + 10 min
    stubs = host.root / "stubs"
    make_stubs(stubs, ["systemctl", "ufw", "nft", "iptables", "fail2ban-client", "sshd"], host.root / "log")
    rc, log = run_script(TxManager(ctx).dir(tx.id) / "rollback.sh", stubs)    # what systemd runs at the deadline
    assert rc == 0, log
    assert ctx.paths.sshd_config.read_text() == original and not ctx.paths.ssh_dropin.exists()
    in_session(monkeypatch, host, 667)
    rc, out = cli(host, "ssh", "cf")
    assert rc == 1 and "already rolled back" in out, "a rolled-back change can never be confirmed afterwards"


def test_legacy_confirm_command_still_works(host):
    migration.begin(host.make_ctx(), 667)
    host.add_ssh_session("alice", 667, "203.0.113.7", 50001, started=NEW_SESSION_START)
    rc, out = cli(host, "ssh", "confirm")
    assert rc == 0 and set(host.listening) == {667}


@pytest.mark.parametrize("arg", ["667", "random"])
def test_custom_and_random_ports(host, monkeypatch, arg):
    rc, out = cli(host, "ssh", "port", arg, "--yes")
    target = migration.describe_pending(host.make_ctx())["target"]
    assert rc == 0 and (target == 667 if arg == "667" else target not in (22, 667) and target >= 1024)
    in_session(monkeypatch, host, target)
    assert cli(host, "ssh", "cf")[0] == 0 and set(host.listening) == {target}


# ---------------------------------------------------------------------------
# 16. Logo
# ---------------------------------------------------------------------------

def test_logo_spells_bant_in_rout_style():
    assert len(logo.LOGO_LINES) == 6 and {len(line) for line in logo.LOGO_LINES} == {logo.LOGO_WIDTH} == {35}
    assert all(set(line) <= set("█╗╔═╝║╚ ") for line in logo.LOGO_LINES), "block letters with box-drawing shadow, like ROUT"
    art = logo.render(100, color=False, rich=False)
    lines = art.rstrip("\n").split("\n")
    assert "BANT" not in art.replace("Support by VAR7IANT", ""), "not plain text"
    assert lines[-2].strip() == "Support by VAR7IANT" and lines[-1].strip() == f"v{__version__}"
    for line in lines[-2:]:   # centred under the 35-column logo
        text = line.strip()
        left = len(line) - len(line.lstrip()) - 2
        assert abs((logo.LOGO_WIDTH - left - len(text)) - left) <= 1


def test_logo_colours_reset_and_degrade():
    rich = logo.render(100, color=True, rich=True)
    assert "\033[38;5;39m" in rich and "\033[38;5;26m" in rich
    basic = logo.render(100, color=True, rich=False)
    assert "38;5;" not in basic and "\033[34m" in basic
    for s in (rich, basic, logo.render(20, color=True, rich=True)):
        for line in s.rstrip("\n").split("\n"):
            assert "\033[" not in line or line.endswith("\033[0m") or "\033[0m " in line, repr(line)


@pytest.mark.parametrize("width", [20, 30, 38])
def test_narrow_terminal_gets_a_compact_title(width):
    out = logo.render(width, color=False, rich=False)
    assert "█" not in out and out.startswith("BANT") and out.count("\n") == 1 and len(out.rstrip("\n")) <= width


def test_short_or_non_utf8_terminal_gets_a_compact_title():
    assert "█" not in logo.render(100, color=False, rich=False, height=24)
    assert "█" not in logo.render(100, color=False, rich=False, unicode=False)
    assert "█" in logo.render(100, color=False, rich=False, height=40)


def test_logo_only_for_people_at_a_terminal(host, monkeypatch):
    ui, raw, _ = scripted([])
    assert main(["version"], ctx=host.make_ctx(), ui=ui) == 0
    assert raw.getvalue() == f"bant {__version__}\n", "pipes and scripts get exactly one line"
    rc, out = cli(host, "--json", "version")
    assert "█" not in out
    ui, out, _ = scripted([""])
    run_tui(host.make_ctx(), ui)
    assert "█" not in out.getvalue(), "captured/non-interactive output never gets the logo"


def test_logo_once_per_session_on_a_terminal(host, monkeypatch):
    monkeypatch.setattr("sys.stdin", TTY())
    stream = TTY()
    ui, out, _ = scripted(["r", "3", "", ""], stream=stream)
    ui.term_size = (100, 50)
    assert run_tui(host.make_ctx(), ui) == 0
    text = stream.getvalue()
    assert text.count(logo.LOGO_LINES[0]) == 1 and "Support by VAR7IANT" in text


def test_version_shows_the_logo_on_a_terminal(host, monkeypatch):
    monkeypatch.setattr("sys.stdin", TTY())
    stream = TTY()
    ui = UI(stream=stream, color=False, force_plain=True)
    ui.term_size = (100, 50)
    assert main(["version"], ctx=host.make_ctx(), ui=ui) == 0
    assert logo.LOGO_LINES[0] in stream.getvalue() and stream.getvalue().endswith(f"bant {__version__}\n")


def test_multi_line_messages_are_translated_line_by_line():
    from bant import i18n
    msg = "\n".join(["You are connected through TCP port 22, not the new port 667.",
                     "  1. Open a NEW terminal and connect: ssh -p 667 root@<server-ip>",
                     "  2. Run `sudo bant ssh cf` in that new session.",
                     "  If the new connection times out, a provider/cloud firewall may be blocking the port; "
                     "allow it there, or run `sudo bant ssh rollback`."])
    try:
        for code in ("zh-CN", "zh-TW"):
            i18n.set_language(code)
            out = i18n.tr(msg)
            assert out.count("\n") == 3 and not re.search(r"\b(connected|terminal|timeout|times out)\b", out), out
            assert "ssh -p 667 root@<server-ip>" in out and "`sudo bant ssh cf`" in out and "`sudo bant ssh rollback`" in out
    finally:
        i18n.set_language("en")
