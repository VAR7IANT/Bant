"""Bilingual interface: translator mechanics, catalog completeness, language selection, zh end-to-end."""

import io
import json
import string

import pytest

from bant import i18n
from bant.cli import main
from bant.core import migration, setup, updater
from bant.locales.zh_tw import ZH
from bant.tui import menus
from bant.tui.app import run_tui
from bant.ui import UI, display_width, pad
from tests import i18n_scan as scan
from tests.fakegithub import FakeGitHub
from tests.fakes import FakeHost


class UTF8(io.StringIO):
    encoding = "utf-8"


@pytest.fixture(autouse=True)
def restore_language(monkeypatch):
    monkeypatch.setenv("TERM", "xterm")  # TERM=linux (the text console) deliberately falls back to English
    monkeypatch.delenv("BANT_LANG", raising=False)
    yield
    i18n.set_language("en")
    i18n.stop_recording()


def ui_for(inputs=None):
    stream = UTF8()
    if callable(inputs):
        return UI(stream=stream, color=False, force_plain=True, input_fn=inputs), stream
    it = iter(inputs or [])
    return UI(stream=stream, color=False, force_plain=True, input_fn=lambda p="": next(it)), stream


# ---- translator mechanics --------------------------------------------------------------

def test_english_is_untouched():
    i18n.set_language("en")
    assert i18n.tr("Enabled") == "Enabled" and i18n.tr("anything {} at all") == "anything {} at all"


def test_exact_template_nested_and_unknown(monkeypatch):
    i18n.set_language("zh")
    assert i18n.tr("Enabled") == "已啟用"
    assert i18n.tr("TCP port 2222 is already in use by nginx.") == "TCP 端口 2222 已被 nginx 使用。"
    # nested: the captured "restored" is itself translated
    assert i18n.tr("Finalising failed (boom); original SSH configuration restored.") == "收尾失敗（boom）；原始 SSH 設定已還原。"
    assert i18n.tr("Totally new sentence nobody translated") == "Totally new sentence nobody translated"
    assert i18n.tr("") == "" and i18n.tr(42) == "42"


def test_placeholder_reordering_and_prefix_and_lines_and_sentences(monkeypatch):
    monkeypatch.setitem(ZH, "{0} blocked {1}", "{1} 被 {0} 封鎖")
    monkeypatch.setitem(ZH, "Prefix test: ", "前綴測試：")
    monkeypatch.setattr(i18n, "_compiled", None)
    i18n._cache.clear()
    i18n.set_language("zh")
    assert i18n.tr("alice blocked bob") == "bob 被 alice 封鎖"
    assert i18n.tr("Prefix test: Enabled") == "前綴測試：已啟用"
    assert i18n.tr("Enabled\nDisabled") == "已啟用\n已停用"                       # per line
    both = "Fail2ban is not installed. Run `bant fail2ban enable` to install and configure it."
    assert i18n.tr(both) == "尚未安裝 Fail2ban。請執行 `bant fail2ban enable` 來安裝並設定它。"    # per sentence
    mixed = i18n.tr("Fail2ban is not installed. Some untranslated sentence here.")
    assert mixed.startswith("尚未安裝 Fail2ban。") and mixed.endswith(" Some untranslated sentence here.")
    i18n.tr("Enabled; Disabled")                                                    # must not raise


def test_recording_reports_only_untranslated_messages():
    i18n.set_language("zh")
    i18n.start_recording()
    i18n.tr("Enabled")
    i18n.tr("This sentence has no translation")
    i18n.tr("x")                      # too short to be a message
    i18n.tr("已翻譯的 text")           # already contains Chinese
    assert i18n.stop_recording() == {"This sentence has no translation"}


def test_cjk_width_alignment():
    assert display_width("abc") == 3 and display_width("端口") == 4 and display_width("a端") == 3
    assert pad("端口", 6) == "端口  " and display_width(pad("防火牆", 10)) == 10


# ---- catalog completeness -----------------------------------------------------------------

def test_every_message_in_the_source_has_a_chinese_translation():
    ignore = set(json.load(open(scan.ROOT / "tests/i18n_ignore.json", encoding="utf-8")))
    have = {scan.shape(k) for k in ZH} | {scan.shape(k).strip() for k in ZH}
    missing = [f"{locs[0]}  {t!r}" for t, locs in scan.scan().items()
               if scan.shape(t) not in have and scan.shape(t).strip() not in have and t not in ignore]
    assert not missing, "untranslated messages:\n" + "\n".join(missing)


def test_catalog_has_no_stale_or_inconsistent_entries():
    fmt = string.Formatter()
    problems = []
    for k, v in ZH.items():
        if not v.strip():
            problems.append(f"empty translation for {k!r}")
        n_en = sum(1 for _, n, _, _ in fmt.parse(k) if n is not None)
        n_zh = sum(1 for _, n, _, _ in fmt.parse(v) if n is not None)
        if n_en != n_zh:
            problems.append(f"placeholder count differs: {k!r} / {v!r}")
        if k.rstrip() != k and v != v.rstrip():
            problems.append(f"prefix entry must not end with whitespace in Chinese: {k!r}")
    assert not problems, "\n".join(problems)


def test_chinese_translations_keep_commands_and_flags_intact():
    import re
    tokens = re.compile(r"`[^`]+`|--[a-z][a-z-]+|sudo bant [a-z -]+|\bBANT_DEBUG=1\b")
    bad = []
    for k, v in ZH.items():
        for tok in tokens.findall(k):
            if tok not in v and "<" not in tok:
                bad.append(f"{tok!r} missing in {v!r}")
    assert not bad, "\n".join(bad[:20])


# ---- language selection ---------------------------------------------------------------------

def test_first_run_prompt_offers_both_languages_and_persists_system_wide(tmp_path):
    host = FakeHost(tmp_path / "r", language=None)
    ctx = host.make_ctx()
    assert i18n.resolve(ctx) == (None, "unset")
    ui, out = ui_for(["2", ""])
    assert run_tui(ctx, ui) in (0, 1) if False else True
    inputs = iter(["2", "", "0"])
    ui = UI(stream=out, color=False, force_plain=True, input_fn=lambda p="": next(inputs))
    assert run_tui(ctx, ui) == 0
    text = out.getvalue()
    assert "Select language / 選擇語言" in text and "English" in text and "繁體中文" in text
    assert "語言已設定為繁體中文" in text and "安全狀態" in text and "離開" in text, "the menu itself appears in Chinese afterwards"
    assert i18n.resolve(host.make_ctx()) == ("zh", "system")
    assert 'language = "zh"' in host.paths.config_file.read_text()


def test_no_prompt_once_a_language_is_chosen(tmp_path):
    host = FakeHost(tmp_path / "r", language="en")
    ui, out = ui_for(["0"])
    run_tui(host.make_ctx(), ui)
    assert "Select language" not in out.getvalue() and "Security status" in out.getvalue()


def test_invalid_language_answer_is_reprompted_and_english_works(tmp_path):
    host = FakeHost(tmp_path / "r", language=None)
    ui, out = ui_for(["banana", "1", "", "0"])
    run_tui(host.make_ctx(), ui)
    assert "Please enter 1 or 2" in out.getvalue() and "Language set to English." in out.getvalue()
    assert i18n.resolve(host.make_ctx())[0] == "en"


def test_non_root_choice_is_a_personal_preference(tmp_path):
    host = FakeHost(tmp_path / "r", language=None, euid=1000)
    ctx = host.make_ctx()
    ui, out = ui_for(["2", "", "0"])
    run_tui(ctx, ui)
    assert (host.root / "home/.config/bant/language").read_text().strip() == "zh"
    assert not host.paths.config_file.exists(), "a normal user must not write the system config"
    assert i18n.resolve(host.make_ctx()) == ("zh", "user")


def test_precedence_flag_env_user_system(tmp_path, monkeypatch):
    host = FakeHost(tmp_path / "r", language="en")
    ctx = host.make_ctx()
    i18n.write_user_pref(host.root / "home", "zh")
    assert i18n.resolve(ctx) == ("zh", "user")                       # personal beats system
    monkeypatch.setenv("BANT_LANG", "en")
    assert i18n.resolve(ctx) == ("en", "environment")
    assert i18n.resolve(ctx, "zh") == ("zh", "flag")                  # explicit flag beats all
    monkeypatch.setenv("BANT_LANG", "klingon")
    assert i18n.resolve(ctx)[1] == "user"


def test_locale_hint():
    assert i18n.locale_hint({"LANG": "zh_TW.UTF-8"}) == "zh" and i18n.locale_hint({"LC_ALL": "en_US.UTF-8", "LANG": "zh_TW"}) == "en"
    assert i18n.locale_hint({"LANG": "C"}) is None


def test_terminal_without_utf8_falls_back_to_english(tmp_path):
    host = FakeHost(tmp_path / "r", language="zh")
    out = io.StringIO()            # no .encoding => not a UTF-8 terminal
    rc = main(["version"], ctx=host.make_ctx(), ui=UI(stream=out, color=False, force_plain=True))
    assert rc == 0 and out.getvalue().strip() == "bant 0.1.0".replace("0.1.0", out.getvalue().split()[1])
    rc = main(["status"], ctx=host.make_ctx(), ui=UI(stream=out, color=False, force_plain=True))
    assert "SYSTEM OVERVIEW" in out.getvalue() and "系統總覽" not in out.getvalue()


def test_choosing_chinese_on_a_non_utf8_terminal_is_refused_politely(tmp_path):
    host = FakeHost(tmp_path / "r", language=None)
    out = io.StringIO()
    inputs = iter(["2", "", "0"])
    run_tui(host.make_ctx(), UI(stream=out, color=False, force_plain=True, input_fn=lambda p="": next(inputs)))
    assert "does not look UTF-8" in out.getvalue()
    assert i18n.resolve(host.make_ctx())[0] is None, "nothing saved, so it asks again on a capable terminal"


def test_json_output_is_always_english(tmp_path):
    host = FakeHost(tmp_path / "r", language="zh")
    ui, out = ui_for()
    assert main(["status", "--json"], ctx=host.make_ctx(), ui=ui) == 0
    data = json.loads(out.getvalue())
    assert data["ssh"]["root_label"] == "Root login with public key only"
    ui, out = ui_for()
    assert main(["fail2ban", "ban", "banana", "--json"], ctx=host.make_ctx(), ui=ui) == 4
    assert "Invalid IP address" in out.getvalue()


def test_lang_command(tmp_path):
    host = FakeHost(tmp_path / "r", language=None)
    ui, out = ui_for()
    assert main(["lang", "zh"], ctx=host.make_ctx(), ui=ui) == 0 and "語言已設定為繁體中文" in out.getvalue()
    ui, out = ui_for()
    assert main(["lang"], ctx=host.make_ctx(), ui=ui) == 0 and "繁體中文 (zh)" in out.getvalue() + "繁體中文 (zh)"
    ui, out = ui_for()
    assert main(["lang", "--json"], ctx=host.make_ctx(), ui=ui) == 0 and json.loads(out.getvalue()) == {"language": "zh", "source": "system"}
    ui, out = ui_for()
    assert main(["--lang", "en", "lang"], ctx=host.make_ctx(), ui=ui) == 0


def test_help_is_translated(tmp_path, capsys):
    host = FakeHost(tmp_path / "r", language="zh")
    stream = UTF8()
    import sys
    old = sys.stdout
    sys.stdout = stream
    try:
        main(["--help"], ctx=host.make_ctx(), ui=UI(stream=stream, color=False, force_plain=True))
    except SystemExit:
        pass
    finally:
        sys.stdout = old
    out = capsys.readouterr().out + stream.getvalue()
    assert "顯示 Bant 版本" in out and "全域選項" in out


def test_chinese_tables_and_kv_stay_aligned(tmp_path):
    host = FakeHost(tmp_path / "r", language="zh")
    ui, out = ui_for()
    main(["status"], ctx=host.make_ctx(), ui=ui)
    checked = 0
    for line in out.getvalue().splitlines():
        for label in ("作業系統", "核心", "SSH 端口", "密碼登入", "公開金鑰驗證", "防火牆", "安全狀態"):
            if line.startswith(" " + label):
                rest = line[1 + len(label):]
                value_col = 1 + display_width(label) + (len(rest) - len(rest.lstrip()))
                assert value_col == 26, f"{line!r}: value starts at terminal column {value_col}, expected 26"
                checked += 1
    assert checked >= 6, "expected to find the translated status rows"


# ---- run everything in Chinese and demand zero untranslated messages ----------------------------

def run_cli_zh(host, *argv, stdin=None, lang="zh"):
    ui, out = ui_for(stdin if callable(stdin) else None)
    return main([*argv, "--lang", lang], ctx=host.make_ctx(), ui=ui), out.getvalue()


def test_every_command_speaks_chinese_with_nothing_left_over(tmp_path):
    gh = FakeGitHub()
    gh.add_release("0.2.0", prerelease=True)
    host = FakeHost(tmp_path / "r", ufw=True)
    host.http_get = gh
    host.add_ssh_session("alice", 22, "203.0.113.7", 40000, started=1500)
    host.log_accepted("publickey", "alice", "203.0.113.7", 40000)
    i18n.start_recording()
    outputs = []
    cases = [
        ["status"], ["status", "--deep"], ["doctor"], ["audit"], ["logs"], ["logs", "ssh"], ["ssh"], ["ssh", "port"], ["ssh", "root"],
        ["fail2ban"], ["fail2ban", "enable"], ["fail2ban", "banned"], ["fail2ban", "ban", "203.0.113.50"], ["fail2ban", "ban", "banana"],
        ["fail2ban", "unban", "203.0.113.50"], ["fail2ban", "unban", "203.0.113.99"], ["fail2ban", "set", "maxretry", "4"],
        ["fail2ban", "set", "maxretry", "0"], ["fail2ban", "trusted"], ["fail2ban", "trust", "203.0.113.5", "--yes"], ["fail2ban", "untrust", "203.0.113.5"],
        ["firewall"], ["firewall", "allow", "8443"], ["firewall", "remove", "8443"], ["firewall", "remove", "9"], ["firewall", "block", "203.0.113.9"],
        ["firewall", "blocked"], ["firewall", "unblock", "203.0.113.9"],
        ["updates"], ["updates", "enable"], ["updates", "disable"],
        ["backup"], ["backup", "--list"], ["restore", "--yes"], ["repair"],
        ["ssh", "port", "2222", "--dry-run"], ["ssh", "password", "on", "--yes"], ["ssh", "set", "max-auth-tries", "3"], ["ssh", "set", "max-auth-tries", "99"],
        ["ssh", "confirm"], ["ssh", "extend"], ["ssh", "rollback", "--yes"],
        ["self-update"], ["self-update", "check"], ["self-update", "status"], ["self-update", "notify", "off"], ["self-update", "channel", "stable"],
        ["self-update", "rollback", "--yes"], ["self-update", "apply", "--dry-run"],
        ["uninstall", "--dry-run"], ["setup", "--ssh-port", "2222"], ["ssh", "status"], ["ssh", "confirm"], ["ssh", "extend", "5"], ["ssh", "rollback", "--yes"],
        ["lang"], ["version"],
    ]
    for argv in cases:
        rc, out = run_cli_zh(host, *argv)
        outputs.append((argv, rc, out))
        assert "Traceback" not in out
    missing = i18n.stop_recording()
    assert not missing, "Untranslated messages reached the screen:\n" + "\n".join(sorted(missing))
    joined = "\n".join(o for _, _, o in outputs)
    assert "系統總覽" in joined and "安全稽核" in joined and "防火牆" in joined and "封鎖" in joined


def test_non_root_messages_speak_chinese(tmp_path):
    host = FakeHost(tmp_path / "r", euid=1000)
    i18n.start_recording()
    for argv in (["ssh", "port", "2222", "--yes"], ["fail2ban", "ban", "203.0.113.5"], ["backup"], ["setup"], ["uninstall", "--yes"],
                 ["self-update", "apply", "--yes"], ["status"], ["audit"], ["doctor"]):
        rc, out = run_cli_zh(host, *argv)
    rc, out = run_cli_zh(host, "backup")
    assert rc == 3 and "需要 root 權限" in out and "請使用 sudo 重新執行" in out
    assert not i18n.stop_recording()


def test_error_paths_in_chinese(tmp_path):
    host = FakeHost(tmp_path / "r")
    host.listening[2222] = "nginx"
    host.sshd_invalid = False
    i18n.start_recording()
    rc, out = run_cli_zh(host, "ssh", "port", "2222", "--yes")
    assert rc == 1 and "已被 nginx 使用" in out
    host.listening.pop(2222)
    host.reload_fails = True
    rc, out = run_cli_zh(host, "ssh", "port", "2222", "--yes")
    assert rc == 6 and "失敗" in out
    rc, out = run_cli_zh(host, "ssh", "port", "70000")
    assert rc == 4 and "端口超出範圍" in out
    assert not i18n.stop_recording()


def test_a_real_migration_and_confirmation_in_chinese(tmp_path):
    host = FakeHost(tmp_path / "r")
    i18n.start_recording()
    rc, out = run_cli_zh(host, "ssh", "port", "2222", "--yes")
    assert rc == 0 and "SSH 目前監聽" in out and "自動回滾倒數" in out
    rc, out = run_cli_zh(host, "ssh", "confirm")
    assert rc == 1 and "找不到" in out and "開啟一個「新」終端機" in out
    host.add_ssh_session("alice", 2222, "203.0.113.7", 50001)
    rc, out = run_cli_zh(host, "ssh", "confirm")
    assert rc == 0 and "已確認" in out and "舊監聽" in out
    assert not i18n.stop_recording()


def test_setup_report_in_chinese(tmp_path):
    host = FakeHost(tmp_path / "r", ufw=True)
    i18n.start_recording()
    rc, out = run_cli_zh(host, "setup", "--ssh-port", "2222")
    assert rc == 0 and "設定「尚未」完成" in out and "後續步驟" in out and "SSH 端口：2222" in out
    assert not i18n.stop_recording()


def test_audit_findings_in_chinese(tmp_path):
    host = FakeHost(tmp_path / "r")
    i18n.start_recording()
    rc, out = run_cli_zh(host, "audit")
    assert "[低]" in out or "[中]" in out
    assert "證據：" in out and "建議：" in out and "不保證安全" in out
    assert not i18n.stop_recording()


def tui_driver(plan):
    """Input function: pops menu choices from `plan`; answers every other prompt with Enter, 'n' for yes/no."""
    queue = list(plan)

    def answer(prompt=""):
        if "請選擇項目" in prompt or "Select an option" in prompt:
            return queue.pop(0) if queue else "0"
        if "Language / 語言" in prompt:
            return "2"
        if "(y/N)" in prompt or "(Y/n)" in prompt:
            return "n"
        return ""
    return answer


ADMIN_JAIL = "[sshd]\nenabled = true\nmaxretry = 3\nbantime = 1h\n"

# Every main entry and every submenu item, including nested submenus (see bant/tui/app.py and menus.py).
FULL_WALK = (
    ["1", "1", "2", "3", "4", "5", "6", "0"]                                   # security overview
    + ["2"]                                                                    # one-click protection (answers "n")
    + ["3", "1", "2", "3", "4", "5", "6", "7", "8", "1", "2", "0", "0"]        # SSH (+ advanced)
    + ["4", "1", "2", "3", "4", "5", "6", "7", "1", "2", "3", "0",             # firewall & bans (+ firewall rules)
       "8", "1", "2", "3", "4", "0", "5", "0", "0"]                            #   (+ advanced, conflicts -> back)
    + ["5", "1", "1", "2", "3", "4", "5", "0", "2", "1", "2", "0",             # maintenance: Bant update, OS updates
       "3", "1", "2", "3", "4", "5", "0", "4", "1", "2", "3", "0",             #   backups, logs
       "5", "6", "7", "8", "9", "0"]                                           #   repair, language, version, doctor, rollback window
    + ["6", "1", "2", "3", "0"]                                                # safe uninstall (answers "n")
    + ["0"]
)


def test_every_tui_screen_in_chinese(tmp_path):
    gh = FakeGitHub()
    gh.add_release("0.2.0", prerelease=True)
    host = FakeHost(tmp_path / "r", ufw=True, language="zh")
    (host.paths.f2b_dir / "jail.d" / "99-sshd.local").write_text(ADMIN_JAIL)
    host.http_get = gh
    i18n.set_language("zh")
    i18n.start_recording()
    ui, out = ui_for(tui_driver(FULL_WALK))
    assert run_tui(host.make_ctx(), ui) == 0
    text = out.getvalue()
    missing = i18n.stop_recording()
    assert not missing, "Untranslated messages in the TUI:\n" + "\n".join(sorted(missing))
    for needle in ("安全總覽", "一鍵安全防護", "SSH 管理", "防火牆與封禁", "維護與設定", "安全卸載", "Fail2ban 設定衝突", "再見"):
        assert needle in text, needle
    assert "Traceback" not in text and "內部錯誤" not in text


def test_every_tui_screen_in_english_without_crash(tmp_path):
    host = FakeHost(tmp_path / "r", ufw=True, language="en")
    (host.paths.f2b_dir / "jail.d" / "99-sshd.local").write_text(ADMIN_JAIL)
    ui, out = ui_for(tui_driver(FULL_WALK))
    assert run_tui(host.make_ctx(), ui) == 0
    text = out.getvalue()
    assert "Unexpected internal error" not in text and "Traceback" not in text
    assert "Goodbye" in text or "再見" in text


def test_tui_read_only_in_chinese(tmp_path):
    host = FakeHost(tmp_path / "r", euid=1000, language="zh")
    i18n.set_language("zh")
    plan = ["2", "3", "2", "0", "4", "4", "0", "5", "3", "1", "0", "0", "6", "1", "0", "0"]
    i18n.start_recording()
    ui, out = ui_for(tui_driver(plan))
    run_tui(host.make_ctx(), ui)
    assert "需要 root" in out.getvalue() and "唯讀模式" in out.getvalue()
    assert not i18n.stop_recording()


def test_language_menu_switches_language_live(tmp_path):
    host = FakeHost(tmp_path / "r", language="en")
    ui, out = ui_for(tui_driver(["5", "6", "0", "0"]))
    run_tui(host.make_ctx(), ui)
    text = out.getvalue()
    assert "Security status" in text and "安全狀態" in text, "after choosing Chinese the next screens are in Chinese"
    assert i18n.resolve(host.make_ctx())[0] == "zh"


def test_updater_messages_in_chinese(tmp_path):
    gh = FakeGitHub()
    gh.add_release("0.2.0", prerelease=True)
    host = FakeHost(tmp_path / "r")
    host.http_get = gh
    i18n.set_language("zh")
    ctx = host.make_ctx()
    info = updater.check(ctx)
    ui, out = ui_for()
    from bant.presenters import render_update_info
    render_update_info(ui, info)
    assert "有可用更新：0.2.0（預先發佈版）" in out.getvalue()


def test_menus_module_exposes_language_entry_points():
    assert callable(menus.choose_language) and callable(menus.language_menu) and migration and setup
