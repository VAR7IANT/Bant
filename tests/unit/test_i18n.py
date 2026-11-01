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
        def echoed(p=""):
            stream.write(p + "\n")
            return inputs(p)
        return UI(stream=stream, color=False, force_plain=True, input_fn=echoed), stream
    it = iter(inputs or [])

    def answer(p=""):
        stream.write(p + "\n")  # like input(): the prompt is part of what the user sees
        return next(it)
    return UI(stream=stream, color=False, force_plain=True, input_fn=answer), stream


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
    monkeypatch.setattr(i18n, "_compiled", {})
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

@pytest.mark.parametrize("code", ["zh-CN", "zh-TW"])
def test_every_message_in_the_source_has_a_chinese_translation(code):
    ignore = set(json.load(open(scan.ROOT / "tests/i18n_ignore.json", encoding="utf-8")))
    cat = i18n.catalog(code)
    have = {scan.shape(k) for k in cat} | {scan.shape(k).strip() for k in cat}
    missing = [f"{locs[0]}  {t!r}" for t, locs in scan.scan().items()
               if scan.shape(t) not in have and scan.shape(t).strip() not in have and t not in ignore]
    assert not missing, "untranslated messages:\n" + "\n".join(missing)


def test_both_chinese_catalogs_have_the_same_keys():
    assert set(i18n.catalog("zh-CN")) == set(i18n.catalog("zh-TW"))


@pytest.mark.parametrize("code", ["zh-CN", "zh-TW"])
def test_catalog_has_no_stale_or_inconsistent_entries(code):
    fmt = string.Formatter()
    problems = []
    for k, v in i18n.catalog(code).items():
        if not v.strip():
            problems.append(f"empty translation for {k!r}")
        n_en = sum(1 for _, n, _, _ in fmt.parse(k) if n is not None)
        n_zh = sum(1 for _, n, _, _ in fmt.parse(v) if n is not None)
        if n_en != n_zh:
            problems.append(f"placeholder count differs: {k!r} / {v!r}")
        if k.rstrip() != k and v != v.rstrip():
            problems.append(f"prefix entry must not end with whitespace in Chinese: {k!r}")
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("code", ["zh-CN", "zh-TW"])
def test_chinese_translations_keep_commands_and_flags_intact(code):
    import re
    tokens = re.compile(r"`[^`]+`|--[a-z][a-z-]+|sudo bant [a-z -]+|\bBANT_DEBUG=1\b")
    bad = []
    for k, v in i18n.catalog(code).items():
        for tok in tokens.findall(k):
            if tok not in v and "<" not in tok:
                bad.append(f"{tok!r} missing in {v!r}")
    assert not bad, "\n".join(bad[:20])


# ---- language selection ---------------------------------------------------------------------

def test_first_run_prompt_offers_three_languages_and_persists_system_wide(tmp_path):
    host = FakeHost(tmp_path / "r", language=None)
    ctx = host.make_ctx()
    assert i18n.resolve(ctx) == (None, "unset")
    ui, out = ui_for(["1", ""])          # 1 = 简体中文, then Enter on the main menu = exit
    assert run_tui(ctx, ui) == 0
    text = out.getvalue()
    assert "简体中文" in text and "繁體中文" in text and "English" in text
    assert "界面语言已设置为简体中文" in text and "安全状态" in text and "请选择操作（Enter 退出）" in text
    assert i18n.resolve(host.make_ctx()) == ("zh-CN", "system")
    assert 'language = "zh-CN"' in host.paths.config_file.read_text()


@pytest.mark.parametrize("answer,code,marker", [("2", "zh-TW", "請選擇操作（Enter 退出）"), ("3", "en", "Select an option (Enter to exit)"),
                                                ("zh-tw", "zh-TW", "安全狀態"), ("en", "en", "Security status")])
def test_first_run_other_languages(tmp_path, answer, code, marker):
    host = FakeHost(tmp_path / "r", language=None)
    ui, out = ui_for([answer, ""])
    assert run_tui(host.make_ctx(), ui) == 0
    assert marker in out.getvalue() and i18n.resolve(host.make_ctx())[0] == code


def test_first_run_enter_uses_the_system_locale(tmp_path, monkeypatch):
    monkeypatch.setenv("LANG", "zh_CN.UTF-8")
    for var in ("LC_ALL", "LC_MESSAGES", "LANGUAGE"):
        monkeypatch.delenv(var, raising=False)
    host = FakeHost(tmp_path / "r", language=None)
    ui, out = ui_for(["", ""])
    run_tui(host.make_ctx(), ui)
    assert i18n.resolve(host.make_ctx())[0] == "zh-CN" and "界面语言已设置为简体中文" in out.getvalue()


def test_no_prompt_once_a_language_is_chosen(tmp_path):
    host = FakeHost(tmp_path / "r", language="en")
    ui, out = ui_for([""])
    run_tui(host.make_ctx(), ui)
    assert "Select language" not in out.getvalue() and "Security status" in out.getvalue()


def test_invalid_language_answer_is_reprompted_and_english_works(tmp_path):
    host = FakeHost(tmp_path / "r", language=None)
    ui, out = ui_for(["banana", "3", ""])
    run_tui(host.make_ctx(), ui)
    assert "Unknown option 'banana'" in out.getvalue() and "Language set to English." in out.getvalue()
    assert i18n.resolve(host.make_ctx())[0] == "en"


def test_non_root_choice_is_a_personal_preference(tmp_path):
    host = FakeHost(tmp_path / "r", language=None, euid=1000)
    ctx = host.make_ctx()
    ui, out = ui_for(["2", ""])
    run_tui(ctx, ui)
    assert (host.root / "home/.config/bant/language").read_text().strip() == "zh-TW"
    assert not host.paths.config_file.exists(), "a normal user must not write the system config"
    assert i18n.resolve(host.make_ctx()) == ("zh-TW", "user")


def test_legacy_zh_setting_still_means_traditional_chinese(tmp_path):
    host = FakeHost(tmp_path / "r", language="zh")       # written by Bant <= 0.1.2
    ctx = host.make_ctx()
    assert i18n.resolve(ctx) == ("zh-TW", "system") and not ctx.config.problems
    ui, out = ui_for()
    assert main(["status"], ctx=ctx, ui=ui) == 0 and "系統總覽" in out.getvalue()
    i18n.write_user_pref(host.root / "home", "zh")
    assert i18n.resolve(host.make_ctx()) == ("zh-TW", "user")
    ui, out = ui_for()
    assert main(["--lang", "zh", "version"], ctx=host.make_ctx(), ui=ui) == 0


def test_precedence_flag_env_user_system(tmp_path, monkeypatch):
    host = FakeHost(tmp_path / "r", language="en")
    ctx = host.make_ctx()
    i18n.write_user_pref(host.root / "home", "zh-CN")
    assert i18n.resolve(ctx) == ("zh-CN", "user")                    # personal beats system
    monkeypatch.setenv("BANT_LANG", "en")
    assert i18n.resolve(ctx) == ("en", "environment")
    assert i18n.resolve(ctx, "zh-TW") == ("zh-TW", "flag")            # explicit flag beats all
    monkeypatch.setenv("BANT_LANG", "klingon")
    assert i18n.resolve(ctx)[1] == "user"


def test_locale_hint():
    hint = i18n.locale_hint
    assert hint({"LANG": "zh_TW.UTF-8"}) == "zh-TW" and hint({"LANG": "zh_HK.UTF-8"}) == "zh-TW"
    assert hint({"LANG": "zh_CN.UTF-8"}) == "zh-CN" and hint({"LANG": "zh_SG"}) == "zh-CN" and hint({"LANGUAGE": "zh_Hant"}) == "zh-TW"
    assert hint({"LC_ALL": "en_US.UTF-8", "LANG": "zh_TW"}) == "en"
    assert hint({"LANG": "C"}) is None and hint({"LANG": "fr_FR.UTF-8"}) is None


def test_normalize_language_codes():
    n = i18n.normalize
    assert n("zh-CN") == n("zh_cn") == n("zh-Hans") == n("ZH_CN.UTF-8") == "zh-CN"
    assert n("zh-TW") == n("zh_tw") == n("zh-Hant") == n("zh") == "zh-TW"
    assert n("en") == n("English") == "en" and n("klingon") is None and n("") is None and n(None) is None


def test_terminal_without_utf8_falls_back_to_english(tmp_path):
    host = FakeHost(tmp_path / "r", language="zh-CN")
    out = io.StringIO()            # no .encoding => not a UTF-8 terminal
    rc = main(["version"], ctx=host.make_ctx(), ui=UI(stream=out, color=False, force_plain=True))
    assert rc == 0 and out.getvalue().strip() == "bant 0.1.0".replace("0.1.0", out.getvalue().split()[1])
    rc = main(["status"], ctx=host.make_ctx(), ui=UI(stream=out, color=False, force_plain=True))
    assert "SYSTEM OVERVIEW" in out.getvalue() and "系统总览" not in out.getvalue()


def test_choosing_chinese_on_a_non_utf8_terminal_is_refused_politely(tmp_path):
    host = FakeHost(tmp_path / "r", language=None)
    out = io.StringIO()
    inputs = iter(["1", ""])
    run_tui(host.make_ctx(), UI(stream=out, color=False, force_plain=True, input_fn=lambda p="": next(inputs)))
    assert "does not look UTF-8" in out.getvalue()
    assert i18n.resolve(host.make_ctx())[0] is None, "nothing saved, so it asks again on a capable terminal"


def test_json_output_is_always_english(tmp_path):
    host = FakeHost(tmp_path / "r", language="zh-CN")
    ui, out = ui_for()
    assert main(["status", "--json"], ctx=host.make_ctx(), ui=ui) == 0
    data = json.loads(out.getvalue())
    assert data["ssh"]["root_label"] == "Root login with public key only"
    ui, out = ui_for()
    assert main(["fail2ban", "ban", "banana", "--json"], ctx=host.make_ctx(), ui=ui) == 4
    assert "Invalid IP address" in out.getvalue()


@pytest.mark.parametrize("code,done", [("zh-CN", "界面语言已设置为简体中文。"), ("zh-TW", "介面語言已設定為繁體中文。"), ("en", "Language set to English.")])
def test_lang_command_switches_and_persists(tmp_path, code, done):
    host = FakeHost(tmp_path / "r", language=None)
    ui, out = ui_for()
    assert main(["lang", code.lower().replace("-", "_")], ctx=host.make_ctx(), ui=ui) == 0 and done in out.getvalue()
    assert i18n.language() == code, "applies immediately, no restart"
    assert i18n.resolve(host.make_ctx()) == (code, "system"), "persisted for the next run"
    ui, out = ui_for()
    assert main(["lang", "--json"], ctx=host.make_ctx(), ui=ui) == 0
    assert json.loads(out.getvalue()) == {"language": code, "source": "system", "available": ["zh-CN", "zh-TW", "en"]}


def test_lang_command_rejects_unknown_codes_and_lists_without_tty(tmp_path):
    host = FakeHost(tmp_path / "r", language="zh-TW")
    ui, out = ui_for()
    assert main(["lang", "klingon"], ctx=host.make_ctx(), ui=ui) == 2
    ui, out = ui_for()
    assert main(["lang"], ctx=host.make_ctx(), ui=ui) == 0 and "繁體中文 (zh-TW)" in out.getvalue()
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

CLI_LANG = {"code": "zh-TW"}


@pytest.fixture(params=["zh-TW", "zh-CN"])
def zh(request):
    """Run a Chinese end-to-end test once per Chinese language."""
    CLI_LANG["code"] = request.param
    yield request.param
    CLI_LANG["code"] = "zh-TW"


def run_cli_zh(host, *argv, stdin=None, lang=None):
    ui, out = ui_for(stdin if callable(stdin) else None)
    return main([*argv, "--lang", lang or CLI_LANG["code"]], ctx=host.make_ctx(), ui=ui), out.getvalue()


def test_every_command_speaks_chinese_with_nothing_left_over(tmp_path, zh):
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
        ["ssh", "confirm"], ["ssh", "cf"], ["ssh", "cf", "--other-session", "--yes"], ["ssh", "extend"], ["ssh", "rollback", "--yes"],
        ["self-update"], ["self-update", "check"], ["self-update", "status"], ["self-update", "notify", "off"], ["self-update", "channel", "stable"],
        ["self-update", "rollback", "--yes"], ["self-update", "apply", "--dry-run"],
        ["uninstall", "--dry-run"], ["setup", "--ssh-port", "2222"], ["ssh", "status"], ["ssh", "confirm"], ["ssh", "cf"],
        ["ssh", "cf", "--other-session", "--yes"], ["ssh", "extend", "5"], ["ssh", "rollback", "--yes"],
        ["lang"], ["version"],
    ]
    for argv in cases:
        rc, out = run_cli_zh(host, *argv)
        outputs.append((argv, rc, out))
        assert "Traceback" not in out
    missing = i18n.stop_recording()
    assert not missing, "Untranslated messages reached the screen:\n" + "\n".join(sorted(missing))
    joined = "\n".join(o for _, _, o in outputs)
    if zh == "zh-TW":
        assert "系統總覽" in joined and "安全稽核" in joined and "防火牆" in joined and "封鎖" in joined
    else:
        assert "系统总览" in joined and "安全审计" in joined and "防火墙" in joined and "封禁" in joined
        assert not any(t in joined for t in ("設定", "伺服器", "連線", "系統")), "no Traditional characters on a zh-CN page"


def test_non_root_messages_speak_chinese(tmp_path, zh):
    host = FakeHost(tmp_path / "r", euid=1000)
    i18n.start_recording()
    for argv in (["ssh", "port", "2222", "--yes"], ["fail2ban", "ban", "203.0.113.5"], ["backup"], ["setup"], ["uninstall", "--yes"],
                 ["self-update", "apply", "--yes"], ["status"], ["audit"], ["doctor"]):
        rc, out = run_cli_zh(host, *argv)
    rc, out = run_cli_zh(host, "backup")
    assert rc == 3 and ("需要 root 權限" in out if zh == "zh-TW" else "需要 root 权限" in out)
    assert not i18n.stop_recording()


def test_error_paths_in_chinese(tmp_path, zh):
    host = FakeHost(tmp_path / "r")
    host.listening[2222] = "nginx"
    host.sshd_invalid = False
    i18n.start_recording()
    rc, out = run_cli_zh(host, "ssh", "port", "2222", "--yes")
    assert rc == 1 and "已被 nginx 使用" in out
    host.listening.pop(2222)
    host.reload_fails = True
    rc, out = run_cli_zh(host, "ssh", "port", "2222", "--yes")
    assert rc == 6 and ("失敗" in out or "失败" in out)
    rc, out = run_cli_zh(host, "ssh", "port", "70000")
    assert rc == 4 and ("端口超出範圍" in out or "端口超出范围" in out)
    assert not i18n.stop_recording()


def test_a_real_migration_and_confirmation_in_chinese(tmp_path, monkeypatch):
    from bant.core import netinfo
    host = FakeHost(tmp_path / "r")
    i18n.start_recording()
    rc, out = run_cli_zh(host, "ssh", "port", "2222", "--yes", lang="zh-CN")
    assert rc == 0 and "新 SSH 端口：2222" in out and "原 SSH 端口暂时保留：22" in out and "sudo bant ssh cf" in out
    assert "自动回滚" in out
    rc, out = run_cli_zh(host, "ssh", "cf", lang="zh-CN")
    assert rc == 1 and "无法证明新连接可用" in out and "--other-session" in out
    pid = host.add_ssh_session("alice", 2222, "203.0.113.7", 50001, started=5000)
    monkeypatch.setattr(netinfo, "self_pid", lambda: pid)
    rc, out = run_cli_zh(host, "ssh", "cf", lang="zh-TW")
    assert rc == 0 and "已確認" in out and "本連線" in out and "舊監聽" in out
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
        if "請選擇" in prompt or "请选择" in prompt or "Select an option" in prompt:
            return queue.pop(0) if queue else ""
        if "(y/N)" in prompt or "(Y/n)" in prompt:
            return "n"
        return ""
    return answer


ADMIN_JAIL = "[sshd]\nenabled = true\nmaxretry = 3\nbantime = 1h\n"

# Every main entry and every submenu item, including nested submenus (see bant/tui/app.py and menus.py).
# "" = Enter (back / cancel); "0" is still accepted as "back" for muscle memory.
FULL_WALK = (
    ["1", "1", "2", "3", "4", "5", "6", ""]                                    # security overview
    + ["2"]                                                                    # one-click protection (answers "n")
    + ["3", "1", "2", "3", "4", "5", "", "6", "7", "8", "1", "2", "", "0"]     # SSH (root policy picker -> Enter, + advanced)
    + ["4", "1", "2", "3", "4", "5", "6", "7", "1", "2", "3", "",              # firewall & bans (+ firewall rules)
       "8", "1", "2", "3", "4", "", "5", "", ""]                               #   (+ advanced, conflicts -> back)
    + ["5", "1", "1", "2", "3", "4", "5", "", "2", "1", "2", "",               # maintenance: Bant update, OS updates
       "3", "1", "2", "3", "4", "5", "", "4", "1", "2", "3", "",               #   backups, logs
       "5", "6", "7", "8", ""]                                                 #   repair, version, doctor, rollback window
    + ["6", ""]                                                                # language picker -> Enter keeps the language
    + ["7", "1", "2", "3", ""]                                                 # safe uninstall (answers "n")
    + [""]                                                                     # Enter on the main menu = exit
)


def test_every_tui_screen_in_chinese(tmp_path, zh):
    gh = FakeGitHub()
    gh.add_release("0.2.0", prerelease=True)
    host = FakeHost(tmp_path / "r", ufw=True, language=zh)
    (host.paths.f2b_dir / "jail.d" / "99-sshd.local").write_text(ADMIN_JAIL)
    host.http_get = gh
    i18n.set_language(zh)
    i18n.start_recording()
    ui, out = ui_for(tui_driver(FULL_WALK))
    assert run_tui(host.make_ctx(), ui) == 0
    text = out.getvalue()
    missing = i18n.stop_recording()
    assert not missing, "Untranslated messages in the TUI:\n" + "\n".join(sorted(missing))
    needles = (("安全總覽", "一鍵安全防護", "SSH 管理", "防火牆與封禁", "維護與設定", "安全卸載", "Fail2ban 設定衝突", "再見", "請選擇操作（Enter 返回）")
               if zh == "zh-TW" else
               ("安全总览", "一键安全防护", "SSH 管理", "防火墙与封禁", "维护与设置", "安全卸载", "Fail2ban 设置冲突", "再见", "请选择操作（Enter 返回）"))
    for needle in needles:
        assert needle in text, needle
    assert "Traceback" not in text and "內部錯誤" not in text and "内部错误" not in text


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
    plan = ["2", "3", "2", "", "4", "4", "", "5", "3", "1", "", "", "7", "1", "", ""]
    i18n.start_recording()
    ui, out = ui_for(tui_driver(plan))
    run_tui(host.make_ctx(), ui)
    assert "需要 root" in out.getvalue() and "唯讀模式" in out.getvalue()
    assert not i18n.stop_recording()


@pytest.mark.parametrize("pick,code,menu", [("1", "zh-CN", "主菜单"), ("2", "zh-TW", "主選單")])
def test_language_menu_switches_language_live(tmp_path, pick, code, menu):
    host = FakeHost(tmp_path / "r", language="en")
    ui, out = ui_for(tui_driver(["6", pick, "1", ""]))   # Language -> pick -> open overview (now translated) -> back
    run_tui(host.make_ctx(), ui)
    text = out.getvalue()
    assert "Security status" in text and menu in text, "after choosing Chinese the next screens are in Chinese"
    assert i18n.resolve(host.make_ctx())[0] == code
    i18n.set_language("en")
    ui, out = ui_for(tui_driver(["6", "3", ""]))          # and back to English
    run_tui(host.make_ctx(), ui)
    assert "Language set to English." in out.getvalue() and i18n.resolve(host.make_ctx())[0] == "en"


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
