"""Menu screens. Each action delegates to the same core functions as the CLI."""

from __future__ import annotations

from collections.abc import Callable

from bant import __version__, i18n
from bant.context import Context
from bant.core import (
    backups,
    bans,
    fail2ban,
    firewall,
    logs,
    migration,
    netinfo,
    ports,
    repair,
    security_audit,
    ssh,
    status,
    updater,
    updates,
)
from bant.errors import BantError
from bant.i18n import tr
from bant.presenters import (
    fmt_ts,
    render_doctor,
    render_fail2ban,
    render_findings,
    render_firewall,
    render_logs,
    render_ssh,
    render_status,
    render_updates,
)
from bant.ui import UI, Abort, stream_shows_cjk
from bant.utils.validation import (
    format_duration,
    parse_duration,
    parse_int_range,
    parse_ip,
    parse_port,
    parse_proto,
)

Action = Callable[[Context, UI], None]


def guarded(fn: Action) -> Action:
    """Run an action, turning Bant errors into friendly messages instead of crashes."""
    def run(ctx: Context, ui: UI) -> None:
        try:
            fn(ctx, ui)
        except BantError as exc:
            ui.error(exc.message)
            if exc.hint:
                ui.info(f"  hint: {exc.hint}")
        except Abort:
            ui.warn("Cancelled.")
    return run


def need_root(ctx: Context, ui: UI, what: str) -> bool:
    if ctx.is_root:
        return True
    ui.error(f"{what} requires root. Quit and re-run with: sudo bant")
    return False


def submenu(ctx: Context, ui: UI, title: str, items: list[tuple[str, str, Action]], render: Callable[[], None] | None = None) -> None:
    table = {k: fn for k, _, fn in items}
    while True:
        ui.clear()
        if render:
            try:
                render()
            except BantError as exc:
                ui.error(exc.message)
        else:
            ui.heading(title)
        ui.rule()
        ui.menu([(k, label) for k, label, _ in items] + [("0", "Back")])
        ui.rule()
        try:
            choice = ui.ask("Select an option").lower()
        except Abort:
            return
        if choice in ("0", "b", "q", "back"):
            return
        if choice in ("", "r"):
            continue
        fn = table.get(choice)
        if fn is None:
            ui.warn(f"Unknown option '{choice}'.")
            continue
        guarded(fn)(ctx, ui)
        try:
            ui.pause()
        except Abort:
            return


def _ask_ip(ui: UI, prompt: str, **kw) -> str:
    return parse_ip(ui.ask(prompt), **kw)


# ---------------------------------------------------------------------------
# 1. Overview / 6. Audit / 11. System information
# ---------------------------------------------------------------------------

def overview(ctx: Context, ui: UI) -> None:
    ui.clear()
    render_status(ui, status.collect(ctx, deep=True))


def audit(ctx: Context, ui: UI) -> None:
    ui.clear()
    ui.info("Running audit checks...")
    findings = security_audit.run(ctx)
    render_findings(ui, findings, security_audit.summarize(findings), verbose=ui.confirm("Show informational findings too?", False))


def system_info(ctx: Context, ui: UI) -> None:
    ui.clear()
    d = status.collect(ctx)
    ui.heading("SYSTEM INFORMATION")
    ui.kv([("Bant version", __version__, None), ("OS", d["os"]["name"], None), ("Kernel", d["os"]["kernel"], None),
           ("Supported release", "yes" if d["os"]["supported"] else "NO", "ok" if d["os"]["supported"] else "warn"),
           ("Privileged", "yes (root)" if d["privileged"] else "no (read-only)", None),
           ("Firewall", f"{d['firewall']['backend']} ({d['firewall']['mode']})", None),
           ("Docker", "detected" if d["firewall"]["docker"] else "not detected", None)])
    if ui.confirm("Run deep diagnostics (doctor)?", True):
        render_doctor(ui, status.doctor(ctx))


# ---------------------------------------------------------------------------
# 2. SSH
# ---------------------------------------------------------------------------

def ssh_view(ctx: Context, ui: UI) -> None:
    render_ssh(ui, ssh.status(ctx), migration.describe_pending(ctx))


def ssh_port(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Changing the SSH port"):
        return
    port, source = ports.resolve_target(ctx, ui.ask("New SSH port (a number, or 'random')", "random"))
    if source == "random":
        ui.info(f"Random free port chosen: {port}")
    p = migration.plan(ctx, port)
    ui.section(f"Plan: move SSH to TCP {port}")
    for s in p.steps:
        ui.bullet(s)
    for w in p.warnings:
        ui.warn(w)
    for b in p.blockers:
        ui.error(b)
    if p.blockers:
        return
    if p.already_done:
        migration.begin(ctx, port)
        ui.success(f"SSH already on {port}; firewall and Fail2ban verified.")
        return
    if not ui.confirm("Start the migration? (the old port stays open until you confirm)", True):
        return
    out = migration.begin(ctx, port)
    ui.success(f"SSH now listens on {sorted(set(out['old_ports'] + [out['target']]))}. Firewall: {out['firewall']}")
    ui.text(f"\n Open a NEW terminal and connect:  {migration.login_hint(ctx, port)}", "warn")
    ui.text(" Then come back here (or any session) and choose 'Confirm pending change'.", "warn")


def ssh_password(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Changing password authentication"):
        return
    st = ssh.status(ctx)
    ui.text(f" Password login is currently {'ENABLED' if st.password_auth else 'DISABLED'}.")
    if st.password_auth:
        ui.info(" Disabling requires a verified key-based login and runs with automatic rollback.")
        if not ui.confirm("Disable password login?", False):
            return
        res = ssh.set_password_auth(ctx, False)
    else:
        ui.info(" Enabling exposes the server to password guessing. Fail2ban should stay active.")
        if not ui.confirm("Enable password login?", False):
            return
        res = ssh.set_password_auth(ctx, True)
    ui.success(res["message"])
    for w in res.get("warnings", []):
        ui.warn(w)
    if res.get("pending"):
        ui.warn("TEMPORARY until verified: open a NEW session with your key, then choose 'Confirm pending change'.")


def ssh_root(ctx: Context, ui: UI) -> None:
    st = ssh.status(ctx)
    ui.text(f" Current: {st.root_login} - {st.root_label}")
    ui.info(f" {st.root_detail}")
    ui.menu([("1", "yes (password or key)"), ("2", "prohibit-password (key only)"), ("3", "no (disabled)"), ("0", "cancel")])
    pick = {"1": "yes", "2": "prohibit-password", "3": "no"}.get(ui.ask("Choose"))
    if not pick:
        return
    if need_root(ctx, ui, "Changing the root login policy"):
        res = ssh.set_option(ctx, "root-login", pick)
        ui.success(res["message"])
        if res.get("pending"):
            ui.warn("TEMPORARY until verified: open a NEW session, then choose 'Confirm pending change'.")


def ssh_limits(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Changing SSH limits"):
        return
    st = ssh.status(ctx)
    ui.text(f" MaxAuthTries={st.max_auth_tries}  LoginGraceTime={st.login_grace_time}s")
    tries = ui.ask("MaxAuthTries (2-10, blank = keep)")
    if tries:
        ui.success(ssh.set_option(ctx, "max-auth-tries", tries)["message"])
    grace = ui.ask("LoginGraceTime in seconds (10-600, blank = keep)")
    if grace:
        ui.success(ssh.set_option(ctx, "login-grace-time", grace)["message"])


def ssh_confirm(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Confirming a change"):
        out = migration.confirm(ctx)
        ui.success(f"Confirmed: {out['verified']}")


def ssh_rollback(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Rolling back") and ui.confirm("Roll back the pending SSH change now?", True):
        out = migration.abort(ctx)
        ui.success(f"Rolled back {out['rolled_back']}.")


def ssh_validate(ctx: Context, ui: UI) -> None:
    ok, msg = ssh.sshconf.validate(ctx)
    if ok:
        ui.success("sshd -t: configuration is valid")
    else:
        ui.error(f"sshd -t: {msg}")


def ssh_menu(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "SSH MANAGEMENT", [
        ("1", "View status", ssh_view), ("2", "Change SSH port", ssh_port), ("3", "Password login on/off", ssh_password),
        ("4", "Root login policy", ssh_root), ("5", "Auth limits (tries / grace time)", ssh_limits),
        ("6", "Confirm pending change", ssh_confirm), ("7", "Roll back pending change", ssh_rollback),
        ("8", "Validate sshd configuration", ssh_validate),
    ], render=lambda: render_ssh(ui, ssh.status(ctx), migration.describe_pending(ctx)))


# ---------------------------------------------------------------------------
# 3. Fail2ban
# ---------------------------------------------------------------------------

def f2b_status(ctx: Context, ui: UI) -> None:
    render_fail2ban(ui, fail2ban.overview(ctx))


def f2b_banned(ctx: Context, ui: UI) -> None:
    rows = [[b["ip"], b["source"], b["jail"], b["expires"], ""] for b in fail2ban.banned(ctx)]
    rows += [[e["ip"], "bant", "-", fmt_ts(e["expires"]) if e.get("expires") else "never", e.get("reason", "")] for e in bans.active_entries(ctx)]
    ui.table(["IP", "Source", "Jail", "Expires", "Reason"], rows)


def f2b_ban(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Banning an IP"):
        return
    ip = _ask_ip(ui, "IP address (or CIDR for a Bant block)", allow_network=True, for_ban=True)
    risk = bans.ban_risk(ctx, ip)
    if risk:
        ui.warn(f"This may lock you out: {risk}")
        if not ui.confirm("Ban it anyway?", False):
            return
    kind = ui.ask("Duration: [j]ail default / [d]uration / [p]ermanent", "j").lower()
    if kind.startswith("p"):
        bans.block(ctx, ip, reason="manual (tui)")
        ui.success(f"{ip} blocked permanently in Bant's nftables table.")
    elif kind.startswith("d"):
        secs = parse_duration(ui.ask("Duration (e.g. 12h, 7d)"))
        bans.block(ctx, ip, duration=secs, reason="manual (tui)")
        ui.success(f"{ip} blocked for {format_duration(secs)}.")
    else:
        ui.success(fail2ban.ban(ctx, ip))


def f2b_unban(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Unbanning an IP"):
        return
    ip = _ask_ip(ui, "IP address to unban", allow_network=True)
    done = False
    if "/" not in ip and fail2ban.installed(ctx)[0] and fail2ban.unban(ctx, ip):
        ui.success(f"Unbanned {ip} in Fail2ban")
        done = True
    if bans.unblock(ctx, ip):
        ui.success(f"Removed Bant block for {ip}")
        done = True
    if not done:
        ui.warn(f"{ip} was not banned by Fail2ban or Bant.")


def f2b_set(key: str, prompt: str) -> Action:
    def run(ctx: Context, ui: UI) -> None:
        if need_root(ctx, ui, "Changing Fail2ban settings"):
            ui.success(fail2ban.set_option(ctx, key, ui.ask(prompt)))
    return run


def f2b_trusted(ctx: Context, ui: UI) -> None:
    ips = bans.trusted(ctx)
    ui.text(" Trusted: " + (", ".join(ips) or "(none)"))
    ui.info(" Trusted addresses are never banned. Only add static addresses you control.")
    act = ui.ask("[a]dd / [r]emove / Enter to go back").lower()
    if act.startswith(("a", "r")) and need_root(ctx, ui, "Changing trusted addresses"):
        ip = _ask_ip(ui, "Address or CIDR", allow_network=True)
        if act.startswith("a"):
            if not ui.confirm(f"Trust {ip}? Dynamic IPs may later belong to someone else.", False):
                return
            bans.trust_add(ctx, ip)
        else:
            bans.trust_remove(ctx, ip)
        fail2ban.sync_if_managed(ctx)
        ui.success("Updated trusted addresses.")


def f2b_events(ctx: Context, ui: UI) -> None:
    lines = logs.read_lines(ctx, "fail2ban", 30)
    for ln in lines:
        ui.text(" " + ln, raw=True)
    if not lines:
        ui.info("  (no events)")


def f2b_toggle(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Changing Fail2ban"):
        return
    ov = fail2ban.overview(ctx)
    if ov.service == "active":
        if ui.confirm("Disable Fail2ban? SSH brute-force protection will be OFF.", False):
            ui.warn(fail2ban.set_enabled(ctx, False))
    else:
        ui.success(fail2ban.set_enabled(ctx, True))


def f2b_menu(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "FAIL2BAN PROTECTION", [
        ("1", "View status", f2b_status), ("2", "View banned IPs", f2b_banned), ("3", "Ban an IP", f2b_ban), ("4", "Unban an IP", f2b_unban),
        ("5", "Configure ban duration", f2b_set("bantime", "Ban duration (e.g. 1h, 1d)")),
        ("6", "Configure attempt limit", f2b_set("maxretry", "Max failed attempts (1-100)")),
        ("7", "Manage trusted IPs", f2b_trusted), ("8", "View security events", f2b_events), ("9", "Enable / disable protection", f2b_toggle),
    ], render=lambda: render_fail2ban(ui, fail2ban.overview(ctx)))


# ---------------------------------------------------------------------------
# 4. Firewall, 5. IP lists
# ---------------------------------------------------------------------------

def fw_view(ctx: Context, ui: UI) -> None:
    render_firewall(ui, firewall.detect(ctx), firewall.managed_summary(ctx), netinfo.listeners(ctx))


def fw_allow(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Changing firewall rules"):
        return
    port, proto = parse_port(ui.ask("Port")), parse_proto(ui.ask("Protocol", "tcp"))
    with ctx.lock():
        res = firewall.allow_port(ctx, port, proto, purpose="manual")
        firewall.commit_rules(ctx, res.rules)
        ctx.audit("firewall.allow", port=port, proto=proto, backend=res.backend, changed=res.changed)
    (ui.success if res.changed else ui.info)(res.message)


def fw_remove(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Changing firewall rules"):
        return
    port, proto = parse_port(ui.ask("Port of a Bant-managed allowance")), parse_proto(ui.ask("Protocol", "tcp"))
    if port in ssh.status(ctx).active_ports and not ui.confirm("This is your SSH port - removing it may lock you out. Continue?", False):
        return
    with ctx.lock():
        for line in firewall.remove_port(ctx, port, proto):
            ui.success(line)


def fw_menu(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "FIREWALL", [("1", "View status & listening ports", fw_view), ("2", "Allow a port", fw_allow),
                                  ("3", "Remove a Bant-managed allowance", fw_remove)])


def ip_menu(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "IP BLACKLIST / ALLOWLIST", [
        ("1", "List banned / blocked IPs", f2b_banned), ("2", "Ban / block an IP", f2b_ban), ("3", "Unban / unblock an IP", f2b_unban),
        ("4", "Manage trusted (allow) list", f2b_trusted),
    ])


# ---------------------------------------------------------------------------
# 7. Updates, 8. Logs, 9. Settings, 10. Backup
# ---------------------------------------------------------------------------

def upd_enable(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Enabling updates"):
        ui.success(updates.enable(ctx))


def upd_disable(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Disabling updates"):
        ui.success(updates.disable(ctx))


def updates_menu(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "SECURITY UPDATES", [("1", "Enable automatic security updates", upd_enable), ("2", "Remove Bant's update settings", upd_disable)],
            render=lambda: render_updates(ui, updates.status(ctx)))


def logs_menu(ctx: Context, ui: UI) -> None:
    def show(source: str) -> Action:
        def run(ctx: Context, ui: UI) -> None:
            grep = ui.ask("Filter text (blank = none)") or None
            if source == "audit":
                render_logs(ui, ctx.audit_log.read(60, grep))
            else:
                for ln in logs.read_lines(ctx, source, 60, grep):
                    ui.text(" " + ln, raw=True)
        return run
    submenu(ctx, ui, "SECURITY LOGS", [("1", "Bant audit trail", show("audit")), ("2", "SSH events", show("ssh")), ("3", "Fail2ban events", show("fail2ban"))])


def settings_show(ctx: Context, ui: UI) -> None:
    c = ctx.config
    ui.kv([("Bant-managed SSH port", c.ssh_port or "random (chosen on first setup)", None), ("Rollback window", f"{c.rollback_minutes} min", None), ("Fail2ban maxretry", c.maxretry, None),
           ("Fail2ban findtime", c.findtime, None), ("Fail2ban bantime", c.bantime, None), ("Trusted IPs", ", ".join(c.trusted_ips) or "-", None),
           ("Config file", str(ctx.paths.config_file), "dim")])


def settings_rollback(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Changing settings"):
        minutes = parse_int_range(ui.ask("Rollback window in minutes (1-1440)", str(ctx.config.rollback_minutes)), 1, 1440, "minutes")
        ctx.config.set("ssh", "rollback_minutes", minutes)
        ctx.config.save()
        ctx.audit("config.set", key="ssh.rollback_minutes", value=minutes)
        ui.success(f"Rollback window is now {minutes} minutes.")


def settings_findtime(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Changing settings"):
        ui.success(fail2ban.set_option(ctx, "findtime", ui.ask("Detection window (e.g. 10m)")))


def settings_menu(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "PROTECTION SETTINGS", [
        ("1", "Rollback window", settings_rollback), ("2", "Fail2ban attempt limit", f2b_set("maxretry", "Max failed attempts (1-100)")),
        ("3", "Fail2ban detection window", settings_findtime), ("4", "Fail2ban ban duration", f2b_set("bantime", "Ban duration (e.g. 1h)")),
    ], render=lambda: (ui.heading("PROTECTION SETTINGS"), settings_show(ctx, ui)))


def bk_create(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Creating a backup"):
        r = backups.create(ctx, ui.ask("Note", "manual (tui)"))
        ui.success(f"Backup {r['id']} created ({r['files']} files).")


def bk_list(ctx: Context, ui: UI) -> None:
    ui.table(["ID", "Created", "Files", "Note"], [[i["id"], fmt_ts(i["created"]), i["files"], i["note"]] for i in backups.list_backups(ctx)])


def bk_restore(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Restoring a backup"):
        return
    bk_list(ctx, ui)
    bid = ui.ask("Backup ID to restore", "latest")
    if ui.confirm(f"Restore '{bid}'? A safety snapshot is taken first.", False):
        r = backups.restore(ctx, bid)
        ui.success(f"Restored {r['id']}; safety snapshot {r['safety_backup']}.")


def bk_repair(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Repair"):
        for a in repair.run(ctx):
            ui.text(f" {ui.glyph('ok' if a['result'] == 'ok' else 'warn')} {tr(a['action'])}" + ("" if a["result"] == "ok" else f" - {tr(a['result'])}"),
                    raw=True)


def bk_help(ctx: Context, ui: UI) -> None:
    ui.text(" Lost SSH access?\n"
            "  1. Open your VPS provider's web/VNC console and log in as root.\n"
            "  2. Run:  bant ssh rollback      (or)   sh /opt/bant/emergency-recovery.sh\n"
            "  3. See docs/RECOVERY.md for the full procedure.")


def backup_menu(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "BACKUP & RECOVERY", [("1", "Create backup", bk_create), ("2", "List backups", bk_list), ("3", "Restore backup", bk_restore),
                                          ("4", "Run repair", bk_repair), ("5", "Provider-console recovery steps", bk_help)])



# ---------------------------------------------------------------------------
# Language
# ---------------------------------------------------------------------------

_LANG_ANSWERS = {"1": "en", "en": "en", "english": "en", "2": "zh", "zh": "zh", "中文": "zh", "繁體中文": "zh", "繁体中文": "zh", "chinese": "zh"}


def choose_language(ctx: Context, ui: UI, *, first_run: bool = False) -> None:
    """Bilingual language picker. Shown on the first launch of the menu and from the Language menu entry."""
    hint = i18n.locale_hint()
    default = "2" if hint == "zh" else "1"
    ui.clear()
    ui.heading("BANT", "Select language / 選擇語言")
    ui.menu([("1", "English"), ("2", "繁體中文 (Traditional Chinese)")])
    while True:
        answer = ui.ask("Language / 語言 (1/2)", default, translate=False).strip().lower()
        code = _LANG_ANSWERS.get(answer)
        if code:
            break
        ui.text("Please enter 1 or 2 / 請輸入 1 或 2", "warn", raw=True)
    if code == "zh" and not stream_shows_cjk(ui.stream):
        i18n.set_language("en")
        ui.warn("This terminal does not look UTF-8, so Chinese would be garbled; showing English. "
                "Use a UTF-8 terminal (e.g. LANG=C.UTF-8) and choose again from the Language menu.")
        return
    i18n.set_language(code)
    try:
        where = i18n.save(ctx, code)
        ui.success("Language set to English." if code == "en" else "語言已設定為繁體中文。")
        if where == "user":
            ui.info("Saved as your personal preference (run with sudo to set it system-wide).")
    except OSError as exc:
        ui.warn(f"Could not save the language choice ({exc}); it applies to this session only.")
    if first_run:
        ui.pause()


def language_menu(ctx: Context, ui: UI) -> None:
    choose_language(ctx, ui)


# ---------------------------------------------------------------------------
# Bant self-update
# ---------------------------------------------------------------------------

def su_check(ctx: Context, ui: UI) -> None:
    from bant.presenters import render_update_info

    render_update_info(ui, updater.check(ctx))


def su_apply(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Updating Bant"):
        return
    info = updater.check(ctx)
    from bant.presenters import render_update_info

    render_update_info(ui, info)
    if not info["available"] or not ui.confirm(f"Install Bant {info['latest']} now?", True):
        return
    res = updater.apply(ctx)
    ui.success(f"Updated Bant {res['previous']} -> {res['current']} ({res['verified']}).")
    ui.info(f"Configuration backup: {res['backup']}. Undo with the 'Roll back' option.")
    ui.warn("Quit and start `bant` again to use the new version.")


def su_rollback(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Rolling back Bant") and ui.confirm("Switch back to the previous Bant version?", True):
        res = updater.rollback(ctx)
        ui.success(f"Bant is now {res['to']} (was {res['from']}). Quit and start `bant` again.")


def su_notify(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Changing the update check"):
        on = not updater.notify_enabled(ctx)
        ui.success(updater.set_notify(ctx, on))


def su_channel(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Changing the update channel"):
        ui.text(f" Current channel: {updater.channel(ctx)}  (auto = include pre-releases while Bant is below 1.0)")
        ui.success(updater.set_channel(ctx, ui.ask("Channel (auto / stable / prerelease)", updater.channel(ctx))))


def selfupdate_menu(ctx: Context, ui: UI) -> None:
    from bant.presenters import render_selfupdate_status

    submenu(ctx, ui, "BANT UPDATE", [
        ("1", "Check for updates", su_check), ("2", "Install the update", su_apply), ("3", "Roll back to the previous version", su_rollback),
        ("4", "Daily update check on / off", su_notify), ("5", "Update channel", su_channel),
    ], render=lambda: render_selfupdate_status(ui, updater.status(ctx)))
