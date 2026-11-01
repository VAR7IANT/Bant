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
    render_port_started,
    render_ssh,
    render_status,
    render_updates,
    yn,
)
from bant.ui import UI, Abort, Cancelled
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
        except (KeyboardInterrupt, EOFError):
            ui.text("")
            ui.warn("Cancelled.")
        except Exception as exc:  # noqa: BLE001 - a menu action must never crash the whole menu
            if type(exc).__name__ == "UninstallDone":
                raise
            from bant.cli import _debug_log

            where = _debug_log(ctx, exc)
            ui.error(f"Unexpected internal error ({type(exc).__name__}). Nothing further was changed by this step.")
            if where:
                ui.info(f"  Details for developers were saved to {where}.")
    return run


def need_root(ctx: Context, ui: UI, what: str) -> bool:
    if ctx.is_root:
        return True
    ui.error(f"{what} requires root. Quit and re-run with: sudo bant")
    return False


def submenu(ctx: Context, ui: UI, title: str, items: list[tuple[str, str, Action]], render: Callable[[], None] | None = None) -> None:
    """Every menu below the main menu: status once on entry, then number -> action, Enter -> back.

    Output is printed in place; after an action its result stays on screen and only the short option list is
    printed again (never the whole screen), so nothing scrolls away and nothing is redrawn.
    """
    table = {k: fn for k, _, fn in items}
    if render:
        try:
            render()
        except BantError as exc:
            ui.error(exc.message)
    else:
        ui.heading(title)
    ui.rule()
    while True:
        ui.menu([(k, label) for k, label, _ in items])
        choice = ui.select(table)
        if choice is None:
            return
        guarded(table[choice])(ctx, ui)
        ui.section(title)


def _ask_ip(ui: UI, prompt: str, **kw) -> str:
    return parse_ip(ui.ask_required(prompt), **kw)


# ---------------------------------------------------------------------------
# 1. Overview / 6. Audit / 11. System information
# ---------------------------------------------------------------------------

def overview(ctx: Context, ui: UI) -> None:
    render_status(ui, status.collect(ctx, deep=True))


def audit(ctx: Context, ui: UI) -> None:
    ui.info("Running audit checks...")
    findings = security_audit.run(ctx)
    render_findings(ui, findings, security_audit.summarize(findings), verbose=ui.confirm("Show informational findings too?", False))


def system_info(ctx: Context, ui: UI) -> None:
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
    ui.text(f" Current SSH port(s): {', '.join(map(str, ssh.status(ctx).active_ports)) or 'unknown'}")
    port, source = ports.resolve_target(ctx, ui.ask_required("New SSH port (a number such as 667, or 'random')"))
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
    if not ui.confirm("Start the migration? (the old port stays open until you confirm)"):
        raise Cancelled
    out = migration.begin(ctx, port)
    render_port_started(ui, out, migration.login_hint(ctx, port), ctx.clock())


def ssh_password(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Changing password authentication"):
        return
    st = ssh.status(ctx)
    ui.text(f" Password login is currently {'ENABLED' if st.password_auth else 'DISABLED'}.")
    if st.password_auth:
        ui.info(" Disabling requires a verified key-based login and runs with automatic rollback.")
        if not ui.confirm("Disable password login?"):
            raise Cancelled
        res = ssh.set_password_auth(ctx, False)
    else:
        ui.info(" Enabling exposes the server to password guessing. Fail2ban should stay active.")
        if not ui.confirm("Enable password login?"):
            raise Cancelled
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
    ui.menu([("1", "yes (password or key)"), ("2", "prohibit-password (key only)"), ("3", "no (disabled)")])
    pick = {"1": "yes", "2": "prohibit-password", "3": "no"}.get(ui.select(["1", "2", "3"]) or "")
    if not pick:
        raise Cancelled
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
    """Same rules as `bant ssh cf`: this session must be the new connection; a console needs explicit consent."""
    if not need_root(ctx, ui, "Confirming a change"):
        return
    try:
        out = migration.confirm(ctx, "current")
    except migration.NotInSshSession as exc:
        ui.warn(exc.message)
        _tx, evidence = migration.check(ctx, "other")
        ui.text(" Bant found this separate new session instead:")
        ui.text(f"   {evidence}", raw=True)
        if not ui.confirm("Is that session yours, and does it work? Confirm the change with it"):
            raise Cancelled from None
        out = migration.confirm(ctx, "other")
    ui.success(f"Confirmed: {out['verified']}")
    if out.get("kind") == "ssh-port":
        ui.success(f"SSH now listens only on TCP {out['port']}; old listener(s) {out['removed_ports']} removed; rollback timer disarmed.")
    for n in out.get("notes", []):
        ui.info(" " + n)


def ssh_rollback(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Rolling back") and ui.confirm("Roll back the pending SSH change now?"):
        out = migration.abort(ctx)
        ui.success(f"Rolled back {out['rolled_back']}.")


def ssh_validate(ctx: Context, ui: UI) -> None:
    ok, msg = ssh.sshconf.validate(ctx)
    if ok:
        ui.success("sshd -t: configuration is valid")
    else:
        ui.error(f"sshd -t: {msg}")


def ssh_keys(ctx: Context, ui: UI) -> None:
    st = ssh.status(ctx)
    pk, pks = yn(st.pubkey_auth)
    pw, pws = yn(st.password_auth)
    ui.section("Public key authentication")
    ui.kv([("Public key login", pk, pks), ("Password login", pw, pws)], label_width=18)
    users = sorted({"root", *ssh.other_admin_exists()})
    ui.table(["User", "Authorized keys"], [[u, ssh.authorized_key_count(ctx, u)] for u in users])
    live = ssh.live_pubkey_sessions(ctx)
    if live:
        ui.success(f"{len(live)} open session(s) logged in with a key - password login can be turned off safely.")
    else:
        ui.info(" No open session logged in with a key was found. Log in with your key in a NEW terminal before turning passwords off.")


def ssh_advanced(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "SSH - ADVANCED", [("1", "Auth limits (tries / grace time)", ssh_limits), ("2", "Validate sshd configuration", ssh_validate)])


def ssh_menu(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "SSH MANAGEMENT", [
        ("1", "View status", ssh_view), ("2", "Change SSH port", ssh_port), ("3", "Password login on/off", ssh_password),
        ("4", "Public key status", ssh_keys), ("5", "Root login policy", ssh_root),
        ("6", "Confirm pending change", ssh_confirm), ("7", "Roll back pending change", ssh_rollback),
        ("8", "Advanced", ssh_advanced),
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
        if not ui.confirm("Ban it anyway?"):
            raise Cancelled
    ui.menu([("1", "Fail2ban jail default"), ("2", "Custom duration"), ("3", "Permanent")])
    kind = ui.select(["1", "2", "3"])
    if kind is None:
        raise Cancelled
    if kind == "3":
        bans.block(ctx, ip, reason="manual (tui)")
        ui.success(f"{ip} blocked permanently in Bant's nftables table.")
    elif kind == "2":
        secs = parse_duration(ui.ask_required("Duration (e.g. 12h, 7d)"))
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
            ui.success(fail2ban.set_option(ctx, key, ui.ask_required(prompt)))
    return run


def f2b_trusted(ctx: Context, ui: UI) -> None:
    ips = bans.trusted(ctx)
    ui.text(" Trusted: " + (", ".join(ips) or "(none)"))
    ui.info(" Trusted addresses are never banned. Only add static addresses you control.")
    act = ui.ask("[a]dd / [r]emove / Enter to go back").lower()
    if act.startswith(("a", "r")) and need_root(ctx, ui, "Changing trusted addresses"):
        ip = _ask_ip(ui, "Address or CIDR", allow_network=True)
        if act.startswith("a"):
            if not ui.confirm(f"Trust {ip}? Dynamic IPs may later belong to someone else."):
                raise Cancelled
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
        if not ui.confirm("Disable Fail2ban? SSH brute-force protection will be OFF."):
            raise Cancelled
        ui.warn(fail2ban.set_enabled(ctx, False))
    else:
        ui.success(fail2ban.set_enabled(ctx, True))


def f2b_conflicts(ctx: Context, ui: UI) -> None:
    from bant.core import f2b_conflicts as fc
    from bant.presenters import render_f2b_conflicts

    items = fc.analyze(ctx)
    render_f2b_conflicts(ui, items, fc.adopt_plan(ctx, items))
    if not items or not ctx.is_root:
        return
    ui.menu([("1", "Keep the administrator's settings (no file changes)"), ("2", "Let Bant take over (backup, then comment out)")])
    choice = ui.select(["1", "2"])
    if choice == "1":
        ui.success(fc.resolve(ctx, "keep")["message"])
    elif choice == "2" and ui.confirm("Let Bant take over these settings?", False):
        ui.success(fc.resolve(ctx, "adopt")["message"])


def f2b_advanced(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "SSH PROTECTION - ADVANCED", [
        ("1", "Configure ban duration", f2b_set("bantime", "Ban duration (e.g. 1h, 1d)")),
        ("2", "Configure attempt limit", f2b_set("maxretry", "Max failed attempts (1-100)")),
        ("3", "Fail2ban detection window", settings_findtime),
        ("4", "Fail2ban configuration conflicts", f2b_conflicts),
        ("5", "View security events", f2b_events),
    ], render=lambda: (ui.heading("SSH PROTECTION - ADVANCED"), settings_show(ctx, ui)))


def firewall_bans_menu(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "FIREWALL & BANS", [
        ("1", "Fail2ban status", f2b_status), ("2", "Enable / disable Fail2ban", f2b_toggle),
        ("3", "View banned IPs", f2b_banned), ("4", "Ban an IP", f2b_ban), ("5", "Unban an IP", f2b_unban),
        ("6", "Manage trusted IPs", f2b_trusted), ("7", "Firewall rules & open ports", fw_menu),
        ("8", "SSH protection settings (advanced)", f2b_advanced),
    ], render=lambda: render_fail2ban(ui, fail2ban.overview(ctx)))


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
    port, proto = _ask_port_proto(ui, "Port to allow (e.g. 8080 or 8080/udp)")
    with ctx.lock():
        res = firewall.allow_port(ctx, port, proto, purpose="manual")
        firewall.commit_rules(ctx, res.rules)
        ctx.audit("firewall.allow", port=port, proto=proto, backend=res.backend, changed=res.changed)
    (ui.success if res.changed else ui.info)(res.message)


def fw_remove(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Changing firewall rules"):
        return
    port, proto = _ask_port_proto(ui, "Port of a Bant-managed allowance (e.g. 8080 or 8080/udp)")
    if port in ssh.status(ctx).active_ports and not ui.confirm("This is your SSH port - removing it may lock you out. Continue?"):
        raise Cancelled
    if not ui.confirm(f"Remove Bant's firewall allowance for {port}/{proto}?"):
        raise Cancelled
    with ctx.lock():
        for line in firewall.remove_port(ctx, port, proto):
            ui.success(line)


def _ask_port_proto(ui: UI, prompt: str) -> tuple[int, str]:
    raw = ui.ask_required(prompt).strip().lower()
    port, _, proto = raw.partition("/")
    return parse_port(port), parse_proto(proto or "tcp")


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
        ui.text(f" Current rollback window: {ctx.config.rollback_minutes} min")
        minutes = parse_int_range(ui.ask_required("Rollback window in minutes (1-1440)"), 1, 1440, "minutes")
        ctx.config.set("ssh", "rollback_minutes", minutes)
        ctx.config.save()
        ctx.audit("config.set", key="ssh.rollback_minutes", value=minutes)
        ui.success(f"Rollback window is now {minutes} minutes.")


def settings_findtime(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Changing settings"):
        ui.success(fail2ban.set_option(ctx, "findtime", ui.ask_required("Detection window (e.g. 10m)")))


def settings_menu(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "PROTECTION SETTINGS", [
        ("1", "Rollback window", settings_rollback), ("2", "Fail2ban attempt limit", f2b_set("maxretry", "Max failed attempts (1-100)")),
        ("3", "Fail2ban detection window", settings_findtime), ("4", "Fail2ban ban duration", f2b_set("bantime", "Ban duration (e.g. 1h)")),
    ], render=lambda: (ui.heading("PROTECTION SETTINGS"), settings_show(ctx, ui)))


def bk_create(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Creating a backup"):
        r = backups.create(ctx, ui.ask_required("Backup note (e.g. before-upgrade)"))
        ui.success(f"Backup {r['id']} created ({r['files']} files).")


def bk_list(ctx: Context, ui: UI) -> None:
    ui.table(["ID", "Created", "Files", "Note"], [[i["id"], fmt_ts(i["created"]), i["files"], i["note"]] for i in backups.list_backups(ctx)])


def bk_restore(ctx: Context, ui: UI) -> None:
    if not need_root(ctx, ui, "Restoring a backup"):
        return
    bk_list(ctx, ui)
    bid = ui.ask_required("Backup ID to restore (or 'latest')")
    if ui.confirm(f"Restore '{bid}'? A safety snapshot is taken first."):
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

LANG_CHOICES = [("1", "zh-CN"), ("2", "zh-TW"), ("3", "en")]


def choose_language(ctx: Context, ui: UI, *, first_run: bool = False) -> None:
    """Language picker (main menu entry, `bant lang`, and the very first start).

    The three options are always shown in their own script, so anyone can find theirs. Enter goes back and keeps
    the current language (on the very first start: the language of the system locale, or English).
    """
    current = i18n.resolve(ctx)[0]
    ui.section("Select language")
    for k, c in LANG_CHOICES:  # native names, never translated
        ui.text(f" {k:>2}. {i18n.LANGS[c]}  ({c})", raw=True)
    if current and not first_run:
        ui.info(f" Current: {i18n.LANGS[current]} ({current})")
    pick = ui.select([k for k, _ in LANG_CHOICES] + [c.lower() for _, c in LANG_CHOICES])
    if pick is None and not first_run:
        return
    code = i18n.normalize(dict(LANG_CHOICES).get(pick or "", pick or "")) or i18n.locale_hint() or i18n.DEFAULT
    shown = i18n.apply(code, ui.stream)
    if shown != code:
        ui.warn("This terminal does not look UTF-8, so Chinese would be garbled; showing English. "
                "Use a UTF-8 terminal (e.g. LANG=C.UTF-8) and choose again from the Language menu.")
        return
    try:
        where = i18n.save(ctx, code)
        ui.success(f"Language set to {i18n.LANGS[code]}.")
        if where == "user":
            ui.info("Saved as your personal preference (run with sudo to set it system-wide).")
    except OSError as exc:
        ui.warn(f"Could not save the language choice ({exc}); it applies to this session only.")


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
    if not info["available"] or not ui.confirm(f"Install Bant {info['latest']} now?"):
        return
    res = updater.apply(ctx)
    ui.success(f"Updated Bant {res['previous']} -> {res['current']} ({res['verified']}).")
    ui.info(f"Configuration backup: {res['backup']}. Undo with the 'Roll back' option.")
    ui.warn("Quit and start `bant` again to use the new version.")


def su_rollback(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Rolling back Bant") and ui.confirm("Switch back to the previous Bant version?"):
        res = updater.rollback(ctx)
        ui.success(f"Bant is now {res['to']} (was {res['from']}). Quit and start `bant` again.")


def su_notify(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Changing the update check"):
        on = not updater.notify_enabled(ctx)
        ui.success(updater.set_notify(ctx, on))


def su_channel(ctx: Context, ui: UI) -> None:
    if need_root(ctx, ui, "Changing the update channel"):
        ui.text(f" Current channel: {updater.channel(ctx)}  (auto = include pre-releases while Bant is below 1.0)")
        ui.success(updater.set_channel(ctx, ui.ask_required("Channel (auto / stable / prerelease)")))


def selfupdate_menu(ctx: Context, ui: UI) -> None:
    from bant.presenters import render_selfupdate_status

    submenu(ctx, ui, "BANT UPDATE", [
        ("1", "Check for updates", su_check), ("2", "Install the update", su_apply), ("3", "Roll back to the previous version", su_rollback),
        ("4", "Daily update check on / off", su_notify), ("5", "Update channel", su_channel),
    ], render=lambda: render_selfupdate_status(ui, updater.status(ctx)))


# ---------------------------------------------------------------------------
# Main menu groups (0.1.2): overview, one-click protection, maintenance, uninstall
# ---------------------------------------------------------------------------

def overview_summary(ctx: Context, ui: UI) -> None:
    from bant.presenters import render_overview_summary

    render_overview_summary(ui, status.collect(ctx))


def full_diagnostics(ctx: Context, ui: UI) -> None:
    ui.info("Running diagnostics...")
    render_doctor(ui, status.doctor(ctx))


def overview_menu(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "SECURITY OVERVIEW", [
        ("1", "Full diagnostics (doctor)", full_diagnostics), ("2", "Security audit", audit),
        ("3", "SSH details", ssh_view), ("4", "Fail2ban details", f2b_status), ("5", "Firewall details", fw_view),
        ("6", "System information", system_info),
    ], render=lambda: (ui.heading("SECURITY OVERVIEW"), overview_summary(ctx, ui)))


def protect(ctx: Context, ui: UI) -> None:
    """One-click protection: the same `setup` the installer runs. Safe to repeat."""
    from bant.cli import _ask_ssh_port
    from bant.core import setup
    from bant.core.rollback import TxManager
    from bant.presenters import render_setup

    ui.heading("ONE-CLICK PROTECTION")
    if not need_root(ctx, ui, "One-click protection"):
        return
    state = setup.initialized(ctx)
    ui.text(" Bant will check and, where needed, set up:", "title")
    for line in ("system check and a backup of the original configuration",
                 "Fail2ban (installed, configured for your SSH port and verified)",
                 "firewall detection (existing rules are kept)",
                 "SSH on a random free port, or one you choose (e.g. 667): the old port stays open until a NEW login works and you confirm",
                 "a final check that SSH and Fail2ban work"):
        ui.bullet(line)
    ui.info(" Password login is not changed. Anything already set up is reported as 'already enabled' and not repeated.")
    if state == "complete":
        ui.success("Security setup was already completed on this server; running it again only re-checks.")
    if not ui.confirm("Start now?"):
        raise Cancelled
    port = None
    if not TxManager(ctx).pending():
        port = _ask_ssh_port(ctx, ui, enter_cancels=True)
    report = setup.run(ctx, port=port)
    render_setup(ui, report)


def version_info(ctx: Context, ui: UI) -> None:
    from bant.presenters import render_selfupdate_status

    render_selfupdate_status(ui, updater.status(ctx))


def maintenance_menu(ctx: Context, ui: UI) -> None:
    submenu(ctx, ui, "MAINTENANCE & SETTINGS", [
        ("1", "Update Bant", selfupdate_menu), ("2", "System security updates", updates_menu),
        ("3", "Backup & restore", backup_menu), ("4", "Security logs", logs_menu),
        ("5", "Repair configuration", bk_repair), ("6", "Version information", version_info),
        ("7", "Advanced diagnostics", full_diagnostics), ("8", "Rollback window", settings_rollback),
    ])


def _uninstall(ctx: Context, ui: UI, *, purge: bool, preview: bool) -> None:
    from bant.cli import render_uninstall_preview, render_uninstall_result
    from bant.core import uninstall

    if not need_root(ctx, ui, "Uninstalling Bant"):
        return
    pre = uninstall.preflight(ctx)
    render_uninstall_preview(ui, pre, uninstall.inventory(ctx, purge=purge, pre=pre))
    if preview or pre["blockers"]:
        if pre["blockers"]:
            ui.error("Uninstall is not possible right now - nothing was changed.")
        return
    question = ("Remove Bant AND delete its configuration, backups and logs?" if purge else "Remove Bant (configuration and backups are kept)?")
    if not ui.confirm(question):
        raise Cancelled
    if purge and ui.ask("Type 'delete' to confirm the full removal", translate=True).strip().lower() not in ("delete", "刪除", "删除"):
        ui.warn("Cancelled.")
        return
    res = uninstall.run(ctx, purge=purge)
    render_uninstall_result(ui, res)
    ui.warn("Bant has been removed. The menu is closed.")
    raise UninstallDone


class UninstallDone(Exception):
    """Raised after a successful uninstall so the menu loop exits."""


def uninstall_menu(ctx: Context, ui: UI) -> None:
    def std(c, u):
        _uninstall(c, u, purge=False, preview=False)

    def full(c, u):
        _uninstall(c, u, purge=True, preview=False)

    def prev(c, u):
        _uninstall(c, u, purge=False, preview=True)
    submenu(ctx, ui, "SAFE UNINSTALL", [
        ("1", "Standard uninstall (keep configuration and backups)", std),
        ("2", "Full removal of Bant data", full),
        ("3", "Preview what would be removed", prev),
    ], render=lambda: (ui.heading("SAFE UNINSTALL"),
                       ui.info(" SSH stays on its current port, Fail2ban keeps protecting it, and rules Bant did not create are not touched.")))
