"""Human-readable rendering of core data structures (used by both CLI and TUI)."""

from __future__ import annotations

import time
from typing import Any

from bant import __version__
from bant.core.security_audit import SEVERITIES, Finding
from bant.i18n import tr
from bant.ui import SEV_STYLE, UI, pad, style_for_state
from bant.utils.validation import humanize_duration


def fmt_ts(ts: float | int | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"


def fmt_left(seconds: int) -> str:
    m, s = divmod(max(0, int(seconds)), 60)
    return f"{m}m {s:02d}s"


def yn(value: bool | None, yes: str = "Enabled", no: str = "Disabled") -> tuple[str, str]:
    if value is None:
        return "Unknown", "dim"
    return (yes, "ok") if value else (no, "warn")


F2B_LABELS = {
    "verified": ("Active (verified)", "ok"), "running": ("Active (not fully verified)", "warn"),
    "misconfigured": ("Misconfigured", "bad"), "inactive": ("Inactive", "bad"), "not_installed": ("Not installed", "bad"),
}


def render_pending(ui: UI, pend: dict[str, Any]) -> None:
    ui.section("Pending SSH change")
    rows = [("Transaction", pend["id"], None), ("Type", pend["kind"], None), ("Phase", pend["phase"], None),
            ("Auto-rollback in", fmt_left(pend["seconds_left"]), "warn" if pend["seconds_left"] > 120 else "bad")]
    ui.kv(rows)
    if pend.get("target"):
        ui.text(f" Reconnect on TCP {pend['target']} in a NEW terminal, then run there: sudo bant ssh cf", "warn")
    else:
        ui.text(" Open a NEW session (using your key) and run there: sudo bant ssh cf", "warn")
    ui.text(" To undo now: sudo bant ssh rollback", "dim")


def render_port_started(ui: UI, out: dict[str, Any], login: str, now: float) -> None:
    """Result of `bant ssh port N`: short, in the order the user needs it, ending with the one next command."""
    old = [p for p in out.get("old_ports", []) if p != out["target"]]
    ui.text("")
    ui.success(f"New SSH port: {out['target']}")
    ui.success("New port is listening and answers as SSH")
    ui.success(f"Firewall: {out['firewall']}")
    if old:
        ui.success(f"Old SSH port kept open for now: {', '.join(map(str, old))}")
    ui.text("")
    ui.text(" Reconnect to the server through the new port:", "title")
    ui.text(f"   {login}", raw=True)
    ui.text(" Once connected, run in that new session:", "title")
    ui.text("   sudo bant ssh cf", raw=True)
    ui.text("")
    minutes = max(1, round((out["deadline"] - now) / 60)) if out.get("deadline") else None
    if minutes:
        ui.warn(f"Without confirmation the change is rolled back automatically at {fmt_ts(out['deadline'])} (in {minutes} min).")
    ui.info(" If the new connection times out, allow the port in your VPS provider's firewall/security group too.")


def render_status(ui: UI, d: dict[str, Any]) -> None:
    ui.heading(f"BANT v{d['bant_version']}", "Linux VPS Security Manager")
    ui.section("System overview")
    ssh, f2b, fw = d["ssh"], d["fail2ban"], d["firewall"]
    ports = ", ".join(str(p) for p in ssh["ports"]) or "unknown"
    pw, pws = yn(ssh["password_auth"])
    pk, pks = yn(ssh["pubkey_auth"])
    f2_label, f2_style = F2B_LABELS.get(f2b["state"], (f2b["state"], None))
    fw_label = f"{fw['backend']} ({'active' if fw['active'] else 'none detected'}, {fw['mode']})"
    health_style = style_for_state(d["health"])
    rows = [
        ("OS", d["os"]["name"] if d["os"]["supported"] else f"{d['os']['name']}  (unsupported release)", None if d["os"]["supported"] else "warn"),
        ("Kernel", d["os"]["kernel"], None),
        ("SSH port", ports, "ok" if len(ssh["ports"]) == 1 and ssh["ports"][0] != 22 else "warn"),
        ("Password login", pw, pws), ("Public key auth", pk, pks),
        ("Root login", tr(ssh["root_label"]) if ssh["root_label"] else ssh["root_login"], "warn" if ssh["root_login"] == "yes" else None),
        ("Fail2ban", f2_label, f2_style),
        ("SSH jail ports", ", ".join(map(str, f2b["ports"])) or "-", None),
        ("Firewall", fw_label, "ok" if fw["active"] else "warn"),
        ("Banned IPs", f"{d['bans']['fail2ban']} (Fail2ban)  {d['bans']['bant']} (Bant)", None),
    ]
    if d.get("updates"):
        u = d["updates"]
        mode = "auto" if u["auto_enabled"] else "manual"
        text = f"{mode}; {u['pending_security']} pending; reboot required" if u["reboot_required"] else f"{mode}; {u['pending_security']} pending"
        rows.append(("Security updates", text, "warn" if u["pending_security"] else "ok"))
    bu = d.get("bant_update") or {}
    if bu.get("available"):
        rows.append(("Bant update", f"{bu['latest']} available - run: sudo bant self-update", "warn"))
    counts = d["findings"]["summary"]
    rows.append(("Critical / High", f"{counts['critical']} / {counts['high']}", "bad" if counts["critical"] or counts["high"] else "ok"))
    rows.append(("Security status", tr(d["health"]).upper(), health_style))
    ui.kv(rows)
    if ssh.get("pending"):
        render_pending(ui, ssh["pending"])
    for f in d["findings"]["critical_and_high"][:5]:
        ui.text(f" ! [{tr(f['severity']).upper()}] {tr(f['title'])}", SEV_STYLE[f["severity"]], raw=True)
    for n in d.get("notes", []):
        ui.info(f" note: {n}")
    if not d["privileged"]:
        ui.info(" Running without root: some values are approximate. Use sudo for full detail.")


def render_findings(ui: UI, findings: list[Finding], summary: dict[str, Any], verbose: bool = True) -> None:
    ui.heading("SECURITY AUDIT", "configuration review - not a guarantee")
    c = summary["counts"]
    ui.text("  " + "   ".join(f"{tr(s).capitalize()}: {c[s]}" for s in SEVERITIES), raw=True)
    ui.text("  " + tr(summary["verdict"]), "bad" if c["critical"] or c["high"] else ("warn" if c["medium"] else "ok"), raw=True)
    for f in findings:
        if f.severity == "info" and not verbose:
            continue
        ui.text("")
        ui.text(f" [{tr(f.severity).upper()}] {f.id}  {tr(f.title)}", SEV_STYLE[f.severity], raw=True)
        ui.text(f"   {pad(tr('Evidence:'), 16)}{f.evidence}", raw=True)
        if f.severity != "info" or f.impact != "None":
            ui.text(f"   {pad(tr('Impact:'), 16)}{tr(f.impact)}", raw=True)
        ui.text(f"   {pad(tr('Recommendation:'), 16)}{tr(f.recommendation)}", raw=True)
        if f.fixable:
            ui.text(f"   {pad(tr('Bant can fix:'), 16)}{tr('yes')}" + (f"  ({f.fix})" if f.fix else ""), "ok", raw=True)
    ui.text("")
    ui.info(" " + tr(summary["disclaimer"]))


def render_ssh(ui: UI, st, pend: dict[str, Any] | None = None) -> None:
    ui.heading("SSH MANAGEMENT")
    if not st.installed:
        ui.error("OpenSSH server is not installed.")
        return
    pw, pws = yn(st.password_auth)
    pk, pks = yn(st.pubkey_auth)
    unit = st.service_unit or "?"
    state = "active" if st.service_active else "inactive"
    mode_txt = f"socket activation ({st.socket_unit})" if st.mode == "socket" else "service"
    cfg_ports = ", ".join(map(str, st.config_ports))
    ui.kv([
        ("Service", f"{unit} ({state}), mode: {mode_txt}", None),
        ("Listening ports", ", ".join(map(str, st.listening_ports)) or "none detected", "ok" if st.listening_ports else "bad"),
        ("Configured ports", f"{cfg_ports}  (ignored: socket activation)" if st.mode == "socket" else cfg_ports, None),
        ("Config valid", {True: "yes", False: f"NO - {st.config_error[:60]}", None: "unknown (needs root)"}[st.config_valid],
         {True: "ok", False: "bad", None: "dim"}[st.config_valid]),
        ("Password login", pw, pws),
        ("Keyboard-interactive", "Enabled" if st.kbd_interactive else "Disabled", "warn" if st.kbd_interactive and not st.password_auth else None),
        ("Public key auth", pk, pks),
        ("Root login", f"{st.root_login}  - {tr(st.root_label)}", "warn" if st.root_login == "yes" else None),
        ("Root password login", "possible" if st.root_password_login else "not possible", "bad" if st.root_password_login else "ok"),
        ("MaxAuthTries", st.max_auth_tries, None), ("LoginGraceTime", f"{st.login_grace_time}s", None),
        ("AuthenticationMethods", st.authentication_methods, None), ("TCP forwarding", st.forwarding, None),
        ("Config source", f"{st.source}  ({tr(st.note)})" if st.note else st.source, "dim"),
    ])
    ui.info(" " + tr(st.root_detail))
    for m in st.match_overrides:
        ui.text(f" Match override: {m}", "warn")
    if pend:
        render_pending(ui, pend)


def render_fail2ban(ui: UI, ov) -> None:
    ui.heading("FAIL2BAN PROTECTION")
    if not ov.installed:
        ui.error("Fail2ban is not installed. Run: sudo bant fail2ban enable")
        return
    label, style = F2B_LABELS.get(ov.state, (ov.state, None))
    ui.kv([
        ("Protection", label, style), ("Version", ov.version, None),
        ("Service", f"{ov.service} (starts at boot)" if ov.enabled_on_boot else f"{ov.service} (NOT enabled at boot)", "ok" if ov.service == "active" else "bad"),
        ("SSH jail", "Enabled, running" if ov.jail_running else ("Defined, not running" if ov.jail_enabled else "Not defined"), "ok" if ov.jail_running else "bad"),
        ("Protected SSH port(s)", ", ".join(map(str, ov.ports)) or "-", None),
        ("Max attempts", ov.maxretry, None), ("Detection window", ov.findtime, None), ("Ban duration", ov.bantime, None),
        ("Log backend", ov.backend, None), ("Ban action", ov.banaction, None),
        ("Currently banned", "-" if ov.currently_banned is None else ov.currently_banned, None),
        ("Total banned", "-" if ov.total_banned is None else ov.total_banned, None),
    ])
    if ov.checks:
        ui.section("Verification")
        for c in ov.checks:
            mark = {True: "ok", False: "bad", None: "warn"}[c.ok]
            ui.text(f" {ui.glyph('ok' if c.ok else ('bad' if c.ok is False else 'warn'))} {tr(c.name)}"
                    + (f" - {tr(c.detail)}" if c.detail and c.ok is not True else ""), mark, raw=True)
    for c in ov.conflicts:
        ui.text(f" Administrator override: {c}", "warn")


def render_firewall(ui: UI, info, rules: list[dict[str, Any]], listeners) -> None:
    ui.heading("FIREWALL")
    ui.kv([("Backend", info.backend, None), ("Active", "yes" if info.active else "no", "ok" if info.active else "warn"),
           ("Bant mode", "manage" if info.mode == "manage" else "observation only", "ok" if info.mode == "manage" else "warn"),
           ("Inbound filtered", "yes" if info.restrictive else "no / unknown", None),
           ("Docker detected", "yes (rules left untouched)" if info.docker else "no", None),
           ("Detail", tr(info.detail), "dim")])
    ui.section("Bant-managed allowances")
    ui.table(["ID", "Backend", "Port", "Purpose", "Added"], [[r["id"], r["backend"], f"{r['port']}/{r['proto']}", r["purpose"], fmt_ts(r["added"])] for r in rules])
    ui.section("Listening sockets")
    seen = sorted({(lst.proto, lst.port, lst.addr, lst.process, lst.scope) for lst in listeners})
    ui.table(["Proto", "Port", "Address", "Process", "Exposure"], [[a, b, c, d or "-", e] for a, b, c, d, e in seen],
             ["warn" if s[4] == "public" else None for s in seen])


def render_doctor(ui: UI, checks) -> None:
    ui.heading("BANT DOCTOR", "deep diagnostics")
    area = None
    for c in checks:
        if c.area != area:
            ui.section(tr(c.area))
            area = c.area
        mark = ui.glyph({"ok": "ok", "warn": "warn", "fail": "bad", "skip": "skip"}[c.status])
        ui.text(f" {mark} {tr(c.name)}" + (f" - {tr(c.detail, record=False)}" if c.detail else ""), style_for_state(c.status), raw=True)
    fails = sum(1 for c in checks if c.status == "fail")
    warns = sum(1 for c in checks if c.status == "warn")
    ui.text("")
    ui.text(f" {len(checks)} checks: {fails} failed, {warns} warnings", "bad" if fails else ("warn" if warns else "ok"))


def render_updates(ui: UI, st) -> None:
    ui.heading("SECURITY UPDATES")
    ui.kv([("unattended-upgrades", "installed" if st.installed else "not installed", None),
           ("Automatic updates", "ON" if st.auto_enabled else "OFF", "ok" if st.auto_enabled else "warn"),
           ("Managed by Bant", "yes" if st.managed_by_bant else "no", None),
           ("Security origin allowed", {True: "yes", False: "NO", None: "unknown"}[st.security_origin_allowed], None),
           ("Automatic reboot", "enabled (your configuration)" if st.auto_reboot else "disabled", None),
           ("Pending security", f"{len(st.pending_security)}" + (" (" + ", ".join(st.pending_security[:5]) + ")" if st.pending_security else ""), "warn" if st.pending_security else "ok"),
           ("Pending total", st.pending_total if st.pending_total is not None else "unknown", None),
           ("Package index age", f"{st.index_age_hours}h" if st.index_age_hours is not None else "unknown", None),
           ("Reboot required", "YES" if st.reboot_required else "no", "warn" if st.reboot_required else None),
           ("Package manager busy", "yes" if st.package_manager_busy else "no", None)])
    ui.info(" Pending counts come from the local package index (no `apt update` is run).")


def render_logs(ui: UI, records: list[dict[str, Any]]) -> None:
    if not records:
        ui.info("  (no matching log entries)")
        return
    for r in records:
        style = {"warning": "warn", "error": "bad"}.get(r.get("level", ""), None)
        detail = " ".join(f"{k}={v}" for k, v in (r.get("detail") or {}).items())
        ui.text(f" {r['ts']}  {r['event']:<22} {r.get('actor', '')}  {detail}"[: ui.width * 3], style, raw=True)


def render_setup(ui: UI, report: dict[str, Any]) -> None:
    ui.heading(f"BANT v{__version__} SETUP")
    for s in report["steps"]:
        mark = ui.glyph({"done": "ok", "already": "ok", "skipped": "skip", "pending": "wait", "failed": "bad", "planned": "wait"}.get(s["status"], "skip"))
        ui.text(f" {mark} {tr(s['step'])}: {tr(s['detail'])}",
                {"done": "ok", "already": "ok", "pending": "warn", "failed": "bad"}.get(s["status"]), raw=True)
    ui.text("")
    outcome = report["outcome"]
    summary = report.get("summary") or {}
    if outcome == "dry_run":
        ui.warn("DRY RUN - nothing was changed. The steps above show what setup would do.")
    elif outcome == "complete":
        ui.success("Setup complete.")
    elif outcome == "pending_confirmation":
        ui.warn("Setup is NOT finished: the SSH migration is waiting for your confirmation.")
    else:
        ui.warn("Setup is incomplete - see the steps above.")
    if outcome == "incomplete" and summary:
        ui.section("Setup report")
        rows = [("Completed", ", ".join(tr(x) for x in summary["completed"]) or "-", "ok"),
                ("Not done yet", ", ".join(tr(x) for x in summary["remaining"]) or "-", None),
                ("Rolled back", "yes - the previous SSH configuration was restored" if summary["rolled_back"] else "no", None)]
        ui.kv(rows)
        for f in summary["failed"]:
            ui.text(f" {ui.glyph('bad')} {tr(f['step'])}: {tr(f['reason'])}", "bad", raw=True)
    if report.get("ssh_port"):
        from bant.core.ports import DESCRIPTIONS
        ui.text("")
        ui.text(f" SSH port: {report['ssh_port']}  ({DESCRIPTIONS.get(report.get('port_source') or '', '')})", "title")
    if report.get("pending"):
        render_pending(ui, report["pending"])
    if report["next_steps"]:
        ui.section("Next steps")
        for n in report["next_steps"]:
            ui.bullet(n)


def human_duration(seconds: int) -> str:
    return humanize_duration(seconds)


def render_update_info(ui: UI, info: dict[str, Any]) -> None:
    ui.heading("BANT UPDATE")
    ui.kv([("Installed version", info["current"], None), ("Update channel", info["channel"], None),
           ("Latest release", info["latest"] or "none found", None)])
    if info["available"]:
        kind = "pre-release" if info["prerelease"] else "stable release"
        ui.text(f" Update available: {info['latest']} ({tr(kind)})", "warn")
        if info.get("url"):
            ui.text(f" Release notes: {info['url']}", "dim")
    else:
        ui.success(f"Bant {info['current']} is up to date.")


def render_selfupdate_status(ui: UI, st: dict[str, Any]) -> None:
    ui.heading("BANT UPDATE SETTINGS")
    last = fmt_ts(st["last_checked"]) if st["last_checked"] else "never"
    ui.kv([("Installed version", st["current"], None), ("Update channel", st["channel"], None), ("Last check", last, None),
           ("Latest known", st["latest"] or "unknown", None),
           ("Update available", "yes" if st["available"] else "no", "warn" if st["available"] else None),
           ("Daily check", "on (check only)" if st["daily_check"] else "off", None),
           ("Previous version kept", st["previous_version"] or "none", None)])


F2B_CONFLICT_LABELS = {"conflict": ("different", "warn"), "duplicate": ("same value", "ok"), "admin-only": ("administrator only", None)}


def render_f2b_conflicts(ui: UI, items: list[dict[str, Any]], plan: list[dict[str, str]]) -> None:
    ui.heading("FAIL2BAN CONFIGURATION CONFLICTS")
    if not items:
        ui.success("No administrator file sets [sshd] options that Bant also manages.")
        return
    ui.text(" Fail2ban reads jail.conf, jail.d/*.conf, jail.local, jail.d/*.local in that order; [sshd] beats [DEFAULT].", "dim")
    ui.text(" Bant leaves out of its own jail every key you define for [sshd] the next time it writes it.", "dim")
    rows = []
    for i in items:
        label, _style = F2B_CONFLICT_LABELS[i["status"]]
        if i["accepted"]:
            label = "kept by you"
        rows.append([i["key"], i["file"], i["value"], i["bant"] if i["bant"] is not None else "-", i["effective"] or "-", i.get("winner", ""), tr(label)])
    ui.table(["Key", "File", "Your value", "Bant's value", "In use", "Source", "Result"], rows)
    real = [i for i in items if i["status"] == "conflict" and not i["accepted"]]
    if real:
        ui.warn(f" {len(real)} setting(s) differ from what Bant would use.")
    else:
        ui.success("No real conflicts: overlapping settings have the same value, so no warning is needed.")
    ui.section("If Bant takes over (adopt)")
    for p in plan:
        ui.text(f" {p['key']}: {p['before']} -> {p['after']}" + ("" if p["change"] == "changes" else "  (" + tr("unchanged") + ")"), raw=True)
    ui.info(" Resolve with: sudo bant fail2ban conflicts --resolve keep   (or --resolve adopt; add --dry-run to preview)")


def render_overview_summary(ui: UI, d: dict[str, Any]) -> None:
    """Short version of `bant status` for the overview menu: what matters, then anything abnormal."""
    ssh, f2b, fw = d["ssh"], d["fail2ban"], d["firewall"]
    pk, pks = yn(ssh["pubkey_auth"])
    pw, pws = yn(ssh["password_auth"])
    f2_label, f2_style = F2B_LABELS.get(f2b["state"], (f2b["state"], None))
    counts = d["findings"]["summary"]
    ui.kv([
        ("Security status", tr(d["health"]).upper(), style_for_state(d["health"])),
        ("SSH port", ", ".join(map(str, ssh["ports"])) or "unknown", "ok" if len(ssh["ports"]) == 1 and ssh["ports"][0] != 22 else "warn"),
        ("Password login", pw, pws), ("Public key auth", pk, pks),
        ("Root login", tr(ssh["root_label"]) if ssh["root_label"] else ssh["root_login"], "warn" if ssh["root_login"] == "yes" else None),
        ("Fail2ban", f2_label, f2_style),
        ("Banned IPs", f"{d['bans']['fail2ban']} (Fail2ban)  {d['bans']['bant']} (Bant)", None),
        ("Firewall", f"{fw['backend']} ({fw['mode']})" if fw["active"] else "none detected", "ok" if fw["active"] else "warn"),
        ("Critical / High", f"{counts['critical']} / {counts['high']}", "bad" if counts["critical"] or counts["high"] else "ok"),
    ], label_width=16)
    alerts = [f"[{tr(f['severity']).upper()}] {tr(f['title'])}" for f in d["findings"]["critical_and_high"][:5]]
    alerts += [tr(p) for p in f2b.get("problems", [])[:3]] + [tr(c) for c in f2b.get("conflicts", [])[:3]]
    if ssh.get("pending"):
        render_pending(ui, ssh["pending"])
    if alerts:
        ui.section("Alerts")
        for a in alerts:
            ui.text(f" ! {a}", "warn", raw=True)
    else:
        ui.success("No alerts.")
