"""Human-readable rendering of core data structures (used by both CLI and TUI)."""

from __future__ import annotations

import time
from typing import Any

from bant import __version__
from bant.core.security_audit import SEVERITIES, Finding
from bant.ui import SEV_STYLE, UI, style_for_state
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
        ui.text(f" Open a NEW terminal and log in on TCP {pend['target']}, then run: sudo bant ssh confirm", "warn")
    else:
        ui.text(" Open a NEW session (using your key) and run: sudo bant ssh confirm", "warn")
    ui.text(" To undo now: sudo bant ssh rollback", "dim")


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
        ("OS", d["os"]["name"] + ("" if d["os"]["supported"] else "  (unsupported release)"), None if d["os"]["supported"] else "warn"),
        ("Kernel", d["os"]["kernel"], None),
        ("SSH port", ports, "ok" if len(ssh["ports"]) == 1 and ssh["ports"][0] != 22 else "warn"),
        ("Password login", pw, pws), ("Public key auth", pk, pks),
        ("Root login", ssh["root_label"] or ssh["root_login"], "warn" if ssh["root_login"] == "yes" else None),
        ("Fail2ban", f2_label, f2_style),
        ("SSH jail ports", ", ".join(map(str, f2b["ports"])) or "-", None),
        ("Firewall", fw_label, "ok" if fw["active"] else "warn"),
        ("Banned IPs", f"{d['bans']['fail2ban']} (Fail2ban)  {d['bans']['bant']} (Bant)", None),
    ]
    if d.get("updates"):
        u = d["updates"]
        rows.append(("Security updates", f"{'auto' if u['auto_enabled'] else 'manual'}; {u['pending_security']} pending"
                     + ("; reboot required" if u["reboot_required"] else ""), "warn" if u["pending_security"] else "ok"))
    counts = d["findings"]["summary"]
    rows.append(("Critical / High", f"{counts['critical']} / {counts['high']}", "bad" if counts["critical"] or counts["high"] else "ok"))
    rows.append(("Security status", d["health"].upper(), health_style))
    ui.kv(rows)
    if ssh.get("pending"):
        render_pending(ui, ssh["pending"])
    for f in d["findings"]["critical_and_high"][:5]:
        ui.text(f" ! [{f['severity'].upper()}] {f['title']}", SEV_STYLE[f["severity"]])
    for n in d.get("notes", []):
        ui.info(f" note: {n}")
    if not d["privileged"]:
        ui.info(" Running without root: some values are approximate. Use sudo for full detail.")


def render_findings(ui: UI, findings: list[Finding], summary: dict[str, Any], verbose: bool = True) -> None:
    ui.heading("SECURITY AUDIT", "configuration review - not a guarantee")
    c = summary["counts"]
    ui.text("  " + "   ".join(f"{s.capitalize()}: {c[s]}" for s in SEVERITIES))
    ui.text(f"  {summary['verdict']}", "bad" if c["critical"] or c["high"] else ("warn" if c["medium"] else "ok"))
    for f in findings:
        if f.severity == "info" and not verbose:
            continue
        ui.text("")
        ui.text(f" [{f.severity.upper()}] {f.id}  {f.title}", SEV_STYLE[f.severity])
        ui.text(f"   Evidence:       {f.evidence}")
        if f.severity != "info" or f.impact != "None":
            ui.text(f"   Impact:         {f.impact}")
        ui.text(f"   Recommendation: {f.recommendation}")
        if f.fixable:
            ui.text(f"   Bant can fix:   yes  ({f.fix})" if f.fix else "   Bant can fix:   yes", "ok")
    ui.text("")
    ui.info(f" {summary['disclaimer']}")


def render_ssh(ui: UI, st, pend: dict[str, Any] | None = None) -> None:
    ui.heading("SSH MANAGEMENT")
    if not st.installed:
        ui.error("OpenSSH server is not installed.")
        return
    pw, pws = yn(st.password_auth)
    pk, pks = yn(st.pubkey_auth)
    ui.kv([
        ("Service", f"{st.service_unit or '?'} ({'active' if st.service_active else 'inactive'}), mode: "
                    + ("socket activation (" + str(st.socket_unit) + ")" if st.mode == "socket" else "service"), None),
        ("Listening ports", ", ".join(map(str, st.listening_ports)) or "none detected", "ok" if st.listening_ports else "bad"),
        ("Configured ports", ", ".join(map(str, st.config_ports)) + ("  (ignored: socket activation)" if st.mode == "socket" else ""), None),
        ("Config valid", {True: "yes", False: "NO - " + st.config_error[:60], None: "unknown (needs root)"}[st.config_valid],
         {True: "ok", False: "bad", None: "dim"}[st.config_valid]),
        ("Password login", pw, pws),
        ("Keyboard-interactive", "Enabled" if st.kbd_interactive else "Disabled", "warn" if st.kbd_interactive and not st.password_auth else None),
        ("Public key auth", pk, pks),
        ("Root login", f"{st.root_login}  - {st.root_label}", "warn" if st.root_login == "yes" else None),
        ("Root password login", "possible" if st.root_password_login else "not possible", "bad" if st.root_password_login else "ok"),
        ("MaxAuthTries", st.max_auth_tries, None), ("LoginGraceTime", st.login_grace_time + "s", None),
        ("AuthenticationMethods", st.authentication_methods, None), ("TCP forwarding", st.forwarding, None),
        ("Config source", st.source + (f"  ({st.note})" if st.note else ""), "dim"),
    ])
    ui.info(f" {st.root_detail}")
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
        ("Service", f"{ov.service}{' (starts at boot)' if ov.enabled_on_boot else ' (NOT enabled at boot)'}", "ok" if ov.service == "active" else "bad"),
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
            ui.text(f" {ui.glyph('ok' if c.ok else ('bad' if c.ok is False else 'warn'))} {c.name}" + (f" - {c.detail}" if c.detail and c.ok is not True else ""), mark)
    for c in ov.conflicts:
        ui.text(f" Administrator override: {c}", "warn")


def render_firewall(ui: UI, info, rules: list[dict[str, Any]], listeners) -> None:
    ui.heading("FIREWALL")
    ui.kv([("Backend", info.backend, None), ("Active", "yes" if info.active else "no", "ok" if info.active else "warn"),
           ("Bant mode", "manage" if info.mode == "manage" else "observation only", "ok" if info.mode == "manage" else "warn"),
           ("Inbound filtered", "yes" if info.restrictive else "no / unknown", None),
           ("Docker detected", "yes (rules left untouched)" if info.docker else "no", None),
           ("Detail", info.detail, "dim")])
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
            ui.section(c.area)
            area = c.area
        mark = ui.glyph({"ok": "ok", "warn": "warn", "fail": "bad", "skip": "skip"}[c.status])
        ui.text(f" {mark} {c.name}" + (f" - {c.detail}" if c.detail else ""), style_for_state(c.status))
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
        ui.text(f" {r['ts']}  {r['event']:<22} {r.get('actor', '')}  {detail}"[: ui.width * 3], style)


def render_setup(ui: UI, report: dict[str, Any]) -> None:
    ui.heading(f"BANT v{__version__} SETUP")
    for s in report["steps"]:
        mark = ui.glyph({"done": "ok", "skipped": "skip", "pending": "wait", "failed": "bad"}[s["status"]])
        ui.text(f" {mark} {s['step']}: {s['detail']}", {"done": "ok", "pending": "warn", "failed": "bad"}.get(s["status"]))
    ui.text("")
    outcome = report["outcome"]
    if outcome == "complete":
        ui.success("Setup complete.")
    elif outcome == "pending_confirmation":
        ui.warn("Setup is NOT finished: the SSH migration is waiting for your confirmation.")
    else:
        ui.warn("Setup is incomplete - see the steps above.")
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
