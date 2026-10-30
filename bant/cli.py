"""Command-line interface. Every command calls the same core functions the TUI uses."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Sequence
from typing import Any

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
    setup,
    ssh,
    status,
    uninstall,
    updater,
    updates,
)
from bant.core.rollback import TxManager
from bant.errors import (
    EX_ERROR,
    EX_OK,
    EX_UNHEALTHY,
    EX_USAGE,
    BantError,
    OperationFailed,
    UsageError,
    ValidationError,
)
from bant.i18n import tr
from bant.presenters import (
    fmt_ts,
    render_doctor,
    render_fail2ban,
    render_findings,
    render_firewall,
    render_logs,
    render_pending,
    render_setup,
    render_ssh,
    render_status,
    render_updates,
)
from bant.ui import UI, Abort, stream_shows_cjk
from bant.utils.validation import (
    parse_duration,
    parse_int_range,
    parse_ip,
    parse_onoff,
    parse_port,
    parse_proto,
)

Handler = Callable[[argparse.Namespace, Context, UI], int]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose help texts are translated into the active interface language."""

    def __init__(self, *args, **kwargs):
        want_help = kwargs.pop("add_help", True)
        super().__init__(*args, add_help=False, **kwargs)
        if want_help:
            self.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help="show this help message and exit")

    def add_argument(self, *args, help=None, **kwargs):  # noqa: A002 - argparse's own parameter name
        return super().add_argument(*args, help=tr(help) if help else help, **kwargs)

    def add_argument_group(self, title=None, *args, **kwargs):
        return super().add_argument_group(tr(title) if title else title, *args, **kwargs)


def _common() -> argparse.ArgumentParser:
    p = _Parser(add_help=False)
    g = p.add_argument_group("global options")
    g.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="machine-readable JSON output")
    g.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS,
                   help="show what would change without changing anything")
    g.add_argument("-y", "--yes", action="store_true", default=argparse.SUPPRESS, help="assume yes for confirmations")
    g.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help="disable colours")
    g.add_argument("--lang", choices=sorted(i18n.LANGS), default=argparse.SUPPRESS, help="interface language for this run (en, zh)")
    return p


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    parser = _Parser(
        prog="bant", parents=[common], formatter_class=argparse.RawDescriptionHelpFormatter,
        description=tr("Bant - lightweight Linux VPS security manager.") + "\n\n" + tr("Run `sudo bant` with no arguments for the interactive menu."),
        epilog=tr("Docs: https://github.com/VAR7IANT/Bant  |  Lost access? See docs/RECOVERY.md"),
    )
    parser.add_argument("--version", action="version", version=f"bant {__version__}", help="show program's version number and exit")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def add(name: str, help_: str, handler: Handler, **kw: Any) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, parents=[common], help=tr(help_), description=tr(help_), **kw)
        sp.set_defaults(handler=handler)
        return sp

    add("version", "show the Bant version", cmd_version)
    p = add("lang", "show or set the interface language (English / 繁體中文)", cmd_lang)
    p.add_argument("code", nargs="?", choices=sorted(i18n.LANGS), help="en or zh")
    p = add("status", "security overview (read-only)", cmd_status)
    p.add_argument("--deep", action="store_true", help="include slower checks (update simulation, log scans)")
    add("doctor", "deep diagnostics: installed vs running vs verified", cmd_doctor)
    p = add("audit", "security audit with evidence and recommendations", cmd_audit)
    p.add_argument("--fail-on", choices=security_audit.SEVERITIES[:4], help="exit 8 if a finding of this severity or worse exists")
    p.add_argument("--quiet-info", action="store_true", help="hide informational findings")
    p = add("logs", "view Bant audit trail, SSH or Fail2ban logs", cmd_logs)
    p.add_argument("source", nargs="?", default="audit", choices=logs.SOURCES)
    p.add_argument("-n", "--lines", type=int, default=50)
    p.add_argument("--grep", help="case-insensitive filter")

    # ssh
    ssh_p = add("ssh", "SSH management (default: status)", cmd_ssh_status)
    ssub = ssh_p.add_subparsers(dest="ssh_cmd", metavar="<action>")

    def sadd(name: str, help_: str, handler: Handler) -> argparse.ArgumentParser:
        sp = ssub.add_parser(name, parents=[common], help=tr(help_), description=tr(help_))
        sp.set_defaults(handler=handler)
        return sp

    sadd("status", "show SSH state", cmd_ssh_status)
    sp = sadd("port", "show or change the SSH port (safe migration; 'random' picks a free random port)", cmd_ssh_port)
    sp.add_argument("port", nargs="?", help="TCP port (1-65535) or 'random'")
    sp.add_argument("--minutes", type=int, help="rollback window in minutes (default from config: 10)")
    sp = sadd("password", "turn SSH password login on or off", cmd_ssh_password)
    sp.add_argument("value", choices=["on", "off"])
    sp = sadd("root", "show or set the root login policy", cmd_ssh_root)
    sp.add_argument("value", nargs="?", choices=["yes", "key-only", "no", "forced-commands-only"])
    sp = sadd("set", "set a hardening option", cmd_ssh_set)
    sp.add_argument("option", choices=sorted(ssh.OPTION_SPECS))
    sp.add_argument("value")
    sadd("confirm", "confirm a pending SSH change after logging in through the NEW path", cmd_ssh_confirm)
    sadd("rollback", "undo a pending SSH change now", cmd_ssh_rollback)
    sp = sadd("extend", "extend the rollback deadline", cmd_ssh_extend)
    sp.add_argument("minutes", nargs="?", type=int, default=10)

    # fail2ban
    f_p = add("fail2ban", "Fail2ban protection (default: status)", cmd_f2b_status)
    fsub = f_p.add_subparsers(dest="f2b_cmd", metavar="<action>")

    def fadd(name: str, help_: str, handler: Handler) -> argparse.ArgumentParser:
        sp = fsub.add_parser(name, parents=[common], help=tr(help_), description=tr(help_))
        sp.set_defaults(handler=handler)
        return sp

    fadd("status", "show Fail2ban and SSH jail state", cmd_f2b_status)
    fadd("enable", "install/configure Fail2ban and enable SSH protection", cmd_f2b_enable)
    fadd("disable", "stop and disable Fail2ban (protection OFF)", cmd_f2b_disable)
    fadd("banned", "list banned IPs (Fail2ban and Bant)", cmd_banned)
    sp = fadd("ban", "ban an IP", cmd_ban)
    sp.add_argument("ip")
    sp.add_argument("--permanent", action="store_true", help="permanent block (Bant-owned nftables table)")
    sp.add_argument("--duration", help="custom duration (e.g. 12h) - Bant-owned block")
    sp.add_argument("--reason", default="manual")
    sp.add_argument("--force", action="store_true", help="allow banning an address that may be you")
    sp = fadd("unban", "remove a ban", cmd_unban)
    sp.add_argument("ip")
    sp = fadd("set", "change maxretry / findtime / bantime", cmd_f2b_set)
    sp.add_argument("key", choices=["maxretry", "findtime", "bantime"])
    sp.add_argument("value")
    fadd("trusted", "list trusted (never banned) addresses", cmd_trusted)
    sp = fadd("trust", "add a trusted address", cmd_trust)
    sp.add_argument("ip")
    sp = fadd("untrust", "remove a trusted address", cmd_untrust)
    sp.add_argument("ip")

    # firewall
    w_p = add("firewall", "firewall status and Bant-managed rules (default: status)", cmd_fw_status)
    wsub = w_p.add_subparsers(dest="fw_cmd", metavar="<action>")

    def wadd(name: str, help_: str, handler: Handler) -> argparse.ArgumentParser:
        sp = wsub.add_parser(name, parents=[common], help=tr(help_), description=tr(help_))
        sp.set_defaults(handler=handler)
        return sp

    wadd("status", "show firewall backend, Bant rules and listening ports", cmd_fw_status)
    sp = wadd("allow", "allow a port (Bant-owned rule)", cmd_fw_allow)
    sp.add_argument("port")
    sp.add_argument("--proto", default="tcp", choices=["tcp", "udp"])
    sp = wadd("remove", "remove a Bant-owned port allowance", cmd_fw_remove)
    sp.add_argument("port")
    sp.add_argument("--proto", default="tcp", choices=["tcp", "udp"])
    sp = wadd("block", "block an IP/CIDR in Bant's own nftables table", cmd_ban)
    sp.add_argument("ip")
    sp.add_argument("--duration")
    sp.add_argument("--reason", default="manual")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(permanent=False, _from_fw=True)
    sp = wadd("unblock", "remove a Bant block", cmd_unban)
    sp.add_argument("ip")
    wadd("blocked", "list all bans (Fail2ban + Bant)", cmd_banned)
    wadd("trusted", "list trusted addresses", cmd_trusted)
    sp = wadd("trust", "add a trusted address", cmd_trust)
    sp.add_argument("ip")
    sp = wadd("untrust", "remove a trusted address", cmd_untrust)
    sp.add_argument("ip")

    # updates
    u_p = add("updates", "automatic security updates (default: status)", cmd_updates_status)
    usub = u_p.add_subparsers(dest="upd_cmd", metavar="<action>")
    for name, h, fn in (("status", "show update state", cmd_updates_status), ("enable", "enable automatic security updates", cmd_updates_enable),
                        ("disable", "remove Bant's update settings", cmd_updates_disable)):
        usub.add_parser(name, parents=[common], help=tr(h), description=tr(h)).set_defaults(handler=fn)

    p = add("backup", "back up Bant-relevant configuration", cmd_backup)
    p.add_argument("--note", default="manual")
    p.add_argument("--list", action="store_true", help="list existing backups")
    p = add("restore", "restore a configuration backup (default: latest)", cmd_restore)
    p.add_argument("backup_id", nargs="?", default="latest")
    p.add_argument("--list", action="store_true")
    add("repair", "reconcile Bant state, timers, Fail2ban policy and firewall registry", cmd_repair)
    p = add("setup", "first-run setup: baseline, Fail2ban, SSH migration (used by install.sh)", cmd_setup)
    p.add_argument("--no-ssh-migration", action="store_true")
    p.add_argument("--no-fail2ban", action="store_true")
    p.add_argument("--no-update-check", action="store_true", help="do not enable the daily check for new Bant releases")
    p.add_argument("--ssh-port", help="SSH port to use: a number, or 'random' (default: random free port, or keep an existing custom port)")
    p.add_argument("--minutes", type=int)
    su_p = add("self-update", "check for and install Bant updates (default: check, then offer to install)", cmd_selfupdate)
    su_p.add_argument("--quiet", action="store_true", help="print only when an update is available or something fails")
    susub = su_p.add_subparsers(dest="su_cmd", metavar="<action>")

    def suadd(name: str, help_: str, handler: Handler) -> argparse.ArgumentParser:
        sp = susub.add_parser(name, parents=[common], help=tr(help_), description=tr(help_))
        sp.set_defaults(handler=handler)
        return sp

    sp = suadd("check", "look for a newer release (read-only)", cmd_su_check)
    sp.add_argument("--quiet", action="store_true", help="print only when an update is available or something fails")
    sp = suadd("apply", "download, verify and install the newest (or a given) release", cmd_su_apply)
    sp.add_argument("--version", help="install this release instead of the newest, e.g. 0.2.0")
    sp.add_argument("--allow-downgrade", action="store_true", help="allow installing an older release")
    suadd("rollback", "switch back to the previously installed version", cmd_su_rollback)
    suadd("status", "installed version, channel, last check, daily check state", cmd_su_status)
    sp = suadd("notify", "turn the daily update CHECK (never an install) on or off", cmd_su_notify)
    sp.add_argument("value", choices=["on", "off"])
    sp = suadd("channel", "which releases count: auto, stable or prerelease", cmd_su_channel)
    sp.add_argument("value", choices=list(updater.CHANNELS))

    p = add("uninstall", "remove Bant safely (SSH port and Fail2ban settings are kept)", cmd_uninstall)
    p.add_argument("--purge", action="store_true", help="also delete backups, logs and configuration")
    p.add_argument("--remove-fail2ban-config", action="store_true")

    p = sub.add_parser("_tx-finish", parents=[common])
    p.add_argument("tx_id")
    p.add_argument("outcome")
    p.set_defaults(handler=cmd_tx_finish)
    sub.add_parser("_fw-apply", parents=[common]).set_defaults(handler=cmd_fw_apply)
    return parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def emit(args: argparse.Namespace, ui: UI, data: Any, human: Callable[[], None] | None = None) -> None:
    if getattr(args, "json", False):
        print(json.dumps(data, indent=2, default=_json_default), file=ui.stream)
    elif human:
        human()


def _plan_footer(ctx: Context, ui: UI) -> None:
    if ctx.dry_run:
        ui.text("")
        ui.warn("DRY RUN - nothing was changed. Actions that would run:")
        for line in ctx.planned:
            ui.bullet(line)


def _need_confirm(args: argparse.Namespace, ui: UI, question: str, default: bool = False) -> bool:
    if getattr(args, "yes", False) or getattr(args, "dry_run", False):
        return True
    if not sys.stdin.isatty():
        raise UsageError("Confirmation required but stdin is not a terminal.", hint="Re-run with --yes to proceed non-interactively.")
    return ui.confirm(question, default)


def _json_default(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return {k: getattr(obj, k) for k in obj.__dataclass_fields__}
    return str(obj)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_version(args, ctx, ui) -> int:
    emit(args, ui, {"name": "bant", "version": __version__}, lambda: ui.text(f"bant {__version__}", raw=True))
    return EX_OK


def cmd_lang(args, ctx, ui) -> int:
    if args.code is None:
        code, source = i18n.resolve(ctx)
        shown = code or i18n.locale_hint() or i18n.DEFAULT
        emit(args, ui, {"language": shown, "source": source},
             lambda: ui.kv([("Language", f"{i18n.LANGS[shown]} ({shown})", "ok"), ("Chosen via", source, None)]))
        return EX_OK
    where = i18n.save(ctx, args.code)
    i18n.set_language(args.code if stream_shows_cjk(ui.stream) or args.code == "en" else "en")
    emit(args, ui, {"language": args.code, "saved": where},
         lambda: ui.success("Language set to English." if args.code == "en" else "語言已設定為繁體中文。"))
    return EX_OK


def cmd_status(args, ctx, ui) -> int:
    data = status.collect(ctx, deep=args.deep)
    emit(args, ui, data, lambda: render_status(ui, data))
    return EX_OK


def cmd_doctor(args, ctx, ui) -> int:
    checks = status.doctor(ctx)
    emit(args, ui, [c.to_dict() for c in checks], lambda: render_doctor(ui, checks))
    return EX_UNHEALTHY if any(c.status == "fail" for c in checks) else EX_OK


def cmd_audit(args, ctx, ui) -> int:
    findings = security_audit.run(ctx)
    summary = security_audit.summarize(findings)
    emit(args, ui, {"summary": summary, "findings": [f.to_dict() for f in findings]},
         lambda: render_findings(ui, findings, summary, verbose=not args.quiet_info))
    if args.fail_on:
        limit = security_audit.SEVERITIES.index(args.fail_on)
        if any(security_audit.SEVERITIES.index(f.severity) <= limit for f in findings):
            return EX_UNHEALTHY
    return EX_OK


def cmd_logs(args, ctx, ui) -> int:
    if args.source == "audit":
        recs = ctx.audit_log.read(args.lines, args.grep)
        emit(args, ui, recs, lambda: render_logs(ui, recs))
    else:
        lines = logs.read_lines(ctx, args.source, args.lines, args.grep)
        emit(args, ui, lines, lambda: [ui.text(" " + ln, raw=True) for ln in lines] or ui.info("  (no entries)"))
    return EX_OK


def cmd_ssh_status(args, ctx, ui) -> int:
    st = ssh.status(ctx)
    pend = migration.describe_pending(ctx)
    emit(args, ui, {"status": st, "pending": pend}, lambda: render_ssh(ui, st, pend))
    return EX_OK


def _print_port_plan(ui: UI, p: migration.PortPlan) -> None:
    ui.section(f"Plan: move SSH to TCP {p.target}")
    ui.kv([("Current port(s)", ", ".join(map(str, p.old_ports)), None), ("Activation", p.mode, None)])
    for s in p.steps:
        ui.bullet(s)
    for w in p.warnings:
        ui.text(f" ! {tr(w)}", "warn", raw=True)
    for b in p.blockers:
        ui.text(f" {ui.glyph('bad')} {tr(b)}", "bad", raw=True)


def cmd_ssh_port(args, ctx, ui) -> int:
    if args.port is None:
        st = ssh.status(ctx)
        configured = ctx.config.ssh_port or None
        emit(args, ui, {"ports": st.active_ports, "configured": st.config_ports, "bant_port": configured},
             lambda: ui.kv([("SSH port(s)", ", ".join(map(str, st.active_ports)), "ok"),
                            ("Bant-managed port", configured or "not chosen yet (random on first setup)", None)]))
        return EX_OK
    ctx.require_root("Moving the SSH port")
    port, source = ports.resolve_target(ctx, args.port)
    if source == "random" and not getattr(args, "json", False):
        ui.info(f"Random free port chosen: {port}")
    if args.minutes is not None:
        parse_int_range(args.minutes, 1, 1440, "--minutes")
    p = migration.plan(ctx, port)
    if not getattr(args, "json", False):
        _print_port_plan(ui, p)
    if p.blockers:
        raise OperationFailed("Cannot migrate: " + " ".join(p.blockers),
                              hint="Choose another port, or let Bant pick one: `sudo bant ssh port random`." if any("in use" in b for b in p.blockers) else None)
    if p.already_done:
        out = migration.begin(ctx, port)
        emit(args, ui, out, lambda: ui.success(f"SSH already uses TCP {port}; firewall and Fail2ban verified."))
        return EX_OK
    if not _need_confirm(args, ui, f"Start migration to TCP {port}? (old port stays open until you confirm)", True):
        ui.warn("Aborted.")
        return EX_ERROR
    if ctx.dry_run:
        ctx.planned += [f"open TCP {port} in firewall", "update Fail2ban policy", "arm persistent rollback timer",
                        f"configure sshd to listen on {sorted(set(p.old_ports + [port]))}"]
        _plan_footer(ctx, ui)
        return EX_OK
    out = migration.begin(ctx, port, minutes=args.minutes)

    def human() -> None:
        ui.success(f"SSH now listens on {sorted(set(out['old_ports'] + [out['target']]))}. Firewall: {out['firewall']}")
        render_pending(ui, migration.describe_pending(ctx))
        ui.text(f"\n Example: {migration.login_hint(ctx, port)}")
    emit(args, ui, out, human)
    return EX_OK


def _report_change(args, ctx, ui, result: dict[str, Any]) -> int:
    def human() -> None:
        if not result.get("changed"):
            ui.info(result["message"])
        else:
            ui.success(result["message"])
        for w in result.get("warnings", []):
            ui.warn(w)
        if result.get("pending"):
            ui.warn("This change is TEMPORARY until verified. Open a NEW SSH session using your key, then run: sudo bant ssh confirm")
            render_pending(ui, migration.describe_pending(ctx))
        _plan_footer(ctx, ui)
    emit(args, ui, result, human)
    return EX_OK


def cmd_ssh_password(args, ctx, ui) -> int:
    enable = parse_onoff(args.value)
    ctx.require_root("Changing SSH password authentication")
    if not enable and not _need_confirm(args, ui, "Disable SSH password login? Key-based login must work."):
        return EX_ERROR
    return _report_change(args, ctx, ui, ssh.set_password_auth(ctx, enable))


def cmd_ssh_root(args, ctx, ui) -> int:
    if args.value is None:
        st = ssh.status(ctx)
        emit(args, ui, {"root_login": st.root_login, "label": st.root_label, "root_password_login": st.root_password_login},
             lambda: (ui.kv([("Root login", st.root_login, None), ("Meaning", st.root_label, None),
                             ("Root password login", "possible" if st.root_password_login else "not possible", None)]), ui.info(" " + st.root_detail)))
        return EX_OK
    ctx.require_root("Changing the root login policy")
    return _report_change(args, ctx, ui, ssh.set_option(ctx, "root-login", args.value))


def cmd_ssh_set(args, ctx, ui) -> int:
    ctx.require_root("Changing SSH settings")
    return _report_change(args, ctx, ui, ssh.set_option(ctx, args.option, args.value))


def cmd_ssh_confirm(args, ctx, ui) -> int:
    out = migration.confirm(ctx)

    def human() -> None:
        ui.success(f"Confirmed: {out['verified']}")
        if out.get("kind") == "ssh-port":
            ui.success(f"SSH now listens only on TCP {out['port']}; old listener(s) {out['removed_ports']} removed; rollback timer disarmed.")
        else:
            ui.success("Change is now permanent; rollback timer disarmed.")
        for n in out.get("notes", []):
            ui.info(" " + n)
    emit(args, ui, out, human)
    return EX_OK


def cmd_ssh_rollback(args, ctx, ui) -> int:
    if not _need_confirm(args, ui, "Roll back the pending SSH change now?", True):
        return EX_ERROR
    out = migration.abort(ctx)
    emit(args, ui, out, lambda: ui.success(f"Rolled back transaction {out['rolled_back']}; original configuration restored."))
    return EX_OK


def cmd_ssh_extend(args, ctx, ui) -> int:
    parse_int_range(args.minutes, 1, 1440, "minutes")
    out = migration.extend(ctx, args.minutes)
    emit(args, ui, out, lambda: ui.success(f"Rollback deadline extended by {args.minutes} minutes."))
    return EX_OK


def cmd_f2b_status(args, ctx, ui) -> int:
    ov = fail2ban.overview(ctx)
    emit(args, ui, ov, lambda: render_fail2ban(ui, ov))
    return EX_OK


def cmd_f2b_enable(args, ctx, ui) -> int:
    msg = fail2ban.set_enabled(ctx, True)
    emit(args, ui, {"message": msg}, lambda: (ui.success(msg), _plan_footer(ctx, ui)))
    return EX_OK


def cmd_f2b_disable(args, ctx, ui) -> int:
    ctx.require_root("Disabling Fail2ban")
    if not _need_confirm(args, ui, "Disable Fail2ban? SSH brute-force protection will be OFF."):
        return EX_ERROR
    msg = fail2ban.set_enabled(ctx, False)
    emit(args, ui, {"message": msg}, lambda: (ui.warn(msg), _plan_footer(ctx, ui)))
    return EX_OK


def _all_bans(ctx: Context) -> list[dict[str, Any]]:
    rows = [{"ip": b["ip"], "source": "fail2ban", "jail": b["jail"], "expires": b["expires"], "reason": "failed logins / manual"}
            for b in fail2ban.banned(ctx)] if fail2ban.installed(ctx)[0] else []
    for e in bans.active_entries(ctx):
        rows.append({"ip": e["ip"], "source": "bant", "jail": "-", "reason": e.get("reason", ""),
                     "expires": fmt_ts(e["expires"]) if e.get("expires") else "never"})
    return rows


def cmd_banned(args, ctx, ui) -> int:
    rows = _all_bans(ctx)

    def human() -> None:
        ui.heading("BANNED / BLOCKED IPS")
        ui.table(["IP", "Source", "Jail", "Expires", "Reason"], [[r["ip"], r["source"], r["jail"], r["expires"], r["reason"]] for r in rows])
        ui.info(" Fail2ban bans come from the jail; Bant blocks live in Bant's own nftables table. External firewall rules are not listed.")
    emit(args, ui, rows, human)
    return EX_OK


def cmd_ban(args, ctx, ui) -> int:
    ctx.require_root("Banning an IP address")
    permanent = getattr(args, "permanent", False)
    custom = args.duration
    ip = parse_ip(args.ip, allow_network=True, for_ban=True)
    risk = bans.ban_risk(ctx, ip)
    if risk:
        if not args.force:
            raise OperationFailed(f"Refusing to ban: {risk}", hint="If you are sure, repeat with --force (keep a provider-console session ready).")
        ui.warn(f"Forcing ban although {risk}")
    if permanent or custom or getattr(args, "_from_fw", False):
        dur = None if permanent or not custom else parse_duration(custom)
        entry = bans.block(ctx, ip, duration=dur, reason=args.reason)
        done = f"Blocked {ip} in Bant's nftables table permanently." if not dur else f"Blocked {ip} in Bant's nftables table for {custom}."
        emit(args, ui, entry, lambda: (ui.success(done), _plan_footer(ctx, ui)))
        return EX_OK
    if "/" in ip:
        raise ValidationError("Fail2ban bans take a single address; use --permanent or --duration for networks.")
    msg = fail2ban.ban(ctx, ip)
    emit(args, ui, {"message": msg}, lambda: (ui.success(msg), _plan_footer(ctx, ui)))
    return EX_OK


def cmd_unban(args, ctx, ui) -> int:
    ctx.require_root("Removing a ban")
    ip = parse_ip(args.ip, allow_network=True)
    msgs = []
    if "/" not in ip and fail2ban.installed(ctx)[0] and fail2ban.unban(ctx, ip):
        msgs.append(f"Unbanned {ip} in Fail2ban")
    if bans.unblock(ctx, ip):
        msgs.append(f"Removed Bant block for {ip}")
    if not msgs:
        raise OperationFailed(f"{ip} is not banned by Fail2ban or Bant.", hint="External firewall rules are never removed by Bant.")
    emit(args, ui, {"messages": msgs}, lambda: ([ui.success(m) for m in msgs], _plan_footer(ctx, ui)))
    return EX_OK


def cmd_f2b_set(args, ctx, ui) -> int:
    msg = fail2ban.set_option(ctx, args.key, args.value)
    emit(args, ui, {"message": msg}, lambda: (ui.success(msg), _plan_footer(ctx, ui)))
    return EX_OK


def cmd_trusted(args, ctx, ui) -> int:
    ips = bans.trusted(ctx)
    emit(args, ui, ips, lambda: (ui.heading("TRUSTED ADDRESSES"), [ui.bullet(i) for i in ips] or ui.info("  (none) - 127.0.0.1 and ::1 are always ignored by Fail2ban")))
    return EX_OK


def cmd_trust(args, ctx, ui) -> int:
    ip = parse_ip(args.ip, allow_network=True)
    if not _need_confirm(args, ui, f"Trust {ip}? It will never be banned by Fail2ban or Bant. Dynamic IPs may later belong to someone else."):
        return EX_ERROR
    ips = bans.trust_add(ctx, ip)
    fail2ban.sync_if_managed(ctx)
    emit(args, ui, ips, lambda: ui.success(f"Trusted: {', '.join(ips)}"))
    return EX_OK


def cmd_untrust(args, ctx, ui) -> int:
    ips = bans.trust_remove(ctx, parse_ip(args.ip, allow_network=True))
    fail2ban.sync_if_managed(ctx)
    emit(args, ui, ips, lambda: ui.success(f"Trusted: {', '.join(ips) or '(none)'}"))
    return EX_OK


def cmd_fw_status(args, ctx, ui) -> int:
    info = firewall.detect(ctx)
    rules = firewall.managed_summary(ctx)
    lst = netinfo.listeners(ctx)
    emit(args, ui, {"firewall": info.to_dict(), "bant_rules": rules,
                    "listeners": [lsn.__dict__ | {"scope": lsn.scope} for lsn in lst]}, lambda: render_firewall(ui, info, rules, lst))
    return EX_OK


def cmd_fw_allow(args, ctx, ui) -> int:
    port, proto = parse_port(args.port), parse_proto(args.proto)
    ctx.require_root("Changing firewall rules")
    with ctx.lock():
        res = firewall.allow_port(ctx, port, proto, purpose="manual")
        if not ctx.dry_run:
            firewall.commit_rules(ctx, res.rules)
            ctx.audit("firewall.allow", port=port, proto=proto, backend=res.backend, changed=res.changed)
    emit(args, ui, res.__dict__, lambda: (ui.success(res.message) if res.changed else ui.info(res.message), _plan_footer(ctx, ui)))
    return EX_OK


def cmd_fw_remove(args, ctx, ui) -> int:
    port, proto = parse_port(args.port), parse_proto(args.proto)
    ctx.require_root("Changing firewall rules")
    if int(port) in (ssh.status(ctx).active_ports) and not getattr(args, "yes", False):
        if not _need_confirm(args, ui, f"{port} is your SSH port. Removing its allowance may lock you out. Continue?"):
            return EX_ERROR
    with ctx.lock():
        out = firewall.remove_port(ctx, port, proto)
    emit(args, ui, out, lambda: [ui.success(o) for o in out])
    return EX_OK


def cmd_updates_status(args, ctx, ui) -> int:
    st = updates.status(ctx)
    emit(args, ui, updates.as_dict(st), lambda: render_updates(ui, st))
    return EX_OK


def cmd_updates_enable(args, ctx, ui) -> int:
    msg = updates.enable(ctx)
    emit(args, ui, {"message": msg}, lambda: (ui.success(msg), _plan_footer(ctx, ui)))
    return EX_OK


def cmd_updates_disable(args, ctx, ui) -> int:
    msg = updates.disable(ctx)
    emit(args, ui, {"message": msg}, lambda: (ui.success(msg), _plan_footer(ctx, ui)))
    return EX_OK


def cmd_backup(args, ctx, ui) -> int:
    if args.list:
        items = backups.list_backups(ctx)
        emit(args, ui, items, lambda: ui.table(["ID", "Created", "Files", "Note"], [[i["id"], fmt_ts(i["created"]), i["files"], i["note"]] for i in items]))
        return EX_OK
    res = backups.create(ctx, args.note)
    emit(args, ui, res, lambda: (ui.success(f"Backup {res['id']} created ({res.get('files', 0)} files) in {res.get('path', '')}"), _plan_footer(ctx, ui)))
    return EX_OK


def cmd_restore(args, ctx, ui) -> int:
    if args.list:
        return cmd_backup(argparse.Namespace(list=True, json=getattr(args, "json", False)), ctx, ui)
    if not _need_confirm(args, ui, f"Restore backup '{args.backup_id}'? A safety snapshot is taken first."):
        return EX_ERROR
    res = backups.restore(ctx, args.backup_id)
    emit(args, ui, res, lambda: (ui.success(f"Restored backup {res['id']}; changed {len(res.get('changed', []))} file(s). Safety snapshot: {res.get('safety_backup', '-')}"),
                                 _plan_footer(ctx, ui)))
    return EX_OK


def cmd_repair(args, ctx, ui) -> int:
    actions = repair.run(ctx)
    emit(args, ui, actions, lambda: ([ui.text(f" {ui.glyph('ok' if a['result'] == 'ok' else 'warn')} {tr(a['action'])}"
                                              + ("" if a["result"] == "ok" else f" - {tr(a['result'])}"),
                                              "ok" if a["result"] == "ok" else "warn", raw=True) for a in actions], _plan_footer(ctx, ui)))
    return EX_ERROR if any("FAILED" in a["result"] for a in actions) else EX_OK


def _ask_ssh_port(ctx: Context, ui: UI) -> int | None:
    """Interactive installs: show the random port Bant would use and let the user accept, change or reroll it."""
    candidate, source = ports.resolve_target(ctx, None)
    if source not in ("random", "remembered"):
        return None  # already decided (configured, or an existing custom port is kept)
    ui.section("SSH port")
    ui.text(f" Bant will move SSH to a random free port: {candidate}")
    ui.info(" Press Enter to accept, type your own port number, or 'r' for another random port.")
    ui.info(" Remember to allow that port in your VPS provider's firewall/security group, if it has one.")
    while True:
        answer = ui.ask("SSH port", str(candidate)).strip().lower()
        if answer in ("r", "random"):
            candidate = ports.pick_random(ctx, exclude=[candidate])
            ui.text(f" New random port: {candidate}")
            continue
        try:
            return parse_port(answer)
        except ValidationError as exc:
            ui.error(exc.message)


def cmd_setup(args, ctx, ui) -> int:
    ctx.require_root("Setting up Bant")
    port: int | str | None = args.ssh_port
    migrate = not args.no_ssh_migration
    if port is None and migrate and sys.stdin.isatty() and not getattr(args, "yes", False) and not getattr(args, "json", False) \
            and not TxManager(ctx).pending():
        port = _ask_ssh_port(ctx, ui)
    report = setup.run(ctx, migrate=migrate, with_fail2ban=not args.no_fail2ban, port=port, minutes=args.minutes,
                       update_check=not args.no_update_check)
    emit(args, ui, report, lambda: render_setup(ui, report))
    return EX_OK if report["outcome"] in ("complete", "pending_confirmation") else EX_ERROR


def cmd_uninstall(args, ctx, ui) -> int:
    ctx.require_root("Uninstalling Bant")
    inv = uninstall.inventory(ctx)
    if not getattr(args, "json", False):
        ui.heading("UNINSTALL BANT")
        ui.table(["Kind", "Item", "Action"], [[tr(i["kind"]), i["item"], tr(i["action"])] for i in inv])
        ui.info(" Bant will NOT revert SSH to port 22, remove the working listener, or uninstall Fail2ban.")
    if args.dry_run:
        ctx.planned += [f"{tr(i['action'])}: {i['item']}" for i in inv]
        _plan_footer(ctx, ui)
        return EX_OK
    if not _need_confirm(args, ui, "Proceed with uninstall?"):
        return EX_ERROR
    purge = args.purge
    if not purge and sys.stdin.isatty() and not args.yes:
        purge = ui.confirm("Also delete backups, logs and Bant configuration?", False)
    res = uninstall.run(ctx, purge=purge, remove_f2b_config=args.remove_fail2ban_config)

    def human() -> None:
        for d in res["done"]:
            ui.success(d)
        for w in res["warnings"]:
            ui.warn(w)
        for k in res["kept"]:
            ui.info(f" kept: {k}")
        ui.info(" " + res["final"]["note"])
    emit(args, ui, res, human)
    return EX_OK


def _print_update_info(ui: UI, info: dict[str, Any]) -> None:
    from bant.presenters import render_update_info

    render_update_info(ui, info)


def cmd_selfupdate(args, ctx, ui) -> int:
    if getattr(args, "su_cmd", None):  # a subcommand was given; argparse already routed it
        return EX_OK
    info = updater.check(ctx)
    if getattr(args, "quiet", False) and not info["available"]:
        return EX_OK
    emit(args, ui, info, lambda: _print_update_info(ui, info))
    if not info["available"] or getattr(args, "json", False):
        return EX_OK
    if not ctx.is_root:
        ui.info("Run with sudo to install it: sudo bant self-update")
        return EX_OK
    if not _need_confirm(args, ui, f"Install Bant {info['latest']} now?", True):
        return EX_ERROR
    return cmd_su_apply(argparse.Namespace(version=None, allow_downgrade=False, json=False, yes=True,
                                           dry_run=getattr(args, "dry_run", False)), ctx, ui)


def cmd_su_check(args, ctx, ui) -> int:
    info = updater.check(ctx)
    if getattr(args, "quiet", False) and not info["available"]:
        return EX_OK
    emit(args, ui, info, lambda: _print_update_info(ui, info))
    return EX_OK


def cmd_su_apply(args, ctx, ui) -> int:
    ctx.require_root("Updating Bant")
    if not args.version and not getattr(args, "dry_run", False):
        info = updater.check(ctx, save=False)
        if not info["available"]:
            emit(args, ui, {"updated": False, "current": info["current"]}, lambda: ui.success(f"Bant {info['current']} is up to date."))
            return EX_OK
        if not getattr(args, "json", False):
            _print_update_info(ui, info)
        if not _need_confirm(args, ui, f"Install Bant {info['latest']} now?", True):
            return EX_ERROR
    elif args.version and not _need_confirm(args, ui, f"Install Bant {args.version}?", True):
        return EX_ERROR
    res = updater.apply(ctx, args.version, allow_downgrade=args.allow_downgrade)

    def human() -> None:
        if res.get("dry_run"):
            ui.success(f"Would update to {res['target']}.")
            _plan_footer(ctx, ui)
        elif res["updated"]:
            ui.success(f"Updated Bant {res['previous']} -> {res['current']} ({res['verified']}).")
            ui.info(f"Configuration backup: {res['backup']}. Undo with: sudo bant self-update rollback")
            ui.warn("Start `bant` again to use the new version.")
        else:
            ui.success(res["message"])
    emit(args, ui, res, human)
    return EX_OK


def cmd_su_rollback(args, ctx, ui) -> int:
    if not _need_confirm(args, ui, "Switch back to the previous Bant version?", True):
        return EX_ERROR
    res = updater.rollback(ctx)
    emit(args, ui, res, lambda: ui.success(f"Bant is now {res['to']} (was {res['from']})."))
    return EX_OK


def cmd_su_status(args, ctx, ui) -> int:
    st = updater.status(ctx)
    from bant.presenters import render_selfupdate_status

    emit(args, ui, st, lambda: render_selfupdate_status(ui, st))
    return EX_OK


def cmd_su_notify(args, ctx, ui) -> int:
    msg = updater.set_notify(ctx, parse_onoff(args.value))
    emit(args, ui, {"message": msg}, lambda: ui.success(msg))
    return EX_OK


def cmd_su_channel(args, ctx, ui) -> int:
    msg = updater.set_channel(ctx, args.value)
    emit(args, ui, {"message": msg}, lambda: ui.success(msg))
    return EX_OK


def cmd_tx_finish(args, ctx, ui) -> int:
    TxManager(ctx).finish_external(args.tx_id, args.outcome)
    return EX_OK


def cmd_fw_apply(args, ctx, ui) -> int:
    notes = firewall.reapply(ctx)
    n = bans.reapply_boot(ctx) if bans.available(ctx) else 0
    emit(args, ui, {"firewall": notes, "blocks": n}, lambda: [ui.text(x) for x in notes])
    return EX_OK


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _flag_value(argv: Sequence[str], flag: str) -> str | None:
    for i, a in enumerate(argv):
        if a == flag and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith(flag + "="):
            return a.split("=", 1)[1]
    return None


def _startup_language(argv: Sequence[str], ctx: Context, stream) -> str:
    """Decide the display language before the parser (and its --help text) is built."""
    if "--json" in argv:
        return "en"  # machine-readable output is always English
    try:
        code, _ = i18n.resolve(ctx, _flag_value(argv, "--lang"))
    except BantError:
        code = None
    code = code or i18n.locale_hint() or i18n.DEFAULT
    return code if code == "en" or stream_shows_cjk(stream) else "en"


def main(argv: Sequence[str] | None = None, ctx: Context | None = None, ui: UI | None = None) -> int:
    argv_list = list(argv) if argv is not None else sys.argv[1:]
    ctx = ctx or Context(interactive=sys.stdin.isatty())
    i18n.set_language(_startup_language(argv_list, ctx, ui.stream if ui else sys.stdout))
    parser = build_parser()
    try:
        args = parser.parse_args(argv_list)
    except SystemExit as exc:  # argparse exits 0 for --help/--version, 2 for usage errors
        return int(exc.code or 0) if isinstance(exc.code, int) else EX_USAGE
    ui = ui or UI(color=False if getattr(args, "no_color", False) else None, assume_yes=getattr(args, "yes", False))
    if getattr(args, "dry_run", False):
        ctx.dry_run = True
    if getattr(args, "yes", False):
        ctx.assume_yes = True
    try:
        handler = getattr(args, "handler", None)
        if handler is None:
            if args.command is None:
                if sys.stdin.isatty() and sys.stdout.isatty() and not getattr(args, "json", False):
                    from bant.tui.app import run_tui

                    return run_tui(ctx, ui)
                return cmd_status(argparse.Namespace(deep=False, json=getattr(args, "json", False)), ctx, ui)
            parser.parse_args([args.command, "--help"])
            return EX_USAGE
        return handler(args, ctx, ui)
    except BantError as exc:
        if getattr(args, "json", False):
            print(json.dumps(exc.to_dict(), indent=2), file=ui.stream)
        else:
            ui.error(exc.message)
            if exc.hint:
                ui.info(f"  hint: {exc.hint}")
        return exc.exit_code
    except Abort:
        ui.warn("Cancelled.")
        return 130
    except KeyboardInterrupt:
        ui.text("")
        ui.warn("Interrupted.")
        return 130
    except BrokenPipeError:
        return EX_OK
    except Exception as exc:  # noqa: BLE001
        if os.environ.get("BANT_DEBUG"):
            raise
        ui.error(f"Unexpected error: {type(exc).__name__}: {exc}")
        ui.info("  Re-run with BANT_DEBUG=1 for a traceback, and check `bant doctor`.")
        return EX_ERROR


if __name__ == "__main__":
    sys.exit(main())
