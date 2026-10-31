"""Safe uninstallation.

Principles: never strand the administrator and never silently weaken protection.
  * SSH: the listener/authentication settings Bant applied are kept as a plain, de-branded
    drop-in - the port is NOT reverted to 22 and the working listener is never removed.
  * Fail2ban: the package is never removed and the service is never stopped; Bant's jail file is
    kept (renamed) so the SSH jail keeps protecting the real port, unless explicitly asked otherwise.
  * Firewall: only rules in Bant's registry are touched. Allowances that are still needed (the SSH
    port, or any port something listens on) are handed over and kept - for nftables/iptables a small
    de-branded boot unit re-creates them, because those backends do not persist rules by themselves.
    Allowances for ports nothing listens on any more, and Bant's own IP-block table, are removed.
  * Order: check -> back up -> change security config (journalled) -> verify -> only then remove
    Bant's units, data and program files. A failed verification restores the journalled files.
  * Idempotent: every step skips what is already gone, so an interrupted run can simply be repeated.

Modes: standard (keep config, backups, logs) and purge (also delete them). Neither mode touches the SSH
listener, the authentication policy, or the Fail2ban package.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from bant.context import Context
from bant.core import backups, bans, fail2ban, firewall, netinfo, ssh, sshconf
from bant.core.rollback import TxManager
from bant.errors import BantError, OperationFailed, RolledBack
from bant.platform import has_systemd
from bant.utils.fsutil import read_text

RETAIN_HEADER = "# Originally configured by Bant (now uninstalled). Kept so SSH/Fail2ban continue to work as configured.\n"
_MANAGED_HEADERS = ("# Managed by Bant - do not edit by hand; changes are overwritten.\n", "# Managed by Bant - do not edit by hand.\n")
BANT_UNITS = ("bant-firewall.service", "bant-update-check.service", "bant-update-check.timer")
RETAINED_TAG = "retained-port-allow"


def _debrand(text: str) -> str:
    for h in _MANAGED_HEADERS:
        text = text.replace(h, RETAIN_HEADER)
    return text if text.startswith(RETAIN_HEADER) else RETAIN_HEADER + text


# ---------------------------------------------------------------------------
# Pre-flight: what is installed, is it safe to proceed?
# ---------------------------------------------------------------------------

def _bant_touched_ssh(ctx: Context) -> bool:
    p = ctx.paths
    return p.ssh_dropin.exists() or any(p.socket_dropin(u).exists() for u in ("ssh.socket", "sshd.socket"))


def _split_rules(ctx: Context, ssh_ports: list[int]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(keep, remove): keep allowances that are still needed - the SSH ports and anything with a listener."""
    listening = {(lst.proto, lst.port) for lst in netinfo.listeners(ctx)}
    keep, remove = [], []
    for r in firewall.registry(ctx):
        needed = (r["proto"] == "tcp" and r["port"] in ssh_ports) or (r["proto"], r["port"]) in listening
        (keep if needed else remove).append(r)
    return keep, remove


def preflight(ctx: Context) -> dict[str, Any]:
    """Facts and safety checks. `blockers` must be empty before anything is changed."""
    blockers: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool | None, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    txm = TxManager(ctx)
    pend = txm.pending()
    if pend:
        blockers.append(f"An SSH change (transaction {pend[-1].id}) is waiting for confirmation. "
                        "Finish it first with `sudo bant ssh confirm` (after logging in on the new port) or undo it with `sudo bant ssh rollback`.")
        check("pending SSH change", False, pend[-1].id)
    else:
        check("pending SSH change", True, "none")
    failed_tx = [t for t in txm.all() if t.status == "rollback_failed"]
    if failed_tx:
        warnings.append(f"An earlier automatic rollback ({failed_tx[-1].id}) reported errors; `sudo bant doctor` shows details.")

    st = ssh.status(ctx)
    touched = _bant_touched_ssh(ctx)
    session = netinfo.current_session(ctx)
    if session:
        check("your SSH session", True, f"{session.user} from {session.remote_ip} on port {session.local_port}")
    if st.installed:
        ok, msg = sshconf.validate(ctx)
        check("sshd configuration", ok, "valid (sshd -t)" if ok else msg)
        if not ok:
            blockers.append(f"The SSH configuration is invalid ({msg}). Fix it, or restore a backup with `sudo bant restore`, before uninstalling.")
        live = [x for x in st.active_ports if netinfo.tcp_listening(ctx, x)]
        check("SSH listening", bool(live), f"TCP {', '.join(map(str, live))}" if live else "no listener found")
        if not live:
            msg2 = "Could not confirm that SSH is listening"
            if touched:
                blockers.append(f"{msg2}; Bant changed the SSH configuration, so it refuses to continue. Check `ss -ltn` and `systemctl status ssh`.")
            else:
                warnings.append(f"{msg2}. Bant never changed the SSH configuration, so uninstalling does not touch SSH.")
        if session and st.active_ports and session.local_port not in st.active_ports:
            warnings.append(f"Your session uses port {session.local_port}, which is not in the SSH configuration ({st.active_ports}). It is not changed.")
    else:
        check("SSH", None, "OpenSSH server not installed - nothing to keep")

    f2b_ok, _ = fail2ban.installed(ctx)
    jail = fail2ban.jail_status(ctx) if f2b_ok and ctx.which("fail2ban-client") else None
    check("Fail2ban", None if not f2b_ok else bool(jail), "not installed" if not f2b_ok else ("sshd jail running" if jail else "sshd jail not running"))

    keep, remove = _split_rules(ctx, st.active_ports)
    return {"blockers": blockers, "warnings": warnings, "checks": checks, "ssh_ports": list(st.active_ports),
            "ssh_installed": st.installed, "bant_touched_ssh": touched, "fail2ban_installed": f2b_ok,
            "fail2ban_jail_running": bool(jail), "rules_keep": keep, "rules_remove": remove,
            "pending": bool(pend), "session": session.peer if session else None}


def inventory(ctx: Context, *, purge: bool = False, remove_f2b_config: bool = False, pre: dict[str, Any] | None = None) -> list[dict[str, str]]:
    p = ctx.paths
    pre = pre or preflight(ctx)
    items: list[dict[str, str]] = []

    def add(kind: str, what: str, action: str) -> None:
        items.append({"kind": kind, "item": what, "action": action})

    if p.ssh_dropin.exists():
        add("ssh", str(p.ssh_dropin), f"keep as {p.ssh_retained_dropin.name} (listener/auth settings preserved)")
    for unit in ("ssh.socket", "sshd.socket"):
        if p.socket_dropin(unit).exists():
            add("ssh", str(p.socket_dropin(unit)), "keep as ssh-port.conf (listener preserved)")
    if pre["ssh_ports"]:
        add("ssh", f"SSH port(s) {', '.join(map(str, pre['ssh_ports']))}", "unchanged (never reverted to 22)")
    if p.f2b_jail.exists():
        if remove_f2b_config:
            add("fail2ban", str(p.f2b_jail), "delete (the sshd jail falls back to distribution defaults)")
        else:
            add("fail2ban", str(p.f2b_jail), f"keep as {p.f2b_retained_jail.name} (use --remove-fail2ban-config to delete)")
    if p.f2b_filter.exists():
        add("fail2ban", str(p.f2b_filter), "delete" if remove_f2b_config else "keep (referenced by the retained jail)")
    if pre["fail2ban_installed"]:
        add("fail2ban", "Fail2ban package and service", "unchanged (never removed or stopped)")
    for r in pre["rules_keep"]:
        add("firewall", f"{r['backend']} rule {r['id']} ({r['port']}/{r['proto']})", "keep (still needed)")
    for r in pre["rules_remove"]:
        add("firewall", f"{r['backend']} rule {r['id']} ({r['port']}/{r['proto']})", "remove (nothing listens on this port)")
    if any(r["backend"] in ("nftables", "iptables") for r in pre["rules_keep"]):
        add("firewall", f"{p.retained_fw_unit.name}", "create (re-adds the kept allowances at boot)")
    if p.blocklist_file.exists() or bans.active_entries(ctx):
        add("firewall", "Bant IP blocks (nft table 'bant')", "remove (Fail2ban bans are not affected)")
    add("firewall", "rules not created by Bant", "unchanged")
    if p.apt_bant_conf.exists():
        add("updates", str(p.apt_bant_conf), "keep (automatic security updates stay on)")
    for u in BANT_UNITS:
        if (p.systemd_system / u).exists():
            add("systemd", u, "disable and remove")
    if p.tx_dir.exists():
        add("data", str(p.tx_dir), "remove (finished SSH transactions)")
    if p.install_dir.exists() or p.launcher.exists():
        add("files", f"{p.install_dir} and {p.launcher}", "remove")
    if purge:
        add("data", f"{p.state_dir} (state, backups), {p.log_dir}, {p.etc_bant}", "delete (after all checks passed)")
    else:
        add("data", f"{p.backup_dir}, {p.log_dir}, {p.config_file}", "keep (use the full-removal mode to delete)")
    return items


# ---------------------------------------------------------------------------
# Journalled file changes (restored if verification fails)
# ---------------------------------------------------------------------------

class _Journal:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.saved: dict[Path, bytes | None] = {}

    def _remember(self, path: Path) -> None:
        if path not in self.saved:
            self.saved[path] = path.read_bytes() if path.exists() else None

    def write(self, path: Path, body: str, mode: int = 0o644) -> None:
        self._remember(path)
        self.ctx.write_file(path, body, mode)

    def unlink(self, path: Path) -> None:
        self._remember(path)
        path.unlink(missing_ok=True)

    def restore(self) -> list[str]:
        failed = []
        for path, data in reversed(list(self.saved.items())):
            try:
                if data is None:
                    path.unlink(missing_ok=True)
                else:
                    self.ctx.write_file(path, data, 0o644)
            except OSError as exc:
                failed.append(f"{path}: {exc}")
        return failed


def _retained_fw_script(rules: list[dict[str, Any]]) -> str:
    lines = [
        "#!/bin/sh",
        "# Originally configured by Bant (now uninstalled).",
        "# Re-creates these firewall accept rules at boot so SSH (and the listed ports) stay reachable,",
        "# because plain nftables/iptables rules do not survive a reboot. To remove it:",
        "#   systemctl disable retained-port-allow.service",
        "#   rm /etc/systemd/system/retained-port-allow.service /usr/local/sbin/retained-port-allow",
        "set -u",
        f'TAG="{RETAINED_TAG}"',
        "nft_allow() {  # family table chain proto port",
        '  command -v nft >/dev/null 2>&1 || return 0',
        '  nft list chain "$1" "$2" "$3" >/dev/null 2>&1 || return 0',
        '  nft list chain "$1" "$2" "$3" | grep -F "dport $5 accept comment \\"$TAG\\"" >/dev/null 2>&1 && return 0',
        '  nft insert rule "$1" "$2" "$3" "$4" dport "$5" accept comment "\\"$TAG\\"" || echo "could not allow $4/$5 in $1 $2 $3" >&2',
        "}",
        "ipt_allow() {  # binary proto port",
        '  command -v "$1" >/dev/null 2>&1 || return 0',
        '  "$1" -C INPUT -p "$2" --dport "$3" -m comment --comment "$TAG" -j ACCEPT 2>/dev/null && return 0',
        '  "$1" -I INPUT 1 -p "$2" --dport "$3" -m comment --comment "$TAG" -j ACCEPT || echo "could not allow $2/$3 with $1" >&2',
        "}",
    ]
    seen = set()
    for r in rules:
        port, proto = int(r["port"]), "udp" if r["proto"] == "udp" else "tcp"
        if r["backend"] == "nftables":
            ch = r.get("chain") or {}
            key = ("nft", ch.get("family"), ch.get("table"), ch.get("chain"), proto, port)
            if key in seen or not all(isinstance(ch.get(k), str) and ch.get(k).replace("_", "").replace("-", "").isalnum()
                                      for k in ("family", "table", "chain")):
                continue
            lines.append(f"nft_allow {ch['family']} {ch['table']} {ch['chain']} {proto} {port}")
        elif r["backend"] == "iptables":
            binary = r.get("binary") or "iptables"
            key = ("ipt", binary, proto, port)
            if key in seen or binary not in ("iptables", "ip6tables"):
                continue
            lines.append(f"ipt_allow {binary} {proto} {port}")
        else:
            continue
        seen.add(key)
    lines.append("exit 0")
    return "\n".join(lines) + "\n"


def _retained_fw_unit() -> str:
    return (
        "# Originally configured by Bant (now uninstalled). See the script for how to remove it.\n"
        "[Unit]\n"
        "Description=Re-allow SSH and kept ports in the firewall at boot (originally configured by Bant)\n"
        "After=network-pre.target nftables.service netfilter-persistent.service iptables.service ufw.service\n"
        "Wants=network-pre.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/bin/sh /usr/local/sbin/retained-port-allow\n"
        "RemainAfterExit=yes\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def _preload() -> None:
    """Import everything the caller may still need: the program directory is deleted at the end."""
    import importlib

    for mod in ("bant.presenters", "bant.locales.zh_tw", "bant.tui.menus"):
        try:
            importlib.import_module(mod)
        except Exception:  # noqa: BLE001 - best effort
            pass


def run(ctx: Context, *, purge: bool = False, remove_f2b_config: bool = False) -> dict[str, Any]:
    ctx.require_root("Uninstalling Bant")
    p = ctx.paths
    done: list[str] = []
    warnings: list[str] = []
    kept: list[str] = []
    with ctx.lock():
        pre = preflight(ctx)
        if pre["blockers"]:
            raise OperationFailed("Uninstall refused: " + " ".join(pre["blockers"]),
                                  hint="Nothing was changed. Resolve the item above and run the uninstall again.")
        warnings += pre["warnings"]
        if ctx.dry_run:
            return {"dry_run": True, "plan": inventory(ctx, purge=purge, remove_f2b_config=remove_f2b_config, pre=pre),
                    "checks": pre["checks"], "warnings": warnings}
        _preload()

        # 1. backup - without one there is no safe way back, so stop here
        try:
            b = backups.create(ctx, note="pre-uninstall")
        except (OSError, BantError) as exc:
            raise OperationFailed(f"Could not create a backup before uninstalling ({exc}). Nothing was changed.",
                                  hint="Free some disk space or fix /var/lib/bant permissions, then try again.") from None
        done.append(f"backup created: {b['id']}")

        st = ssh.status(ctx)
        before_ports = list(st.active_ports)
        journal = _Journal(ctx)

        def undo(reason: str) -> RolledBack:
            failed = journal.restore()
            _reload_ssh(ctx, st)
            if pre["fail2ban_installed"] and ctx.which("fail2ban-client"):
                ctx.run_mut(["fail2ban-client", "reload"])
            msg = f"Uninstall stopped: {reason}. The SSH and Fail2ban files were restored; Bant is still installed."
            if failed:
                msg += " Could not restore: " + "; ".join(failed) + f". Restore manually with `sudo bant restore {b['id']}`."
            ctx.audit("uninstall.aborted", level="error", reason=reason, unrestored=failed)
            return RolledBack(msg, hint=f"Backup {b['id']} holds the state from before the uninstall.")

        # 2. SSH: keep Bant's settings under a neutral name
        if p.ssh_dropin.exists():
            journal.write(p.ssh_retained_dropin, _debrand(read_text(p.ssh_dropin)), 0o644)
            journal.unlink(p.ssh_dropin)
            done.append(f"SSH settings kept in {p.ssh_retained_dropin.name}")
        for unit in ("ssh.socket", "sshd.socket"):
            sd = p.socket_dropin(unit)
            if sd.exists():
                journal.write(p.socket_retained_dropin(unit), _debrand(read_text(sd)), 0o644)
                journal.unlink(sd)
                done.append(f"{unit} listener settings kept in ssh-port.conf")
        if st.installed and journal.saved:
            ok, msg = sshconf.validate(ctx)
            after = sshconf.effective(ctx).ports
            if not ok:
                raise undo(f"the SSH configuration did not validate after renaming Bant's file ({msg})")
            if st.mode == "service" and set(after) != set(before_ports):
                raise undo(f"keeping the SSH settings would change the SSH ports ({before_ports} -> {after})")

        # 3. Fail2ban: keep the jail (the package and service are never touched)
        f2b_changed = False
        if p.f2b_jail.exists():
            if remove_f2b_config:
                journal.unlink(p.f2b_jail)
                journal.unlink(p.f2b_filter)
                done.append("removed Bant's Fail2ban jail (the sshd jail reverts to distribution defaults - port 22!)")
                warnings.append("Fail2ban's sshd jail now protects the default SSH port only.")
            else:
                journal.write(p.f2b_retained_jail, _debrand(read_text(p.f2b_jail)), 0o644)
                journal.unlink(p.f2b_jail)
                if p.f2b_filter.exists():
                    journal.write(p.f2b_filter, _debrand(read_text(p.f2b_filter)), 0o644)
                done.append(f"Fail2ban SSH jail settings kept in {p.f2b_retained_jail.name}")
            f2b_changed = True
        if f2b_changed and ctx.which("fail2ban-client"):
            if not ctx.run(["fail2ban-client", "-t"]).ok:
                raise undo("Fail2ban rejected the configuration after the change (fail2ban-client -t)")
            ctx.run_mut(["fail2ban-client", "reload"])  # harmless if the service is stopped; it is never stopped here
            if pre["fail2ban_jail_running"] and not ctx.wait_until(lambda: fail2ban.jail_status(ctx) is not None, attempts=10):
                raise undo("the Fail2ban sshd jail did not come back after reloading")

        # 4. firewall: keep what is still needed, remove what is not
        keep, remove = pre["rules_keep"], pre["rules_remove"]
        native = [r for r in keep if r["backend"] in ("nftables", "iptables")]
        if native:
            journal.write(p.retained_fw_script, _retained_fw_script(native), 0o755)
            journal.write(p.retained_fw_unit, _retained_fw_unit(), 0o644)
            if has_systemd(ctx):
                ctx.run_mut(["systemctl", "daemon-reload"])
                ctx.run_mut(["systemctl", "enable", p.retained_fw_unit.name])
            done.append(f"kept firewall allowances survive reboots via {p.retained_fw_unit.name}")
        for r in keep:
            kept.append(f"firewall allowance {r['port']}/{r['proto']} ({r['backend']})")
        for rule in remove:
            ok, msg = firewall.remove_rule(ctx, rule)
            if ok:
                done.append(f"removed firewall rule {rule['id']} ({rule['port']}/{rule['proto']}), nothing listens there")
            else:
                warnings.append(f"could not remove firewall rule {rule['id']}: {msg}")

        # 5. reload SSH against the final files and verify everything that must still work
        _reload_ssh(ctx, st)
        problems = []
        if st.installed and before_ports and not ctx.wait_until(lambda: all(netinfo.tcp_listening(ctx, x) for x in before_ports)):
            problems.append(f"SSH is not listening on {before_ports} after the reload")
        for r in keep:
            if not firewall.rule_present(ctx, r):
                problems.append(f"the firewall allowance {r['port']}/{r['proto']} disappeared")
        if problems:
            raise undo("; ".join(problems))

        # 6. from here on only Bant's own things are removed
        ctx.state.update(lambda d: d.setdefault("firewall", {}).__setitem__("rules", []))
        if ctx.which("nft") and (p.blocklist_file.exists() or bans.active_entries(ctx)):
            if ctx.run(["nft", "list", "table", "inet", bans.TABLE]).ok:
                ctx.run_mut(["nft", "delete", "table", "inet", bans.TABLE])
            done.append("removed Bant's IP-block table (Fail2ban bans are not affected)")
        p.blocklist_file.unlink(missing_ok=True)
        if has_systemd(ctx):
            for unit in ("bant-firewall.service", "bant-update-check.timer"):
                if (p.systemd_system / unit).exists():
                    ctx.run_mut(["systemctl", "disable", "--now", unit])
            for tx in TxManager(ctx).all():
                TxManager(ctx).abandon_units(tx)
            removed = [u for u in BANT_UNITS if (p.systemd_system / u).exists()]
            for unit in BANT_UNITS:
                (p.systemd_system / unit).unlink(missing_ok=True)
            ctx.run_mut(["systemctl", "daemon-reload"])
            if removed:
                done.append("removed Bant systemd units: " + ", ".join(removed))

        final = {"ssh_ports": before_ports, "ssh_valid": sshconf.validate(ctx)[0] if st.installed else None,
                 "fail2ban": ("sshd jail running" if fail2ban.jail_status(ctx) else "installed, sshd jail not running")
                 if pre["fail2ban_installed"] and ctx.which("fail2ban-client") else "not installed",
                 "note": "SSH was not reverted to port 22 and no listener was removed."}
        ctx.audit("uninstall", done=done, warnings=warnings, purge=purge, final=final)

        # 7. data, then the program itself (last, so a failure above leaves a working Bant to retry with)
        if purge:
            for d in (p.state_dir, p.log_dir, p.etc_bant):
                shutil.rmtree(d, ignore_errors=True)
            done.append("deleted Bant configuration, state, backups and logs")
        else:
            shutil.rmtree(p.tx_dir, ignore_errors=True)
            kept += [str(p.backup_dir), str(p.log_dir), str(p.config_file)]
        shutil.rmtree(p.install_dir, ignore_errors=True)
        p.launcher.unlink(missing_ok=True)
        done.append("removed Bant program files and the `bant` command")
    return {"done": done, "warnings": warnings, "kept": kept, "checks": pre["checks"], "final": final, "backup": b["id"],
            "purge": purge}


def _reload_ssh(ctx: Context, st: ssh.SshStatus) -> None:
    if not st.installed or not has_systemd(ctx):
        return
    if st.mode == "socket" and st.socket_unit:
        ctx.run_mut(["systemctl", "daemon-reload"])  # same listener content under a new name; no socket restart needed
    elif st.service_unit:
        ctx.run_mut(["systemctl", "reload", st.service_unit])
