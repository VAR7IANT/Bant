"""Safe uninstallation.

Principles: never strand the administrator and never silently weaken protection.
  * SSH: the listener/authentication settings Bant applied are kept as a plain, de-branded
    drop-in - the port is NOT reverted to 22 and the working listener is never removed.
  * Fail2ban: the package is never removed; Bant's jail file is retained (renamed) unless asked.
  * Firewall: only rules in Bant's registry (and Bant's own nft table) are removed.
"""

from __future__ import annotations

import shutil
from typing import Any

from bant.context import Context
from bant.core import backups, bans, firewall, netinfo, ssh, sshconf
from bant.core.rollback import TxManager
from bant.errors import OperationFailed
from bant.platform import has_systemd
from bant.utils.fsutil import read_text

RETAIN_HEADER = "# Originally configured by Bant (now uninstalled). Kept so SSH/Fail2ban continue to work as configured.\n"


def inventory(ctx: Context) -> list[dict[str, str]]:
    p = ctx.paths
    items: list[dict[str, str]] = []

    def add(kind: str, what: str, action: str) -> None:
        items.append({"kind": kind, "item": what, "action": action})

    if p.ssh_dropin.exists():
        add("ssh", str(p.ssh_dropin), f"keep as {p.ssh_retained_dropin.name} (listener/auth settings preserved)")
    for unit in ("ssh.socket", "sshd.socket"):
        if p.socket_dropin(unit).exists():
            add("ssh", str(p.socket_dropin(unit)), "keep as ssh-port.conf (listener preserved)")
    if p.f2b_jail.exists():
        add("fail2ban", str(p.f2b_jail), f"keep as {p.f2b_retained_jail.name} (use --remove-fail2ban-config to delete)")
    if p.f2b_filter.exists():
        add("fail2ban", str(p.f2b_filter), "keep (referenced by the retained jail)")
    for r in firewall.registry(ctx):
        add("firewall", f"{r['backend']} rule {r['id']} ({r['port']}/{r['proto']})", "remove (Bant-owned)")
    if bans.active_entries(ctx):
        add("firewall", f"{len(bans.active_entries(ctx))} Bant IP block(s) in nft table 'bant'", "remove")
    if p.apt_bant_conf.exists():
        add("updates", str(p.apt_bant_conf), "keep (automatic security updates stay on)")
    for u in ("bant-firewall.service",):
        if (p.systemd_system / u).exists():
            add("systemd", u, "remove")
    add("files", str(p.install_dir) + " and " + str(p.launcher), "remove")
    add("data", f"{p.state_dir} (backups, state), {p.log_dir}, {p.etc_bant}", "keep backups/logs unless --purge")
    return items


def run(ctx: Context, *, purge: bool = False, remove_f2b_config: bool = False) -> dict[str, Any]:
    ctx.require_root("Uninstalling Bant")
    p = ctx.paths
    done: list[str] = []
    warnings: list[str] = []
    with ctx.lock():
        if TxManager(ctx).pending():
            raise OperationFailed("An SSH change is pending confirmation.",
                                  hint="Run `bant ssh confirm` or `bant ssh rollback` before uninstalling.")
        st = ssh.status(ctx)
        if st.installed:
            ok, msg = sshconf.validate(ctx)
            if not ok:
                raise OperationFailed(f"SSH configuration is invalid ({msg}); refusing to uninstall.",
                                      hint="Fix it or run `bant restore` first.")
            if not st.active_ports or not any(netinfo.tcp_listening(ctx, x) for x in st.active_ports):
                raise OperationFailed("Could not confirm a working SSH listener; refusing to uninstall.")
        if ctx.dry_run:
            return {"dry_run": True, "plan": inventory(ctx)}
        b = backups.create(ctx, note="pre-uninstall")
        done.append(f"backup created: {b['id']}")

        # firewall: only registry-owned rules
        for rule in firewall.registry(ctx):
            ok, msg = firewall.remove_rule(ctx, rule)
            if ok:
                done.append(f"removed firewall rule {rule['id']} ({rule['port']}/{rule['proto']})")
            else:
                warnings.append(f"could not remove firewall rule {rule['id']}: {msg}")
        ctx.state.update(lambda d: d.setdefault("firewall", {}).__setitem__("rules", []))
        if ctx.which("nft") and p.blocklist_file.exists():
            ctx.run_mut(["nft", "delete", "table", "inet", bans.TABLE])
            done.append("removed Bant nftables blocklist table")

        # SSH: retain settings under a neutral name
        before_ports = list(st.active_ports)
        if p.ssh_dropin.exists():
            body = read_text(p.ssh_dropin).replace("# Managed by Bant - do not edit by hand; changes are overwritten.\n", RETAIN_HEADER)
            ctx.write_file(p.ssh_retained_dropin, body, 0o644)
            p.ssh_dropin.unlink()
            done.append(f"SSH settings kept in {p.ssh_retained_dropin.name}")
        for unit in ("ssh.socket", "sshd.socket"):
            sd = p.socket_dropin(unit)
            if sd.exists():
                body = read_text(sd).replace("# Managed by Bant - do not edit by hand.\n", RETAIN_HEADER)
                ctx.write_file(p.socket_retained_dropin(unit), body, 0o644)
                sd.unlink()
                done.append(f"{unit} listener settings kept in ssh-port.conf")
        if st.installed:
            ok, msg = sshconf.validate(ctx)
            after = sshconf.effective(ctx).ports
            if not ok or (st.mode == "service" and set(after) != set(before_ports)):
                # restore the Bant drop-in: uninstall must not change what SSH listens on
                backups.apply_manifest(ctx, backups.resolve(ctx, b["id"]))
                raise OperationFailed(f"Retaining SSH settings changed the effective ports ({before_ports} -> {after}); restored.")

        # Fail2ban
        if p.f2b_jail.exists():
            if remove_f2b_config:
                p.f2b_jail.unlink()
                p.f2b_filter.unlink(missing_ok=True)
                done.append("removed Bant's Fail2ban jail (SSH jail reverts to distribution defaults - port 22!)")
                warnings.append("Fail2ban's sshd jail now protects the default SSH port only.")
            else:
                body = read_text(p.f2b_jail).replace("# Managed by Bant - do not edit by hand; changes are overwritten.\n", RETAIN_HEADER)
                ctx.write_file(p.f2b_retained_jail, body, 0o644)
                p.f2b_jail.unlink()
                done.append(f"Fail2ban SSH jail settings kept in {p.f2b_retained_jail.name}")
            if p.f2b_filter.exists() and not remove_f2b_config:
                body = read_text(p.f2b_filter).replace("# Managed by Bant - do not edit by hand; changes are overwritten.\n", RETAIN_HEADER)
                ctx.write_file(p.f2b_filter, body, 0o644)
            if ctx.which("fail2ban-client") and ctx.run(["fail2ban-client", "-t"]).ok:
                ctx.run_mut(["fail2ban-client", "reload"])
            else:
                warnings.append("fail2ban-client -t failed after the change; check `fail2ban-client -t`.")

        # reload ssh against the final config
        if st.installed and has_systemd(ctx):
            if st.mode == "socket" and st.socket_unit:
                ctx.run_mut(["systemctl", "daemon-reload"])
            elif st.service_unit:
                ctx.run_mut(["systemctl", "reload", st.service_unit])
            if before_ports and not ctx.wait_until(lambda: all(netinfo.tcp_listening(ctx, x) for x in before_ports)):
                warnings.append("SSH listener state changed after reload - verify with `ss -ltn` immediately.")

        # systemd units and stale transaction units
        if has_systemd(ctx):
            ctx.run_mut(["systemctl", "disable", "--now", "bant-firewall.service"])
            for tx in TxManager(ctx).all():
                TxManager(ctx).abandon_units(tx)
            (p.systemd_system / "bant-firewall.service").unlink(missing_ok=True)
            ctx.run_mut(["systemctl", "daemon-reload"])
            done.append("removed Bant systemd units")

        ctx.audit("uninstall", done=done, warnings=warnings, purge=purge)
        # data
        kept = []
        if purge:
            for d in (p.state_dir, p.log_dir, p.etc_bant):
                shutil.rmtree(d, ignore_errors=True)
            done.append("purged Bant data, logs and configuration")
        else:
            shutil.rmtree(p.tx_dir, ignore_errors=True)
            kept = [str(p.backup_dir), str(p.log_dir), str(p.config_file)]
        shutil.rmtree(p.install_dir, ignore_errors=True)
        p.launcher.unlink(missing_ok=True)
        done.append("removed Bant program files and the `bant` command")
    return {"done": done, "warnings": warnings, "kept": kept,
            "final": {"ssh_ports": before_ports, "fail2ban": "left installed",
                      "note": "SSH was not reverted to port 22 and no listener was removed."}}
