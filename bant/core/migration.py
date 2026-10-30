"""Safe SSH port migration (to a random free port by default, or the port you choose).

Lifecycle of an `ssh-port` transaction:

  prepared  -> rollback timer armed, nothing changed yet
  dual      -> firewall open, Fail2ban covers old+new, sshd listens on old AND new port
  (user opens a NEW session on the new port)
  confirm   -> server-side verification of that session, then
  finalized -> old listener removed, Fail2ban narrowed, timer disarmed

Anything that goes wrong - or a missing confirmation before the deadline - restores the original
configuration through the persistent rollback script.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from bant.context import Context
from bant.core import fail2ban, firewall, netinfo, ports, ssh, sshconf
from bant.core.rollback import Transaction, TxManager
from bant.errors import BantError, OperationFailed, RolledBack
from bant.platform import detect_os, has_systemd
from bant.utils.validation import parse_port


@dataclass
class PortPlan:
    target: int
    old_ports: list[int] = field(default_factory=list)
    mode: str = "service"
    service_unit: str | None = None
    socket_unit: str | None = None
    already_done: bool = False
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)


def plan(ctx: Context, target: int) -> PortPlan:
    target = parse_port(target)
    st = ssh.status(ctx)
    p = PortPlan(target, st.active_ports, st.mode if st.installed else "none", st.service_unit, st.socket_unit)
    if not st.installed:
        p.blockers.append("OpenSSH server is not installed.")
        return p
    if not has_systemd(ctx):
        p.blockers.append("systemd is required for automatic rollback.")
    if st.pending_tx:
        p.blockers.append(f"SSH transaction {st.pending_tx} is still pending - run `bant ssh confirm` or `bant ssh rollback`.")
    if st.config_valid is False:
        p.blockers.append(f"Current SSH configuration is invalid: {st.config_error}")
    if st.mode == "socket" and not st.socket_unit:
        p.blockers.append("Could not identify the SSH socket unit.")
    pinned = sshconf.listen_addresses_with_ports(sshconf.parse_config(ctx))
    if pinned and st.mode != "socket":
        p.blockers.append(f"sshd_config pins ports inside ListenAddress ({pinned[0].raw.strip()}); Bant cannot move those "
                          "automatically. Convert them to plain `ListenAddress <ip>` + `Port` first.")
    if not p.old_ports:
        p.blockers.append("Could not determine the current SSH port(s).")
    if p.old_ports == [target]:
        p.already_done = True
        return p
    owner = netinfo.port_owner(ctx, target)
    if owner is not None and target not in p.old_ports:
        p.blockers.append(f"TCP port {target} is already in use by {owner or 'another process'}.")
    osi = detect_os(ctx)
    if not osi.supported:
        p.warnings.append(f"{osi.pretty} is not an officially supported release; proceeding with extra care.")
    if ports.in_ephemeral_range(ctx, target):
        p.warnings.append(f"TCP {target} is inside the kernel's ephemeral range {ports.ephemeral_range(ctx)}: an outgoing connection could "
                          "occasionally hold it when sshd starts. A port below that range (or `random`) is safer.")
    fw = firewall.detect(ctx)
    if fw.mode == "observe":
        p.warnings.append("Firewall is in observation-only mode: Bant cannot open the new port. "
                          "Make sure it is reachable (including any provider/cloud firewall).")
    p.warnings.append("If your VPS provider has its own firewall/security group, allow TCP "
                      f"{target} there BEFORE confirming, or the new connection will time out.")
    p.steps = [
        f"Open TCP {target} in the {fw.backend} firewall" if fw.restrictive else "No inbound filtering detected; no firewall change needed",
        f"Make Fail2ban protect ports {sorted(set(p.old_ports + [target]))}",
        f"Configure sshd to listen on {sorted(set(p.old_ports + [target]))} ({'ssh.socket drop-in' if st.mode == 'socket' else 'sshd_config.d/00-bant.conf'})",
        f"Verify TCP {target} accepts SSH connections",
        f"Wait for you to log in on port {target} and run `bant ssh confirm`",
        f"Then remove the old listener(s) {[x for x in p.old_ports if x != target]}",
    ]
    return p


def _write_listeners(ctx: Context, tx: Transaction, txm: TxManager, st: ssh.SshStatus, listen_ports: list[int],
                     dropin_ports: list[int]) -> None:
    """Write the sshd drop-in (always) and the socket drop-in (socket mode), then apply."""
    ports_opts = sshconf.read_dropin(ctx)[1]
    txm.backup_file(tx, ctx.paths.ssh_dropin)
    ctx.write_file(ctx.paths.ssh_dropin, sshconf.render_dropin(dropin_ports, ports_opts), 0o644)
    ok, msg = sshconf.validate(ctx)
    if not ok:
        raise OperationFailed(f"sshd rejected the new configuration: {msg}")
    if st.mode == "socket" and st.socket_unit:
        sock = ctx.paths.socket_dropin(st.socket_unit)
        txm.backup_file(tx, sock)
        hosts = ssh.socket_hosts(ctx, st.socket_unit)
        body = "[Socket]\nListenStream=\n" + "".join(f"ListenStream={h}:{p}\n" for p in listen_ports for h in hosts)
        ctx.write_file(sock, "# Managed by Bant - do not edit by hand.\n" + body, 0o644)
        txm.add_post(tx, ["systemctl", "daemon-reload"])
        txm.add_post(tx, ["systemctl", "restart", st.socket_unit])
        for argv in (["systemctl", "daemon-reload"], ["systemctl", "restart", st.socket_unit]):
            res = ctx.run_mut(argv, timeout=60)
            if not res.ok:
                raise OperationFailed(f"{' '.join(argv)} failed: {res.output}")
    else:
        txm.add_post(tx, ["systemctl", "reload", st.service_unit or "ssh.service"])
        ssh.reload_ssh(ctx, st)


def begin(ctx: Context, target: int, *, minutes: int | None = None) -> dict[str, Any]:
    """Start the migration: leaves SSH listening on old+new ports with automatic rollback armed."""
    ctx.require_root("Moving the SSH port")
    target = parse_port(target)
    with ctx.lock():
        p = plan(ctx, target)
        if p.blockers:
            raise OperationFailed("Cannot migrate SSH: " + " ".join(p.blockers),
                                  hint="Resolve the issue above, or choose another port: `bant ssh port <PORT>`.")
        if p.already_done:
            return _ensure_protection(ctx, p)
        if ctx.dry_run:
            return {"dry_run": True, "plan": p}
        st = ssh.status(ctx)
        ports.remember(ctx, target)
        minutes = minutes or ctx.config.rollback_minutes
        dual = sorted(set(p.old_ports + [target]))
        txm = TxManager(ctx)
        tx = txm.begin("ssh-port", minutes, {
            "target": target, "old_ports": p.old_ports, "mode": p.mode, "service_unit": p.service_unit,
            "socket_unit": p.socket_unit, "require": {"port": target, "method": None},
        })
        try:
            directives = sshconf.parse_config(ctx)
            explicit = {int(d.args.strip()) for d in sshconf.explicit_ports(directives, exclude=ctx.paths.ssh_dropin)
                        if d.args.strip().isdigit()}
            emit = [x for x in dual if x not in explicit]
            fw_res = firewall.allow_port(ctx, target, "tcp", purpose="ssh", tx=tx, txm=txm)
            tx.meta["firewall"] = fw_res.message
            f2b_installed = fail2ban.installed(ctx)[0]
            if f2b_installed:
                fail2ban.apply_policy(ctx, dual, tx=tx, txm=txm)
            _write_listeners(ctx, tx, txm, st, dual, emit)
            if not ctx.wait_until(lambda: netinfo.tcp_listening(ctx, target)):
                raise OperationFailed(f"sshd is not listening on TCP {target} after the change.")
            if not ctx.banner_probe("127.0.0.1", target):
                raise OperationFailed(f"TCP {target} is open but did not answer with an SSH banner.")
            for old in p.old_ports:
                if old != target and not netinfo.tcp_listening(ctx, old):
                    raise OperationFailed(f"The old SSH port {old} stopped listening; aborting to keep access.")
            txm.set_phase(tx, "dual", f"sshd listens on {dual}")
        except (Exception, KeyboardInterrupt) as exc:  # Ctrl+C must not leave a half-applied change behind
            done = txm.rollback(tx, str(exc) or type(exc).__name__)
            ctx.audit("ssh.port.failed", level="error", target=target, error=str(exc), rolled_back=done)
            msg = exc.message if isinstance(exc, BantError) else f"{type(exc).__name__}: {exc}"
            raise RolledBack(
                f"SSH migration to port {target} failed and the original configuration was "
                f"{'restored' if done else 'NOT fully restored - run `bant repair` or see docs/RECOVERY.md'}: {msg}"
            ) from exc
        ctx.audit("ssh.port.dual", target=target, old=p.old_ports, tx=tx.id)
        return {"tx": tx.id, "deadline": tx.deadline, "target": target, "old_ports": p.old_ports,
                "firewall": fw_res.message, "mode": p.mode, "warnings": p.warnings}


def _ensure_protection(ctx: Context, p: PortPlan) -> dict[str, Any]:
    """SSH is already on the target port: make sure the firewall and Fail2ban agree (idempotent)."""
    with ctx.lock():
        fw_res = firewall.allow_port(ctx, p.target, "tcp", purpose="ssh")
        for rule in fw_res.rules:
            firewall.commit_rules(ctx, [rule])
        if fail2ban.installed(ctx)[0]:
            fail2ban.apply_policy(ctx, [p.target])
        ctx.config.set("ssh", "port", p.target)
        ctx.config.save()
    return {"already_done": True, "target": p.target, "firewall": fw_res.message}


# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------

def pending(ctx: Context) -> Transaction | None:
    txs = TxManager(ctx).pending()
    return txs[-1] if txs else None


def verify_new_session(ctx: Context, tx: Transaction) -> tuple[bool, str, netinfo.SshSession | None]:
    """Server-side proof that a NEW authenticated session arrived as required by the transaction."""
    req = tx.meta.get("require", {})
    port = req.get("port")
    local = netinfo.local_addresses(ctx)
    cands = [s for s in netinfo.ssh_sessions(ctx)
             if s.started >= tx.created - 2 and (port is None or s.local_port == port) and s.remote_ip not in local]
    if req.get("method") == "publickey":
        keyed = {(s.pid) for s in ssh.live_pubkey_sessions(ctx, since=tx.created - 2)}
        cands = [s for s in cands if s.pid in keyed]
    if cands:
        s = cands[0]
        return True, f"verified: {s.user} from {s.remote_ip} via port {s.local_port}", s
    where = f"on TCP port {port}" if port else "using your SSH key"
    how = f"(for example: ssh -p {port} <user>@<server-ip>)" if port else "with your key (ssh -i <key> <user>@<server-ip>)"
    msg = "\n".join([
        f"No authenticated SSH session {where} that started after this change was found on the server.",
        f"  1. Open a NEW terminal and connect {how}.",
        "  2. Keep it open and run `sudo bant ssh confirm` again (from either session).",
        "  If the new connection times out, a provider/cloud firewall may be blocking the port; "
        "allow it there, or run `sudo bant ssh rollback`.",
    ])
    return False, msg, None


def confirm(ctx: Context) -> dict[str, Any]:
    ctx.require_root("Confirming an SSH change")
    with ctx.lock():
        tx = pending(ctx)
        if tx is None:
            last = next(iter(sorted(TxManager(ctx).all(), key=lambda t: t.created, reverse=True)), None)
            if last is not None and last.status == "rolled_back":
                raise OperationFailed(
                    f"The last SSH change ({last.kind}, {last.id}) was already rolled back - its deadline passed or it failed.",
                    hint="Your previous configuration is active. Check `bant logs`, then start again (e.g. `sudo bant ssh port random`).")
            raise OperationFailed("No SSH change is waiting for confirmation.", hint="Run `bant ssh` to see the current state.")
        ok, detail, sess = verify_new_session(ctx, tx)
        if not ok:
            raise OperationFailed(detail)
        txm = TxManager(ctx)
        if tx.kind == "ssh-port":
            result = finalize_port(ctx, tx, txm)
        else:
            txm.confirm(tx)
            result = {"kind": tx.kind, "changes": tx.meta.get("changes", {})}
        result["verified"] = detail
        ctx.audit("ssh.confirmed", tx=tx.id, kind=tx.kind, session=detail)
        return result


def finalize_port(ctx: Context, tx: Transaction, txm: TxManager) -> dict[str, Any]:
    target = tx.meta["target"]
    old = [p for p in tx.meta["old_ports"] if p != target]
    st = ssh.status(ctx)
    f2b_note = ""
    try:
        txm.set_phase(tx, "finalizing", "removing old listener(s)")
        directives = sshconf.parse_config(ctx)
        disabled = sshconf.comment_out_ports(ctx, directives, set(old), lambda path: txm.backup_file(tx, path))
        remaining = {int(d.args.strip()) for d in sshconf.explicit_ports(sshconf.parse_config(ctx), exclude=ctx.paths.ssh_dropin)
                     if d.args.strip().isdigit()}
        emit = [] if target in remaining else [target]
        _write_listeners(ctx, tx, txm, st, [target], emit)
        if not ctx.wait_until(lambda: netinfo.tcp_listening(ctx, target)):
            raise OperationFailed(f"sshd stopped listening on TCP {target}.")
        if not ctx.wait_until(lambda: not any(netinfo.tcp_listening(ctx, p) for p in old)):
            raise OperationFailed(f"Old SSH port(s) {old} are still listening after the change.")
        if not ctx.banner_probe("127.0.0.1", target):
            raise OperationFailed(f"sshd does not answer on TCP {target}.")
        if fail2ban.installed(ctx)[0]:
            try:
                fail2ban.apply_policy(ctx, [target], tx=tx, txm=txm)
            except BantError as exc:
                # Not fatal: apply_policy restored the previous jail, which still covers the new port.
                f2b_note = f"Fail2ban could not be narrowed to port {target} ({exc.message}); it still protects the new port."
        eff = sshconf.effective(ctx)
        if st.mode != "socket" and eff.ports != [target]:
            raise OperationFailed(f"Effective sshd ports are {eff.ports}, expected [{target}].")
    except (Exception, KeyboardInterrupt) as exc:
        done = txm.rollback(tx, f"finalize failed: {exc}")
        msg = exc.message if isinstance(exc, BantError) else str(exc)
        raise RolledBack(f"Finalising failed ({msg}); original SSH configuration "
                         f"{'restored' if done else 'NOT fully restored - see docs/RECOVERY.md'}.") from exc
    permanent = [r for r in tx.meta.get("firewall_rules", []) if not r.get("temporary")]
    firewall.commit_rules(ctx, permanent)
    txm.confirm(tx)
    ctx.config.set("ssh", "port", target)
    ctx.config.save()
    ctx.state.update(lambda d: d.setdefault("migration", {}).update({"status": "done", "port": target, "tx": tx.id}))
    ctx.audit("ssh.port.done", target=target, removed=old, disabled=[f"{d.file}:{d.lineno}" for d in disabled])
    notes = [f2b_note] if f2b_note else []
    if old:
        notes.append(f"Firewall rules for the old port(s) {old} that Bant did not create were left untouched; "
                     "remove them yourself if no longer needed.")
    return {"kind": "ssh-port", "port": target, "removed_ports": old, "notes": notes}


def abort(ctx: Context) -> dict[str, Any]:
    ctx.require_root("Rolling back an SSH change")
    with ctx.lock():
        tx = pending(ctx)
        if tx is None:
            raise OperationFailed("No SSH change is pending.")
        txm = TxManager(ctx)
        done = txm.rollback(tx, "rolled back by administrator")
        if not done:
            raise OperationFailed("Rollback did not complete.", hint="Run the emergency script: see docs/RECOVERY.md")
        return {"rolled_back": tx.id, "log": txm.rollback_log(tx.id)[-800:]}


def extend(ctx: Context, minutes: int) -> dict[str, Any]:
    ctx.require_root("Extending the rollback window")
    with ctx.lock():
        tx = pending(ctx)
        if tx is None:
            raise OperationFailed("No SSH change is pending.")
        txm = TxManager(ctx)
        txm.extend(tx, minutes)
        return {"tx": tx.id, "deadline": tx.deadline}


def describe_pending(ctx: Context) -> dict[str, Any] | None:
    tx = pending(ctx)
    if tx is None:
        return None
    return {"id": tx.id, "kind": tx.kind, "phase": tx.phase, "seconds_left": tx.seconds_left(ctx.clock()),
            "deadline": tx.deadline, "target": tx.meta.get("target"), "require": tx.meta.get("require", {})}


def login_hint(ctx: Context, port: int) -> str:
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "<user>"
    sess = netinfo.current_session(ctx)
    return f"ssh -p {port} {sess.user if sess else user}@<server-ip>"
