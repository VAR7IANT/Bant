"""`bant repair`: reconcile Bant's own state with the system. Never makes a risky SSH change."""

from __future__ import annotations

import os
import stat

from bant.context import Context
from bant.core import bans, fail2ban, firewall, ssh
from bant.core.rollback import TxManager
from bant.platform import has_systemd, unit_state


def run(ctx: Context) -> list[dict[str, str]]:
    ctx.require_root("Repairing Bant")
    actions: list[dict[str, str]] = []

    def note(what: str, result: str = "ok") -> None:
        actions.append({"action": what, "result": result})

    with ctx.lock():
        # 1. permissions of Bant's own state
        for path, mode in ((ctx.paths.state_dir, 0o700), (ctx.paths.backup_dir, 0o700), (ctx.paths.tx_dir, 0o700),
                           (ctx.paths.log_dir, 0o750), (ctx.paths.state_file, 0o600), (ctx.paths.audit_log, 0o600)):
            if path.exists() and not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) & ~mode:
                if not ctx.dry_run:
                    os.chmod(path, mode)
                note(f"tightened permissions on {path}", oct(mode))

        # 2. transactions: timers that outlived their transaction, past-deadline open transactions
        txm = TxManager(ctx)
        for tx in txm.all():
            svc, tmr = txm.unit_names(tx.id)
            exists = unit_state(ctx, tmr)["LoadState"] not in ("", "not-found")
            if tx.status in ("confirmed", "rolled_back") and exists:
                if not ctx.dry_run:
                    txm.abandon_units(tx)
                note(f"removed leftover timer {tmr}")
            elif tx.status == "open" and tx.deadline < ctx.clock():
                done = txm.rollback(tx, "repair: transaction past its deadline")
                note(f"rolled back overdue transaction {tx.id}", "ok" if done else "FAILED")
            elif tx.status == "rollback_failed":
                done = txm.rollback(tx, "repair: retrying failed rollback")
                note(f"retried rollback of {tx.id}", "ok" if done else "FAILED - see docs/RECOVERY.md")
            elif tx.status == "open" and not exists and has_systemd(ctx):
                note(f"transaction {tx.id} has no rollback timer", "re-arming")
                if not ctx.dry_run:
                    txm.extend(tx, 1)

        # 3. firewall registry and blocklist
        for line in firewall.reapply(ctx) if not ctx.dry_run else []:
            note(line)
        if bans.available(ctx) and not ctx.dry_run:
            n = bans.reapply_boot(ctx)
            if n:
                note(f"re-applied {n} Bant block(s)")

        # 4. Fail2ban policy matches SSH ports
        if fail2ban.installed(ctx)[0] and ctx.paths.f2b_jail.exists():
            st = ssh.status(ctx)
            ov = fail2ban.overview(ctx, st.active_ports)
            if ov.state in ("misconfigured", "inactive") or any("covers" in p for p in ov.problems):
                try:
                    if not ctx.dry_run:
                        fail2ban.apply_policy(ctx, st.active_ports)
                    note("re-applied Fail2ban SSH policy")
                except Exception as exc:  # noqa: BLE001
                    note("re-apply Fail2ban policy", f"FAILED: {exc}")
        if not actions:
            note("nothing to repair")
        ctx.audit("repair", actions=actions)
    return actions
