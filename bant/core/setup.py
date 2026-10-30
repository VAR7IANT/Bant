"""First-run setup (`bant setup`, called by install.sh). Idempotent and resumable.

Order of operations: baseline files -> backup -> Fail2ban (for the *current* SSH ports) ->
SSH port migration to a random free port or the port you choose (dual listener, rollback armed) -> summary. The migration is never
finalised here: that needs a verified new connection (`bant ssh confirm`).
"""

from __future__ import annotations

from typing import Any

from bant.context import Context
from bant.core import backups, fail2ban, firewall, migration, ports, ssh
from bant.core.rollback import TxManager
from bant.errors import BantError
from bant.platform import detect_os, has_systemd
from bant.utils import fsutil


def _step(ctx: Context, name: str, status: str, detail: str = "") -> dict[str, str]:
    rec = {"step": name, "status": status, "detail": detail}
    ctx.state.update(lambda d: d.setdefault("install", {}).setdefault("steps", {}).__setitem__(name, {"status": status, "detail": detail}))
    return rec


def run(ctx: Context, *, migrate: bool = True, with_fail2ban: bool = True, port: int | str | None = None,
        minutes: int | None = None) -> dict[str, Any]:
    ctx.require_root("Setting up Bant")
    steps: list[dict[str, str]] = []
    next_steps: list[str] = []
    osi = detect_os(ctx)
    with ctx.lock():
        # 1 baseline
        fsutil.ensure_dir(ctx.paths.etc_bant, 0o755)
        fsutil.ensure_dir(ctx.paths.state_dir, 0o700)
        fsutil.ensure_dir(ctx.paths.log_dir, 0o750)
        if not ctx.paths.config_file.exists():
            ctx.config.save()
        steps.append(_step(ctx, "baseline", "done", f"{osi.pretty}; config {ctx.paths.config_file}"))
        if not osi.supported:
            steps[-1]["detail"] += " (unsupported release - proceeding cautiously)"

        # 2 backup
        if not backups.list_backups(ctx):
            b = backups.create(ctx, note="pre-setup baseline")
            steps.append(_step(ctx, "backup", "done", f"backup {b['id']}"))
        else:
            steps.append(_step(ctx, "backup", "skipped", "backups already exist"))

        st = ssh.status(ctx)
        if not st.installed:
            steps.append(_step(ctx, "ssh", "skipped", "OpenSSH server not installed"))
            migrate = False

        pend = TxManager(ctx).pending()
        target, port_source = 0, ""
        if migrate and not pend:
            target, port_source = ports.resolve_target(ctx, port)

        # 3 Fail2ban for the ports in use right now
        if with_fail2ban:
            try:
                if pend:
                    steps.append(_step(ctx, "fail2ban", "skipped", "an SSH change is pending; Fail2ban follows that transaction"))
                else:
                    msg = fail2ban.install(ctx)
                    res = fail2ban.apply_policy(ctx, st.active_ports or None)
                    ctx.run_mut(["systemctl", "enable", "--now", "fail2ban.service"])
                    detail = f"{msg}; sshd jail on ports {res['ports']}"
                    if res["conflicts"]:
                        detail += "; kept administrator settings: " + "; ".join(res["conflicts"])
                    steps.append(_step(ctx, "fail2ban", "done", detail))
            except BantError as exc:
                steps.append(_step(ctx, "fail2ban", "failed", exc.message))
                next_steps.append("Fix Fail2ban, then run `sudo bant fail2ban enable`: " + exc.message)

        # 4 firewall (observation + registry reconciliation)
        fw = firewall.detect(ctx)
        steps.append(_step(ctx, "firewall", "done", f"{fw.backend} ({fw.mode}): {fw.detail}"))

        # 5 SSH migration
        migration_result: dict[str, Any] | None = None
        if pend:
            tx = pend[-1]
            steps.append(_step(ctx, "ssh-migration", "pending", f"transaction {tx.id} awaits `bant ssh confirm`"))
        elif migrate:
            p = migration.plan(ctx, target)
            if p.already_done:
                migration_result = migration.begin(ctx, target)
                steps.append(_step(ctx, "ssh-migration", "done", f"SSH already on TCP {target} ({ports.DESCRIPTIONS[port_source]})"))
            elif p.blockers:
                steps.append(_step(ctx, "ssh-migration", "skipped", " ".join(p.blockers)))
                next_steps.append(f"Resolve the blocker, then run `sudo bant ssh port {target}` (or `sudo bant ssh port random`).")
            else:
                try:
                    migration_result = migration.begin(ctx, target, minutes=minutes)
                    steps.append(_step(ctx, "ssh-migration", "pending",
                                       f"new SSH port {target} ({ports.DESCRIPTIONS[port_source]}); listening on {sorted(set(p.old_ports + [target]))}"))
                except BantError as exc:
                    steps.append(_step(ctx, "ssh-migration", "failed", exc.message))
        else:
            steps.append(_step(ctx, "ssh-migration", "skipped", "disabled by option"))

        # 6 systemd unit for firewall persistence
        if has_systemd(ctx) and (ctx.paths.systemd_system / "bant-firewall.service").exists():
            ctx.run_mut(["systemctl", "enable", "bant-firewall.service"])

        pend = TxManager(ctx).pending()
        failed = [s for s in steps if s["status"] == "failed"]
        skipped_mig = any(s["step"] == "ssh-migration" and s["status"] == "skipped" for s in steps)
        if pend:
            outcome = "pending_confirmation"
            d = migration.describe_pending(ctx)
            if d and d.get("target"):
                next_steps.insert(0, f"FIRST allow inbound TCP {d['target']} in your VPS provider's firewall / security group, if it has one.")
                next_steps.insert(1, f"Open a NEW terminal and connect: {migration.login_hint(ctx, d['target'])}")
                next_steps.insert(2, "Then run `sudo bant ssh confirm` within the deadline (`sudo bant ssh extend` adds time).")
        elif failed or skipped_mig:
            outcome = "incomplete"
        else:
            outcome = "complete"
        ctx.state.update(lambda d: d.setdefault("install", {}).update({"outcome": outcome, "updated": int(ctx.clock())}))
        ctx.audit("setup", outcome=outcome, steps=steps)

    return {"outcome": outcome, "steps": steps, "next_steps": next_steps, "migration": migration_result,
            "pending": migration.describe_pending(ctx), "ssh_port": target or None, "port_source": port_source or None}
