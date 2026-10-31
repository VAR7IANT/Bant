"""One-click protection / first-run setup (`bant setup`, called by install.sh). Idempotent and resumable.

Order of operations: environment check -> baseline files -> backup -> Fail2ban (for the *current* SSH
ports) -> firewall detection -> SSH port migration to a random free port or the port you choose
(dual listener, rollback armed) -> verification summary. The migration is never finalised here: that
needs a verified new connection (`bant ssh confirm`). Password login is never changed here.

Every step is independent: a failure is recorded with its reason and the remaining steps still run
where that is safe. Running setup again resumes: finished steps report "already enabled" and are not
repeated, and an unfinished migration is picked up where it stopped.
"""

from __future__ import annotations

from typing import Any

from bant.context import Context
from bant.core import backups, fail2ban, firewall, migration, ports, ssh, updater
from bant.core.rollback import TxManager
from bant.errors import BantError
from bant.platform import detect_os, has_systemd
from bant.utils import fsutil

ALREADY = "already enabled, no reconfiguration needed"
STEP_ORDER = ["environment", "baseline", "backup", "fail2ban", "firewall", "ssh-migration", "update-check", "verify"]


def _step(ctx: Context, name: str, status: str, detail: str = "") -> dict[str, str]:
    rec = {"step": name, "status": status, "detail": detail}
    if not ctx.dry_run:
        ctx.state.update(lambda d: d.setdefault("install", {}).setdefault("steps", {}).__setitem__(name, {"status": status, "detail": detail}))
    return rec


def initialized(ctx: Context) -> str:
    """'complete', 'pending_confirmation', 'incomplete' or 'never' (program installed, setup not run)."""
    outcome = ctx.state.get("install", "outcome")
    if TxManager(ctx).pending():
        return "pending_confirmation"
    if outcome in ("complete", "incomplete", "pending_confirmation"):
        return "incomplete" if outcome == "pending_confirmation" else outcome
    return "never"


def preview(ctx: Context, *, migrate: bool = True, with_fail2ban: bool = True, port: int | str | None = None) -> dict[str, Any]:
    """What setup would do, without writing anything (`--dry-run`)."""
    steps: list[dict[str, str]] = []
    osi = detect_os(ctx)
    steps.append({"step": "environment", "status": "planned",
                  "detail": osi.pretty + ("" if osi.supported else " (unsupported release - proceeding cautiously)")})
    steps.append({"step": "backup", "status": "planned" if not backups.list_backups(ctx) else "skipped",
                  "detail": "back up SSH, Fail2ban and firewall configuration" if not backups.list_backups(ctx) else "backups already exist"})
    if with_fail2ban:
        ok, ver = fail2ban.installed(ctx)
        steps.append({"step": "fail2ban", "status": "planned", "detail": f"configure Fail2ban {ver}" if ok else "install and configure Fail2ban"})
    fw = firewall.detect(ctx)
    steps.append({"step": "firewall", "status": "planned", "detail": f"{fw.backend} ({fw.mode})"})
    target, source = None, None
    if migrate and ssh.status(ctx).installed and not TxManager(ctx).pending():
        try:
            target, source = ports.resolve_target(ctx, port)
            p = migration.plan(ctx, target)
            if p.already_done:
                steps.append({"step": "ssh-migration", "status": "skipped", "detail": f"SSH already on TCP {target}"})
            elif p.blockers:
                steps.append({"step": "ssh-migration", "status": "failed", "detail": " ".join(p.blockers)})
            else:
                steps.append({"step": "ssh-migration", "status": "planned",
                              "detail": f"new SSH port {target} ({ports.DESCRIPTIONS[source]}); the old port stays open until you confirm"})
        except BantError as exc:
            steps.append({"step": "ssh-migration", "status": "failed", "detail": exc.message})
    return {"outcome": "dry_run", "dry_run": True, "steps": steps, "next_steps": [], "migration": None, "pending": None,
            "ssh_port": target, "port_source": source, "summary": summarize(steps, None)}


def summarize(steps: list[dict[str, str]], tx_status: str | None) -> dict[str, Any]:
    done = [s["step"] for s in steps if s["status"] in ("done", "already")]
    failed = [{"step": s["step"], "reason": s["detail"]} for s in steps if s["status"] == "failed"]
    seen = {s["step"] for s in steps}
    remaining = [s["step"] for s in steps if s["status"] in ("pending", "skipped", "planned")] + \
        [n for n in STEP_ORDER if n not in seen]
    return {"completed": done, "failed": failed, "remaining": remaining, "rolled_back": tx_status == "rolled_back"}


def run(ctx: Context, *, migrate: bool = True, with_fail2ban: bool = True, port: int | str | None = None,
        minutes: int | None = None, update_check: bool = True) -> dict[str, Any]:
    ctx.require_root("Setting up Bant")
    if ctx.dry_run:
        return preview(ctx, migrate=migrate, with_fail2ban=with_fail2ban, port=port)
    steps: list[dict[str, str]] = []
    next_steps: list[str] = []
    osi = detect_os(ctx)
    with ctx.lock():
        # 1 environment + baseline
        steps.append(_step(ctx, "environment", "done",
                           osi.pretty + ("" if osi.supported else " (unsupported release - proceeding cautiously)")))
        try:
            fsutil.ensure_dir(ctx.paths.etc_bant, 0o755)
            fsutil.ensure_dir(ctx.paths.state_dir, 0o700)
            fsutil.ensure_dir(ctx.paths.log_dir, 0o750)
            if not ctx.paths.config_file.exists():
                ctx.config.save()
            steps.append(_step(ctx, "baseline", "done", f"config {ctx.paths.config_file}"))
        except OSError as exc:
            steps.append(_step(ctx, "baseline", "failed", f"could not create Bant's directories: {exc}"))
            next_steps.append("Check disk space and permissions of /etc/bant, /var/lib/bant and /var/log/bant, then run `sudo bant setup` again.")

        # 2 backup of the original configuration (once; later runs keep the original)
        try:
            if not backups.list_backups(ctx):
                b = backups.create(ctx, note="pre-setup baseline")
                steps.append(_step(ctx, "backup", "done", f"original configuration saved as backup {b['id']}"))
            else:
                steps.append(_step(ctx, "backup", "already", "the original configuration was backed up by an earlier run"))
        except (BantError, OSError) as exc:
            steps.append(_step(ctx, "backup", "failed", str(getattr(exc, "message", exc))))
            migrate = False  # no SSH change without a way back
            next_steps.append("Fix the backup problem (disk space?) and run `sudo bant setup` again; SSH was not changed.")

        st = ssh.status(ctx)
        if not st.installed:
            migrate = False

        txm = TxManager(ctx)
        pend = txm.pending()
        target, port_source = 0, ""
        port_error: BantError | None = None
        if migrate and not pend:
            try:
                target, port_source = ports.resolve_target(ctx, port)
            except BantError as exc:
                # independent steps (Fail2ban, firewall) still run; the migration is reported as failed
                port_error = exc

        # 3 Fail2ban for the ports in use right now
        if with_fail2ban:
            try:
                if pend:
                    steps.append(_step(ctx, "fail2ban", "skipped", "an SSH change is pending; Fail2ban follows that transaction"))
                else:
                    was_installed = fail2ban.installed(ctx)[0]
                    msg = fail2ban.install(ctx)
                    res = fail2ban.apply_policy(ctx, st.active_ports or None)
                    if not res.get("unchanged"):
                        ctx.run_mut(["systemctl", "enable", "--now", "fail2ban.service"])
                    detail = f"{msg}; sshd jail on ports {res['ports']}"
                    if res["conflicts"]:
                        detail += f"; kept administrator settings: {'; '.join(res['conflicts'])} (see `sudo bant fail2ban conflicts`)"
                    if res.get("unchanged") and was_installed:
                        steps.append(_step(ctx, "fail2ban", "already", f"{ALREADY} (sshd jail on ports {res['ports']})"))
                    else:
                        steps.append(_step(ctx, "fail2ban", "done", detail))
            except BantError as exc:
                steps.append(_step(ctx, "fail2ban", "failed", exc.message))
                next_steps.append(f"Fix Fail2ban, then run `sudo bant fail2ban enable` (or `sudo bant setup` again): {exc.message}")
        else:
            steps.append(_step(ctx, "fail2ban", "skipped", "disabled by option"))

        # 4 firewall (observation + registry reconciliation)
        try:
            fw = firewall.detect(ctx)
            steps.append(_step(ctx, "firewall", "done", f"{fw.backend} ({fw.mode}): {fw.detail}"))
        except BantError as exc:
            steps.append(_step(ctx, "firewall", "failed", exc.message))

        # 5 SSH migration
        migration_result: dict[str, Any] | None = None
        if not st.installed:
            steps.append(_step(ctx, "ssh-migration", "skipped", "OpenSSH server not installed"))
        elif pend:
            tx = pend[-1]
            steps.append(_step(ctx, "ssh-migration", "pending", f"transaction {tx.id} awaits `bant ssh confirm`"))
        elif migrate and port_error is not None:
            steps.append(_step(ctx, "ssh-migration", "failed", port_error.message))
            next_steps.append(port_error.hint or "Choose an SSH port yourself: `sudo bant ssh port <PORT>`.")
        elif migrate:
            p = migration.plan(ctx, target)
            if p.already_done:
                migration_result = migration.begin(ctx, target)
                steps.append(_step(ctx, "ssh-migration", "already", f"SSH already on TCP {target} ({ports.DESCRIPTIONS[port_source]}); {ALREADY}"))
            elif p.blockers:
                steps.append(_step(ctx, "ssh-migration", "failed", " ".join(p.blockers)))
                next_steps.append(f"Resolve the problem above, then run `sudo bant setup --ssh-port <PORT>` or `sudo bant ssh port {target}`.")
            else:
                try:
                    migration_result = migration.begin(ctx, target, minutes=minutes)
                    steps.append(_step(ctx, "ssh-migration", "pending",
                                       f"new SSH port {target} ({ports.DESCRIPTIONS[port_source]}); listening on {sorted(set(p.old_ports + [target]))}"))
                except BantError as exc:
                    steps.append(_step(ctx, "ssh-migration", "failed", exc.message))
                    next_steps.append("Nothing was left half-done: the SSH change was rolled back. Fix the cause and run `sudo bant setup` again.")
        else:
            steps.append(_step(ctx, "ssh-migration", "skipped", "disabled by option" if st.installed else "OpenSSH server not installed"))

        # 6 daily check for new Bant releases (check only; never installs by itself)
        if update_check and has_systemd(ctx) and (ctx.paths.systemd_system / updater.TIMER).exists():
            try:
                was = updater.notify_enabled(ctx)
                if not was:
                    updater.set_notify(ctx, True)
                steps.append(_step(ctx, "update-check", "already" if was else "done",
                                   ALREADY if was else "daily check for new Bant releases enabled (check only)"))
            except BantError as exc:
                steps.append(_step(ctx, "update-check", "skipped", exc.message))

        # systemd unit for firewall persistence
        if has_systemd(ctx) and (ctx.paths.systemd_system / "bant-firewall.service").exists():
            ctx.run_mut(["systemctl", "enable", "bant-firewall.service"])

        # 7 verification of the resulting state
        steps.append(_verify(ctx))

        pend = TxManager(ctx).pending()
        failed = [s for s in steps if s["status"] == "failed"]
        if pend:
            outcome = "pending_confirmation"
            d = migration.describe_pending(ctx)
            if d and d.get("target"):
                next_steps.insert(0, f"FIRST allow inbound TCP {d['target']} in your VPS provider's firewall / security group, if it has one.")
                next_steps.insert(1, f"Open a NEW terminal and connect: {migration.login_hint(ctx, d['target'])}")
                next_steps.insert(2, "Then run `sudo bant ssh confirm` within the deadline (`sudo bant ssh extend` adds time).")
        elif failed or not any(s["step"] == "ssh-migration" and s["status"] in ("done", "already") for s in steps) and migrate and st.installed:
            outcome = "incomplete"
        else:
            outcome = "complete"
        if outcome == "incomplete":
            next_steps.append("Run `sudo bant setup` again at any time: finished steps are skipped and the rest is resumed.")
        last = txm.all()[-1] if txm.all() else None
        ctx.state.update(lambda d: d.setdefault("install", {}).update({"outcome": outcome, "updated": int(ctx.clock())}))
        ctx.audit("setup", outcome=outcome, steps=steps)

    return {"outcome": outcome, "steps": steps, "next_steps": next_steps, "migration": migration_result,
            "pending": migration.describe_pending(ctx), "ssh_port": target or None, "port_source": port_source or None,
            "summary": summarize(steps, last.status if last and outcome != "pending_confirmation" else None)}


def _verify(ctx: Context) -> dict[str, str]:
    from bant.core import netinfo, sshconf

    problems, good = [], []
    st = ssh.status(ctx)
    if st.installed:
        ok, msg = sshconf.validate(ctx)
        (good if ok else problems).append("sshd configuration valid" if ok else f"sshd -t: {msg}")
        live = [x for x in st.active_ports if netinfo.tcp_listening(ctx, x)]
        (good if live else problems).append(f"SSH listening on {live}" if live else "SSH listener not found")
    if fail2ban.installed(ctx)[0]:
        running = fail2ban.jail_status(ctx) is not None
        (good if running else problems).append("Fail2ban sshd jail running" if running else "Fail2ban sshd jail not running")
    if problems:
        return _step(ctx, "verify", "failed", "; ".join(problems))
    return _step(ctx, "verify", "done", "; ".join(good) or "nothing to verify")
