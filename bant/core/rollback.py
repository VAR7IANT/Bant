"""Persistent rollback transactions.

Every risky change (SSH port move, authentication policy change) opens a Transaction *before*
anything is modified. The transaction records, write-ahead, how to undo each step. Recovery
does not depend on this Python process, an open terminal or the SSH session:

  * /var/lib/bant/tx/<id>/tx.json      machine-readable state (0600)
  * /var/lib/bant/tx/<id>/backup/      original copies of every file touched
  * /var/lib/bant/tx/<id>/rollback.sh  generated POSIX shell script (re-run safe)
  * bant-rollback-<id>.timer/.service  persistent systemd timer that runs the script at the deadline
                                       (OnCalendar + Persistent=true, so it also fires after a reboot)

A transaction is only ever marked *confirmed* by the caller after server-side verification.
"""

from __future__ import annotations

import json
import re
import secrets
import shlex
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from bant.context import Context
from bant.errors import BantError, OperationFailed, Unsupported, ValidationError
from bant.platform import has_systemd
from bant.utils import fsutil

TX_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")
KEEP_FINISHED = 10


@dataclass
class Transaction:
    id: str
    kind: str
    created: float
    deadline: float
    status: str = "open"  # open | confirmed | rolled_back | rollback_failed
    files: list[dict[str, Any]] = field(default_factory=list)
    undo_cmds: list[list[str]] = field(default_factory=list)
    post_cmds: list[list[str]] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    phase: str = "prepared"
    log: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Transaction:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})

    def seconds_left(self, now: float) -> int:
        return max(0, int(self.deadline - now))


def new_id(now: float) -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now)) + "-" + secrets.token_hex(3)


def check_id(tx_id: str) -> str:
    if not TX_ID_RE.match(tx_id):
        raise ValidationError(f"Invalid transaction id: {tx_id!r}")
    return tx_id


class TxManager:
    def __init__(self, ctx: Context):
        self.ctx = ctx

    # ---- paths -----------------------------------------------------------
    def dir(self, tx_id: str) -> Path:
        return self.ctx.paths.tx_dir / check_id(tx_id)

    def unit_names(self, tx_id: str) -> tuple[str, str]:
        return f"bant-rollback-{tx_id}.service", f"bant-rollback-{tx_id}.timer"

    # ---- lifecycle -------------------------------------------------------
    def begin(self, kind: str, minutes: int, meta: dict[str, Any] | None = None) -> Transaction:
        """Create the transaction and arm the rollback timer BEFORE any change is made."""
        ctx = self.ctx
        ctx.require_root("Starting a transaction")
        if not has_systemd(ctx):
            raise Unsupported(
                "systemd is required for Bant's automatic rollback.",
                hint="Bant refuses risky SSH changes on systems without systemd.",
            )
        now = ctx.clock()
        tx = Transaction(new_id(now), kind, now, now + minutes * 60, meta=dict(meta or {}))
        d = self.dir(tx.id)
        fsutil.ensure_dir(ctx.paths.tx_dir, 0o700)
        fsutil.ensure_dir(d, 0o700)
        fsutil.ensure_dir(d / "backup", 0o700)
        self.save(tx)
        self._arm(tx)
        ctx.audit("tx.begin", tx=tx.id, kind=kind, deadline=int(tx.deadline))
        return tx

    def save(self, tx: Transaction) -> None:
        d = self.dir(tx.id)
        fsutil.atomic_write(d / "tx.json", tx.to_json(), 0o600)
        fsutil.atomic_write(d / "rollback.sh", self.render_script(tx), 0o700)

    # ---- write-ahead recording ------------------------------------------
    def backup_file(self, tx: Transaction, path: Path) -> None:
        """Record the original state of `path` (once). Must be called before modifying it."""
        if any(f["target"] == str(path) for f in tx.files):
            return
        entry: dict[str, Any] = {"target": str(path), "backup": None, "mode": 0o644, "uid": 0, "gid": 0}
        if path.is_symlink():
            raise OperationFailed(f"Refusing to manage symbolic link {path}")
        if path.exists():
            meta = fsutil.file_meta(path)
            rel = f"backup/{len(tx.files):03d}-{path.name}"
            fsutil.copy_private(path, self.dir(tx.id) / rel)
            entry.update(backup=str(self.dir(tx.id) / rel), mode=meta["mode"], uid=meta["uid"], gid=meta["gid"])
        tx.files.append(entry)
        self.save(tx)

    def add_undo(self, tx: Transaction, argv: list[str]) -> None:
        tx.undo_cmds.append([str(a) for a in argv])
        self.save(tx)

    def add_post(self, tx: Transaction, argv: list[str]) -> None:
        argv = [str(a) for a in argv]
        if argv not in tx.post_cmds:
            tx.post_cmds.append(argv)
            self.save(tx)

    def set_phase(self, tx: Transaction, phase: str, note: str | None = None) -> None:
        tx.phase = phase
        if note:
            tx.log.append(f"{time.strftime('%H:%M:%S', time.gmtime(self.ctx.clock()))} {note}")
        self.save(tx)

    # ---- queries ---------------------------------------------------------
    def load(self, tx_id: str) -> Transaction:
        path = self.dir(tx_id) / "tx.json"
        try:
            data = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            raise ValidationError(f"Unknown or unreadable transaction: {tx_id}") from exc
        tx = Transaction.from_dict(data)
        # The shell script is authoritative about its own outcome.
        d = self.dir(tx_id)
        if tx.status == "open":
            if (d / "rolled_back").exists():
                tx.status = "rolled_back"
            elif (d / "confirmed").exists():
                tx.status = "confirmed"
        return tx

    def all(self) -> list[Transaction]:
        out = []
        try:
            names = sorted(p.name for p in self.ctx.paths.tx_dir.iterdir() if TX_ID_RE.match(p.name))
        except OSError:
            return []
        for name in names:
            try:
                out.append(self.load(name))
            except BantError:
                continue
        return out

    def pending(self) -> list[Transaction]:
        return [t for t in self.all() if t.status == "open"]

    # ---- timer management -----------------------------------------------
    def _arm(self, tx: Transaction) -> None:
        ctx = self.ctx
        svc, tmr = self.unit_names(tx.id)
        sysd = ctx.paths.systemd_system
        script = self.dir(tx.id) / "rollback.sh"
        service = (
            "[Unit]\n"
            f"Description=Bant automatic rollback of change {tx.id}\n"
            "\n[Service]\nType=oneshot\n"
            f"ExecStart=/bin/sh {shlex.quote(str(script))}\n"
        )
        calendar = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(tx.deadline))
        timer = (
            "[Unit]\n"
            f"Description=Bant rollback deadline for change {tx.id}\n"
            "\n[Timer]\n"
            f"OnCalendar={calendar}\nAccuracySec=1s\nPersistent=true\n"
            f"Unit={svc}\n"
            "\n[Install]\nWantedBy=timers.target\n"
        )
        fsutil.atomic_write(sysd / svc, service, 0o644)
        fsutil.atomic_write(sysd / tmr, timer, 0o644)
        # `restart` (not just `enable --now`) so an already-running timer picks up a new deadline.
        for argv in (["systemctl", "daemon-reload"], ["systemctl", "enable", tmr], ["systemctl", "restart", tmr]):
            res = ctx.run_mut(argv)
            if not res.ok:
                self._unarm(tx)
                raise OperationFailed(
                    f"Could not arm the rollback timer ({' '.join(argv)}): {res.output}",
                    hint="No changes were made. Bant will not proceed without a working rollback.",
                )
        active = ctx.run(["systemctl", "is-active", tmr])
        if active.stdout.strip() != "active":
            self._unarm(tx)
            raise OperationFailed(
                f"Rollback timer {tmr} is not active after enabling it.",
                hint="No changes were made. Bant will not proceed without a working rollback.",
            )

    def _unarm(self, tx: Transaction) -> None:
        ctx = self.ctx
        svc, tmr = self.unit_names(tx.id)
        ctx.run_mut(["systemctl", "disable", "--now", tmr])
        for unit in (svc, tmr):
            ctx.remove_file(ctx.paths.systemd_system / unit)
        ctx.run_mut(["systemctl", "daemon-reload"])

    def extend(self, tx: Transaction, minutes: int) -> Transaction:
        """Push the deadline out (never while a rollback has already run)."""
        if tx.status != "open":
            raise OperationFailed(f"Transaction {tx.id} is {tx.status}; cannot extend.")
        tx.deadline = max(tx.deadline, self.ctx.clock()) + minutes * 60
        self.save(tx)
        self._arm(tx)
        self.ctx.audit("tx.extend", tx=tx.id, deadline=int(tx.deadline))
        return tx

    # ---- outcomes --------------------------------------------------------
    def confirm(self, tx: Transaction) -> None:
        """Mark confirmed and disarm the timer. Call ONLY after server-side verification succeeded."""
        d = self.dir(tx.id)
        if (d / "rolled_back").exists():
            raise OperationFailed(f"Transaction {tx.id} was already rolled back; it cannot be confirmed.")
        fsutil.atomic_write(d / "confirmed", f"{int(self.ctx.clock())}\n", 0o600)
        tx.status = "confirmed"
        self.save(tx)
        self._unarm(tx)
        self.ctx.audit("tx.confirmed", tx=tx.id, kind=tx.kind)
        self._prune(keep=tx.id)

    def rollback(self, tx: Transaction, reason: str) -> bool:
        """Run the generated rollback script now. Returns True if it reports completion."""
        ctx = self.ctx
        ctx.audit("tx.rollback.start", level="warning", tx=tx.id, reason=reason)
        script = self.dir(tx.id) / "rollback.sh"
        if not script.exists():
            self.save(tx)
        res = ctx.run_mut(["/bin/sh", str(script), "--lock-held"], timeout=180)
        d = self.dir(tx.id)
        done = (d / "rolled_back").exists()
        tx.status = "rolled_back" if done else "rollback_failed"
        if not done:
            fsutil.atomic_write(d / "rollback.error", res.output + "\n", 0o600)
        self.save(tx)
        ctx.audit("tx.rollback.end", level="info" if done else "error", tx=tx.id, ok=done, output=res.output[-500:])
        return done

    def finish_external(self, tx_id: str, outcome: str) -> None:
        """Bookkeeping after the systemd-triggered script ran (called via `bant _tx-finish`)."""
        tx = self.load(tx_id)
        if outcome == "rolled_back" and (self.dir(tx_id) / "rolled_back").exists():
            tx.status = "rolled_back"
            self.save(tx)
            self.ctx.audit("tx.rollback.timer", level="warning", tx=tx.id, kind=tx.kind,
                           log=self.rollback_log(tx.id)[-1200:])
            for rule in tx.meta.get("firewall_rules", []):
                self._forget_rule(rule)

    def _forget_rule(self, rule: dict[str, Any]) -> None:
        def fn(data: dict[str, Any]) -> None:
            rules = data.get("firewall", {}).get("rules", [])
            data.setdefault("firewall", {})["rules"] = [r for r in rules if r.get("id") != rule.get("id")]
        self.ctx.state.update(fn)

    def rollback_log(self, tx_id: str) -> str:
        return fsutil.read_text(self.dir(tx_id) / "rollback.log")

    def _prune(self, keep: str) -> None:
        """Delete the oldest finished transactions (by creation time), never the one just finished."""
        finished = sorted((t for t in self.all() if t.status != "open" and t.id != keep), key=lambda t: (t.created, t.id))
        for tx in finished[: max(0, len(finished) + 1 - KEEP_FINISHED)]:
            shutil.rmtree(self.dir(tx.id), ignore_errors=True)

    def abandon_units(self, tx: Transaction) -> None:
        """Remove timer/unit files of a finished transaction (used by repair)."""
        self._unarm(tx)

    # ---- script generation ----------------------------------------------
    def render_script(self, tx: Transaction) -> str:
        ctx = self.ctx
        q = shlex.quote
        tx_dir = self.dir(tx.id)
        svc, tmr = self.unit_names(tx.id)
        lines = [
            "#!/bin/sh",
            f"# Bant rollback for transaction {tx.id} ({tx.kind}). Generated file; safe to run repeatedly.",
            f"TX={q(str(tx_dir))}",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "export PATH",
            'LOG="$TX/rollback.log"',
            "log() { printf '%s %s\\n' \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \"$*\" >> \"$LOG\"; }",
            'run() { "$@" >> "$LOG" 2>&1 || log "command failed (continuing): $*"; }',
            f"exec 9> {q(str(ctx.paths.lock_file))}",
            'if [ "$1" != "--lock-held" ] && command -v flock >/dev/null 2>&1; then',
            '  flock -w 120 9 || log "could not obtain lock after 120s; continuing"',
            "fi",
            'if [ -e "$TX/confirmed" ]; then log "already confirmed; nothing to roll back"; exit 0; fi',
            'if [ -e "$TX/rolled_back" ]; then log "already rolled back"; exit 0; fi',
            'log "rollback started"',
            "failed=0",
            "restore() {",
            '  # $1 backup ($2 target, $3 mode, $4 uid, $5 gid); empty backup means the file did not exist',
            '  if [ -z "$1" ]; then rm -f "$2" || { log "could not remove $2"; failed=1; }; return; fi',
            '  tmp="$2.bant-rb.$$"',
            '  if cp "$1" "$tmp" && chmod "$3" "$tmp" && chown "$4:$5" "$tmp" && mv -f "$tmp" "$2"; then',
            '    log "restored $2"',
            "  else",
            '    rm -f "$tmp"; log "FAILED to restore $2"; failed=1',
            "  fi",
            "}",
            "",
            "# 1. undo commands, newest first",
        ]
        for argv in reversed(tx.undo_cmds):
            lines.append("run " + " ".join(q(a) for a in argv))
        lines.append("")
        lines.append("# 2. restore original files")
        for f in reversed(tx.files):
            lines.append(
                "restore {} {} {} {} {}".format(
                    q(f["backup"] or ""), q(f["target"]), q(format(f["mode"], "o")), q(str(f["uid"])), q(str(f["gid"]))
                )
            )
        lines.append("")
        lines.append("# 3. reload services against the restored configuration")
        for argv in tx.post_cmds:
            lines.append("run " + " ".join(q(a) for a in argv))
        lines += [
            "",
            'if [ "$failed" -ne 0 ]; then',
            '  log "rollback INCOMPLETE: some files could not be restored; run: bant repair (or see docs/RECOVERY.md)"',
            '  touch "$TX/rollback.error"',
            "  exit 1",
            "fi",
            'touch "$TX/rolled_back"',
            'log "rollback finished"',
            "",
            "# 4. disarm the timer and clean up its units",
            f"systemctl disable {q(tmr)} >/dev/null 2>&1",
            f"rm -f {q(str(ctx.paths.systemd_system / svc))} {q(str(ctx.paths.systemd_system / tmr))}",
            "systemctl daemon-reload >/dev/null 2>&1",
            "",
            "# 5. best-effort bookkeeping through Bant itself",
            f"if [ -x {q(str(ctx.paths.launcher))} ]; then",
            f"  {q(str(ctx.paths.launcher))} _tx-finish {q(tx.id)} rolled_back >> \"$LOG\" 2>&1 || true",
            "fi",
            "exit 0",
            "",
        ]
        return "\n".join(lines)
