"""Configuration backups and restore.

Backups are plain directory snapshots (0700 dirs, 0600 files) so they can be restored by hand
with `cp` if Bant itself is unavailable. Host keys, authorized_keys and password databases are
never included.
"""

from __future__ import annotations

import glob
import json
import secrets
import shutil
import time
from pathlib import Path
from typing import Any

from bant.context import Context
from bant.core import sshconf
from bant.errors import OperationFailed, ValidationError
from bant.utils import fsutil

GLOBS = [
    "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*",
    "/etc/systemd/system/ssh.socket.d/*", "/etc/systemd/system/sshd.socket.d/*",
    "/etc/fail2ban/jail.local", "/etc/fail2ban/jail.d/*", "/etc/fail2ban/filter.d/bant-sshd.conf",
    "/etc/bant/bant.toml", "/var/lib/bant/state.json", "/var/lib/bant/blocklist.json",
    "/etc/apt/apt.conf.d/20auto-upgrades", "/etc/apt/apt.conf.d/52bant-unattended-upgrades",
    "/etc/ufw/ufw.conf", "/etc/ufw/user.rules", "/etc/ufw/user6.rules", "/etc/nftables.conf",
]
NEVER_PATTERNS = ("ssh_host_", "authorized_keys", "shadow", "id_rsa", "id_ed25519", "id_ecdsa", ".key")


def _bant_owned(ctx: Context) -> list[Path]:
    p = ctx.paths
    return [p.ssh_dropin, p.f2b_jail, p.f2b_filter, p.apt_bant_conf, p.socket_dropin("ssh.socket"), p.socket_dropin("sshd.socket")]


def _collect(ctx: Context) -> list[Path]:
    paths: list[Path] = []
    for g in GLOBS:
        for m in sorted(glob.glob(str(ctx.paths.p(g)))):
            pth = Path(m)
            if pth.is_file() and not pth.is_symlink() and not any(n in pth.name for n in NEVER_PATTERNS):
                paths.append(pth)
    return paths


def _id(now: float) -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now)) + "-" + secrets.token_hex(3)


def create(ctx: Context, note: str = "manual") -> dict[str, Any]:
    ctx.require_root("Creating a backup")
    now = ctx.clock()
    bid = _id(now)
    root = ctx.paths.backup_dir / bid
    if ctx.dry_run:
        ctx.planned.append(f"backup -> {root}")
        return {"id": bid, "dry_run": True}
    with ctx.lock():
        fsutil.ensure_dir(ctx.paths.backup_dir, 0o700)
        fsutil.ensure_dir(root, 0o700)
        fsutil.ensure_dir(root / "files", 0o700)
        entries: list[dict[str, Any]] = []
        existing = _collect(ctx)
        for i, path in enumerate(existing):
            meta = fsutil.file_meta(path)
            rel = f"files/{i:03d}-{path.name}"
            fsutil.copy_private(path, root / rel)
            entries.append({"path": str(path), "backup": rel, "sha256": fsutil.sha256_file(path), "existed": True, **meta})
        for path in _bant_owned(ctx):
            if str(path) not in {e["path"] for e in entries}:
                entries.append({"path": str(path), "backup": None, "existed": False})
        from bant import __version__
        manifest = {"id": bid, "created": int(now), "note": note[:80], "bant_version": __version__, "files": entries}
        fsutil.atomic_write(root / "manifest.json", json.dumps(manifest, indent=2) + "\n", 0o600)
        _prune(ctx)
        ctx.audit("backup.create", id=bid, files=len(existing), note=note)
    return {"id": bid, "files": len(existing), "path": str(root), "note": note}


def _prune(ctx: Context, keep: int = 30) -> None:
    items = list_backups(ctx)
    for old in items[:-keep]:
        shutil.rmtree(ctx.paths.backup_dir / old["id"], ignore_errors=True)


def list_backups(ctx: Context) -> list[dict[str, Any]]:
    out = []
    try:
        names = sorted(p.name for p in ctx.paths.backup_dir.iterdir() if p.is_dir())
    except OSError:
        return []
    for name in names:
        try:
            m = json.loads((ctx.paths.backup_dir / name / "manifest.json").read_text())
        except (OSError, json.JSONDecodeError):
            continue
        out.append({"id": m["id"], "created": m["created"], "note": m.get("note", ""), "files": sum(1 for f in m["files"] if f["existed"])})
    return out


def resolve(ctx: Context, backup_id: str) -> dict[str, Any]:
    items = list_backups(ctx)
    if not items:
        raise OperationFailed("No backups exist.", hint="Create one with `bant backup`.")
    if backup_id in ("latest", ""):
        backup_id = items[-1]["id"]
    if "/" in backup_id or ".." in backup_id:
        raise ValidationError("Invalid backup id.")
    try:
        return json.loads((ctx.paths.backup_dir / backup_id / "manifest.json").read_text())
    except (OSError, json.JSONDecodeError):
        raise ValidationError(f"Unknown backup: {backup_id}", hint="List backups with `bant restore --list`.") from None


def apply_manifest(ctx: Context, manifest: dict[str, Any]) -> list[str]:
    root = ctx.paths.backup_dir / manifest["id"]
    changed = []
    for e in manifest["files"]:
        target = Path(e["path"])
        if not str(target).startswith(str(ctx.paths.root)):
            raise ValidationError(f"Backup entry outside root: {target}")
        if e["existed"]:
            data = (root / e["backup"]).read_bytes()
            if fsutil.sha256_file(root / e["backup"]) != e["sha256"]:
                raise OperationFailed(f"Backup file for {target} is corrupt (checksum mismatch); aborting before any change.")
            current = target.read_bytes() if target.exists() else None
            if current != data:
                fsutil.atomic_write(target, data, e["mode"], uid=e["uid"], gid=e["gid"])
                changed.append(str(target))
        elif target.exists():
            fsutil.refuse_symlink(target)
            target.unlink()
            changed.append(str(target))
    return changed


def _validate_and_reload(ctx: Context, changed: list[str]) -> list[str]:
    notes = []
    ssh_changed = any("/ssh/" in c or "/ssh." in c for c in changed)
    if ssh_changed:
        ok, msg = sshconf.validate(ctx)
        if not ok:
            raise OperationFailed(f"Restored SSH configuration is invalid: {msg}")
        if any("systemd/system" in c for c in changed):
            ctx.run_mut(["systemctl", "daemon-reload"])
            for unit in ("ssh.socket", "sshd.socket"):
                if ctx.run(["systemctl", "is-active", "--quiet", unit]).ok:
                    ctx.run_mut(["systemctl", "restart", unit])
        for unit in ("ssh.service", "sshd.service"):
            if ctx.run(["systemctl", "is-active", "--quiet", unit]).ok:
                res = ctx.run_mut(["systemctl", "reload", unit])
                if not res.ok:
                    raise OperationFailed(f"Reloading {unit} failed: {res.output}")
                break
        notes.append("sshd reloaded")
    if any("fail2ban" in c for c in changed) and ctx.which("fail2ban-client"):
        if not ctx.run(["fail2ban-client", "-t"]).ok:
            raise OperationFailed("Restored Fail2ban configuration is invalid.")
        ctx.run_mut(["fail2ban-client", "reload"])
        notes.append("fail2ban reloaded")
    return notes


def restore(ctx: Context, backup_id: str = "latest") -> dict[str, Any]:
    ctx.require_root("Restoring a backup")
    from bant.core import netinfo
    from bant.core.rollback import TxManager

    manifest = resolve(ctx, backup_id)
    if TxManager(ctx).pending():
        raise OperationFailed("An SSH transaction is pending; confirm or roll it back before restoring a backup.")
    if ctx.dry_run:
        ctx.planned.append(f"restore backup {manifest['id']} ({len(manifest['files'])} entries)")
        return {"id": manifest["id"], "dry_run": True}
    with ctx.lock():
        sess = netinfo.current_session(ctx)
        safety = create(ctx, note=f"automatic pre-restore snapshot (before restoring {manifest['id']})")
        try:
            changed = apply_manifest(ctx, manifest)
            notes = _validate_and_reload(ctx, changed)
            if sess is not None and not ctx.wait_until(lambda: netinfo.tcp_listening(ctx, sess.local_port), attempts=10):
                raise OperationFailed(f"After restore SSH no longer listens on port {sess.local_port}, which your session uses.")
        except Exception as exc:
            ctx.audit("backup.restore.failed", level="error", id=manifest["id"], error=str(exc))
            try:
                undo = resolve(ctx, safety["id"])
                _validate_and_reload(ctx, apply_manifest(ctx, undo))
            except Exception as inner:  # noqa: BLE001
                raise OperationFailed(f"Restore failed ({exc}) and the automatic undo also failed ({inner}). "
                                      f"Manual recovery: see docs/RECOVERY.md; snapshot is {safety['id']}.") from exc
            raise OperationFailed(f"Restore failed and was undone: {exc}") from exc
        ctx.audit("backup.restore", id=manifest["id"], changed=changed, safety=safety["id"])
    return {"id": manifest["id"], "changed": changed, "notes": notes, "safety_backup": safety["id"]}


def verify_integrity(ctx: Context) -> tuple[int, int]:
    """(ok, bad) counts of checksum validity across all backups."""
    ok = bad = 0
    for item in list_backups(ctx):
        m = resolve(ctx, item["id"])
        good = True
        for e in m["files"]:
            if e["existed"]:
                p = ctx.paths.backup_dir / m["id"] / e["backup"]
                if not p.exists() or fsutil.sha256_file(p) != e["sha256"]:
                    good = False
        ok, bad = (ok + 1, bad) if good else (ok, bad + 1)
    return ok, bad


def secure_perms(ctx: Context) -> list[str]:
    """Paths under Bant's state that are more permissive than intended."""
    issues = []
    for path, want in ((ctx.paths.state_dir, 0o700), (ctx.paths.backup_dir, 0o700), (ctx.paths.tx_dir, 0o700), (ctx.paths.state_file, 0o600)):
        if path.exists() and (path.stat().st_mode & 0o777) & ~want:
            issues.append(f"{path} has mode {oct(path.stat().st_mode & 0o777)} (expected {oct(want)})")
    return issues
