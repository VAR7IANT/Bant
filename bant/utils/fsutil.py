"""Filesystem helpers: atomic writes, safe ownership checks, backups."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from pathlib import Path

from bant.errors import OperationFailed

MANAGED_HEADER = "# Managed by Bant - do not edit by hand; changes are overwritten.\n"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def refuse_symlink(path: Path) -> None:
    if path.is_symlink():
        raise OperationFailed(
            f"Refusing to modify symbolic link: {path}",
            hint="Bant does not follow symlinks for files it writes. Replace the link with a regular file first.",
        )


def ensure_dir(path: Path, mode: int = 0o755) -> None:
    if path.is_symlink():
        raise OperationFailed(f"Refusing to use symlinked directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    if os.geteuid() == 0 or path.stat().st_uid == os.geteuid():
        os.chmod(path, mode)


def atomic_write(path: Path, data: str | bytes, mode: int = 0o644, *, uid: int | None = None, gid: int | None = None) -> None:
    """Write via a temp file in the same directory, fsync, then rename over the target."""
    refuse_symlink(path)
    ensure_dir(path.parent, 0o755) if not path.parent.exists() else None
    raw = data.encode() if isinstance(data, str) else data
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.bant-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        if uid is not None or gid is not None:
            os.chown(tmp, -1 if uid is None else uid, -1 if gid is None else gid)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    try:
        dfd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(errors="replace")
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return default


def file_meta(path: Path) -> dict:
    st = path.lstat()
    return {"mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size}


def copy_private(src: Path, dst: Path) -> None:
    """Copy file contents to dst with 0600, creating parent directories 0700."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(dst.parent, 0o700)
    with open(src, "rb") as r, open(dst, "wb") as w:
        os.fchmod(w.fileno(), 0o600)
        shutil.copyfileobj(r, w)
        w.flush()
        os.fsync(w.fileno())


def mode_str(path: Path) -> str:
    try:
        return oct(stat.S_IMODE(path.lstat().st_mode))
    except OSError:
        return "?"
