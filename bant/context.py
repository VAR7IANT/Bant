"""Execution context: filesystem root, command runner, config, state, audit log, dry-run.

Every core function receives a Context instead of reaching for globals, which keeps
privileged behaviour explicit and lets tests run against a temporary root with a fake
command runner. Nothing here mutates the system at import time.
"""

from __future__ import annotations

import contextlib
import copy
import fcntl
import json
import os
import random
import time
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

from bant.config import Config
from bant.constants import Paths
from bant.errors import Busy, PermissionDenied
from bant.utils import fsutil
from bant.utils.commands import CmdResult, Runner
from bant.utils.logging import AuditLog

STATE_SCHEMA = 1


def _tcp_banner(host: str, port: int) -> str | None:
    """First line an SSH server sends (e.g. 'SSH-2.0-OpenSSH_9.6'), or None if nothing answers."""
    import socket

    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            sock.settimeout(3)
            return sock.recv(255).decode("ascii", "replace").strip() or None
    except OSError:
        return None


class State:
    """Runtime state persisted as JSON (0600). Mutations go through update()."""

    def __init__(self, path: Path):
        self.path = path

    def load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text())
            if isinstance(data, dict):
                return data
        except (FileNotFoundError, PermissionError, json.JSONDecodeError):
            pass
        return {"schema": STATE_SCHEMA}

    def save(self, data: dict[str, Any]) -> None:
        data["schema"] = STATE_SCHEMA
        fsutil.ensure_dir(self.path.parent, 0o700)
        fsutil.atomic_write(self.path, json.dumps(data, indent=2, sort_keys=True) + "\n", 0o600)

    def update(self, fn: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        data = self.load()
        fn(data)
        self.save(data)
        return data

    def get(self, *keys: str, default: Any = None) -> Any:
        cur: Any = self.load()
        for key in keys:
            if not isinstance(cur, dict) or key not in cur:
                return default
            cur = cur[key]
        return copy.deepcopy(cur)


class Context:
    def __init__(
        self,
        paths: Paths | None = None,
        runner: Runner | None = None,
        *,
        euid: int | None = None,
        dry_run: bool = False,
        assume_yes: bool = False,
        interactive: bool = False,
        clock: Callable[[], float] = time.time,
        config: Config | None = None,
        mirror_syslog: bool = True,
        sleep: Callable[[float], None] = time.sleep,
        banner_probe: Callable[[str, int], str | None] | None = None,
        rng: random.Random | None = None,
    ):
        self.paths = paths or Paths()
        self.runner = runner or Runner()
        self.euid = os.geteuid() if euid is None else euid
        self.dry_run = dry_run
        self.assume_yes = assume_yes
        self.interactive = interactive
        self.clock = clock
        self._config = config
        self.state = State(self.paths.state_file)
        self.audit_log = AuditLog(self.paths.audit_log, clock=clock, mirror_syslog=mirror_syslog)
        self.sleep = sleep
        self.rng = rng or random.SystemRandom()
        self.banner_probe = banner_probe or _tcp_banner
        self.planned: list[str] = []
        self._memo: dict[str, Any] | None = None
        self._lock_fd: int | None = None
        self._lock_depth = 0

    # ---- privileges ------------------------------------------------------
    @property
    def is_root(self) -> bool:
        return self.euid == 0

    def require_root(self, action: str = "This operation") -> None:
        if not self.is_root:
            raise PermissionDenied(f"{action} requires root privileges.", hint="Re-run with sudo.")

    # ---- config ----------------------------------------------------------
    @property
    def config(self) -> Config:
        if self._config is None:
            self._config = Config.load(self.paths.config_file)
        return self._config

    def reload_config(self) -> Config:
        self._config = Config.load(self.paths.config_file)
        return self._config

    # ---- commands --------------------------------------------------------
    def run(self, argv: Sequence[str], *, timeout: float | None = None, input: str | None = None) -> CmdResult:
        """Run a command that does not change the system."""
        return self.runner.run(argv, timeout=timeout, input=input)

    def run_mut(self, argv: Sequence[str], *, timeout: float | None = None, input: str | None = None) -> CmdResult:
        """Run a command that changes the system. Honours --dry-run."""
        argv = [str(a) for a in argv]
        if self.dry_run:
            self.planned.append(" ".join(argv))
            return CmdResult(argv, 0, "", "", dry_run=True)
        return self.runner.run(argv, timeout=timeout, input=input)

    def which(self, name: str) -> str | None:
        return self.runner.which(name)

    # ---- files -----------------------------------------------------------
    def write_file(self, path: Path, content: str | bytes, mode: int = 0o644) -> None:
        if self.dry_run:
            self.planned.append(f"write {path}")
            return
        fsutil.atomic_write(path, content, mode)

    def remove_file(self, path: Path) -> None:
        if self.dry_run:
            self.planned.append(f"remove {path}")
            return
        with contextlib.suppress(FileNotFoundError):
            path.unlink()

    def wait_until(self, predicate: Callable[[], bool], attempts: int = 20, interval: float = 0.5) -> bool:
        for i in range(attempts):
            if predicate():
                return True
            if i < attempts - 1:
                self.sleep(interval)
        return False

    @contextlib.contextmanager
    def cached(self) -> Iterator[None]:
        """Within this block, memo() results are reused (read-only reports such as status/audit)."""
        outer = self._memo
        self._memo = {} if outer is None else outer
        try:
            yield
        finally:
            self._memo = outer

    def memo(self, key: str, fn: Callable[[], Any]) -> Any:
        if self._memo is None:
            return fn()
        if key not in self._memo:
            self._memo[key] = fn()
        return self._memo[key]

    # ---- audit -----------------------------------------------------------
    def audit(self, event: str, level: str = "info", **detail: Any) -> None:
        if self.dry_run:
            return
        self.audit_log.write(event, level, **detail)

    # ---- locking ---------------------------------------------------------
    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        """Exclusive, re-entrant lock for mutating operations (non-blocking)."""
        if self._lock_depth == 0:
            fsutil.ensure_dir(self.paths.lock_file.parent, 0o700)
            fd = os.open(self.paths.lock_file, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                raise Busy(
                    "Another Bant operation is already running.",
                    hint="Wait for it to finish, or check `bant status` for a pending SSH transaction.",
                ) from None
            self._lock_fd = fd
        self._lock_depth += 1
        try:
            yield
        finally:
            self._lock_depth -= 1
            if self._lock_depth == 0 and self._lock_fd is not None:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
                self._lock_fd = None
