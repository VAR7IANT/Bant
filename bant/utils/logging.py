"""Structured local audit trail (JSON lines) with redaction, rotation and syslog mirroring."""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

MAX_BYTES = 1_000_000
KEEP_FILES = 4

_REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED KEY]"),
    (re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key)\b\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


_SENSITIVE_KEY = re.compile(r"(?i)(pass(word|wd|phrase)?|token|secret|api[_-]?key|private|credential)")


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)[:2000]
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if _SENSITIVE_KEY.search(str(k)) else _clean(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value][:200]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact(str(value))[:2000]


class AuditLog:
    def __init__(self, path: Path, *, clock=time.time, mirror_syslog: bool = True):
        self.path = path
        self.clock = clock
        self.mirror_syslog = mirror_syslog

    def write(self, event: str, level: str = "info", **detail: Any) -> bool:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock())),
            "level": level,
            "event": event,
            "actor": os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.geteuid()),
            "detail": _clean(detail),
        }
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        ok = False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(self.path.parent, 0o750)
            self._rotate()
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, (line + "\n").encode())
            finally:
                os.close(fd)
            ok = True
        except OSError:
            ok = False
        if self.mirror_syslog:
            try:
                import syslog

                syslog.openlog("bant", 0, syslog.LOG_AUTH)
                syslog.syslog(syslog.LOG_WARNING if level in ("warning", "error") else syslog.LOG_NOTICE, f"{event} {json.dumps(record['detail'])[:500]}")
            except Exception:  # noqa: BLE001 - logging must never break an operation
                pass
        return ok

    def _rotate(self) -> None:
        try:
            if self.path.stat().st_size < MAX_BYTES:
                return
        except FileNotFoundError:
            return
        for i in range(KEEP_FILES, 0, -1):
            src = self.path.with_name(f"{self.path.name}.{i - 1}") if i > 1 else self.path
            dst = self.path.with_name(f"{self.path.name}.{i}")
            if src.exists():
                if i == KEEP_FILES and dst.exists():
                    dst.unlink()
                os.replace(src, dst)

    def read(self, limit: int = 50, grep: str | None = None) -> list[dict]:
        records: list[dict] = []
        try:
            lines = self.path.read_text(errors="replace").splitlines()
        except OSError:
            return []
        for line in reversed(lines):
            if grep and grep.lower() not in line.lower():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(records) >= limit:
                break
        records.reverse()
        return records
