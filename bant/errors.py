"""Exception hierarchy and process exit codes."""

from __future__ import annotations

EX_OK = 0
EX_ERROR = 1
EX_USAGE = 2
EX_PERM = 3
EX_INPUT = 4
EX_UNSUPPORTED = 5
EX_ROLLED_BACK = 6
EX_BUSY = 7
EX_UNHEALTHY = 8


class BantError(Exception):
    """Base class. Carries a user-facing message and an optional recovery hint."""

    exit_code = EX_ERROR

    def __init__(self, message: str, *, hint: str | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint

    def to_dict(self) -> dict:
        return {"error": type(self).__name__, "message": self.message, "hint": self.hint}


class UsageError(BantError):
    exit_code = EX_USAGE


class PermissionDenied(BantError):
    exit_code = EX_PERM


class ValidationError(BantError):
    exit_code = EX_INPUT


class Unsupported(BantError):
    exit_code = EX_UNSUPPORTED


class RolledBack(BantError):
    """An operation failed and the previous state was restored."""

    exit_code = EX_ROLLED_BACK


class Busy(BantError):
    exit_code = EX_BUSY


class OperationFailed(BantError):
    exit_code = EX_ERROR
