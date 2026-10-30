"""Minimal TOML reader/writer for Bant's flat, two-level configuration."""

from __future__ import annotations

import json
from typing import Any

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10 only
    try:
        import tomli as _toml  # type: ignore[no-redef]
    except ModuleNotFoundError:
        _toml = None  # type: ignore[assignment]

from bant.errors import OperationFailed


def loads(text: str) -> dict[str, Any]:
    if _toml is None:
        raise OperationFailed(
            "No TOML parser available.", hint="Install python3-tomli (Python < 3.11) and retry."
        )
    return _toml.loads(text)


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_scalar(v) for v in value) + "]"
    raise TypeError(f"Unsupported TOML value: {value!r}")


def dumps(data: dict[str, dict[str, Any]], header: str = "") -> str:
    out = [header.rstrip("\n")] if header else []
    for section, values in data.items():
        if out:
            out.append("")
        out.append(f"[{section}]")
        for key, value in values.items():
            out.append(f"{key} = {_scalar(value)}")
    return "\n".join(out) + "\n"
