"""Administrator configuration (/etc/bant/bant.toml) with defaults, validation and migration."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from bant.constants import AUTO_SSH_PORT, DEFAULT_ROLLBACK_MINUTES
from bant.errors import ValidationError
from bant.utils import fsutil, tomlio
from bant.utils.validation import parse_duration, parse_int_range, parse_ip, parse_port

CONFIG_VERSION = 1

DEFAULTS: dict[str, dict[str, Any]] = {
    "general": {"config_version": CONFIG_VERSION},
    "ssh": {"port": AUTO_SSH_PORT, "rollback_minutes": DEFAULT_ROLLBACK_MINUTES},
    "fail2ban": {"maxretry": 5, "findtime": "10m", "bantime": "1h"},
    "trust": {"ips": []},
}

HEADER = (
    "# Bant configuration. Edit with `bant` or by hand; unknown keys are preserved on save.\n"
    "# ssh.port = 0 means \"random\": Bant picks a free random port when it first moves SSH and stores it here.\n"
)


def _migrate(data: dict) -> dict:
    """Upgrade older config layouts in place. No migrations are needed yet."""
    version = data.get("general", {}).get("config_version", 1)
    if version > CONFIG_VERSION:
        raise ValidationError(
            f"Configuration version {version} is newer than this Bant ({CONFIG_VERSION}).",
            hint="Upgrade Bant before using this configuration.",
        )
    data.setdefault("general", {})["config_version"] = CONFIG_VERSION
    return data


class Config:
    def __init__(self, data: dict[str, dict[str, Any]] | None = None, path: Path | None = None):
        self.path = path
        merged = copy.deepcopy(DEFAULTS)
        for section, values in (data or {}).items():
            merged.setdefault(section, {}).update(values)
        self.data = _migrate(merged)
        self.problems: list[str] = []
        self._validate()

    @classmethod
    def load(cls, path: Path) -> Config:
        try:
            text = path.read_text()
        except FileNotFoundError:
            return cls(path=path)
        except PermissionError:
            cfg = cls(path=path)
            cfg.problems.append(f"{path} is not readable; using defaults")
            return cfg
        try:
            return cls(tomlio.loads(text), path)
        except ValidationError:
            raise
        except Exception as exc:  # noqa: BLE001
            cfg = cls(path=path)
            cfg.problems.append(f"{path} could not be parsed ({exc}); using defaults")
            return cfg

    def _validate(self) -> None:
        d = self.data
        for section, key, check in (
            ("ssh", "port", lambda v: AUTO_SSH_PORT if int(v) == AUTO_SSH_PORT else parse_port(v)),
            ("ssh", "rollback_minutes", lambda v: parse_int_range(v, 1, 1440, "rollback_minutes")),
            ("fail2ban", "maxretry", lambda v: parse_int_range(v, 1, 100, "maxretry")),
            ("fail2ban", "findtime", parse_duration),
            ("fail2ban", "bantime", parse_duration),
        ):
            try:
                check(d[section][key])
            except (ValidationError, KeyError, TypeError, ValueError):
                self.problems.append(f"invalid [{section}] {key}={d[section].get(key)!r}; using default")
                d[section][key] = DEFAULTS[section][key]
        clean = []
        for ip in d["trust"].get("ips", []):
            try:
                clean.append(parse_ip(ip, allow_network=True))
            except ValidationError:
                self.problems.append(f"invalid trusted address ignored: {ip!r}")
        d["trust"]["ips"] = clean

    def get(self, section: str, key: str) -> Any:
        return self.data[section][key]

    def set(self, section: str, key: str, value: Any) -> None:
        self.data.setdefault(section, {})[key] = value
        self._validate()

    def save(self) -> None:
        if self.path is None:
            raise ValueError("Config has no path")
        fsutil.ensure_dir(self.path.parent, 0o755)
        fsutil.atomic_write(self.path, tomlio.dumps(self.data, HEADER), 0o640)

    # convenient typed accessors
    @property
    def ssh_port(self) -> int: return int(self.data["ssh"]["port"])
    @property
    def rollback_minutes(self) -> int: return int(self.data["ssh"]["rollback_minutes"])
    @property
    def maxretry(self) -> int: return int(self.data["fail2ban"]["maxretry"])
    @property
    def findtime(self) -> str: return str(self.data["fail2ban"]["findtime"])
    @property
    def bantime(self) -> str: return str(self.data["fail2ban"]["bantime"])
    @property
    def trusted_ips(self) -> list[str]: return list(self.data["trust"]["ips"])
