"""Input validation. Anything that reaches a config file or a command line passes through here."""

from __future__ import annotations

import ipaddress
import re

from bant.errors import ValidationError

_DURATION_RE = re.compile(r"^(\d+)\s*([smhdw]?)$")
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_port(value: str | int) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValidationError(f"Invalid port: {value!r}", hint="Use a number between 1 and 65535.") from None
    if not 1 <= port <= 65535:
        raise ValidationError(f"Port out of range: {port}", hint="Use a number between 1 and 65535.")
    return port


def parse_proto(value: str) -> str:
    v = str(value).strip().lower()
    if v not in ("tcp", "udp"):
        raise ValidationError(f"Invalid protocol: {value!r}", hint="Use tcp or udp.")
    return v


def parse_ip(value: str, *, allow_network: bool = False, for_ban: bool = False) -> str:
    """Return the normalised textual form of an IPv4/IPv6 address (or network)."""
    text = str(value).strip()
    if not text or len(text) > 64 or any(c.isspace() for c in text):
        raise ValidationError(f"Invalid IP address: {value!r}")
    try:
        if "/" in text:
            if not allow_network:
                raise ValidationError(f"Expected a single address, got a network: {text}")
            obj = ipaddress.ip_network(text, strict=False)
        else:
            obj = ipaddress.ip_address(text)
    except ValueError:
        raise ValidationError(f"Invalid IP address: {value!r}") from None
    if for_ban:
        probe = obj if not isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else obj.network_address
        if probe.is_unspecified or probe.is_loopback or probe.is_multicast:
            raise ValidationError(f"Refusing to use special address {text}")
        if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and obj.prefixlen < (8 if obj.version == 4 else 16):
            raise ValidationError(f"Refusing overly broad network {text}", hint="Use a narrower prefix.")
    return str(obj)


def parse_duration(value: str | int) -> int:
    """Parse '10m', '1h', '2d', '90' (seconds) into seconds. -1 means permanent."""
    text = str(value).strip().lower()
    if text in ("-1", "permanent", "forever"):
        return -1
    m = _DURATION_RE.match(text)
    if not m:
        raise ValidationError(f"Invalid duration: {value!r}", hint="Examples: 30s, 10m, 1h, 2d, or 'permanent'.")
    seconds = int(m.group(1)) * _UNITS[m.group(2)]
    if seconds <= 0:
        raise ValidationError("Duration must be positive.")
    return seconds


def format_duration(seconds: int) -> str:
    """Compact form that Fail2ban also understands (e.g. 3600 -> '1h')."""
    if seconds < 0:
        return "permanent"
    for unit, size in (("w", 604800), ("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0 and seconds >= size:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def humanize_duration(seconds: int) -> str:
    if seconds < 0:
        return "permanent"
    parts = []
    for name, size in (("day", 86400), ("hour", 3600), ("min", 60), ("sec", 1)):
        n, seconds = divmod(seconds, size)
        if n:
            parts.append(f"{n} {name}{'s' if n != 1 and name != 'min' else ''}")
    return " ".join(parts) or "0 sec"


def parse_int_range(value: str | int, lo: int, hi: int, what: str) -> int:
    try:
        n = int(str(value).strip())
    except ValueError:
        raise ValidationError(f"{what} must be a number, got {value!r}") from None
    if not lo <= n <= hi:
        raise ValidationError(f"{what} must be between {lo} and {hi}, got {n}")
    return n


def parse_onoff(value: str) -> bool:
    v = str(value).strip().lower()
    if v in ("on", "yes", "true", "1", "enable", "enabled"):
        return True
    if v in ("off", "no", "false", "0", "disable", "disabled"):
        return False
    raise ValidationError(f"Expected on/off, got {value!r}")


_SAFE_COMMENT = re.compile(r"[^A-Za-z0-9 _.,:@/+=-]")


def sanitize_comment(text: str, limit: int = 80) -> str:
    """Strip characters that could break config syntax or inject options."""
    return _SAFE_COMMENT.sub("", str(text))[:limit].strip()
