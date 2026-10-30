"""IP blocking and trusted addresses.

Ownership model (one owner per mechanism, no overlap):
  * Fail2ban owns automatic and `bant fail2ban ban` bans (jail bantime, via fail2ban-client).
  * Bant owns manual/permanent blocks, enforced ONLY in its own `inet bant` nftables table
    (raw prerouting priority). Bant never inserts DROP rules into anyone else's chains.
  * Trusted IPs are never banned by either; they feed Fail2ban's ignoreip and block validation.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from bant.context import Context
from bant.core import netinfo
from bant.errors import OperationFailed, Unsupported, ValidationError
from bant.utils import fsutil
from bant.utils.validation import parse_ip

TABLE = "bant"


def _load(ctx: Context) -> list[dict[str, Any]]:
    try:
        data = json.loads(ctx.paths.blocklist_file.read_text())
        return list(data.get("entries", []))
    except (FileNotFoundError, PermissionError, json.JSONDecodeError):
        return []


def _save(ctx: Context, entries: list[dict[str, Any]]) -> None:
    fsutil.ensure_dir(ctx.paths.blocklist_file.parent, 0o700)
    fsutil.atomic_write(ctx.paths.blocklist_file, json.dumps({"entries": entries}, indent=2) + "\n", 0o600)


def active_entries(ctx: Context) -> list[dict[str, Any]]:
    now = ctx.clock()
    return [e for e in _load(ctx) if e.get("expires") is None or e["expires"] > now]


def render_ruleset(entries: list[dict[str, Any]], now: float) -> str:
    v4, v6 = [], []
    for e in entries:
        net = ipaddress.ip_network(e["ip"], strict=False)
        item = str(net) if net.num_addresses > 1 else str(net.network_address)
        if e.get("expires") is not None:
            remaining = int(e["expires"] - now)
            if remaining <= 0:
                continue
            item += f" timeout {remaining}s"
        (v4 if net.version == 4 else v6).append(item)

    def elems(items: list[str]) -> str:
        return f"        elements = {{ {', '.join(items)} }}\n" if items else ""

    return (
        f"add table inet {TABLE}\n"
        f"delete table inet {TABLE}\n"
        f"table inet {TABLE} {{\n"
        "    set blocked4 {\n        type ipv4_addr\n        flags interval, timeout\n" + elems(v4) + "    }\n"
        "    set blocked6 {\n        type ipv6_addr\n        flags interval, timeout\n" + elems(v6) + "    }\n"
        "    chain prerouting {\n"
        "        type filter hook prerouting priority raw; policy accept;\n"
        '        ip saddr @blocked4 counter drop comment "bant:block"\n'
        '        ip6 saddr @blocked6 counter drop comment "bant:block"\n'
        "    }\n}\n"
    )


def available(ctx: Context) -> bool:
    return ctx.which("nft") is not None


def apply(ctx: Context) -> None:
    """Rebuild Bant's nftables table from the blocklist atomically (single nft transaction)."""
    if not available(ctx):
        raise Unsupported(
            "Bant-managed blocking needs the `nft` command (package nftables).",
            hint="Install nftables, or use `bant fail2ban ban <IP>` for jail-based temporary bans.",
        )
    entries = active_entries(ctx)
    script = render_ruleset(entries, ctx.clock())
    chk = ctx.run(["nft", "-c", "-f", "-"], input=script)
    if not chk.ok:
        raise OperationFailed(f"nftables rejected the blocklist ruleset: {chk.output}")
    res = ctx.run_mut(["nft", "-f", "-"], input=script)
    if not res.ok:
        raise OperationFailed(f"Could not apply blocklist: {res.output}")


def reapply_boot(ctx: Context) -> int:
    if not _load(ctx):
        return 0
    apply(ctx)
    return len(active_entries(ctx))


def trusted(ctx: Context) -> list[str]:
    return ctx.config.trusted_ips


def _covers(a: str, b: str) -> bool:
    na, nb = ipaddress.ip_network(a, strict=False), ipaddress.ip_network(b, strict=False)
    return na.version == nb.version and (nb.subnet_of(na) or na.subnet_of(nb))


def ban_risk(ctx: Context, ip: str) -> str | None:
    """A warning when banning `ip` could cut off the administrator, else None."""
    sess = netinfo.current_session(ctx)
    candidates = []
    if sess:
        candidates.append((sess.remote_ip, "your current SSH session"))
    for t in (s for s in netinfo.ssh_sessions(ctx) if not sess or s.pid != sess.pid):
        candidates.append((t.remote_ip, f"another SSH session ({t.user})"))
    for addr, what in candidates:
        try:
            if _covers(ip, addr):
                return f"{ip} includes {addr}, the source of {what}."
        except ValueError:
            continue
    for t in trusted(ctx):
        if _covers(ip, t):
            return f"{ip} overlaps trusted address {t}."
    return None


def block(ctx: Context, ip: str, *, duration: int | None = None, reason: str = "manual") -> dict[str, Any]:
    ctx.require_root("Blocking an IP address")
    ip = parse_ip(ip, allow_network=True, for_ban=True)
    for t in trusted(ctx):
        if _covers(ip, t):
            raise ValidationError(f"{ip} overlaps trusted address {t}; remove it from the trusted list first.")
    with ctx.lock():
        entries = _load(ctx)
        now = ctx.clock()
        entry = {"ip": ip, "added": int(now), "expires": None if not duration or duration < 0 else int(now + duration),
                 "reason": reason[:80], "source": "bant"}
        entries = [e for e in entries if e["ip"] != ip] + [entry]
        if ctx.dry_run:
            ctx.planned.append(f"block {ip}")
            return entry
        _save(ctx, entries)
        try:
            apply(ctx)
        except Exception:
            _save(ctx, [e for e in entries if e["ip"] != ip])
            raise
        ctx.audit("ban.add", ip=ip, source="bant", expires=entry["expires"], reason=entry["reason"])
    return entry


def unblock(ctx: Context, ip: str) -> bool:
    ctx.require_root("Unblocking an IP address")
    ip = parse_ip(ip, allow_network=True)
    with ctx.lock():
        entries = _load(ctx)
        kept = [e for e in entries if e["ip"] != ip]
        if len(kept) == len(entries):
            return False
        if ctx.dry_run:
            ctx.planned.append(f"unblock {ip}")
            return True
        _save(ctx, kept)
        apply(ctx)
        ctx.audit("ban.remove", ip=ip, source="bant")
    return True


def trust_add(ctx: Context, ip: str) -> list[str]:
    ctx.require_root("Changing trusted addresses")
    ip = parse_ip(ip, allow_network=True)
    with ctx.lock():
        ips = trusted(ctx)
        if ip not in ips:
            ips.append(ip)
            ctx.config.set("trust", "ips", ips)
            if not ctx.dry_run:
                ctx.config.save()
                ctx.audit("trust.add", ip=ip)
    return trusted(ctx)


def trust_remove(ctx: Context, ip: str) -> list[str]:
    ctx.require_root("Changing trusted addresses")
    ip = parse_ip(ip, allow_network=True)
    with ctx.lock():
        ips = [i for i in trusted(ctx) if i != ip]
        ctx.config.set("trust", "ips", ips)
        if not ctx.dry_run:
            ctx.config.save()
            ctx.audit("trust.remove", ip=ip)
    return trusted(ctx)
