"""Fail2ban: administrator files that also configure the [sshd] jail.

Example (seen on a real VPS): /etc/fail2ban/jail.d/99-sshd.local sets port, backend, banaction,
maxretry, findtime and bantime for [sshd] while Bant manages zz-bant-sshd.local.

How it works
  * Bant never writes a key that an administrator defines for [sshd]; the administrator's value is
    what Fail2ban uses. That is safe, but the two files can disagree.
  * `analyze` compares, key by key, the administrator's value, the value Bant would use, and the value
    the running configuration actually has (`fail2ban-client -d`). Equal values (after normalising
    durations, port lists, booleans) are *duplicates* and are not warned about; different values are
    *conflicts*.
  * `resolve(..., "keep")` records that the administrator keeps managing those keys: no file changes,
    no warning for them until the administrator's file changes.
  * `resolve(..., "adopt")` hands the keys to Bant: the administrator's lines are commented out (not
    deleted) after a backup, Bant's jail takes them over - keeping the administrator's numbers for
    maxretry/findtime/bantime and other values Bant has no own opinion on, but using the real SSH
    port(s) for `port` - then the configuration is tested, Fail2ban reloaded and the sshd jail
    verified. Any failure restores every file and reloads again.
  Other jails and other sections are never touched.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from bant.context import Context
from bant.core import backups, fail2ban, sshconf
from bant.errors import BantError, OperationFailed, RolledBack, ValidationError
from bant.utils.validation import format_duration, parse_duration, parse_int_range

RESOLVE_MODES = ("keep", "adopt")
TAKEN_FROM_CONFIG = ("maxretry", "findtime", "bantime")  # adopted into bant.toml with the administrator's value
BANT_DECIDES = ("port", "enabled")  # Bant always uses the real SSH ports and enables the jail


def _norm(key: str, value: Any) -> Any:
    text = str(value if value is not None else "").strip()
    if key in ("findtime", "bantime"):
        try:
            return parse_duration(text)
        except ValidationError:
            return text.lower()
    if key == "port":
        ports = fail2ban.parse_ports(text)
        return tuple(ports) if ports else text.lower()
    if key == "enabled":
        return text.lower() in ("true", "1", "yes", "on")
    if key == "ignoreip":
        return frozenset(text.split())
    if key == "maxretry":
        return text
    return text.lower()


def _effective_value(eff: dict[str, Any], key: str) -> str | None:
    if key == "enabled":
        return "true" if eff.get("present") else "false"
    if key == "banaction":
        return eff.get("banaction") or None
    if key == "ignoreip":
        return " ".join(eff.get("ignoreip", [])) or None
    if key == "logpath":
        return " ".join(eff.get("logpath", [])) or None
    v = eff.get(key)
    return None if v in (None, "") else str(v)


def _accept_key(path: str, key: str, value: str) -> str:
    return f"{path}|{key}|{value}"


def analyze(ctx: Context, ssh_ports: list[int] | None = None) -> list[dict[str, Any]]:
    """One entry per key an administrator file defines for [sshd]."""
    ok, _ = fail2ban.installed(ctx)
    if not ok:
        return []
    ports = ssh_ports if ssh_ports else sshconf.effective(ctx).ports
    owned = fail2ban.admin_defined(ctx)
    jail_keys = {k: v for k, v in owned.items() if v[1] == fail2ban.JAIL}
    if not jail_keys:
        return []
    wanted = fail2ban.bant_wanted(ctx, ports or [22], owned)
    eff = fail2ban.effective_jail(ctx)
    winner: dict[str, str] = {}  # key -> file whose [sshd] value Fail2ban uses (the last one read)
    for path in fail2ban.read_order(ctx):
        for key in fail2ban._sections(path).get(fail2ban.JAIL, {}):
            winner[key] = path.name
    accepted = set(ctx.state.get("fail2ban", "accepted_conflicts", default=[]) or [])
    out = []
    for key in fail2ban.MANAGED_KEYS:
        if key not in jail_keys:
            continue
        path, _section, value = jail_keys[key]
        bant = wanted.get(key)
        if bant is None:
            status = "admin-only"  # Bant has no value of its own for this key on this host
        elif _norm(key, value) == _norm(key, bant):
            status = "duplicate"
        else:
            status = "conflict"
        out.append({"key": key, "file": path.name, "path": str(path), "value": value, "bant": bant,
                    "effective": _effective_value(eff, key), "status": status,
                    "accepted": _accept_key(str(path), key, value) in accepted,
                    "winner": winner.get(key, path.name),
                    "precedence": (f"{path.name} is read last, so its value is used" if winner.get(key, path.name) == path.name else
                                   f"{winner[key]} is read after {path.name}, so its value is used until Bant next updates its jail")})
    return out


def summary(items: list[dict[str, Any]]) -> dict[str, int]:
    return {s: sum(1 for i in items if i["status"] == s) for s in ("conflict", "duplicate", "admin-only")} | \
        {"unresolved": sum(1 for i in items if i["status"] == "conflict" and not i["accepted"])}


def adopt_plan(ctx: Context, items: list[dict[str, Any]]) -> list[dict[str, str]]:
    """What `adopt` would do, key by key: the value Fail2ban uses now -> the value it uses afterwards."""
    plan = []
    for i in items:
        if i["key"] in BANT_DECIDES:
            after = i["bant"] if i["bant"] is not None else i["value"]
        else:
            after = i["value"] if (i["key"] in TAKEN_FROM_CONFIG or i["bant"] is None) else i["bant"]
        plan.append({"key": i["key"], "file": i["file"], "before": i["effective"] or i["value"], "after": str(after),
                     "change": "unchanged" if _norm(i["key"], i["effective"] or i["value"]) == _norm(i["key"], after) else "changes"})
    return plan


_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def comment_out(text: str, keys: set[str], note: str) -> tuple[str, list[str]]:
    """Comment out `key = value` lines (and their continuation lines) inside [sshd] only."""
    out, hit = [], []
    section, in_key = None, False
    for line in text.splitlines(keepends=True):
        m = _SECTION_RE.match(line)
        if m:
            section, in_key = m.group(1).strip(), False
            out.append(line)
            continue
        if section == fail2ban.JAIL:
            km = re.match(r"^([A-Za-z_][\w.-]*)\s*[=:]", line)
            if km and km.group(1) in keys:
                hit.append(km.group(1))
                out.append(f"# {line.rstrip()}    # {note}\n")
                in_key = True
                continue
            if in_key and line[:1] in (" ", "\t") and line.strip():
                out.append(f"# {line.rstrip()}\n")
                continue
        in_key = False
        out.append(line)
    return "".join(out), hit


def resolve(ctx: Context, mode: str, *, keys: list[str] | None = None) -> dict[str, Any]:
    ctx.require_root("Resolving Fail2ban configuration conflicts")
    if mode not in RESOLVE_MODES:
        raise ValidationError(f"Unknown mode {mode!r}.", hint="Use 'keep' (administrator keeps managing) or 'adopt' (Bant takes over).")
    with ctx.lock():
        items = [i for i in analyze(ctx) if keys is None or i["key"] in keys]
        if not items:
            return {"mode": mode, "changed": False, "message": "No administrator [sshd] settings overlap with Bant's jail."}
        if mode == "keep":
            acc = sorted({*(ctx.state.get("fail2ban", "accepted_conflicts", default=[]) or []),
                          *(_accept_key(i["path"], i["key"], i["value"]) for i in items)})
            if not ctx.dry_run:
                ctx.state.update(lambda d: d.setdefault("fail2ban", {}).__setitem__("accepted_conflicts", acc))
                ctx.audit("fail2ban.conflicts.keep", keys=[i["key"] for i in items])
            return {"mode": mode, "changed": False, "items": items,
                    "message": f"Kept the administrator's settings for {', '.join(i['key'] for i in items)}; no files were changed."}
        return _adopt(ctx, items)


def _adopt(ctx: Context, items: list[dict[str, Any]]) -> dict[str, Any]:
    plan = adopt_plan(ctx, items)
    if ctx.dry_run:
        ctx.planned += [f"{p['file']}: comment out [sshd] {p['key']} ({p['before']} -> {p['after']})" for p in plan]
        ctx.planned.append(f"write {ctx.paths.f2b_jail}, test with fail2ban-client -t, reload, verify the sshd jail")
        return {"mode": "adopt", "dry_run": True, "plan": plan, "changed": False}
    try:
        b = backups.create(ctx, note="before fail2ban conflict adopt")
    except (OSError, BantError) as exc:
        raise OperationFailed(f"Could not create a backup ({exc}); nothing was changed.") from None
    by_file: dict[str, set[str]] = {}
    for i in items:
        by_file.setdefault(i["path"], set()).add(i["key"])
    originals: dict[Path, bytes | None] = {Path(f): Path(f).read_bytes() for f in by_file}
    for p in (ctx.paths.f2b_jail, ctx.paths.f2b_filter):
        originals.setdefault(p, p.read_bytes() if p.exists() else None)
    old_cfg = {k: ctx.config.data["fail2ban"].get(k) for k in TAKEN_FROM_CONFIG}
    old_state = {k: ctx.state.get("fail2ban", k) for k in ("explicit", "carried")}

    def restore(reason: str) -> RolledBack:
        for path, data in originals.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                ctx.write_file(path, data, 0o644)
        for k, v in old_cfg.items():
            if v is not None:
                ctx.config.data["fail2ban"][k] = v
        ctx.config.save()
        ctx.state.update(lambda d: d.setdefault("fail2ban", {}).update(old_state))
        ctx.run_mut(["fail2ban-client", "reload"])
        ctx.audit("fail2ban.conflicts.adopt_failed", level="error", reason=reason)
        return RolledBack(f"Taking over the Fail2ban settings failed ({reason}); every file was restored and Fail2ban reloaded.",
                          hint=f"Backup {b['id']} holds the previous configuration.")

    try:
        carried = dict(ctx.state.get("fail2ban", "carried", default={}) or {})
        explicit = set(ctx.state.get("fail2ban", "explicit", default=[]) or [])
        for i in items:
            k = i["key"]
            if k in TAKEN_FROM_CONFIG:
                if k == "maxretry":
                    ctx.config.set("fail2ban", k, parse_int_range(i["value"], 1, 100, "maxretry"))
                else:
                    ctx.config.set("fail2ban", k, format_duration(parse_duration(i["value"])))
                explicit.add(k)
            elif k not in BANT_DECIDES and i["bant"] is None:
                carried[k] = i["value"]
        ctx.config.save()
        ctx.state.update(lambda d: d.setdefault("fail2ban", {}).update({"carried": carried, "explicit": sorted(explicit)}))
        note = f"moved to {ctx.paths.f2b_jail.name} by Bant on {time.strftime('%Y-%m-%d', time.gmtime(ctx.clock()))}; backup {b['id']}"
        for f, keys in by_file.items():
            path = Path(f)
            text, _ = comment_out(path.read_text(), keys, note)
            ctx.write_file(path, text, 0o644)
        res = fail2ban.apply_policy(ctx)
        st = fail2ban.jail_status(ctx)
        if fail2ban.unit_active(ctx, "fail2ban.service") and st is None:
            raise OperationFailed("the sshd jail is not running after the reload")
        missing = sorted(set(sshconf.effective(ctx).ports) - set(fail2ban.parse_ports(fail2ban.effective_jail(ctx).get("port", ""))))
        if missing:
            raise OperationFailed(f"the jail no longer covers SSH port(s) {missing}")
    except (BantError, OSError) as exc:
        raise restore(str(getattr(exc, "message", exc))) from None
    ctx.audit("fail2ban.conflicts.adopt", keys=[i["key"] for i in items], files=sorted(by_file), backup=b["id"])
    return {"mode": "adopt", "changed": True, "plan": plan, "backup": b["id"], "ports": res["ports"],
            "message": f"Bant now manages {', '.join(i['key'] for i in items)} for the sshd jail; "
                       f"the administrator lines were commented out (backup {b['id']})."}
