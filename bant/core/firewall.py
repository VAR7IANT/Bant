"""Firewall detection and safe, ownership-tracked port allowances.

Rules:
  * Never flush, never change default policies, never touch Docker/proxy chains.
  * A rule is Bant's only if it is in Bant's registry (state.json) AND carries its tag
    (where the backend supports tagging). Removal uses the recorded rule, never a text search.
  * New accept rules are appended before an unconditional trailing drop (or at the end of a
    policy-drop chain) so they cannot bypass the administrator's earlier drop rules.
  * Persistence for native nft/iptables is provided by bant-firewall.service re-applying the registry.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import asdict, dataclass, field
from typing import Any

from bant.constants import BANT_TAG
from bant.context import Context
from bant.errors import OperationFailed, Unsupported
from bant.platform import unit_active
from bant.utils.fsutil import read_text

IGNORED_NFT_TABLES = {"bant", "docker", "f2b-table", "firewalld", "libvirt_network"}


@dataclass
class FirewallInfo:
    backend: str = "none"  # ufw | firewalld | nftables | iptables | none
    active: bool = False
    mode: str = "observe"  # manage | observe
    detail: str = ""
    restrictive: bool = False  # inbound traffic is filtered by default
    docker: bool = False
    nft_chains: list[dict[str, Any]] = field(default_factory=list)
    available: dict[str, bool] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AllowResult:
    changed: bool
    owned: bool
    backend: str
    message: str
    rules: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def nft_input_chains(ruleset: dict[str, Any]) -> list[dict[str, Any]]:
    """Input-hook base chains that filter by default (policy drop, or an unconditional final drop/reject)."""
    chains: dict[tuple, dict[str, Any]] = {}
    last_rule: dict[tuple, dict[str, Any]] = {}
    for item in ruleset.get("nftables", []):
        if "chain" in item:
            c = item["chain"]
            if c.get("hook") == "input" and c.get("table") not in IGNORED_NFT_TABLES:
                chains[(c["family"], c["table"], c["name"])] = {
                    "family": c["family"], "table": c["table"], "chain": c["name"],
                    "policy": c.get("policy", "accept"), "last_handle": None, "last_drop": False,
                }
        elif "rule" in item:
            r = item["rule"]
            last_rule[(r["family"], r["table"], r["chain"])] = r
    for key, info in chains.items():
        r = last_rule.get(key)
        if r:
            info["last_handle"] = r.get("handle")
            exprs = r.get("expr", [])
            kinds = [next(iter(e)) for e in exprs]
            info["last_drop"] = bool(kinds) and kinds[-1] in ("drop", "reject") and all(
                k in ("drop", "reject", "counter", "log") for k in kinds
            )
    return [c for c in chains.values() if c["policy"] == "drop" or c["last_drop"]]


def parse_iptables_input(text: str) -> dict[str, Any]:
    policy, rules = "ACCEPT", []
    for line in text.splitlines():
        if line.startswith("-P INPUT"):
            policy = line.split()[-1]
        elif line.startswith("-A INPUT"):
            rules.append(line.strip())
    last = rules[-1] if rules else ""
    last_drop = bool(re.match(r"^-A INPUT -j (DROP|REJECT)\b", last))
    return {"policy": policy, "count": len(rules), "last_drop": last_drop,
            "restrictive": policy == "DROP" or last_drop}


def detect(ctx: Context) -> FirewallInfo:
    return ctx.memo("firewall.detect", lambda: _detect(ctx))


def _detect(ctx: Context) -> FirewallInfo:
    info = FirewallInfo()
    ufw_conf = read_text(ctx.paths.p("/etc/ufw/ufw.conf"))
    ufw_enabled = bool(re.search(r"^ENABLED=yes\s*$", ufw_conf, re.M)) and unit_active(ctx, "ufw.service")
    fwd_active = unit_active(ctx, "firewalld.service")
    nft_bin, ipt_bin = ctx.which("nft"), ctx.which("iptables")
    info.available = {"ufw": ctx.which("ufw") is not None, "firewalld": ctx.which("firewall-cmd") is not None,
                      "nft": nft_bin is not None, "iptables": ipt_bin is not None}
    info.docker = unit_active(ctx, "docker.service") or ctx.paths.p("/var/run/docker.sock").exists()

    if ufw_enabled and info.available["ufw"]:
        info.backend, info.active, info.mode, info.restrictive = "ufw", True, "manage", True
        info.detail = "UFW is active; Bant adds allow rules through ufw."
        return info
    if fwd_active and info.available["firewalld"]:
        info.backend, info.active, info.mode, info.restrictive = "firewalld", True, "manage", True
        info.detail = "firewalld is running; Bant adds ports through firewall-cmd."
        return info

    if nft_bin and ctx.is_root:
        res = ctx.run(["nft", "-j", "list", "ruleset"], timeout=15)
        if res.ok and res.stdout.strip():
            try:
                ruleset = json.loads(res.stdout)
            except json.JSONDecodeError:
                ruleset = {}
            info.nft_chains = nft_input_chains(ruleset)
            tables = {i["table"]["name"] for i in ruleset.get("nftables", []) if "table" in i}
            foreign = tables - IGNORED_NFT_TABLES
            if info.nft_chains or foreign:
                info.backend, info.active, info.mode = "nftables", True, "manage"
                info.restrictive = bool(info.nft_chains)
                info.detail = (f"nftables ruleset with {len(info.nft_chains)} filtering input chain(s)."
                               if info.nft_chains else "nftables ruleset present; inbound traffic is not filtered by default.")
                return info
    if ipt_bin and ctx.is_root:
        v4 = ctx.run(["iptables", "-S", "INPUT"], timeout=10)
        if v4.ok:
            parsed = parse_iptables_input(v4.stdout)
            if parsed["count"] > 0 or parsed["policy"] != "ACCEPT":
                info.backend, info.active, info.mode = "iptables", True, "manage"
                info.restrictive = parsed["restrictive"]
                info.detail = ("iptables rules present (inbound filtered by default)." if parsed["restrictive"]
                               else "iptables rules present.")
                return info
    if not ctx.is_root:
        info.mode = "observe"
        info.detail = "Run as root to inspect nftables/iptables."
        info.notes.append("Native firewall rules cannot be read without root; observation only.")
        return info
    info.detail = "No active host firewall detected."
    info.mode = "manage"
    return info


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def registry(ctx: Context) -> list[dict[str, Any]]:
    return ctx.state.get("firewall", "rules", default=[]) or []


def _register(ctx: Context, rule: dict[str, Any]) -> None:
    def fn(data: dict[str, Any]) -> None:
        rules = data.setdefault("firewall", {}).setdefault("rules", [])
        rules[:] = [r for r in rules if r["id"] != rule["id"]]
        rules.append(rule)
    ctx.state.update(fn)


def _unregister(ctx: Context, rule_id: str) -> None:
    def fn(data: dict[str, Any]) -> None:
        rules = data.get("firewall", {}).get("rules", [])
        data.setdefault("firewall", {})["rules"] = [r for r in rules if r["id"] != rule_id]
    ctx.state.update(fn)


def commit_rules(ctx: Context, rules: list[dict[str, Any]]) -> None:
    """Move rules added inside a transaction into the persistent registry (called at confirmation)."""
    for rule in rules:
        _register(ctx, rule)


# ---------------------------------------------------------------------------
# Per-backend helpers
# ---------------------------------------------------------------------------

def _new_id() -> str:
    return "r" + secrets.token_hex(4)


def _ufw_allowed(ctx: Context, port: int, proto: str) -> bool:
    out = ctx.run(["ufw", "status"], timeout=15).stdout
    pat = re.compile(rf"^{port}(/{proto})?(\s+\(v6\))?\s+ALLOW\b", re.M)
    return bool(pat.search(out))


def _firewalld_allowed(ctx: Context, port: int, proto: str) -> bool:
    return ctx.run(["firewall-cmd", "--query-port", f"{port}/{proto}"]).ok


def _nft_find_handle(ctx: Context, chain: dict[str, Any], tag: str) -> int | None:
    res = ctx.run(["nft", "-a", "list", "chain", chain["family"], chain["table"], chain["chain"]], timeout=15)
    for line in res.lines():
        if f'comment "{tag}"' in line:
            m = re.search(r"# handle (\d+)", line)
            if m:
                return int(m.group(1))
    return None


def _iptables_spec(binary: str, chain_cfg: dict[str, Any], port: int, proto: str, tag: str) -> list[str]:
    return [binary, "-p", proto, "--dport", str(port), "-m", "comment", "--comment", tag, "-j", "ACCEPT"]


def allow_port(ctx: Context, port: int, proto: str = "tcp", *, purpose: str = "manual",
               temporary: bool = False, tx=None, txm=None) -> AllowResult:
    """Ensure `port/proto` is reachable through the active firewall without disturbing existing rules.

    With `tx`/`txm`, undo commands are recorded in the transaction before each change.
    """
    ctx.require_root("Changing firewall rules")
    info = detect(ctx)
    rid = _new_id()
    tag = f"{BANT_TAG}:{rid}"
    base = {"id": rid, "backend": info.backend, "port": port, "proto": proto, "purpose": purpose,
            "temporary": temporary, "added": int(ctx.clock()), "tag": tag, "undo": []}

    def track(rule: dict[str, Any]) -> None:
        if tx is not None:
            tx.meta.setdefault("firewall_rules", []).append(rule)
            txm.save(tx)

    if info.mode == "observe":
        return AllowResult(False, False, info.backend, info.detail or "Firewall is in observation-only mode.")

    if info.backend == "none" or (not info.restrictive and info.backend in ("nftables", "iptables")):
        return AllowResult(False, False, info.backend, "No inbound filtering detected; nothing to allow.")

    if info.backend == "ufw":
        if _ufw_allowed(ctx, port, proto):
            return AllowResult(False, False, "ufw", f"{port}/{proto} is already allowed (not owned by Bant).")
        base["undo"] = [["ufw", "delete", "allow", f"{port}/{proto}"]]
        if tx is not None:
            txm.add_undo(tx, base["undo"][0])
        res = ctx.run_mut(["ufw", "allow", f"{port}/{proto}", "comment", tag])
        if not res.ok:
            raise OperationFailed(f"ufw allow failed: {res.output}")
        if not ctx.dry_run and not _ufw_allowed(ctx, port, proto):
            raise OperationFailed("ufw reports success but the rule is not present.")
        track(base)
        return AllowResult(True, True, "ufw", f"Allowed {port}/{proto} in ufw.", [base])

    if info.backend == "firewalld":
        if _firewalld_allowed(ctx, port, proto):
            return AllowResult(False, False, "firewalld", f"{port}/{proto} is already open (not owned by Bant).")
        spec = f"{port}/{proto}"
        base["undo"] = [["firewall-cmd", "--remove-port", spec], ["firewall-cmd", "--permanent", "--remove-port", spec]]
        if tx is not None:
            for u in base["undo"]:
                txm.add_undo(tx, u)
        for argv in (["firewall-cmd", "--add-port", spec], ["firewall-cmd", "--permanent", "--add-port", spec]):
            res = ctx.run_mut(argv)
            if not res.ok:
                raise OperationFailed(f"firewall-cmd failed: {res.output}")
        track(base)
        return AllowResult(True, True, "firewalld", f"Opened {spec} in firewalld.", [base])

    if info.backend == "nftables":
        added: list[dict[str, Any]] = []
        for ch in info.nft_chains:
            rule = dict(base, id=_new_id(), chain=ch)
            rule["tag"] = f"{BANT_TAG}:{rule['id']}"
            match = ["tcp" if proto == "tcp" else "udp", "dport", str(port), "accept", "comment", rule["tag"]]
            if ch["last_drop"] and ch["last_handle"]:
                argv = ["nft", "insert", "rule", ch["family"], ch["table"], ch["chain"], "position", str(ch["last_handle"])] + match
            else:
                argv = ["nft", "add", "rule", ch["family"], ch["table"], ch["chain"]] + match
            res = ctx.run_mut(argv)
            if not res.ok:
                raise OperationFailed(f"nft failed: {res.output}")
            handle = None if ctx.dry_run else _nft_find_handle(ctx, ch, rule["tag"])
            if handle is None and not ctx.dry_run:
                raise OperationFailed("nft accepted the rule but it cannot be found afterwards.")
            rule["handle"] = handle
            if tx is not None and handle is not None:
                txm.add_undo(tx, ["nft", "delete", "rule", ch["family"], ch["table"], ch["chain"], "handle", str(handle)])
            track(rule)
            added.append(rule)
        return AllowResult(True, True, "nftables", f"Added accept rule to {len(added)} nftables input chain(s).", added)

    if info.backend == "iptables":
        added = []
        for binary in ("iptables", "ip6tables"):
            if not ctx.which(binary):
                continue
            listing = ctx.run([binary, "-S", "INPUT"])
            parsed = parse_iptables_input(listing.stdout)
            if not parsed["restrictive"]:
                continue
            rule = dict(base, id=_new_id(), binary=binary)
            rule["tag"] = f"{BANT_TAG}:{rule['id']}"
            spec = _iptables_spec(binary, {}, port, proto, rule["tag"])
            if parsed["last_drop"]:
                argv = [binary, "-I", "INPUT", str(parsed["count"])] + spec[1:]
            else:
                argv = [binary, "-A", "INPUT"] + spec[1:]
            rule["undo"] = [[binary, "-D", "INPUT"] + spec[1:]]
            if tx is not None:
                txm.add_undo(tx, rule["undo"][0])
            res = ctx.run_mut(argv)
            if not res.ok:
                raise OperationFailed(f"{binary} failed: {res.output}")
            track(rule)
            added.append(rule)
        return AllowResult(bool(added), bool(added), "iptables",
                           f"Added accept rule via {len(added)} iptables binary(ies)." if added else "No restrictive iptables INPUT chain.", added)

    return AllowResult(False, False, info.backend, "Unsupported firewall backend; no change made.")


_ABSENT_HINTS = ("not exist", "bad rule", "could not delete", "no chain/target/match", "not_enabled", "not found")


def _already_absent(output: str) -> bool:
    low = output.lower()
    return any(h in low for h in _ABSENT_HINTS)


def remove_rule(ctx: Context, rule: dict[str, Any]) -> tuple[bool, str]:
    """Remove one registry rule. Ownership is re-checked against the live tag where possible."""
    ctx.require_root("Changing firewall rules")
    backend = rule.get("backend")
    if backend == "nftables":
        ch = rule.get("chain", {})
        handle = _nft_find_handle(ctx, ch, rule["tag"])
        if handle is None:
            return True, "rule already absent"
        res = ctx.run_mut(["nft", "delete", "rule", ch["family"], ch["table"], ch["chain"], "handle", str(handle)])
        return res.ok, res.output
    ok_all, msgs = True, []
    for argv in rule.get("undo", []):
        res = ctx.run_mut(argv)
        if not res.ok and not _already_absent(res.output):
            ok_all = False
        msgs.append(res.output)
    return ok_all, "; ".join(m for m in msgs if m)


def rule_present(ctx: Context, rule: dict[str, Any]) -> bool:
    """Is this registry rule live right now?"""
    backend = rule.get("backend")
    if backend == "nftables":
        return _nft_find_handle(ctx, rule.get("chain", {}), rule["tag"]) is not None
    if backend == "ufw":
        return _ufw_allowed(ctx, rule["port"], rule["proto"])
    if backend == "firewalld":
        return _firewalld_allowed(ctx, rule["port"], rule["proto"])
    if backend == "iptables" and rule.get("undo"):
        undo = rule["undo"][0]
        return ctx.run([undo[0], "-C"] + undo[2:]).ok
    return False


def remove_port(ctx: Context, port: int, proto: str = "tcp") -> list[str]:
    """Remove Bant-owned allowances for this port. Refuses to touch anything not in the registry."""
    ctx.require_root("Changing firewall rules")
    mine = [r for r in registry(ctx) if r["port"] == port and r["proto"] == proto]
    if not mine:
        raise OperationFailed(
            f"No Bant-managed allowance for {port}/{proto}.",
            hint="Bant only removes rules it created. Remove other rules with your firewall's own tools.",
        )
    results = []
    for rule in mine:
        ok, msg = remove_rule(ctx, rule)
        if ok:
            _unregister(ctx, rule["id"])
            ctx.audit("firewall.remove", port=port, proto=proto, backend=rule["backend"], rule=rule["id"])
            results.append(f"removed {rule['id']} ({rule['backend']})")
        else:
            raise OperationFailed(f"Could not remove rule {rule['id']}: {msg}")
    return results


def reapply(ctx: Context) -> list[str]:
    """Boot-time: recreate registry rules for backends that do not persist them themselves."""
    notes = []
    info = detect(ctx)
    for rule in registry(ctx):
        if rule["backend"] not in ("nftables", "iptables") or rule["backend"] != info.backend:
            continue
        present = False
        if rule["backend"] == "nftables":
            present = _nft_find_handle(ctx, rule["chain"], rule["tag"]) is not None
        else:
            undo = rule["undo"][0]
            present = ctx.run([undo[0], "-C"] + undo[2:]).ok
        if present:
            continue
        res = allow_port(ctx, rule["port"], rule["proto"], purpose=rule["purpose"])
        _unregister(ctx, rule["id"])
        for new in res.rules:
            _register(ctx, new)
        notes.append(f"re-applied {rule['port']}/{rule['proto']}: {res.message}")
        ctx.audit("firewall.reapply", port=rule["port"], proto=rule["proto"], backend=rule["backend"])
    return notes


def managed_summary(ctx: Context) -> list[dict[str, Any]]:
    return [{"id": r["id"], "backend": r["backend"], "port": r["port"], "proto": r["proto"],
             "purpose": r["purpose"], "added": r["added"]} for r in registry(ctx)]


def require_manageable(info: FirewallInfo) -> None:
    if info.mode != "manage":
        raise Unsupported(info.detail or "Firewall is in observation-only mode.")
