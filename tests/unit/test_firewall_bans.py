import json

import pytest

from bant.core import bans, firewall
from bant.errors import OperationFailed, ValidationError
from tests.fakes import FakeHost

NFT_DROP_POLICY = {"nftables": [
    {"table": {"family": "inet", "name": "filter", "handle": 1}},
    {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4, "expr": [{"match": {}}, {"accept": None}]}},
    {"table": {"family": "ip", "name": "docker", "handle": 2}},
    {"chain": {"family": "ip", "table": "docker", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
    {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
]}


def test_nft_input_chain_analysis_ignores_docker_and_forward():
    chains = firewall.nft_input_chains(NFT_DROP_POLICY)
    assert [(c["table"], c["chain"]) for c in chains] == [("filter", "input")]


def test_nft_trailing_unconditional_drop_detected():
    rs = {"nftables": [
        {"chain": {"family": "ip", "table": "t", "name": "in", "hook": "input", "policy": "accept"}},
        {"rule": {"family": "ip", "table": "t", "chain": "in", "handle": 9, "expr": [{"counter": {}}, {"drop": None}]}},
    ]}
    [c] = firewall.nft_input_chains(rs)
    assert c["last_drop"] and c["last_handle"] == 9


def test_nft_accept_policy_without_drop_is_not_restrictive():
    rs = {"nftables": [{"chain": {"family": "ip", "table": "t", "name": "in", "hook": "input", "policy": "accept"}}]}
    assert firewall.nft_input_chains(rs) == []


def test_iptables_parse():
    p = firewall.parse_iptables_input("-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n")
    assert p["restrictive"] and p["count"] == 2 and not p["last_drop"]
    p = firewall.parse_iptables_input("-P INPUT ACCEPT\n-A INPUT -j DROP\n")
    assert p["restrictive"] and p["last_drop"]
    assert not firewall.parse_iptables_input("-P INPUT ACCEPT\n")["restrictive"]


def test_ufw_allow_is_idempotent_and_removal_only_for_owned(tmp_path):
    host = FakeHost(tmp_path / "r", ufw=True)
    host.ufw_rules.append("443/tcp")
    ctx = host.make_ctx()
    r1 = firewall.allow_port(ctx, 8443, "tcp")
    firewall.commit_rules(ctx, r1.rules)
    r2 = firewall.allow_port(ctx, 8443, "tcp")
    assert r1.changed and not r2.changed and host.ufw_rules.count("8443/tcp") == 1
    with pytest.raises(OperationFailed, match="No Bant-managed"):
        firewall.remove_port(ctx, 443, "tcp")
    assert "443/tcp" in host.ufw_rules, "administrator rules must never be removed"
    firewall.remove_port(ctx, 8443, "tcp")
    assert "8443/tcp" not in host.ufw_rules and "443/tcp" in host.ufw_rules


def test_firewalld_allow_and_ownership(tmp_path):
    host = FakeHost(tmp_path / "r", firewalld=True)
    host.firewalld_ports.add("80/tcp")
    ctx = host.make_ctx()
    r = firewall.allow_port(ctx, 667, "tcp")
    firewall.commit_rules(ctx, r.rules)
    assert "667/tcp" in host.firewalld_ports
    assert not firewall.allow_port(ctx, 80, "tcp").changed
    firewall.remove_port(ctx, 667, "tcp")
    assert host.firewalld_ports == {"80/tcp"}


def test_no_firewall_means_no_change(host, ctx):
    r = firewall.allow_port(ctx, 667, "tcp")
    assert not r.changed and "nothing to allow" in r.message


def test_observation_only_for_non_root(tmp_path):
    host = FakeHost(tmp_path / "r", euid=1000)
    ctx = host.make_ctx()
    info = firewall.detect(ctx)
    assert info.mode == "observe"


def test_no_destructive_firewall_commands_are_ever_issued(tmp_path):
    host = FakeHost(tmp_path / "r", ufw=True)
    ctx = host.make_ctx()
    firewall.allow_port(ctx, 667, "tcp")
    joined = [" ".join(c) for c in host.calls]
    assert not any(("flush" in c) or ("--reset" in c) or ("default deny" in c) or ("-P INPUT" in c) for c in joined)


def test_nft_rule_registered_with_handle_and_removed_by_handle(tmp_path):
    host = FakeHost(tmp_path / "r")
    ctx = host.make_ctx()
    state = {"added": False}
    chain = {"family": "inet", "table": "filter", "chain": "input", "policy": "drop", "last_handle": None, "last_drop": False}

    def fake_run(argv, *, timeout=None, input=None):  # noqa: A002
        from bant.utils.commands import CmdResult
        key = " ".join(argv)
        host.calls.append(argv)
        if key.startswith("nft -j list ruleset"):
            return CmdResult(argv, 0, json.dumps(NFT_DROP_POLICY), "")
        if key.startswith("nft add rule"):
            state["added"] = True
            return CmdResult(argv, 0, "", "")
        if key.startswith("nft -a list chain"):
            body = '\t\ttcp dport 667 accept comment "bant:TAG" # handle 17\n' if state["added"] else ""
            return CmdResult(argv, 0, body, "")
        if key.startswith("nft delete rule"):
            state["added"] = False
            return CmdResult(argv, 0, "", "")
        return CmdResult(argv, 0, "", "")

    host.run = fake_run
    # run through the real code path but with a deterministic tag
    import bant.core.firewall as fw
    orig = fw._new_id
    fw._new_id = lambda: "TAG"
    try:
        res = fw.allow_port(ctx, 667, "tcp")
    finally:
        fw._new_id = orig
    assert res.changed and res.rules[0]["handle"] == 17 and res.rules[0]["chain"]["chain"] == "input"
    assert any(c[:3] == ["nft", "add", "rule"] for c in host.calls)
    firewall.commit_rules(ctx, res.rules)
    firewall.remove_port(ctx, 667, "tcp")
    assert any(c[:3] == ["nft", "delete", "rule"] and c[-1] == "17" for c in host.calls)
    assert chain  # chain layout documented above


# ---- Bant blocklist ----------------------------------------------------------

def test_block_unblock_roundtrip_and_ruleset(host, ctx):
    bans.block(ctx, "203.0.113.9", reason="scanner")
    bans.block(ctx, "2001:db8::/48", duration=3600)
    entries = bans.active_entries(ctx)
    assert {e["ip"] for e in entries} == {"203.0.113.9", "2001:db8::/48"}
    script = bans.render_ruleset(entries, ctx.clock())
    assert "add table inet bant\ndelete table inet bant" in script
    assert "203.0.113.9" in script and "2001:db8::/48 timeout 3600s" in script
    assert "hook prerouting priority raw" in script
    assert "flush ruleset" not in script
    assert bans.unblock(ctx, "203.0.113.9") is True
    assert bans.unblock(ctx, "203.0.113.9") is False
    assert ctx.paths.blocklist_file.stat().st_mode & 0o777 == 0o600


def test_block_rejects_special_and_trusted_addresses(host, ctx):
    for bad in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "0.0.0.0/0", "10.0.0.0/4", "not-an-ip"):
        with pytest.raises(ValidationError):
            bans.block(ctx, bad)
    ctx.config.set("trust", "ips", ["198.51.100.0/24"])
    with pytest.raises(ValidationError, match="trusted"):
        bans.block(ctx, "198.51.100.7")


def test_ban_risk_detects_current_admin(host, ctx):
    host.add_ssh_session("alice", 22, "203.0.113.7", 40000)
    assert "203.0.113.7" in bans.ban_risk(ctx, "203.0.113.7")
    assert bans.ban_risk(ctx, "203.0.113.0/24")
    assert bans.ban_risk(ctx, "198.51.100.1") is None


def test_block_requires_nft(tmp_path):
    host = FakeHost(tmp_path / "r")
    host.binaries.discard("nft")
    ctx = host.make_ctx()
    from bant.errors import Unsupported
    with pytest.raises(Unsupported, match="nft"):
        bans.block(ctx, "203.0.113.9")
    assert bans.active_entries(ctx) == [], "failed apply must not leave a phantom block"


def test_expired_blocks_are_not_applied(host, ctx):
    bans.block(ctx, "203.0.113.9", duration=60)
    later = host.make_ctx(clock=lambda: 2000.0 + 3600)
    assert bans.active_entries(later) == []


def test_trust_roundtrip_persists(host, ctx):
    bans.trust_add(ctx, "203.0.113.5")
    bans.trust_add(ctx, "203.0.113.5")
    assert bans.trusted(host.make_ctx()) == ["203.0.113.5"]
    bans.trust_remove(ctx, "203.0.113.5")
    assert bans.trusted(host.make_ctx()) == []
