"""The always-visible system overview at the top of the main menu (live data, never hardcoded)."""

from __future__ import annotations

from bant.context import Context
from bant.core import status
from bant.presenters import F2B_LABELS, render_pending, yn
from bant.ui import UI, style_for_state


def draw(ctx: Context, ui: UI) -> dict:
    from bant import __version__

    d = status.collect(ctx)
    ui.heading(f"BANT v{__version__}", "Linux VPS Security Manager")
    ui.section("System overview")
    ssh, f2b, fw = d["ssh"], d["fail2ban"], d["firewall"]
    pw, pws = yn(ssh["password_auth"])
    pk, pks = yn(ssh["pubkey_auth"])
    f2l, f2s = F2B_LABELS.get(f2b["state"], (f2b["state"], None))
    ports = ", ".join(map(str, ssh["ports"])) or "unknown"
    rows = [
        ("SSH Port", ports, "ok" if len(ssh["ports"]) == 1 and ssh["ports"][0] != 22 else "warn"),
        ("Password Login", pw, pws), ("Public Key Auth", pk, pks),
        ("Fail2ban", f2l, f2s),
        ("Firewall", f"{fw['backend']}" if fw["active"] else "none detected", "ok" if fw["active"] else "warn"),
        ("Security Status", d["health"].capitalize(), style_for_state(d["health"])),
    ]
    ui.kv(rows)
    if not d["privileged"]:
        ui.info(" Read-only mode (not root) - run with sudo to make changes.")
    if ssh.get("pending"):
        render_pending(ui, ssh["pending"])
    ui.rule()
    return d
