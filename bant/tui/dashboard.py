"""The compact status block at the top of the main menu (live data, never hardcoded).

Five lines of status, then at most a couple of one-line notices; everything else lives in submenus.
Designed to fit phone SSH clients (about 40 columns).
"""

from __future__ import annotations

from bant.context import Context
from bant.core import status
from bant.i18n import tr
from bant.presenters import F2B_LABELS, yn
from bant.ui import UI, style_for_state

HEALTH_LABELS = {"healthy": "Secure", "attention": "Needs attention", "critical": "At risk", "unknown": "Unknown"}


def draw(ctx: Context, ui: UI) -> dict:
    from bant import __version__

    d = status.collect(ctx)
    if not ui._logo_shown:  # the block-letter logo already names the tool and its version
        ui.heading(f"BANT v{__version__}", "Linux VPS Security Manager")
    else:
        ui.text(" Linux VPS Security Manager", "dim")
    ssh, f2b, fw = d["ssh"], d["fail2ban"], d["firewall"]
    pw, pws = yn(ssh["password_auth"])
    pw = {"yes": "on", "no": "off"}.get(pw, pw)
    f2l, f2s = F2B_LABELS.get(f2b["state"], (f2b["state"], None))
    ports = ", ".join(map(str, ssh["ports"])) or "unknown"
    health = d["health"]
    if health == "healthy" and d.get("setup") in ("never", "incomplete") and d["privileged"]:
        health = "attention"  # nothing alarming found, but the protection is not set up yet
    dot = ui.glyph("dot")
    ui.kv([
        ("Security status", f"{dot} {tr(HEALTH_LABELS.get(health, health))}", style_for_state(health)),
        ("SSH port", ports, "ok" if len(ssh["ports"]) == 1 and ssh["ports"][0] != 22 else "warn"),
        ("Password login", pw, pws),
        ("Fail2ban", f2l, f2s),
        ("Firewall", f"{fw['backend']}" if fw["active"] else "none detected", "ok" if fw["active"] else "warn"),
    ], label_width=16)
    notices = []
    if ssh.get("pending"):
        p = ssh["pending"]
        if p.get("target"):
            notices.append((f"SSH change pending: reconnect on port {p.get('target')}, then run: bant ssh cf", "warn"))
        else:
            notices.append(("SSH change pending: log in again with your key, then run: bant ssh cf", "warn"))
    elif d.get("setup") == "never" and d["privileged"]:
        notices.append(("Bant is installed, but security setup has not been run yet - choose 2.", "warn"))
    elif d.get("setup") == "incomplete" and d["privileged"]:
        notices.append(("Security setup is not finished - choose 2 to resume.", "warn"))
    if d.get("bant_update", {}).get("available"):
        notices.append((f"Bant {d['bant_update']['latest']} is available - 5 -> Update Bant.", "warn"))
    if not d["privileged"]:
        notices.append(("Read-only mode (not root) - run with sudo to make changes.", "dim"))
    if notices:
        ui.rule()
        for text, style in notices:
            ui.text(f" {text}", style)
    ui.rule()
    return d
