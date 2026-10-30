"""Interactive terminal UI main loop."""

from __future__ import annotations

from bant import i18n
from bant.context import Context
from bant.tui import dashboard, menus
from bant.ui import UI, Abort

MAIN_ITEMS = [
    ("1", "Security Overview", menus.overview),
    ("2", "SSH Management", menus.ssh_menu),
    ("3", "Fail2ban Protection", menus.f2b_menu),
    ("4", "Firewall Management", menus.fw_menu),
    ("5", "IP Blacklist / Allowlist", menus.ip_menu),
    ("6", "Security Audit", menus.audit),
    ("7", "Security Updates", menus.updates_menu),
    ("8", "Security Logs", menus.logs_menu),
    ("9", "Protection Settings", menus.settings_menu),
    ("10", "Backup & Recovery", menus.backup_menu),
    ("11", "System Information", menus.system_info),
    ("12", "Language / 語言", menus.language_menu),
    ("13", "Update Bant", menus.selfupdate_menu),
]
DIRECT = {"1", "6", "11"}  # screens that print and return (need a pause); others are menus that pause themselves


def run_tui(ctx: Context, ui: UI) -> int:
    table = {k: fn for k, _, fn in MAIN_ITEMS}
    try:
        if i18n.resolve(ctx)[0] is None:
            menus.choose_language(ctx, ui, first_run=True)
        while True:
            ui.clear()
            dashboard.draw(ctx, ui)
            ui.menu([(k, label) for k, label, _ in MAIN_ITEMS] + [("0", "Exit")])
            ui.rule()
            choice = ui.ask("Select an option").lower()
            if choice in ("0", "q", "quit", "exit"):
                break
            if choice in ("r", ""):
                continue
            if choice in ("?", "h", "help"):
                ui.text(" Type a number and press Enter. 'r' refreshes, '0' or 'q' exits, Ctrl+C cancels the current screen.")
                ui.pause()
                continue
            fn = table.get(choice)
            if fn is None:
                ui.warn(f"Unknown option '{choice}'.")
                ui.pause()
                continue
            try:
                menus.guarded(fn)(ctx, ui)
                if choice in DIRECT:
                    ui.pause()
            except Abort:
                continue
    except (Abort, KeyboardInterrupt):
        ui.text("")
    ui.text("Goodbye.")
    return 0
