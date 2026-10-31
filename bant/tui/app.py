"""Interactive terminal UI main loop (0.1.2: six entries, details live in submenus)."""

from __future__ import annotations

from bant import i18n
from bant.context import Context
from bant.tui import dashboard, menus
from bant.ui import UI, Abort

MAIN_ITEMS = [
    ("1", "Security overview", menus.overview_menu),
    ("2", "One-click protection", menus.protect),
    ("3", "SSH management", menus.ssh_menu),
    ("4", "Firewall & bans", menus.firewall_bans_menu),
    ("5", "Maintenance & settings", menus.maintenance_menu),
    ("6", "Safe uninstall", menus.uninstall_menu),
]
DIRECT = {"2"}  # screens that print and return (need a pause); others are menus that pause themselves


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
            try:
                choice = ui.ask("Select an option").strip().lower()
            except Abort:
                break
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
                ui.warn(f"Unknown option '{choice}'. Type a number from the list.")
                ui.pause()
                continue
            try:
                menus.guarded(fn)(ctx, ui)
                if choice in DIRECT:
                    ui.pause()
            except Abort:
                continue
            except menus.UninstallDone:
                try:
                    ui.pause()
                except Abort:
                    pass
                return 0
    except (Abort, KeyboardInterrupt, EOFError):
        ui.text("")
    ui.text("Goodbye.")
    return 0
