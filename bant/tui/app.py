"""Interactive menu main loop.

Everything is printed in place, in the normal terminal output stream: no alternate screen, no clearing,
no full-screen redraws. Output and errors stay in the scrollback and can be copied. Every menu uses the same
prompt (`UI.select`): a number opens an entry, Enter goes back (on this main menu: exits Bant).
"""

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
    ("6", "Language", menus.language_menu),
    ("7", "Safe uninstall", menus.uninstall_menu),
]
REFRESH = "r"  # not advertised in the menu: redraws the status block


def run_tui(ctx: Context, ui: UI) -> int:
    table = {k: fn for k, _, fn in MAIN_ITEMS}
    ui.menu_mode = True
    try:
        if i18n.resolve(ctx)[0] is None:
            menus.choose_language(ctx, ui, first_run=True)
        ui.logo()
        dashboard.draw(ctx, ui)
        first = True
        while True:
            if not first:
                ui.section("Main menu")
            first = False
            ui.menu([(k, label) for k, label, _ in MAIN_ITEMS])
            choice = ui.select([*table, REFRESH], top=True)
            if choice is None:
                break
            if choice == REFRESH:
                dashboard.draw(ctx, ui)
                first = True
                continue
            try:
                menus.guarded(table[choice])(ctx, ui)
            except Abort:
                continue
            except menus.UninstallDone:
                return 0
    except (Abort, KeyboardInterrupt, EOFError):
        ui.text("")
    ui.text("Goodbye.")
    return 0
