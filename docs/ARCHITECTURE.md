# Architecture

```
bant/
  cli.py            argparse CLI; thin: parse -> core call -> presenter
  ui.py             Rich/plain output primitives, prompts (case-insensitive y/n)
  presenters.py     data -> screens (shared by CLI and TUI)
  tui/              dashboard + menus + loop; every action calls the same core functions
  context.py        Context: Paths(root), Runner, Config, State, AuditLog, dry-run, lock
  constants.py      Paths dataclass (everything resolves under an optional root => testable)
  config.py         /etc/bant/bant.toml (defaults, validation, versioned migration)
  platform.py       OS release, systemd, unit state, ssh unit detection
  core/
    sshconf.py      sshd_config parser (Include/Match), sshd -T/-t, drop-in rendering
    ssh.py          status, auth policy changes (password/root/limits), pre-checks
    migration.py    port migration state machine + confirmation + finalise
    rollback.py     TxManager: persistent transactions, generated rollback.sh, systemd timer
    netinfo.py      /proc/net/tcp, ss, sshd session discovery (server-side truth)
    firewall.py     detection + ownership-tracked allowances (ufw/firewalld/nft/iptables)
    bans.py         Bant-owned inet bant table, trusted list, self-lockout check
    fail2ban.py     install, effective-config reader (-d), policy writer, verification
    updates.py      unattended-upgrades drop-in
    security_audit  findings; status.py  status + doctor; repair.py; backups.py
    setup.py        one-click protection / first run: independent, resumable steps and a report
    logs.py         journal/auth.log/audit trail access
    updater.py      self-update: check GitHub releases, verify, safe-extract, install, roll back
    f2b_conflicts.py  administrator [sshd] settings vs Bant's jail: analyse, keep, adopt (backup/verify/restore)
    uninstall.py    preflight checks, journalled changes, post-verification, program removed last
    ports.py        SSH port choice: requested / existing / remembered / random (outside the ephemeral range)
  i18n.py           language selection + output-boundary translator (English source text, zh catalog)
  locales/zh_tw.py  Traditional Chinese message catalog (~1100 entries)
  utils/            commands (Runner), fsutil (atomic IO), logging (audit), validation, tomlio
scripts/emergency-recovery.sh   POSIX sh, no Python
systemd/bant-firewall.service   oneshot boot re-apply of Bant-owned firewall state
systemd/bant-update-check.*     daily timer + oneshot that only CHECKS for a newer release
install.sh                      checkout-based installer (DESTDIR aware)
```

**Layering.** `cli`/`tui` -> `core` -> `Context` (runner, paths, state). Core modules never print;
presenters never mutate. Nothing runs at import time. `Context` takes a filesystem *root* and a
*Runner*, so tests drive the real code against a temporary tree and a fake host, and the integration
tests swap in the real `sshd`/`fail2ban-client` for read-only inspection.

## Why not a daemon?

There is no resident Bant process. Fail2ban does real-time detection; systemd timers provide the
rollback deadline; a oneshot unit re-applies Bant's firewall state at boot. Bant runs only when invoked.

## On-disk layout

| Path | Contents | Mode |
|---|---|---|
| `/opt/bant/lib/bant`, `/usr/local/bin/bant` | program, launcher (`python3 -I`) | 755 |
| `/etc/bant/bant.toml` | administrator configuration (`config_version`) | 640 |
| `/var/lib/bant/state.json` | install steps, firewall rule registry, flags | 600 |
| `/var/lib/bant/tx/<id>/` | `tx.json`, `rollback.sh`, `backup/`, markers (`confirmed`/`rolled_back`), `rollback.log` | 700 |
| `/var/lib/bant/backups/<id>/` | `manifest.json` (sha256, mode, owner), `files/` | 700 |
| `/var/lib/bant/blocklist.json` | Bant IP blocks (source of the `inet bant` table) | 600 |
| `/var/log/bant/audit.jsonl` (+ syslog `bant`) | audit trail, rotated at 1 MB x 4 | 600 |
| `/etc/ssh/sshd_config.d/00-bant.conf` | managed SSH directives (loaded first => wins) | 644 |
| `/etc/systemd/system/ssh.socket.d/bant-port.conf` | listener under socket activation | 644 |
| `/etc/fail2ban/jail.d/zz-bant-sshd.local`, `filter.d/bant-sshd.conf` | managed jail/filter | 644 |
| `/etc/apt/apt.conf.d/52bant-unattended-upgrades` | update policy drop-in | 644 |

## Transaction state machine

```
begin (timer armed) -> prepared -> [changes, each write-ahead recorded] -> dual / awaiting_confirmation
     confirm() --verified--> finalising --verified--> confirmed (timer disarmed)
     any failure / Ctrl+C / deadline / kill -9 --> rollback.sh --> rolled_back
```

The rollback script executes (1) undo commands newest-first (firewall removals), (2) file
restorations (missing originals are deleted), (3) post commands (reload sshd/Fail2ban, restart
`ssh.socket`), marks `rolled_back` only if every restoration succeeded (else `rollback.error`), then
disarms its own timer and notifies Bant for bookkeeping.

## Internationalisation

Source messages stay plain English strings/f-strings. `i18n.tr()` translates at the *output boundary* (UI methods, error printing):
exact match -> template match (catalog keys with `{}` placeholders are matched against the already-formatted text, captured values are
translated recursively) -> prefix keys (ending in a space) -> per-line -> per-sentence -> unchanged English. A missing translation can
therefore never break output. Tests keep the catalog honest: an AST scan lists every message-like string in the source and fails if one
has no Chinese entry, and the whole CLI plus every TUI screen is run in Chinese with a recorder that fails on any message that reaches the
screen untranslated. `--json` is always English. CJK text is width-aware (`ui.pad`, `display_width`).

## Design decisions

- **Python + Rich (optional)**: Rich is a distribution package on all targets; the UI degrades to
  plain text without it. TOML via `tomllib`/`tomli` - no extra parser. No SQLite: the data is a few
  small JSON documents.
- **Drop-in named `00-` for SSH**: OpenSSH is first-value-wins and Debian/Ubuntu `Include` the
  directory at the top; effective values are nevertheless verified because that layout is not guaranteed.
- **Own nftables table for manual blocks**: a base chain at `prerouting`/`raw` drops regardless of
  other tables' accept rules, and nothing of anybody else's is edited. Cost: it needs the `nft` binary.
- **Fail2ban filter override** (`bant-sshd`): stock `sshd.conf` journal matching targets
  `sshd.service`/`_COMM=sshd`; Debian logs under `ssh.service` and OpenSSH >= 9.8 logs from
  `sshd-session`. The override matches both and is only used with the systemd backend.
