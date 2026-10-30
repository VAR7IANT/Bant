# Command reference

`bant` with no arguments opens the interactive menu on a terminal (read-only unless run as root) and
prints `bant status` otherwise. Global options work before or after the command:

| Option | Meaning |
|---|---|
| `--json` | machine-readable output (errors become `{"error","message","hint"}`) |
| `--dry-run` | show what would change; nothing is modified |
| `-y`, `--yes` | assume "yes" for confirmations (required when stdin is not a terminal) |
| `--no-color` | plain output (also honoured: `NO_COLOR`, `TERM=dumb`, non-tty) |

Read-only commands work without root: `version status doctor audit logs ssh status fail2ban status
firewall status updates status backup --list`. Everything that changes the system requires root
and fails with exit code 3 *before* doing anything otherwise.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | operation failed (nothing changed, or a change was rolled back) |
| 2 | usage error (bad arguments, confirmation required in non-interactive mode) |
| 3 | root privileges required |
| 4 | invalid input (port, IP, duration, ...) |
| 5 | unsupported on this system |
| 6 | operation failed and the previous state was restored |
| 7 | another Bant operation holds the lock |
| 8 | `doctor` found failures / `audit --fail-on` threshold reached |
| 130 | cancelled (Ctrl+C) |

## Overview

| Command | Purpose |
|---|---|
| `bant version` | print version |
| `bant status [--deep]` | SSH port/auth, Fail2ban, firewall, bans, findings; `--deep` adds update and log checks |
| `bant doctor` | deep diagnostics, separating *installed / running / verified / misconfigured / unavailable* |
| `bant audit [--fail-on SEV] [--quiet-info]` | findings with evidence, impact, recommendation, fixability |
| `bant logs [audit\|ssh\|fail2ban] [-n N] [--grep TEXT]` | Bant's audit trail, SSH or Fail2ban events (secrets redacted) |

## SSH

| Command | Purpose |
|---|---|
| `bant ssh` / `bant ssh status` | listeners, activation mode, effective auth settings, Match overrides, pending change |
| `bant ssh port` | show current port(s) |
| `sudo bant ssh port N\|random [--minutes N]` | start the safe migration to port N, or to a random free port (see INSTALL.md) |
| `sudo bant ssh confirm` | after logging in through the **new** path: verify server-side, then finalise |
| `sudo bant ssh rollback` | undo a pending change now |
| `sudo bant ssh extend [MIN]` | push the rollback deadline out |
| `sudo bant ssh password on\|off` | password login. `off` needs a verified public-key login, a usable `AuthenticationMethods`, runs under rollback and needs a confirmed new key session |
| `bant ssh root` / `sudo bant ssh root yes\|key-only\|no\|forced-commands-only` | root login policy (shows whether root *password* login is possible) |
| `sudo bant ssh set max-auth-tries N` / `login-grace-time 60s` / `empty-passwords no` / `pubkey yes` | hardening options with range validation |

## Fail2ban

| Command | Purpose |
|---|---|
| `bant fail2ban [status]` | service, jail, ports, thresholds, ban counts and the verification checklist |
| `sudo bant fail2ban enable` / `disable` | install+configure / stop (protection OFF) |
| `bant fail2ban banned` | bans from Fail2ban and from Bant, with source and expiry |
| `sudo bant fail2ban ban IP [--permanent] [--duration 12h] [--reason TEXT] [--force]` | default: jail ban. `--permanent`/`--duration`: Bant block (nftables). Refuses addresses matching your SSH session unless `--force` |
| `sudo bant fail2ban unban IP` | remove from Fail2ban and from Bant blocks (never external rules) |
| `sudo bant fail2ban set maxretry\|findtime\|bantime VALUE` | tune the managed jail (validated, reverted on failure) |
| `bant fail2ban trusted` / `sudo ... trust IP` / `untrust IP` | never-ban list (feeds `ignoreip`) |

## Firewall and IP management

| Command | Purpose |
|---|---|
| `bant firewall [status]` | detected backend, manage/observe mode, Bant-owned rules, listening sockets |
| `sudo bant firewall allow PORT [--proto tcp\|udp]` | add a Bant-owned allowance (idempotent; pre-existing rules are never claimed) |
| `sudo bant firewall remove PORT [--proto ...]` | remove only Bant-owned allowances |
| `sudo bant firewall block IP/CIDR [--duration D] [--reason T]` | permanent/timed block in Bant's own `inet bant` table (needs `nft`) |
| `sudo bant firewall unblock IP` / `blocked` / `trusted` / `trust` / `untrust` | list and manage |

## Maintenance

| Command | Purpose |
|---|---|
| `bant updates [status]` / `sudo bant updates enable\|disable` | unattended-upgrades through one Bant-owned apt drop-in; never enables automatic reboot |
| `sudo bant backup [--note T] [--list]` | checksummed snapshot of SSH, Fail2ban, Bant, ufw, nftables and apt settings (no host keys/secrets) |
| `sudo bant restore [ID\|latest] [--list]` | validated restore; snapshot first; undoes itself on failure |
| `sudo bant repair` | fix permissions, clean/re-arm timers, roll back overdue changes, re-apply policy |
| `sudo bant setup [--no-ssh-migration] [--no-fail2ban] [--ssh-port N\|random]` | what the installer runs; resumable. Default port: random (asks interactively; keeps an existing custom port) |
| `sudo bant uninstall [--purge] [--remove-fail2ban-config] [--dry-run]` | see INSTALL.md |

Internal commands used by systemd (`_tx-finish`, `_fw-apply`) are not part of the public interface.

## Examples

```bash
sudo bant ssh port random --dry-run       # preview the plan
sudo bant ssh port 667                    # use your own port (any free port 1-65535)
bant status --json | jq .fail2ban.state
sudo bant fail2ban set bantime 1d
sudo bant firewall block 203.0.113.0/24 --duration 7d --reason "scanner"
bant audit --fail-on high; echo $?        # CI-style gate
```
