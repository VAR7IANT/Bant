# Installing Bant

## Requirements

- Debian 12/13 or Ubuntu 22.04/24.04 with **systemd** (other releases need `--force-unsupported`)
- root access and a way to reach your VPS **provider's web console** (keep it open during install)
- Python 3.10+ (installed from the distribution if missing), `python3-rich`, and `python3-tomli` on 3.10

The installer is intentionally *not* a `curl | sh` one-liner: you review the checked-out source first.
If a remote installer is added later it will be built on signed release artifacts, and its trust
assumptions will be documented here.

## Install

```bash
git clone https://github.com/VAR7IANT/Bant.git && cd Bant
sudo bash install.sh            # add --yes for non-interactive apt
```

Options: `--no-setup`, `--no-ssh-migration`, `--no-fail2ban`, `--ssh-port N`, `--minutes N`,
`--force-unsupported`, `--dry-run` (see `bash install.sh --help`).

What happens, in order:

1. Preflight: root, supported OS, systemd, existing Bant/SSH/Fail2ban/firewall detection.
2. Missing dependencies from the distribution repositories (`python3-rich`, ...).
3. Program files to `/opt/bant/lib` (replaced atomically), launcher `/usr/local/bin/bant`
   (isolated interpreter, ignores `PYTHONPATH`), `/opt/bant/emergency-recovery.sh`,
   `bant-firewall.service`.
4. `bant setup`: baseline backup -> Fail2ban (reuse or install, Bant-owned jail) -> SSH migration.

Re-running the installer is safe: configuration and state are preserved, an open migration is not
duplicated, no duplicate directives/rules/units are created.

## The SSH migration, step by step

`bant setup` (or `sudo bant ssh port 667`) performs:

| # | Step | If it fails |
|---|------|-------------|
| 1 | Inspect OS, sshd, `ssh.socket`, Include/drop-ins, listeners, firewall | refuses with the reason |
| 2 | Refuse if TCP 667 is used by another program (offer another port) | nothing changed |
| 3 | Back up files; open a transaction; **arm the persistent rollback timer** | nothing changed |
| 4 | Allow 667 in the active firewall (ufw/firewalld/nft/iptables) | automatic rollback |
| 5 | Update Fail2ban to protect old+new port, validate with `fail2ban-client -t` | automatic rollback |
| 6 | Configure sshd (drop-in `00-bant.conf`, or an `ssh.socket` drop-in), `sshd -t`, reload | automatic rollback |
| 7 | Verify 667 listens and answers with an SSH banner; old port still listens | automatic rollback |
| 8 | **You** log in on 667 from a new terminal and run `sudo bant ssh confirm` | timer rolls back |
| 9 | Server-side check that a new, authenticated, non-local session arrived on 667 after step 3 | stays pending |
| 10 | Remove old listener (comment-out `Port` lines Bant didn't write), narrow Fail2ban, verify | automatic rollback |
| 11 | Disarm timer; record rules Bant created; mark migration complete | - |

Commands while a migration is pending: `bant status`, `sudo bant ssh confirm`,
`sudo bant ssh rollback`, `sudo bant ssh extend 10`.

**Provider firewalls.** Cloud security groups are outside the server's view. Allow TCP 667 there
*before* confirming. If you forget, the new login times out and the rollback restores access.

**Not supported automatically** (Bant explains and stops): `ListenAddress` lines that pin a port
(`ListenAddress 1.2.3.4:22`) outside socket-activation mode.

## Upgrade

```bash
cd Bant && git pull && sudo bash install.sh
```

Configuration (`/etc/bant`), state (`/var/lib/bant`) and Bant-managed SSH/Fail2ban files are kept.
`config_version` in `bant.toml` supports forward migration; a config from a *newer* Bant is rejected.

## Uninstall

```bash
sudo bant uninstall            # shows exactly what will happen; --dry-run to preview
```

SSH stays on its current port (settings are kept as `00-ssh-hardening.conf`, no longer branded),
Fail2ban stays installed with its SSH jail settings retained, and only firewall rules recorded in
Bant's registry are removed. `--purge` also deletes backups, logs and configuration.
