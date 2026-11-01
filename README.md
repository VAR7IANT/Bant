# Bant

**Bant** is a lightweight Linux VPS security manager. It moves SSH to a hardened port, installs and
verifies Fail2ban, manages firewall allowances and IP blocks without disturbing your existing
workloads, audits the server, and gives you one interactive command - `bant` - to manage it all.

> **Status: pre-release (v0.1.x).** The code is covered by automated unit and integration tests, and
> the real `sshd` and `fail2ban-client` binaries validate the configuration Bant generates. It has
> **not yet been acceptance-tested on a disposable VPS over a real network.** Read
> [`docs/TESTING.md`](docs/TESTING.md) before trusting it with a production server, and always keep
> your provider's web console available.

## Design principle

> Never sacrifice server accessibility or operational stability for aggressive hardening.

Every risky change runs inside a **persistent rollback transaction**: the original files are backed
up, a systemd timer is armed *before* anything changes, and the change only becomes permanent after
Bant has seen - server-side - a **new** authenticated SSH session that proves the new path works.
If you never confirm, close your terminal, or the installer is killed, the timer restores the
previous state by itself.

## Install

Supported: Debian 12/13, Ubuntu 22.04/24.04 LTS (systemd required).

```bash
git clone https://github.com/VAR7IANT/Bant.git
cd Bant
sudo bash install.sh
```

The installer installs Bant, registers `/usr/local/bin/bant`, installs and configures Fail2ban, and
**starts** (does not finish) the migration of SSH to a **random free port** - or to the port you choose
(`sudo bash install.sh --ssh-port 667`, or any other port; you can also type your own at the interactive prompt):

1. SSH listens on the old port **and** the new one; the firewall allows it; Fail2ban protects both.
   The installer prints the chosen port - note it, and allow it in your provider's firewall if it has one.
2. Open a **new** terminal: `ssh -p <new-port> you@your-server`
3. In that new session run **`sudo bant ssh cf`** (`cf` = confirm). Bant finds the pending change by
   itself, proves on the server that *this* session arrived through the new port, removes the old
   listener, narrows Fail2ban to the new port and disarms the rollback timer.

If you do nothing, everything reverts after ~10 minutes. If a provider/cloud firewall blocks the new port,
the new connection simply times out and the rollback restores the original state. See
[`docs/INSTALL.md`](docs/INSTALL.md).

## Use

`sudo bant` opens a short menu that also fits a phone SSH client. It prints in place - no screen
switching, no clearing - so every result and error stays in your scrollback:

```text
  ██████╗  █████╗ ███╗   ██╗████████╗
  ██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝
  ██████╔╝███████║██╔██╗ ██║   ██║
  ██╔══██╗██╔══██║██║╚██╗██║   ██║
  ██████╔╝██║  ██║██║ ╚████║   ██║
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝
         Support by VAR7IANT
               v0.1.2
 Linux VPS Security Manager
 Security status  • Secure
 SSH port         48213
 Password login   off
 Fail2ban         Active (verified)
 Firewall         nftables
 ────────────────────────────────
  1. Security overview        summary first, full diagnostics on request
  2. One-click protection     the whole safe setup; repeatable ("already enabled")
  3. SSH management           port, password login, keys, root login, confirm / roll back
  4. Firewall & bans          Fail2ban, banned IPs, trusted list, open ports, advanced
  5. Maintenance & settings   Bant update, OS updates, backups, logs, repair
  6. Language                 简体中文 / 繁體中文 / English
  7. Safe uninstall           standard / full removal / preview
Select an option (Enter to exit):
```

Type a number to open an entry; **Enter goes back** one level (on the main menu it exits). In a prompt
that needs a value, Enter cancels; risky actions need an explicit `y` - Enter is never consent. The logo
is shown only on a real terminal; narrow windows get a one-line `BANT v0.1.2 · Support by VAR7IANT`
title, and pipes, scripts and `--json` get no banner at all.

The same actions are available as commands (scripts written for 0.1.x keep working):

```text
sudo bant                      interactive menu (read-only without root)
bant status | doctor | audit   what is installed, running, and actually verified
sudo bant ssh port random|N    move SSH to a random free port, or to port N (safe migration)
sudo bant ssh password off     only after a verified key login; with automatic rollback
sudo bant fail2ban ban <IP>    ban / unban, trusted IPs, jail tuning
sudo bant firewall allow 8443  Bant-owned, removable allowances
sudo bant backup | restore | repair | uninstall [--dry-run|--purge]
sudo bant fail2ban conflicts   your [sshd] settings vs Bant's: duplicates, real conflicts, keep or adopt
sudo bant ssh cf               confirm a pending SSH change - run it inside the NEW connection
sudo bant lang zh-CN|zh-TW|en  简体中文 / 繁體中文 / English (picker without a code)
sudo bant self-update          update Bant itself from a newer GitHub release (check / apply / rollback)
```

The interface speaks **简体中文 (zh-CN), 繁體中文 (zh-TW) and English (en)**. The first time you open the
menu Bant asks (Enter picks the language of your system locale, or English) and remembers the choice;
switch any time with `bant lang` or menu item 6 - it applies immediately. The old code `zh` still means
Traditional Chinese. `--json` output is always English.

**Updating Bant.** From 0.1.1 on, `sudo bant self-update` checks GitHub Releases, verifies the download
(release `SHA256SUMS`, or the tag's commit), installs it and keeps the previous version for
`sudo bant self-update rollback`. A daily timer only *checks*; it never installs by itself, and
`install.sh --no-update-check` turns it off. Details and limits (no signatures yet) in
[`docs/SECURITY.md`](docs/SECURITY.md#self-update). Older installs upgrade once with `git pull && sudo bash install.sh`.

Full reference: [`docs/CLI.md`](docs/CLI.md). Every command supports `--help`; most support
`--json`; changes support `--dry-run`.

## What Bant will and will not do

| Bant does | Bant never does |
|---|---|
| Detect `sshd_config` Includes, drop-ins, Match blocks, `ssh.socket` | Replace port 22 and drop your session |
| Verify the *effective* config with `sshd -T` after every change | Assume an appended directive wins (OpenSSH is first-value-wins) |
| Preserve your password-login and root-login policy at install | Disable passwords/root unless you ask - and only when safe |
| Use its own Fail2ban files; report if your files override its policy | Overwrite your jails, filters or ban policy |
| Track ownership of every firewall rule it adds | Flush rules, change default policies, touch Docker/proxy chains |
| Keep manual IP blocks in its own `inet bant` nftables table | Change sysctl, forwarding, routing, NAT, IPv6, conntrack |
| Keep SSH on the new port when you uninstall it | Revert to port 22, remove or stop Fail2ban, or strand you |
| Keep the firewall allowance for your SSH port after uninstall (also across reboots) | Uninstall while an SSH change is pending, or without a backup |

## Documentation

- [`docs/INSTALL.md`](docs/INSTALL.md) - installation, upgrade, the migration walkthrough
- [`docs/CLI.md`](docs/CLI.md) - every command, exit codes, JSON output
- [`docs/SECURITY.md`](docs/SECURITY.md) - safety invariants, threat model, limitations
- [`docs/RECOVERY.md`](docs/RECOVERY.md) - **locked out? start here** (provider console procedure)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - modules, data layout, transaction engine
- [`docs/TESTING.md`](docs/TESTING.md) - test layers and the real-VPS acceptance checklist
- [`docs/RELEASING.md`](docs/RELEASING.md) - publishing a release that installed copies can update to

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check bant tests
pytest tests/unit                          # fake host, no privileges
sudo -E env "PATH=$PATH" pytest tests/integration tests/system   # real sshd/fail2ban-client on temp trees
```

Tests never change the machine they run on: see [`docs/TESTING.md`](docs/TESTING.md).

## License

MIT - see [`LICENSE`](LICENSE).
