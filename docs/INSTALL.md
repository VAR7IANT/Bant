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

Options: `--no-setup`, `--no-ssh-migration`, `--no-fail2ban`, `--no-update-check`, `--ssh-port N|random`,
`--minutes N`, `--force-unsupported`, `--dry-run` (see `bash install.sh --help`).

`--no-setup` installs **only the program**: the security setup does not run, and nothing about SSH or
Fail2ban changes. The menu then says "Bant is installed, but security setup has not been run yet"; run it
with `sudo bant setup` or menu **2 One-click protection**.

What happens, in order:

1. Preflight: root, supported OS, systemd, existing Bant/SSH/Fail2ban/firewall detection.
2. Missing dependencies from the distribution repositories (`python3-rich`, ...).
3. Program files to `/opt/bant/lib` (replaced atomically), launcher `/usr/local/bin/bant`
   (isolated interpreter, ignores `PYTHONPATH`), `/opt/bant/emergency-recovery.sh`,
   `bant-firewall.service`.
4. `bant setup`: system check -> backup of the original configuration -> Fail2ban (reuse or install,
   Bant-owned jail) -> firewall detection -> SSH migration -> verification. Password login is never changed here.

Re-running the installer is safe and decides by itself:

| Situation | What the installer does |
|---|---|
| fresh server | installs, runs the setup |
| setup already completed | upgrades the program only; SSH port, password policy, Fail2ban, firewall, backups and state are kept |
| an SSH change waits for confirmation | upgrades the program only and tells you to confirm |
| installed earlier with `--no-setup`, or setup unfinished | says "security setup is not complete" and offers to run it now (with `--yes`: runs it) |

If the setup fails, the installer does not just exit: the report lists the failed step and its reason, what
was completed, what is still to do, whether an SSH change was rolled back, and how to continue. Running
`sudo bant setup` again resumes - finished steps are skipped.

**Random SSH port.** Bant picks a free port from 10240-65535 outside the kernel's outgoing-connection
(ephemeral) range, avoiding ports anything listens on (TCP or UDP) and ports popular software uses. Some VPS
images set that range to almost everything (e.g. `1024 65535`); then Bant uses ports from
`ip_local_reserved_ports`, or a port inside the range that no socket uses at all - once sshd listens on it
the kernel no longer hands it out. Only if no port passes these checks does Bant stop - with an explanation,
asking for a port (interactive) or suggesting `--ssh-port 667` - while the other setup steps still run.

## The SSH migration, step by step

`bant setup` (or `sudo bant ssh port random|N`) performs the steps below. **Which port?** In order: a port you pass
(`--ssh-port N` / `bant ssh port N`); otherwise the port from `/etc/bant/bant.toml` if set; otherwise, if SSH already
runs on a single non-22 port, that port is kept (no needless move); otherwise a **random free port** is chosen. It is drawn
from 10240-65535, never from the kernel's ephemeral (outgoing-connection) range, never one that anything already listens
on (TCP or UDP), and never a handful of well-known application ports. To always use a fixed port such as 667, pass `--ssh-port 667`, or put `port = 667` under `[ssh]` in `/etc/bant/bant.toml`
(then every `bant setup` uses it). On an interactive install you see the proposal and
can press Enter, type your own port, or type `r` for another random one. The chosen port is remembered, so re-running
after an interrupted or rolled-back attempt proposes the same port.


| # | Step | If it fails |
|---|------|-------------|
| 1 | Inspect OS, sshd, `ssh.socket`, Include/drop-ins, listeners, firewall | refuses with the reason |
| 2 | Refuse if the chosen TCP port is used by another program (a random choice already avoids busy ports) | nothing changed |
| 3 | Back up files; open a transaction; **arm the persistent rollback timer** | nothing changed |
| 4 | Allow the new port in the active firewall (ufw/firewalld/nft/iptables) | automatic rollback |
| 5 | Update Fail2ban to protect old+new port, validate with `fail2ban-client -t` | automatic rollback |
| 6 | Configure sshd (drop-in `00-bant.conf`, or an `ssh.socket` drop-in), `sshd -t`, reload | automatic rollback |
| 7 | Verify the new port listens and answers with an SSH banner; old port still listens | automatic rollback |
| 8 | **You** log in on the new port from a new terminal and, in that session, run `sudo bant ssh cf` | timer rolls back |
| 9 | Server-side check that *the session running the command* is a new, authenticated, non-local session on the new port that started after step 3 (no ID or token to type) | stays pending |
| 10 | Remove old listener (comment-out `Port` lines Bant didn't write), narrow Fail2ban, verify | automatic rollback |
| 11 | Disarm timer; record rules Bant created; mark migration complete | - |

Commands while a migration is pending: `bant status`, `sudo bant ssh cf`,
`sudo bant ssh rollback`, `sudo bant ssh extend 10`.

What you see after `sudo bant ssh port 667`:

```text
✔ New SSH port: 667
✔ New port is listening and answers as SSH
✔ Firewall: Opened TCP 667 in ufw
✔ Old SSH port kept open for now: 22

 Reconnect to the server through the new port:
   ssh -p 667 alice@<server-ip>
 Once connected, run in that new session:
   sudo bant ssh cf

! Without confirmation the change is rolled back automatically at 2026-11-01 12:10:00 (in 10 min).
```

`sudo bant ssh cf` refuses - and changes nothing - when no change is pending, when the deadline has passed
(finish with `sudo bant ssh rollback`), when several changes are pending at once, or when it runs in the
old session, a session opened before the change, or a session from the server itself. **From the provider's
web console** (not an SSH session, so it cannot be verified) use `sudo bant ssh cf --other-session`: Bant
shows the separate verified new session it found on the new port and asks before using it as proof. The
old `sudo bant ssh confirm` still works for existing scripts.

**Provider firewalls.** Cloud security groups are outside the server's view. Allow the new TCP port there
*before* confirming. If you forget, the new login times out and the rollback restores access.

**Not supported automatically** (Bant explains and stops): `ListenAddress` lines that pin a port
(`ListenAddress 1.2.3.4:22`) outside socket-activation mode.

## Language

The first time you open the menu (`sudo bant`) Bant asks which language to use - **简体中文** (`zh-CN`), **繁體中文** (`zh-TW`) or
**English** (`en`); Enter takes the language of the system locale (`zh_CN`/`zh_SG` -> zh-CN, `zh_TW`/`zh_HK`/`zh_MO` -> zh-TW,
otherwise English). The choice is remembered (`/etc/bant/bant.toml` when run as root, otherwise a personal preference in
`~/.config/bant/language`). Change it later from main menu item 6, with `sudo bant lang` (picker) or `sudo bant lang zh-CN|zh-TW|en`,
or for one run with `--lang zh-CN` / `BANT_LANG=zh-CN`. The switch applies at once. A saved `zh` from Bant 0.1.2 keeps meaning
Traditional Chinese. `--json` output is always English. On a terminal that is not UTF-8 (e.g. the Linux text console, `TERM=linux`)
Bant shows English instead of garbled characters.

## Upgrade

**From Bant 0.1.1 on**, Bant updates itself:

```bash
sudo bant self-update        # checks GitHub, shows what is new, asks before installing
sudo bant self-update rollback   # if the new version misbehaves
```

The installer enables a daily *check* (never an install); the dashboard then shows "Bant x.y.z is available". See
[SECURITY.md](SECURITY.md#self-update) for how downloads are verified. Releases are published by the maintainers, see
[RELEASING.md](RELEASING.md).

**From a version older than 0.1.1** (which has no `self-update`) do one manual upgrade, after which the above applies:

```bash
cd Bant && git pull && sudo bash install.sh
```

Configuration (`/etc/bant`), state (`/var/lib/bant`) and Bant-managed SSH/Fail2ban files are kept.
`config_version` in `bant.toml` supports forward migration; a config from a *newer* Bant is rejected.

## Uninstall

```bash
sudo bant uninstall --dry-run  # preview: safety checks and every item with what will happen to it
sudo bant uninstall            # standard: asks before doing anything
sudo bant uninstall --purge    # full removal of Bant's own data as well
```

Or from the menu: **6 Safe uninstall** -> 1 standard / 2 full removal / 3 preview.

Before anything changes Bant checks your SSH session, that sshd's configuration is valid and listening,
and that no SSH change is waiting for confirmation (if one is, it refuses and tells you to `ssh cf`
or `ssh rollback` - it never finishes or breaks a migration for you). Then it takes a backup; if that is
impossible it stops without changing anything.

| | Standard | Full removal (`--purge`) |
|---|---|---|
| Bant program, `bant` command, Bant systemd units, update-check timer | removed | removed |
| SSH port and authentication settings | **kept** (`00-ssh-hardening.conf`), never reverted to 22 | **kept** |
| Fail2ban package, service and SSH jail | **kept** (`zz-sshd-protection.local`); never stopped or uninstalled | **kept** |
| Firewall allowances Bant made that are still needed (your SSH port, ports something listens on) | **kept** | **kept** |
| Bant allowances for ports nothing listens on any more, Bant's own IP-block table | removed | removed |
| Rules Bant did not create | untouched | untouched |
| Bant configuration, backups, logs, state | kept | deleted (after all checks passed) |

For nftables/iptables, whose rules do not survive a reboot on their own, the kept allowances are re-created
at boot by a small de-branded unit, `retained-port-allow.service` (its script explains how to remove it).
Removing Fail2ban itself is your decision: `apt remove fail2ban` (Bant never does it).
`--remove-fail2ban-config` deletes the retained jail - the sshd jail then falls back to the distribution
default (port 22).

After the change Bant verifies that sshd's configuration is valid, SSH still listens on the same ports, the
Fail2ban sshd jail runs and the kept firewall allowances exist. If any check fails, every file it changed is
restored and Bant stays installed. The program files are removed last, so an interrupted uninstall can simply
be run again; things already gone are skipped.
