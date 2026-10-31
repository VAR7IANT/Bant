# Changelog

All notable changes to Bant are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.2] - Unreleased (pre-release)

### Fixed
- **`sudo bant setup` crashed with `ValueError: empty range for randrange()`** on a VPS whose kernel
  ephemeral port range covers every preferred port (seen on an AS3 VPS). Random port selection now validates
  the range (malformed or illegal values fall back to the Linux default), uses `ip_local_reserved_ports` or a
  port that no socket uses at all as a verified fallback, and otherwise stops with a clear message and a way
  to choose a port. Backup, Fail2ban and firewall steps still run when no port can be chosen.
- **`sudo bant uninstall` crashed with `AttributeError: 'Namespace' object has no attribute 'dry_run'`**
  (AS3 VPS). Global options are now filled in once after parsing for every command; a test parses every
  command without optional flags.
- **Uninstall removed the firewall allowance for the SSH port.** With ufw (or nftables/iptables) denying
  inbound traffic, new SSH logins would have been blocked after uninstalling. Allowances that are still
  needed are now kept, and survive reboots on nftables/iptables via `retained-port-allow.service`.
- `bant doctor` warned about every `[sshd]` key in an administrator file (5 warnings on VMISS9929 for
  `jail.d/99-sshd.local`) even when the values equal Bant's. Only real differences are reported now.
- Fail2ban files are evaluated in Fail2ban's real order (jail.d/*.conf, jail.local, jail.d/*.local) and
  `[sshd]` beats `[DEFAULT]`.
- `setup --dry-run` no longer creates Bant's directories or state; `ssh port --dry-run --json` prints valid JSON.
- Unexpected internal errors no longer show Python exceptions to users; details go to `/var/log/bant/debug.log`.

### Added
- **New main menu** with six entries: Security overview, One-click protection, SSH management, Firewall &
  bans, Maintenance & settings, Safe uninstall. Compact status block, update and "setup not finished"
  notices, details and advanced options in submenus, every submenu has Back, invalid input never crashes,
  narrow terminals (phones) get a box-less layout with width-aware wrapping. English and 繁體中文.
- **Safe uninstall** (CLI and menu: standard / full removal / preview): safety checks (your session, sshd
  valid and listening, no pending SSH change), backup first (or stop), journalled changes with automatic
  restore if a post-check fails, verification of SSH, Fail2ban and kept firewall allowances, program files
  removed last so an interrupted uninstall can be repeated; works for partial and failed installations.
- **`bant fail2ban conflicts`** with `--resolve keep|adopt`: compares administrator `[sshd]` settings with
  Bant's (normalised durations/ports), shows source and precedence, and resolves with preview, backup,
  validation, reload, verification and rollback. Administrator lines are commented out, never deleted.
- Setup report: completed / failed (with reason) / remaining steps and whether an SSH change was rolled back;
  "already enabled, no reconfiguration needed" for steps that are in place; Fail2ban is not reloaded when
  nothing changed.

### Changed
- `install.sh` decides by the existing state: upgrades only when setup is complete or a change is pending,
  offers the setup when the program was installed with `--no-setup` or setup is unfinished, and explains a
  failed setup instead of just exiting.
- Doctor check "admin override" renamed to "administrator setting differs".

### Not yet verified
- None of this has been run on a real VPS yet; see the 0.1.2 items in `docs/TESTING.md`.

## [0.1.1] - 2026-10-31 (pre-release)

### Added
- **Bilingual interface (English / 繁體中文).** The first time the menu is opened Bant asks for a language and remembers it
  (`/etc/bant/bant.toml` for root, `~/.config/bant/language` otherwise). `bant lang [en|zh]`, `--lang`, `BANT_LANG`, and a Language entry
  in the menu. Everything a user sees is translated (menus, status, audit findings, errors and hints, `--help`); `--json` stays English;
  terminals that are not UTF-8 fall back to English. Wide (CJK) characters are aligned correctly.
- **Built-in updater** `bant self-update` (`check`, `apply`, `rollback`, `status`, `notify`, `channel`): downloads only from GitHub over
  HTTPS, verifies a release's `SHA256SUMS` (or, for releases without assets, that the source archive's commit equals the tag's commit),
  extracts defensively, installs through the release's own `install.sh`, verifies the result and restores the previous version on any
  failure. Optional daily *check-only* timer; the dashboard shows when an update is available. Release assets are produced by
  `.github/workflows/release.yml`; maintainers' procedure in `docs/RELEASING.md`.
- SSH port: random free port by default (outside the kernel's ephemeral range), any port you choose (including 667), an existing custom
  port is kept (carried over from the previous unreleased work).

### Changed
- `install.sh` installs the update-check units; `--no-update-check` skips enabling the timer. `uninstall` removes them.

## [0.1.0] - 2026-10-30 (pre-release)

First functional release (foundation). Verified by automated unit and integration tests only;
real-VPS acceptance testing is still required before production use (see `docs/TESTING.md`).

### Added
- `bant` command with an interactive terminal UI (Rich, with a plain-text fallback) and structured
  subcommands: `status`, `doctor`, `audit`, `logs`, `ssh`, `fail2ban`, `firewall`, `updates`,
  `backup`, `restore`, `repair`, `setup`, `uninstall`. JSON output and `--dry-run` where applicable.
- Safe SSH migration to a random free port by default (or any port you choose; an existing custom port is
  kept): dual listener, firewall allowance, Fail2ban update, persistent
  systemd-timer rollback, and server-side verification of a *new* authenticated session before the
  old listener is removed (`bant ssh confirm`). Supports sshd_config includes/drop-ins, Match blocks
  and `ssh.socket` activation.
- SSH authentication management: password login on/off (requires a verified public-key login and a
  confirmed new session), root login policy, `MaxAuthTries`, `LoginGraceTime`, empty passwords,
  public-key authentication. Effective configuration is verified with `sshd -T`.
- Fail2ban installation and a Bant-owned `sshd` jail with journald/auth.log backend detection,
  administrator-override detection, ban-action compatibility checks and operational verification.
- Firewall detection (ufw, firewalld, nftables, iptables) with ownership-tracked port allowances,
  and a Bant-owned `inet bant` nftables table for manual/permanent IP blocks.
- Trusted-address list, self-lockout protection for bans.
- Security audit with evidence, impact, recommendation and fixability per finding.
- unattended-upgrades integration through a single Bant-owned apt drop-in.
- Backups with checksums, restore with automatic undo, `bant repair`.
- Structured, redacted, size-bounded audit trail (`/var/log/bant/audit.jsonl` + syslog).
- `install.sh`, `scripts/emergency-recovery.sh` (no Python needed), systemd unit for boot-time
  re-application of Bant-owned firewall state.
