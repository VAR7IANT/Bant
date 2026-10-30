# Changelog

All notable changes to Bant are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
