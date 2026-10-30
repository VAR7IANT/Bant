# Security model

Bant is privileged software that edits SSH, Fail2ban and firewall state. This document lists the
invariants it enforces, how they are tested, and what it deliberately does not do.

## Invariants

1. **A rollback exists before any risky change.** `TxManager.begin` writes the transaction, a
   generated POSIX `rollback.sh` and a persistent systemd timer (`OnCalendar` + `Persistent=true`)
   *first*. If the timer cannot be armed and verified active, nothing is changed.
2. **Write-ahead recording.** Each file is backed up, and each undo command registered, *before* the
   corresponding forward action; the script is regenerated atomically on every step.
3. **Confirmation is evidence, not assertion.** `bant ssh confirm` scans `/proc` for an
   *authenticated* `sshd` session whose socket's local port is the new port, that started after
   the transaction began, from a non-local peer. Environment variables (`SSH_CONNECTION`) are never
   trusted. For "password off" it additionally requires a matching `Accepted publickey` log entry.
4. **Effective configuration is verified, not assumed.** After each change `sshd -T` (and
   `fail2ban-client -d`) is compared to the request. Because OpenSSH is first-value-wins, a shadowed
   directive is detected, the change reverted, and the offending `file:line` reported.
5. **Ownership before deletion.** Firewall rules are removed only if they are in Bant's registry and
   (nft/iptables) carry Bant's tag. Pre-existing rules are never claimed. No flush, no policy change,
   no Docker/proxy chain edits. Manual blocks live in Bant's own nftables table.
6. **Administrator files win.** Bant writes only `00-bant.conf`, `zz-bant-sshd.local`,
   `bant-sshd.conf`, an optional `ssh.socket` drop-in and `52bant-unattended-upgrades`. Fail2ban keys the administrator
   already set for `[sshd]` or `[DEFAULT]` are not overridden and are reported. The only edit of an
   administrator file is commenting out an old `Port` line during a confirmed migration (backed up,
   recorded, reversible).
7. **No lockout by omission.** Refuses: password-off without a key login or with
   `AuthenticationMethods` requiring a password; root-off when root is the only admin;
   pubkey-off with passwords off; bans matching your own SSH session; uninstall that would change the
   listener; restore that would drop your session's port.
8. **No silent success.** Every mutation re-reads state (listening port, banner, jail status, rule
   presence). Failure -> rollback -> non-zero exit and a hint.
9. **Concurrency.** One exclusive `flock` on `/var/lib/bant/lock` for mutations; the rollback script
   honours it.
10. **Input hygiene.** All subprocesses are argv lists (`shell=False`); IPs/ports/durations/transaction
    ids are validated before use; files written by Bant refuse symlinks; writes are atomic
    (temp file + fsync + rename); state is `0600/0700`.
11. **Secrets.** The audit trail redacts private keys and values under sensitive keys; backups exclude
    host keys, `authorized_keys` and password databases.

## Limits you should know about

- **Provider firewalls** cannot be seen from inside the server. The confirm step is the safeguard.
- **Bant is not an intrusion-detection system.** v0.1 relies on Fail2ban's detection; it does not
  watch processes, files or traffic. Absence of findings is not proof of security; the audit is a
  configuration review and deliberately has no score.
- **nftables/iptables persistence**: Bant re-applies *its own* rules at boot via
  `bant-firewall.service`. If another tool flushes the whole ruleset at runtime (`flush ruleset`),
  run `sudo bant repair`.
- **Cloud images** may regenerate `sshd_config.d` or ufw at boot; Bant re-verifies on the next
  `status`/`doctor` and `bant repair` re-applies its policy.
- Fail2ban detection for the systemd backend is verified by (a) the journal match returning sshd
  entries and (b) the filter parsing a synthetic failure line. A *live* end-to-end ban from a real
  failed login is part of the manual acceptance checklist (`TESTING.md`).
- Banning/blocking is per source address. Large botnets, IPv6 /64 rotation and CGNAT are out of scope.
- Root can always undo anything; Bant defends against mistakes, not against a hostile root.

## Reporting vulnerabilities

Open a private security advisory at https://github.com/VAR7IANT/Bant/security/advisories/new.
