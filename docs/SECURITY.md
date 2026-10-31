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
   already set for `[sshd]` or `[DEFAULT]` are not overridden; differing values are reported
   (`bant fail2ban conflicts`), equal values are not. Taking such keys over (`--resolve adopt`) needs your
   confirmation, comments the lines out instead of deleting them, and is backed up and reversible. The only edit of an
   administrator file is commenting out an old `Port` line during a confirmed migration (backed up,
   recorded, reversible).
7. **No lockout by omission.** Refuses: password-off without a key login or with
   `AuthenticationMethods` requiring a password; root-off when root is the only admin;
   pubkey-off with passwords off; bans matching your own SSH session; uninstall that would change the
   listener, run while an SSH change is pending, or proceed without a backup; restore that would drop your
   session's port. Uninstall keeps every firewall allowance that is still needed (your SSH port above all) and
   makes it survive reboots on nftables/iptables; it restores its own changes if a post-check fails.
8. **No silent success.** Every mutation re-reads state (listening port, banner, jail status, rule
   presence). Failure -> rollback -> non-zero exit and a hint.
9. **Concurrency.** One exclusive `flock` on `/var/lib/bant/lock` for mutations; the rollback script
   honours it.
10. **Input hygiene.** All subprocesses are argv lists (`shell=False`); IPs/ports/durations/transaction
    ids are validated before use; files written by Bant refuse symlinks; writes are atomic
    (temp file + fsync + rename); state is `0600/0700`.
11. **Secrets.** The audit trail redacts private keys and values under sensitive keys; backups exclude
    host keys, `authorized_keys` and password databases.

## Self-update

`bant self-update` runs as root and installs code downloaded from the internet, so it is deliberately strict.

- **Where from:** only `https://` URLs on `github.com` / `githubusercontent.com` hosts, for the fixed repository
  `VAR7IANT/Bant`. Redirects are re-validated hop by hop. Size caps: 4 MiB API data, 30 MiB archive.
- **Authenticity checks**, in order of preference:
  1. the release asset `bant-<version>.tar.gz` verified against the release's `SHA256SUMS` asset (published automatically by
     `.github/workflows/release.yml`);
  2. otherwise GitHub's source archive of the release tag, accepted only if the commit id embedded in the archive equals the commit the
     tag resolves to through the GitHub API (annotated tags are dereferenced).
- **What this does *not* give you:** there are no cryptographic signatures yet. These checks catch corruption, truncated downloads and
  tag/archive mix-ups; they do not protect against a compromised GitHub account or release. If you need more assurance, install from a
  `git clone` and verify the commit yourself.
- **Safe extraction:** the archive is unpacked by Bant's own extractor into a root-only directory; absolute paths, `..`, symlinks, hard
  links, devices, more than one top-level directory, or implausible sizes abort the update. Permissions are normalised (no setuid).
- **Declared version must match:** the version in the archive's `bant/__init__.py` (read as text, not executed) must equal the release,
  and `install.sh` must pass `bash -n`.
- **Reversible:** configuration is backed up first, the running version is kept as `/opt/bant/lib.prev`, and the installed version and the
  new `bant` command are verified afterwards; any failure restores the previous program directory automatically.
  `bant self-update rollback` does the same on demand.
- **Never automatic:** the optional daily timer (`bant-update-check.timer`) only *checks* and records the result; it never installs.
  Disable it with `sudo bant self-update notify off` or `install.sh --no-update-check`. An update is refused while an SSH change is
  pending confirmation.

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
