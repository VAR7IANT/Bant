# Testing

Three layers, kept strictly apart. **None of them modifies the machine running the tests.**

| Layer | Where | What it proves | What it cannot prove |
|---|---|---|---|
| **Unit** | `tests/unit` | Logic and orchestration against `FakeHost` (a temp root that fakes `systemctl`, `sshd`, `ss`, `ufw`, `fail2ban-client`, `/proc`). The *generated rollback script* is executed for real with stubbed system commands. | Behaviour of the real daemons |
| **Integration / system** | `tests/integration`, `tests/system` | Bant's parser and generated config against the **real** `sshd -t/-T` and `fail2ban-client -t/-d` on throwaway directories; `install.sh` under `DESTDIR`; the launcher; a TUI session on a real pty; shellcheck of every shell script including the generated rollback script. | Real network, real systemd, real firewalls |
| **Real-VPS acceptance** | manual, below | End-to-end behaviour on a disposable server | - |

```bash
pytest tests/unit                                                    # no privileges
sudo -E env "PATH=$PATH" pytest tests/integration tests/system       # needs openssh-server + fail2ban installed
```

CI (`.github/workflows/ci.yml`) runs lint, shellcheck, unit tests on Ubuntu 22.04/24.04 x Python
3.10-3.13, and the integration layer on Ubuntu 24.04. It starts no services and changes no SSH or
firewall configuration on the runner.

## Real-VPS acceptance checklist (NOT yet executed)

Use a **disposable** VPS per distribution (Debian 12, Debian 13, Ubuntu 22.04, Ubuntu 24.04), with
console access. Record results in the release notes before tagging anything stable.

**Install**
- [ ] `sudo bash install.sh` finishes; `bant` is in PATH; summary says migration *pending*
- [ ] `ss -ltn` shows 22 **and** the printed random port (outside 32768-60999); `bant status` shows a countdown
- [ ] `install.sh --ssh-port 667` (and `port = 667` in bant.toml) migrates to 667; the interactive prompt (Enter / own number / `r`) behave as documented
- [ ] A host that already uses a custom port (e.g. 2222) keeps it
- [ ] Re-run `install.sh`: no duplicate rules/units/directives; still one transaction

**Migration**
- [ ] New session `ssh -p <PORT>` works; `sudo bant ssh confirm` succeeds; 22 stops listening; existing sessions survive
- [ ] Same flow on Ubuntu 24.04 with `ssh.socket` (socket drop-in) and on a host with a custom `Port 2222`
- [ ] Do nothing for the deadline: SSH returns to the original state; repeat with `kill -9` of the installer and with a reboot before the deadline
- [ ] Provider firewall closed on the new port: confirm fails, rollback restores
- [ ] Chosen port occupied by `nc -l <PORT>`: refused with explanation; `random` never picks it
- [ ] Confirm from the *old* session without a new login: refused
- [ ] ufw active / firewalld active / nftables default-drop / iptables default-drop: the new port reachable, rule removable with `bant firewall remove <PORT>`, admin rules untouched

**Authentication**
- [ ] `password off` refused when logged in with a password; accepted after a key login; new key session needed to confirm; password login then fails
- [ ] `password on` works even if `50-cloud-init.conf` says `no`
- [ ] `root` policy changes reflected in `sshd -T`

**Fail2ban**
- [ ] 6 bad passwords from another host produce a ban (`fail2ban-client status sshd`), IPv4 and IPv6; unban works
- [ ] Journald-only server (no `/var/log/auth.log`) and rsyslog server both detect failures
- [ ] An existing custom jail and `jail.local` are untouched; conflicting `[sshd]` keys are reported

**Language and updates**
- [ ] First `sudo bant` asks for a language; choosing 繁體中文 persists and every menu/screen is Chinese; `sudo bant lang en` switches back
- [ ] Over SSH with a UTF-8 terminal the box drawing and Chinese text render correctly; on the provider's text console (`TERM=linux`) Bant shows English
- [ ] After publishing a newer release: `bant self-update check` sees it, the dashboard shows the banner after the daily timer ran,
      `sudo bant self-update` installs it, `bant version` shows the new number, `self-update rollback` returns to the old one
- [ ] Update while an SSH change is pending is refused; a tampered `SHA256SUMS`/asset is refused (try on a test fork)
- [ ] `systemctl list-timers | grep bant-update` shows the daily check; `systemctl status bant-update-check.service` is not "failed" without internet

**0.1.2: menu, one-click protection, uninstall, regressions**
- [ ] Fresh VPS whose `ip_local_port_range` is `1024 65535` (or set it with `sysctl -w` on a throwaway VPS): `sudo bant setup` picks a port, no traceback (AS3 regression)
- [ ] `sudo bant uninstall`, `--dry-run`, `--purge`, `--yes`, `--json`: none crash (AS3 regression)
- [ ] Server with `/etc/fail2ban/jail.d/99-sshd.local` (port 667, same values as Bant): `sudo bant doctor` shows no Fail2ban override warnings (VMISS9929 regression); with a different `maxretry` it shows one, `sudo bant fail2ban conflicts --resolve adopt` keeps the jail running and banning
- [ ] Main menu fits a phone client (Termius, ~40-50 columns) and Windows Terminal; garbage input never crashes; every submenu returns with 0
- [ ] Menu 2 One-click protection on a fresh VPS, and again afterwards ("already enabled")
- [ ] `install.sh` again after completed setup: program upgraded only, SSH port and password policy unchanged
- [ ] `install.sh --no-setup`, then `install.sh` again: offers "Run the security setup now?"
- [ ] Setup with an unreachable apt mirror: Fail2ban step reported as failed, other steps done, rerun resumes
- [ ] Uninstall on: completed install, `--no-setup` install, failed setup, socket-activated SSH (Ubuntu 24.04), ufw default-deny (**the SSH port must stay reachable after uninstall and after a reboot**), nftables default-drop (same, via `retained-port-allow.service`)
- [ ] Uninstall with a pending migration is refused; interrupting an uninstall (Ctrl+C) and running it again completes; after uninstall a NEW SSH login works

**Coexistence**
- [ ] With Docker, sing-box/Xray (TCP+UDP), Caddy running: no connectivity change, no rule or sysctl changes (compare `nft list ruleset`, `iptables-save`, `sysctl -a` before/after, ignoring Bant's own entries)

**Lifecycle**
- [ ] `backup`/`restore` round trip; `repair`; `uninstall` leaves SSH on its new port, Fail2ban active, only Bant rules removed
- [ ] `emergency-recovery.sh rollback|restore-ssh|open-port` from the provider console
