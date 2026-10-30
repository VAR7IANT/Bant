# Recovery - locked out or something looks wrong

**Assume SSH might be unavailable.** Everything below works from your VPS provider's web/VNC/serial
console (log in as root or a sudo user there). None of it needs Python or a working `bant`.

## 0. Wait first (if a migration is pending)

If you started `bant ssh port` / `bant setup` or changed password login and **did not confirm**,
Bant restores the previous configuration automatically at the deadline (default 10 minutes), even
after a reboot. `sudo bant status` (from any working session or the console) shows the countdown.

## 1. Undo any unconfirmed Bant SSH change right now

```bash
sh /opt/bant/emergency-recovery.sh rollback
```

Equivalent when Bant works: `sudo bant ssh rollback`.

## 2. Show what is going on

```bash
sh /opt/bant/emergency-recovery.sh status
```

Shows `sshd -t`, effective ports, listening sockets, pending transactions and Bant drop-ins.

## 3. Remove all Bant SSH overrides

```bash
sh /opt/bant/emergency-recovery.sh restore-ssh
```

Deletes `/etc/ssh/sshd_config.d/00-bant.conf`, the emergency drop-in and
`/etc/systemd/system/ssh.socket.d/bant-port.conf`, validates with `sshd -t`, reloads sshd.
SSH then follows your own `sshd_config` (usually port 22).

## 4. Open an extra SSH port (e.g. 22) temporarily

```bash
sh /opt/bant/emergency-recovery.sh open-port 22
```

Adds a listener (sshd drop-in, or socket drop-in under socket activation) and a ufw/firewalld
allowance if those are active. **nftables/iptables rulesets are not edited automatically**: if
inbound traffic is filtered, allow the port yourself. Remove the file named in the output afterwards.

## 5. Manual steps, no scripts at all

```bash
sshd -t                                 # must print nothing
rm -f /etc/ssh/sshd_config.d/00-bant.conf
rm -f /etc/systemd/system/ssh.socket.d/bant-port.conf && systemctl daemon-reload
systemctl restart ssh.socket 2>/dev/null; systemctl reload ssh || systemctl reload sshd
ss -ltnp | grep sshd                    # confirm the listener
```

Pre-change copies of every file Bant touched live in `/var/lib/bant/tx/<id>/backup/` and
`/var/lib/bant/backups/<id>/files/`; plain `cp` restores them. Check `/var/lib/bant/tx/<id>/rollback.log`.

## 6. Provider firewall

If `ssh -p <PORT>` times out but `ss -ltn` on the console shows sshd listening on that port, the block is
outside the server: add an inbound TCP rule for it in your provider's firewall/security group.
Forgot which port Bant chose? `ss -ltnp | grep sshd` on the console, or `sudo bant ssh status`.

## 7. Banned yourself?

```bash
fail2ban-client status sshd             # see banned IPs
fail2ban-client unban <your-ip>
sudo bant firewall unblock <your-ip>    # if you blocked it through Bant
```

Prevent it: `sudo bant fail2ban trust <your-static-ip>` (Bant warns before banning an address that
matches an active SSH session).

## 8. Restore a backup / repair

```bash
sudo bant restore --list
sudo bant restore <id>        # takes a safety snapshot first, validates, undoes itself on failure
sudo bant repair              # re-arms/cleans timers, fixes permissions, re-applies Fail2ban policy
```

## If a rollback reports INCOMPLETE

`/var/lib/bant/tx/<id>/rollback.error` and `rollback.log` say which file could not be restored.
Restore it manually from `/var/lib/bant/tx/<id>/backup/` (the `rollback.sh` next to it lists every
source/target pair), then run `sudo bant repair`.
