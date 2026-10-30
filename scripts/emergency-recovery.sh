#!/bin/sh
# Bant emergency recovery - POSIX sh, no Python required.
# Use from your VPS provider's web/VNC console when SSH access was lost.
#
#   sh emergency-recovery.sh status
#   sh emergency-recovery.sh rollback          undo any unconfirmed Bant SSH change
#   sh emergency-recovery.sh restore-ssh       remove Bant's SSH overrides (back to distro defaults)
#   sh emergency-recovery.sh open-port [PORT]  add an extra SSH listener (default 22) + firewall allowance
#
# Safe to run repeatedly. Nothing here removes Fail2ban or touches non-Bant firewall rules.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
TX_DIR=/var/lib/bant/tx
DROPIN=/etc/ssh/sshd_config.d/00-bant.conf
EMERGENCY=/etc/ssh/sshd_config.d/00-bant-emergency.conf
SOCKET_DROPIN_DIR=/etc/systemd/system/ssh.socket.d

say() { printf '%s\n' "$*"; }
need_root() { [ "$(id -u)" -eq 0 ] || { say "Run as root."; exit 1; }; }

ssh_unit() {
  for u in ssh.service sshd.service; do
    if systemctl cat "$u" >/dev/null 2>&1; then echo "$u"; return; fi
  done
}

socket_active() { systemctl is-active --quiet ssh.socket 2>/dev/null; }

reload_ssh() {
  if sshd -t; then
    if socket_active; then
      systemctl daemon-reload
      systemctl restart ssh.socket
    else
      systemctl reload "$(ssh_unit)" || systemctl restart "$(ssh_unit)"
    fi
    say "sshd reloaded."
  else
    say "sshd -t FAILED - not reloading. Fix the configuration shown above."
    return 1
  fi
}

pending_tx() {
  for d in "$TX_DIR"/*/; do
    [ -f "${d}rollback.sh" ] || continue
    [ -e "${d}confirmed" ] && continue
    [ -e "${d}rolled_back" ] && continue
    printf '%s\n' "${d%/}"
  done
}

cmd_status() {
  say "== sshd configuration test =="; sshd -t && say "valid"
  say "== effective ports =="; sshd -T 2>/dev/null | grep -E '^(port|listenaddress) ' || true
  say "== listening on TCP =="; ss -ltnp 2>/dev/null | grep -E 'sshd|ssh' || say "(no ssh listener found)"
  say "== pending Bant transactions =="; p=$(pending_tx)
  if [ -n "$p" ]; then say "$p"; else say "(none)"; fi
  say "== Bant drop-ins =="; ls -l "$DROPIN" "$EMERGENCY" "$SOCKET_DROPIN_DIR"/bant-port.conf 2>/dev/null || say "(none)"
}

cmd_rollback() {
  need_root
  p=$(pending_tx)
  if [ -z "$p" ]; then say "No pending Bant transaction."; return 0; fi
  for d in $p; do
    say "Rolling back $d ..."
    sh "$d/rollback.sh" --lock-held
    if [ -e "$d/rolled_back" ]; then say "done."; else say "INCOMPLETE - see $d/rollback.log"; fi
  done
}

cmd_restore_ssh() {
  need_root
  rm -f "$DROPIN" "$EMERGENCY" "$SOCKET_DROPIN_DIR/bant-port.conf"
  say "Removed Bant SSH overrides. SSH will use distribution/administrator settings."
  say "(If you had moved the port with Bant, SSH is back on the port in /etc/ssh/sshd_config, usually 22.)"
  reload_ssh
}

cmd_open_port() {
  need_root
  port=${1:-22}
  case $port in ''|*[!0-9]*) say "Invalid port"; return 1 ;; esac
  if socket_active; then
    mkdir -p "$SOCKET_DROPIN_DIR"
    cat > "$SOCKET_DROPIN_DIR/bant-emergency.conf" <<EOT
# Bant emergency listener - remove after recovering access
[Socket]
ListenStream=0.0.0.0:$port
ListenStream=[::]:$port
EOT
  else
    printf '# Bant emergency listener - remove after recovering access\nPort %s\n' "$port" > "$EMERGENCY"
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then ufw allow "$port/tcp"; fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then firewall-cmd --add-port="$port/tcp"; fi
  say "NOTE: nftables/iptables rulesets are not edited automatically; if inbound is filtered, allow TCP $port yourself."
  reload_ssh
  say "Extra SSH listener on TCP $port enabled. Remove $EMERGENCY (and the socket drop-in) when done."
}

case ${1:-status} in
  status) cmd_status ;;
  rollback) cmd_rollback ;;
  restore-ssh) cmd_restore_ssh ;;
  open-port) cmd_open_port "$2" ;;
  *) say "usage: $0 {status|rollback|restore-ssh|open-port [PORT]}"; exit 2 ;;
esac
