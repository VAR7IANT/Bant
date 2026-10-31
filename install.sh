#!/usr/bin/env bash
# Bant installer - run from a checked-out copy of the repository:
#
#   sudo bash install.sh [options]
#
# Installs Bant, registers the global `bant` command and runs the security setup (`bant setup`), which
#   * installs/configures Fail2ban for SSH,
#   * starts a SAFE migration of SSH to a RANDOM free port (or the port you choose); the old port stays
#     open and an automatic rollback is armed,
#   * leaves the final switch to you: log in on the new port, then run `sudo bant ssh confirm`.
#
# Re-running it upgrades the program and keeps everything else: SSH port, password policy, Fail2ban,
# firewall rules, backups and state. A finished setup is not repeated; an unfinished one is offered again.
#
# Options:
#   -y, --yes               non-interactive (assume yes for package installation)
#   --no-setup              install the program only; security setup is NOT run (later: `sudo bant setup`)
#   --no-ssh-migration      skip the SSH port migration
#   --no-fail2ban           skip Fail2ban installation/configuration
#   --no-update-check       do not enable the daily check for new Bant releases (check only, never installs)
#   --ssh-port PORT|random  SSH port to use (default: a random free port; an existing custom port is kept)
#   --minutes N             rollback window in minutes (default 10)
#   --force-unsupported     continue on a distribution Bant does not officially support
#   --dry-run               print what would be done and exit
#   -h, --help
#
# Environment: DESTDIR=/some/dir installs into that tree and skips apt/systemd/setup (packaging, tests).
set -Eeuo pipefail
umask 022

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESTDIR="${DESTDIR:-}"
LIB_DIR=/opt/bant/lib
BIN=/usr/local/bin/bant
UNIT_DIR=/etc/systemd/system

ASSUME_YES=0 RUN_SETUP=1 DRY_RUN=0 FORCE_UNSUPPORTED=0
SETUP_ARGS=()

log()  { printf '\033[1;34m[bant]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bant] WARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[bant] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" -eq 1 ]; then printf '  would run: %s\n' "$*"; else "$@"; fi; }

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1 ;;
    --no-setup) RUN_SETUP=0 ;;
    --no-ssh-migration) SETUP_ARGS+=(--no-ssh-migration) ;;
    --no-fail2ban) SETUP_ARGS+=(--no-fail2ban) ;;
    --no-update-check) SETUP_ARGS+=(--no-update-check) ;;
    --ssh-port) [ $# -ge 2 ] || die "--ssh-port needs a value"; SETUP_ARGS+=(--ssh-port "$2"); shift ;;
    --minutes) [ $# -ge 2 ] || die "--minutes needs a value"; SETUP_ARGS+=(--minutes "$2"); shift ;;
    --force-unsupported) FORCE_UNSUPPORTED=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

# ---- preflight --------------------------------------------------------------
if [ ! -f "$SRC_DIR/bant/__init__.py" ]; then die "run install.sh from a checkout of the Bant repository"; fi
if [ -z "$DESTDIR" ] && [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then die "must be run as root (use sudo)"; fi

OS_ID="unknown" OS_VER=""
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release; OS_ID="${ID:-unknown}"; OS_VER="${VERSION_ID:-}"
fi
case "$OS_ID:$OS_VER" in
  debian:12|debian:13|ubuntu:22.04|ubuntu:24.04) log "Detected supported system: $OS_ID $OS_VER" ;;
  *)
    if [ "$FORCE_UNSUPPORTED" -eq 1 ] || [ -n "$DESTDIR" ]; then warn "Unsupported system ($OS_ID $OS_VER); continuing."
    else die "Unsupported system: $OS_ID $OS_VER. Bant supports Debian 12/13 and Ubuntu 22.04/24.04. Use --force-unsupported to override at your own risk."; fi ;;
esac

if [ -z "$DESTDIR" ] && [ ! -d /run/systemd/system ]; then
  if [ "$DRY_RUN" -eq 1 ]; then warn "systemd not detected (a real install would stop here)."
  else die "systemd is required (Bant's automatic SSH rollback depends on it)."; fi
fi
PY=""
for cand in /usr/bin/python3 "$(command -v python3 2>/dev/null || true)"; do
  if [ -n "$cand" ] && [ -x "$cand" ]; then PY="$cand"; break; fi
done
if [ -z "$PY" ] && [ -z "$DESTDIR" ] && [ "$DRY_RUN" -eq 0 ]; then
  log "python3 not found; it will be installed."
  PY=/usr/bin/python3
fi

EXISTING=""
if [ -r "$DESTDIR$LIB_DIR/bant/__init__.py" ]; then
  EXISTING="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$DESTDIR$LIB_DIR/bant/__init__.py")"
fi
NEW="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SRC_DIR/bant/__init__.py")"
if [ -n "$EXISTING" ]; then log "Existing Bant $EXISTING found; upgrading to $NEW (configuration and state are preserved)."; else log "Installing Bant $NEW."; fi
if command -v sshd >/dev/null 2>&1; then log "OpenSSH server: present"; else warn "OpenSSH server not found; SSH features will be skipped."; fi
if command -v fail2ban-client >/dev/null 2>&1; then log "Fail2ban: already installed (will be reused, not overwritten)"; else log "Fail2ban: will be installed from the distribution repositories"; fi
for fw in ufw firewall-cmd nft iptables; do
  if command -v "$fw" >/dev/null 2>&1; then log "Firewall tool present: $fw (existing rules are never flushed)"; fi
done

# ---- dependencies -----------------------------------------------------------
if [ -z "$DESTDIR" ]; then
  pkgs=()
  command -v python3 >/dev/null 2>&1 || pkgs+=(python3)
  "$PY" -c 'import rich' >/dev/null 2>&1 || pkgs+=(python3-rich)
  "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1 \
    || "$PY" -c 'import tomli' >/dev/null 2>&1 || pkgs+=(python3-tomli)
  if [ ${#pkgs[@]} -gt 0 ]; then
    log "Installing dependencies: ${pkgs[*]}"
    apt_opts=(-o DPkg::Lock::Timeout=120)
    if [ "$ASSUME_YES" -eq 1 ]; then apt_opts+=(-y); fi
    run env DEBIAN_FRONTEND=noninteractive apt-get install "${apt_opts[@]}" "${pkgs[@]}"
  fi
fi

# ---- install files ----------------------------------------------------------
log "Installing program files to $LIB_DIR"
if [ "$DRY_RUN" -eq 0 ]; then
  install -d -m 0755 "$DESTDIR$(dirname "$LIB_DIR")" "$DESTDIR$(dirname "$BIN")"
  tmp_lib="$DESTDIR$LIB_DIR.new.$$"
  rm -rf "$tmp_lib"; install -d -m 0755 "$tmp_lib"
  cp -r "$SRC_DIR/bant" "$tmp_lib/bant"
  find "$tmp_lib" -name '__pycache__' -type d -prune -exec rm -rf {} +
  chmod -R go-w "$tmp_lib"
  rm -rf "$DESTDIR$LIB_DIR.old"
  if [ -d "$DESTDIR$LIB_DIR" ]; then mv "$DESTDIR$LIB_DIR" "$DESTDIR$LIB_DIR.old"; fi
  mv "$tmp_lib" "$DESTDIR$LIB_DIR"
  rm -rf "$DESTDIR$LIB_DIR.old"
  install -m 0700 "$SRC_DIR/scripts/emergency-recovery.sh" "$DESTDIR/opt/bant/emergency-recovery.sh"
  launcher_tmp="$DESTDIR$BIN.new.$$"
  cat > "$launcher_tmp" <<LAUNCHER
#!/bin/sh
# Bant launcher (generated by install.sh). Isolated interpreter: ignores PYTHONPATH and user site-packages.
exec ${PY:-/usr/bin/python3} -I -c 'import sys; sys.path.insert(0, "$LIB_DIR"); from bant.cli import main; sys.exit(main())' "\$@"
LAUNCHER
  chmod 0755 "$launcher_tmp"
  mv -f "$launcher_tmp" "$DESTDIR$BIN"
  install -d -m 0755 "$DESTDIR$UNIT_DIR"
  for unit in bant-firewall.service bant-update-check.service bant-update-check.timer; do
    install -m 0644 "$SRC_DIR/systemd/$unit" "$DESTDIR$UNIT_DIR/$unit"
  done
  install -d -m 0755 "$DESTDIR/etc/bant"
  install -d -m 0700 "$DESTDIR/var/lib/bant"
  install -d -m 0750 "$DESTDIR/var/log/bant"
else
  printf '  would copy %s/bant -> %s, create launcher %s, install units and emergency script\n' "$SRC_DIR" "$LIB_DIR" "$BIN"
fi

if [ -z "$DESTDIR" ] && [ "$DRY_RUN" -eq 0 ]; then
  systemctl daemon-reload
  "$BIN" version >/dev/null || die "installed bant command does not start"
  log "The 'bant' command is installed at $BIN"
fi

# ---- setup ------------------------------------------------------------------
# State of an earlier installation: complete | pending_confirmation | incomplete | never
SETUP_STATE="never"
if [ -z "$DESTDIR" ] && [ "$DRY_RUN" -eq 0 ]; then
  SETUP_STATE="$("$BIN" _setup-state 2>/dev/null || echo never)"
fi
EXPLICIT_SETUP=0
if [ ${#SETUP_ARGS[@]} -gt 0 ]; then EXPLICIT_SETUP=1; fi

run_setup() {
  log "Running security setup (backup, Fail2ban, firewall check, SSH migration)..."
  if [ "$ASSUME_YES" -eq 1 ]; then SETUP_ARGS+=(--yes); fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  would run: %s setup %s\n' "$BIN" "${SETUP_ARGS[*]:-}"
    return 0
  fi
  if "$BIN" setup "${SETUP_ARGS[@]}"; then
    return 0
  fi
  warn "Security setup did not finish. The report above lists the failed step, its reason, and what was already done."
  warn "Bant itself is installed. Nothing is left half-changed: an unfinished SSH change is rolled back automatically."
  warn "Fix the reported problem and run 'sudo bant setup' again - finished steps are skipped and the rest resumes."
  return 1
}

if [ -n "$DESTDIR" ]; then
  log "DESTDIR install: setup skipped."
elif [ "$RUN_SETUP" -eq 0 ]; then
  log "Bant is installed, but security setup has NOT been run (--no-setup)."
  log "Run it when you are ready: sudo bant setup   (or: sudo bant -> 2. One-click protection)"
elif [ "$SETUP_STATE" = "pending_confirmation" ]; then
  log "An SSH change from an earlier run is waiting for confirmation; setup is not repeated now."
  log "Log in on the new port in a NEW terminal, then run: sudo bant ssh confirm   (status: sudo bant ssh status)"
elif [ "$SETUP_STATE" = "complete" ] && [ "$EXPLICIT_SETUP" -eq 0 ]; then
  log "Security setup was already completed on this server: SSH port, password policy, Fail2ban and firewall are kept as they are."
  log "Re-check at any time with: sudo bant doctor   (or re-run: sudo bant setup)"
elif [ -n "$EXISTING" ] && [ "$SETUP_STATE" != "complete" ] && [ "$ASSUME_YES" -eq 0 ] && [ -t 0 ] && [ "$EXPLICIT_SETUP" -eq 0 ]; then
  log "Bant is installed, but security setup is not complete yet."
  printf '[bant] Run the security setup now? [Y/n] '
  read -r answer || answer="n"
  case "$answer" in
    ""|y|Y|yes|YES) run_setup || exit 1 ;;
    *) log "Skipped. Run it later with: sudo bant setup" ;;
  esac
else
  run_setup || exit 1
fi
