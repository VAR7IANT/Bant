#!/usr/bin/env bash
# Bant installer - run from a checked-out copy of the repository:
#
#   sudo bash install.sh [options]
#
# Installs Bant, registers the global `bant` command and runs `bant setup`, which
#   * installs/configures Fail2ban for SSH,
#   * starts a SAFE migration of SSH to TCP 667 (old port stays open, automatic rollback armed),
#   * leaves the final switch to you: log in on the new port, then run `sudo bant ssh confirm`.
#
# Options:
#   -y, --yes               non-interactive (assume yes for package installation)
#   --no-setup              install files only; do not run `bant setup`
#   --no-ssh-migration      skip the SSH port migration
#   --no-fail2ban           skip Fail2ban installation/configuration
#   --ssh-port PORT         target SSH port instead of 667
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

usage() { sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1 ;;
    --no-setup) RUN_SETUP=0 ;;
    --no-ssh-migration) SETUP_ARGS+=(--no-ssh-migration) ;;
    --no-fail2ban) SETUP_ARGS+=(--no-fail2ban) ;;
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
  install -m 0644 "$SRC_DIR/systemd/bant-firewall.service" "$DESTDIR$UNIT_DIR/bant-firewall.service"
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
if [ "$RUN_SETUP" -eq 1 ] && [ -z "$DESTDIR" ]; then
  log "Running initial setup (baseline, Fail2ban, SSH migration)..."
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  would run: %s setup %s\n' "$BIN" "${SETUP_ARGS[*]:-}"
  else
    "$BIN" setup "${SETUP_ARGS[@]}"
  fi
else
  log "Skipping setup. Run it later with: sudo bant setup"
fi
