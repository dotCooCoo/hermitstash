#!/usr/bin/env bash
# HermitStash — native uninstall script for Ubuntu/Debian
#
# Reverses deploy/install.sh. Stops + disables the service, removes the systemd
# unit + drop-in, unmounts the tmpfs and removes its /etc/fstab entry, deletes
# the hermit system user, and — after confirmation — removes /opt/hermitstash.
#
# Usage:
#   sudo bash /opt/hermitstash/deploy/uninstall.sh
#   curl -fsSL https://raw.githubusercontent.com/dotCooCoo/hermitstash/main/deploy/uninstall.sh | sudo bash
#
# By default, DATA IS PRESERVED. Pass --purge to also delete /opt/hermitstash
# (including data/, uploads/, and the vault key — irreversible).
#
# Flags:
#   --purge     Delete /opt/hermitstash after uninstalling (destroys data)
#   --yes       Non-interactive: assume yes to all prompts
#   --help      Show this message

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[hermitstash]${NC} $*"; }
warn() { echo -e "${YELLOW}[hermitstash]${NC} $*"; }
err()  { echo -e "${RED}[hermitstash]${NC} $*" >&2; }

# ---- Args ----

PURGE=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --help|-h)
      sed -n '2,20p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      err "Unknown argument: $arg"
      exit 1
      ;;
  esac
done

# ---- Checks ----

if [ "$(id -u)" -ne 0 ]; then
  err "This script must be run as root (sudo)"
  exit 1
fi

INSTALL_DIR="/opt/hermitstash"
SHM_DIR="${INSTALL_DIR}/shm"
SERVICE_USER="hermit"
SERVICE_FILE="/etc/systemd/system/hermitstash.service"
DROPIN_DIR="/etc/systemd/system/hermitstash.service.d"

confirm() {
  if [ "$ASSUME_YES" -eq 1 ]; then return 0; fi
  local prompt="$1"
  printf "%s [y/N] " "$prompt"
  read -r reply </dev/tty || return 1
  case "$reply" in
    [yY]|[yY][eE][sS]) return 0 ;;
    *) return 1 ;;
  esac
}

log "Uninstalling HermitStash from ${INSTALL_DIR}"
echo ""

# ---- Step 1: Stop + disable service ----

if systemctl list-unit-files hermitstash.service &>/dev/null; then
  log "Stopping hermitstash service..."
  systemctl disable --now hermitstash 2>/dev/null || true
else
  warn "hermitstash.service not registered with systemd — skipping"
fi

# ---- Step 2: Remove unit + drop-in ----

if [ -f "$SERVICE_FILE" ]; then
  log "Removing systemd unit..."
  rm -f "$SERVICE_FILE"
fi

if [ -d "$DROPIN_DIR" ]; then
  log "Removing systemd drop-in directory..."
  rm -rf "$DROPIN_DIR"
fi

systemctl daemon-reload
systemctl reset-failed hermitstash 2>/dev/null || true

# ---- Step 3: Unmount tmpfs + remove fstab entry ----

if mountpoint -q "$SHM_DIR" 2>/dev/null; then
  log "Unmounting tmpfs at ${SHM_DIR}..."
  umount "$SHM_DIR" || warn "Could not unmount ${SHM_DIR} (still in use?)"
fi

if grep -qE "[[:space:]]${SHM_DIR}[[:space:]]" /etc/fstab 2>/dev/null; then
  log "Removing tmpfs entry from /etc/fstab..."
  # Keep a backup so operators can see what was removed.
  cp /etc/fstab "/etc/fstab.hermitstash.bak.$(date +%s)"
  # Delete only lines that mention our shm dir as a mount point.
  sed -i "\#[[:space:]]${SHM_DIR}[[:space:]]#d" /etc/fstab
fi

# ---- Step 4: Remove system user ----

if id "$SERVICE_USER" &>/dev/null; then
  # Only remove the user if they own the install dir (i.e. were created by install.sh).
  # This avoids clobbering a pre-existing hermit user an operator set up manually.
  OWNER="$(stat -c '%U' "$INSTALL_DIR" 2>/dev/null || echo "")"
  if [ "$OWNER" = "$SERVICE_USER" ]; then
    log "Removing system user '${SERVICE_USER}'..."
    # --remove would nuke the home directory (== INSTALL_DIR) — we handle that
    # ourselves below based on --purge, so just delete the user account.
    userdel "$SERVICE_USER" 2>/dev/null || warn "Could not delete user ${SERVICE_USER}"
  else
    warn "User '${SERVICE_USER}' does not own ${INSTALL_DIR} — leaving it alone"
  fi
fi

# ---- Step 5: Optionally purge data ----

if [ "$PURGE" -eq 1 ]; then
  warn "--purge requested: this will delete ${INSTALL_DIR} including data/, uploads/, and vault.key."
  warn "Without the vault key, any backed-up sealed data CANNOT be recovered."
  if confirm "Really delete ${INSTALL_DIR}?"; then
    log "Removing ${INSTALL_DIR}..."
    rm -rf "$INSTALL_DIR"
  else
    warn "Skipped — ${INSTALL_DIR} preserved."
  fi
else
  if [ -d "$INSTALL_DIR" ]; then
    log "Data preserved at ${INSTALL_DIR}."
    echo "  Back up ${INSTALL_DIR}/data/vault.key before deleting — it's required to decrypt any sealed data."
    echo "  To remove everything later: sudo rm -rf ${INSTALL_DIR}"
  fi
fi

echo ""
log "Uninstall complete."
