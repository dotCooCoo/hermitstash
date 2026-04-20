#!/usr/bin/env bash
# HermitStash — native install script for Ubuntu/Debian
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/dotCooCoo/hermitstash/main/deploy/install.sh | bash
#
# What it does:
#   1. Installs Node.js 24 (required for PQC / OpenSSL 3.5)
#   2. Creates a 'hermit' system user
#   3. Clones HermitStash to /opt/hermitstash
#   4. Sets up tmpfs for in-memory database (256MB)
#   5. Installs and starts a systemd service
#
# Requirements: Ubuntu 22.04+ or Debian 12+, root access
# Uninstall: sudo bash /opt/hermitstash/deploy/uninstall.sh
#   (or: curl -fsSL https://raw.githubusercontent.com/dotCooCoo/hermitstash/main/deploy/uninstall.sh | sudo bash)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[hermitstash]${NC} $*"; }
warn() { echo -e "${YELLOW}[hermitstash]${NC} $*"; }
err()  { echo -e "${RED}[hermitstash]${NC} $*" >&2; }

# ---- Checks ----

if [ "$(id -u)" -ne 0 ]; then
  err "This script must be run as root (sudo)"
  exit 1
fi

if ! command -v apt-get &>/dev/null; then
  err "This script requires apt-get (Ubuntu/Debian)"
  exit 1
fi

INSTALL_DIR="/opt/hermitstash"
SHM_DIR="${INSTALL_DIR}/shm"
DATA_DIR="${INSTALL_DIR}/data"
UPLOADS_DIR="${INSTALL_DIR}/uploads"
SERVICE_USER="hermit"
PORT="${PORT:-3000}"
# Auto-update: set HERMITSTASH_AUTO_UPDATE=yes to install and enable the
# daily hermitstash-update.timer. Default is off — updates remain a
# conscious operator action until the operator opts in.
HERMITSTASH_AUTO_UPDATE="${HERMITSTASH_AUTO_UPDATE:-no}"

log "Installing HermitStash to ${INSTALL_DIR}"
echo ""

# ---- Step 1: Node.js 24 ----

if command -v node &>/dev/null; then
  NODE_VER=$(node -v | sed 's/v//' | cut -d. -f1)
  if [ "$NODE_VER" -ge 24 ]; then
    log "Node.js $(node -v) already installed"
  else
    warn "Node.js $(node -v) found but v24+ required for PQC support"
    log "Installing Node.js 24..."
    curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
    apt-get install -y nodejs
  fi
else
  log "Installing Node.js 24..."
  curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
  apt-get install -y nodejs
fi

log "Node.js $(node -v), OpenSSL $(node -e 'console.log(process.versions.openssl)')"

# ---- Step 2: System user ----

if id "$SERVICE_USER" &>/dev/null; then
  log "User '${SERVICE_USER}' already exists"
else
  log "Creating system user '${SERVICE_USER}'..."
  useradd -r -m -d "$INSTALL_DIR" -s /bin/false "$SERVICE_USER"
fi

# ---- Step 3: Clone / update ----

UPGRADE=0
if [ -d "${INSTALL_DIR}/.git" ]; then
  log "Updating existing installation..."
  cd "$INSTALL_DIR"
  sudo -u "$SERVICE_USER" git pull --ff-only origin main
  UPGRADE=1
else
  log "Cloning HermitStash..."
  git clone https://github.com/dotCooCoo/hermitstash.git "$INSTALL_DIR"
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "$INSTALL_DIR"
fi

# ---- Step 4: Directories ----

for dir in "$DATA_DIR" "$UPLOADS_DIR" "$SHM_DIR"; do
  mkdir -p "$dir"
  chown "${SERVICE_USER}:${SERVICE_USER}" "$dir"
  chmod 700 "$dir"
done

# ---- Step 5: tmpfs mount ----

FSTAB_ENTRY="tmpfs ${SHM_DIR} tmpfs size=256M,mode=700,uid=${SERVICE_USER},gid=${SERVICE_USER} 0 0"

if grep -q "$SHM_DIR" /etc/fstab; then
  log "tmpfs already configured in /etc/fstab"
else
  log "Adding tmpfs mount for in-memory database (256MB)..."
  echo "$FSTAB_ENTRY" >> /etc/fstab
  mount "$SHM_DIR"
fi

# ---- Step 6: systemd service ----
#
# Install the checked-in unit file (single source of truth — deploy/hermitstash.service)
# rather than emitting an inline heredoc, which drifts silently over time. The unit
# assumes the defaults used above (hermit user, /opt/hermitstash, port 3000, shm path);
# if any of those were overridden via env vars, patch the unit before enabling.

log "Installing systemd service from deploy/hermitstash.service..."
install -m 0644 "${INSTALL_DIR}/deploy/hermitstash.service" /etc/systemd/system/hermitstash.service

# Apply non-default overrides via a drop-in so we never edit the shipped unit.
DROPIN_DIR="/etc/systemd/system/hermitstash.service.d"
DROPIN_FILE="${DROPIN_DIR}/override.conf"
NEED_DROPIN=0
DROPIN_LINES=""

if [ "$PORT" != "3000" ]; then
  NEED_DROPIN=1
  DROPIN_LINES="${DROPIN_LINES}Environment=PORT=${PORT}"$'\n'
fi
if [ "$INSTALL_DIR" != "/opt/hermitstash" ]; then
  NEED_DROPIN=1
  DROPIN_LINES="${DROPIN_LINES}WorkingDirectory=${INSTALL_DIR}"$'\n'
  DROPIN_LINES="${DROPIN_LINES}Environment=HERMITSTASH_TMPDIR=${SHM_DIR}"$'\n'
  DROPIN_LINES="${DROPIN_LINES}ReadWritePaths=${DATA_DIR} ${UPLOADS_DIR} ${SHM_DIR}"$'\n'
fi
if [ "$SERVICE_USER" != "hermit" ]; then
  NEED_DROPIN=1
  DROPIN_LINES="${DROPIN_LINES}User=${SERVICE_USER}"$'\n'
  DROPIN_LINES="${DROPIN_LINES}Group=${SERVICE_USER}"$'\n'
fi

if [ "$NEED_DROPIN" -eq 1 ]; then
  log "Applying systemd drop-in override for non-default settings..."
  mkdir -p "$DROPIN_DIR"
  printf "[Service]\n%s" "$DROPIN_LINES" > "$DROPIN_FILE"
  chmod 0644 "$DROPIN_FILE"
fi

systemctl daemon-reload

if [ "$UPGRADE" -eq 1 ]; then
  log "Restarting hermitstash to pick up new code..."
  systemctl restart hermitstash
else
  systemctl enable --now hermitstash
fi

# ---- Step 6b: Auto-update timer (opt-in) ----
#
# The update path lives at deploy/update.sh and is driven by a systemd
# timer. Install the unit files unconditionally so operators can enable
# them later with one systemctl command — but only *start* the timer
# when the caller explicitly opted in via HERMITSTASH_AUTO_UPDATE=yes.

if [ -f "${INSTALL_DIR}/deploy/hermitstash-update.service" ] && [ -f "${INSTALL_DIR}/deploy/hermitstash-update.timer" ]; then
  log "Installing hermitstash-update.{service,timer}..."
  install -m 0644 "${INSTALL_DIR}/deploy/hermitstash-update.service" /etc/systemd/system/hermitstash-update.service
  install -m 0644 "${INSTALL_DIR}/deploy/hermitstash-update.timer"   /etc/systemd/system/hermitstash-update.timer
  systemctl daemon-reload

  case "$HERMITSTASH_AUTO_UPDATE" in
    yes|true|1)
      log "HERMITSTASH_AUTO_UPDATE=yes — enabling daily update timer."
      systemctl enable --now hermitstash-update.timer
      ;;
    *)
      log "Auto-update timer installed but NOT enabled."
      echo "  To enable later:  sudo systemctl enable --now hermitstash-update.timer"
      echo "  To run once now:  sudo systemctl start hermitstash-update.service"
      echo "  Dry-run preview:  sudo DRY_RUN=1 ${INSTALL_DIR}/deploy/update.sh"
      ;;
  esac
fi

# ---- Step 7: Wait for health ----

log "Waiting for HermitStash to start..."
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:${PORT}/health" > /dev/null 2>&1; then
    break
  fi
  sleep 1
done

if curl -sf "http://localhost:${PORT}/health" > /dev/null 2>&1; then
  echo ""
  log "HermitStash is running!"
  echo ""
  echo "  URL:    http://$(hostname -I | awk '{print $1}'):${PORT}"
  echo "  Logs:   journalctl -u hermitstash -f"
  echo "  Status: systemctl status hermitstash"
  echo ""
  echo "  Complete the setup wizard at the URL above."
  echo ""
  echo "  IMPORTANT: Back up ${DATA_DIR}/vault.key"
  echo "  Loss of this file means all sealed data is unrecoverable."
else
  warn "HermitStash may still be starting. Check: systemctl status hermitstash"
fi
