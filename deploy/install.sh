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
# Uninstall: sudo systemctl disable --now hermitstash && sudo userdel hermit && sudo rm -rf /opt/hermitstash

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

if [ -d "${INSTALL_DIR}/.git" ]; then
  log "Updating existing installation..."
  cd "$INSTALL_DIR"
  sudo -u "$SERVICE_USER" git pull --ff-only origin main
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

log "Installing systemd service..."
cat > /etc/systemd/system/hermitstash.service <<EOF
[Unit]
Description=HermitStash — Post-quantum encrypted file uploads
Documentation=https://github.com/dotCooCoo/hermitstash
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
Environment=NODE_ENV=production
Environment=PORT=${PORT}
Environment=HERMITSTASH_TMPDIR=${SHM_DIR}
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=${DATA_DIR} ${UPLOADS_DIR} ${SHM_DIR}
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hermitstash

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now hermitstash

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
