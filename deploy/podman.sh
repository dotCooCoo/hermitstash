#!/usr/bin/env bash
# HermitStash — Podman deployment script
#
# Podman is the default container runtime on RHEL, Fedora, Rocky Linux,
# and Alma Linux. It's daemonless and rootless by default.
#
# Usage (rootless):
#   bash podman.sh
#
# Usage (rootful, for systemd integration):
#   sudo bash podman.sh
#
# Environment variables (all optional):
#   PORT              — host port        (default: 3000)
#   DATA_DIR          — data directory   (default: ./hermitstash-data)
#   UPLOADS_DIR       — uploads dir      (default: ./hermitstash-uploads)
#   SHM_SIZE          — shared memory    (default: 256m)
#   TRUST_PROXY       — proxy trust      (default: false)
#   RP_ORIGIN         — origin URL       (default: empty)
#   GENERATE_SYSTEMD  — create unit file (default: true)

set -euo pipefail

# ---- Check for Podman ----
if ! command -v podman &>/dev/null; then
  echo "Error: Podman not found."
  echo ""
  echo "Install it for your distro:"
  echo "  Fedora:       sudo dnf install podman"
  echo "  RHEL/Rocky:   sudo dnf install podman"
  echo "  Alma Linux:   sudo dnf install podman"
  echo "  Ubuntu:       sudo apt install podman"
  echo "  Debian:       sudo apt install podman"
  echo "  Arch:         sudo pacman -S podman"
  echo "  openSUSE:     sudo zypper install podman"
  exit 1
fi

PORT="${PORT:-3000}"
DATA_DIR="${DATA_DIR:-./hermitstash-data}"
UPLOADS_DIR="${UPLOADS_DIR:-./hermitstash-uploads}"
SHM_SIZE="${SHM_SIZE:-256m}"
TRUST_PROXY="${TRUST_PROXY:-false}"
RP_ORIGIN="${RP_ORIGIN:-}"
GENERATE_SYSTEMD="${GENERATE_SYSTEMD:-true}"
IMAGE="ghcr.io/dotcoocoo/hermitstash:latest"
CONTAINER_NAME="hermitstash"

echo "=== HermitStash Podman Installer ==="
echo ""
echo "Image:      $IMAGE"
echo "Port:       $PORT"
echo "Data:       $(realpath -m "$DATA_DIR")"
echo "Uploads:    $(realpath -m "$UPLOADS_DIR")"
echo "SHM size:   $SHM_SIZE"
if [ "$(id -u)" -eq 0 ]; then
  echo "Mode:       rootful"
else
  echo "Mode:       rootless"
fi
echo ""

# ---- Create directories ----
mkdir -p "$DATA_DIR" "$UPLOADS_DIR"
DATA_DIR="$(realpath "$DATA_DIR")"
UPLOADS_DIR="$(realpath "$UPLOADS_DIR")"

# ---- Pull image ----
echo "Pulling image..."
podman pull "$IMAGE"

# ---- Remove existing container if present ----
if podman container exists "$CONTAINER_NAME" 2>/dev/null; then
  echo "Stopping existing container..."
  podman stop "$CONTAINER_NAME" 2>/dev/null || true
  podman rm "$CONTAINER_NAME" 2>/dev/null || true
fi

# ---- Build environment flags ----
ENV_FLAGS="-e NODE_ENV=production"
if [ "$TRUST_PROXY" != "false" ]; then
  ENV_FLAGS="$ENV_FLAGS -e TRUST_PROXY=$TRUST_PROXY"
fi
if [ -n "$RP_ORIGIN" ]; then
  ENV_FLAGS="$ENV_FLAGS -e RP_ORIGIN=$RP_ORIGIN"
fi

# ---- Run container ----
echo "Starting HermitStash..."
# shellcheck disable=SC2086 # intentional word-splitting for multiple -e flags
podman run -d \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  -p "${PORT}:3000" \
  -v "${DATA_DIR}:/app/data:Z" \
  -v "${UPLOADS_DIR}:/app/uploads:Z" \
  --shm-size="$SHM_SIZE" \
  $ENV_FLAGS \
  "$IMAGE"

# ---- Wait for health ----
echo "Waiting for HermitStash to start..."
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:${PORT}/health" > /dev/null 2>&1; then
    break
  fi
  sleep 1
done

if curl -sf "http://localhost:${PORT}/health" > /dev/null 2>&1; then
  echo ""
  echo "HermitStash is running at: http://localhost:${PORT}"
else
  echo ""
  echo "HermitStash may still be starting. Check: podman logs $CONTAINER_NAME"
fi

# ---- Generate systemd unit (rootful only) ----
if [ "$GENERATE_SYSTEMD" = "true" ] && [ "$(id -u)" -eq 0 ]; then
  echo ""
  echo "Generating systemd service..."
  UNIT_DIR="/etc/systemd/system"
  podman generate systemd --name "$CONTAINER_NAME" --new --files --restart-policy=on-failure
  mv "container-${CONTAINER_NAME}.service" "${UNIT_DIR}/"
  systemctl daemon-reload
  systemctl enable "container-${CONTAINER_NAME}.service"
  echo "Systemd service installed: container-${CONTAINER_NAME}.service"
  echo "  Status: systemctl status container-${CONTAINER_NAME}"
  echo "  Logs:   journalctl -u container-${CONTAINER_NAME} -f"
elif [ "$GENERATE_SYSTEMD" = "true" ] && [ "$(id -u)" -ne 0 ]; then
  echo ""
  echo "Generating user systemd service (rootless)..."
  UNIT_DIR="${HOME}/.config/systemd/user"
  mkdir -p "$UNIT_DIR"
  podman generate systemd --name "$CONTAINER_NAME" --new --files --restart-policy=on-failure
  mv "container-${CONTAINER_NAME}.service" "${UNIT_DIR}/"
  systemctl --user daemon-reload
  systemctl --user enable "container-${CONTAINER_NAME}.service"
  echo "User systemd service installed."
  echo "  Status: systemctl --user status container-${CONTAINER_NAME}"
  echo "  Logs:   journalctl --user -u container-${CONTAINER_NAME} -f"
  echo ""
  echo "To start on boot without login: loginctl enable-linger $(whoami)"
fi

echo ""
echo "Complete the setup wizard at http://localhost:${PORT}"
echo ""
echo "Management:"
echo "  podman logs $CONTAINER_NAME        # view logs"
echo "  podman stop $CONTAINER_NAME        # stop"
echo "  podman start $CONTAINER_NAME       # start"
echo "  podman exec -it $CONTAINER_NAME bash  # shell"
