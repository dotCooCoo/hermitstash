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
#   AUTO_UPDATE       — enable podman auto-update (default: false)
#                       When true, adds io.containers.autoupdate=registry
#                       to the container and enables podman-auto-update.timer
#                       so new tagged images are pulled + the container
#                       recreated on a schedule. Opt-in by design.

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
AUTO_UPDATE="${AUTO_UPDATE:-false}"
IMAGE="ghcr.io/dotcoocoo/hermitstash:1"
CONTAINER_NAME="hermitstash"

# Podman's auto-update works by watching containers labeled
# io.containers.autoupdate=registry. A periodic timer (podman-auto-update.timer)
# re-checks the image digest for each labeled container and, if it changed,
# pulls the new image and recreates the container with the same run args.
# The :1 tag is a moving major-version pointer published by the Docker
# workflow — every v1.* release updates it — so `registry` mode is exactly
# what we want: stay on v1.*, auto-advance through minor + patch bumps.
AUTOUPDATE_LABEL=""
if [ "$AUTO_UPDATE" = "true" ] || [ "$AUTO_UPDATE" = "yes" ] || [ "$AUTO_UPDATE" = "1" ]; then
  AUTOUPDATE_LABEL="--label io.containers.autoupdate=registry"
fi

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
  $AUTOUPDATE_LABEL \
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

# ---- Enable podman-auto-update timer (opt-in) ----
if [ -n "$AUTOUPDATE_LABEL" ]; then
  echo ""
  echo "Enabling podman-auto-update timer..."
  if [ "$(id -u)" -eq 0 ]; then
    systemctl enable --now podman-auto-update.timer 2>/dev/null \
      || echo "  Warning: could not enable podman-auto-update.timer — run manually: systemctl enable --now podman-auto-update.timer"
    echo "  Auto-update will run daily. Preview with: podman auto-update --dry-run"
  else
    systemctl --user enable --now podman-auto-update.timer 2>/dev/null \
      || echo "  Warning: could not enable user podman-auto-update.timer — run manually: systemctl --user enable --now podman-auto-update.timer"
    echo "  Auto-update will run daily. Preview with: podman auto-update --dry-run"
  fi
fi

echo ""
echo "Complete the setup wizard at http://localhost:${PORT}"
echo ""
echo "Management:"
echo "  podman logs $CONTAINER_NAME        # view logs"
echo "  podman stop $CONTAINER_NAME        # stop"
echo "  podman start $CONTAINER_NAME       # start"
echo "  podman exec -it $CONTAINER_NAME bash  # shell"
if [ -n "$AUTOUPDATE_LABEL" ]; then
  echo "  podman auto-update --dry-run       # preview pending image updates"
  echo "  podman auto-update                 # apply updates now"
fi
