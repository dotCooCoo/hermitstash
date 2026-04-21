#!/usr/bin/env bash
# HermitStash — LXD / Incus deployment script
#
# Works with both LXD (Ubuntu) and Incus (Debian/upstream).
# Run on the host machine:
#   bash lxd-incus.sh
#
# Creates a Debian 12 system container, installs Docker inside it,
# and runs HermitStash as a Docker container.
#
# Environment variables (all optional):
#   CONTAINER_NAME  — container name       (default: hermitstash)
#   MEMORY          — memory limit         (default: 1GB)
#   DISK            — root disk size       (default: 16GB)
#   CPU             — CPU cores            (default: 2)
#   PORT            — host port to forward (default: 3000)

set -euo pipefail

# ---- Auto-detect LXD vs Incus ----
if command -v incus &>/dev/null; then
  CLI="incus"
elif command -v lxc &>/dev/null && lxc version &>/dev/null 2>&1; then
  CLI="lxc"
else
  echo "Error: Neither Incus nor LXD found."
  echo "Install one of:"
  echo "  Ubuntu:  sudo snap install lxd && lxd init --minimal"
  echo "  Debian:  apt install incus && incus admin init --minimal"
  exit 1
fi

echo "Using: $CLI"

# ---- Configuration ----
NAME="${CONTAINER_NAME:-hermitstash}"
MEMORY="${MEMORY:-1GB}"
DISK="${DISK:-16GB}"
CPU="${CPU:-2}"
PORT="${PORT:-3000}"

echo ""
echo "=== HermitStash LXD/Incus Installer ==="
echo ""
echo "Container:  $NAME"
echo "Memory:     $MEMORY"
echo "Disk:       $DISK"
echo "CPUs:       $CPU"
echo "Host port:  $PORT → 3000"
echo ""

# ---- Launch container ----
if $CLI info "$NAME" &>/dev/null; then
  echo "Container '$NAME' already exists. Starting if stopped..."
  $CLI start "$NAME" 2>/dev/null || true
else
  echo "Launching Debian 12 container..."
  $CLI launch images:debian/12 "$NAME" \
    --config limits.memory="$MEMORY" \
    --config limits.cpu="$CPU" \
    --device root,size="$DISK"

  # Allow nested containers (required for Docker inside LXD)
  $CLI config set "$NAME" security.nesting true

  # Restart to apply nesting
  $CLI restart "$NAME"
  sleep 3
fi

# ---- Wait for network ----
echo "Waiting for network..."
for _ in $(seq 1 30); do
  if $CLI exec "$NAME" -- ping -c1 -W1 8.8.8.8 &>/dev/null; then
    break
  fi
  sleep 1
done

# ---- Install Docker + run HermitStash ----
# Quoted-delimiter heredoc (<<'REMOTE_SCRIPT') is the idiom for "literal
# payload, expand inside the target shell, not on the host." The $(...)
# expansions here evaluate inside the LXC container (dpkg, /etc/os-release)
# rather than on the host.
echo "Installing Docker and HermitStash..."
$CLI exec "$NAME" -- bash -s <<'REMOTE_SCRIPT'
  apt-get update && apt-get install -y curl ca-certificates gnupg

  # Install Docker
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
  apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

  # Create data directories
  mkdir -p /opt/hermitstash/data /opt/hermitstash/uploads

  # Run HermitStash
  docker run -d --name hermitstash \
    --restart unless-stopped \
    -p 3000:3000 \
    -v /opt/hermitstash/data:/app/data \
    -v /opt/hermitstash/uploads:/app/uploads \
    --shm-size=256m \
    ghcr.io/dotcoocoo/hermitstash:1

  # Wait for health
  echo "Waiting for HermitStash to start..."
  for _ in $(seq 1 30); do
    if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
      echo "HermitStash is running inside container"
      break
    fi
    sleep 1
  done
REMOTE_SCRIPT

# ---- Port forward ----
echo "Adding proxy device for port forwarding..."
$CLI config device add "$NAME" hermitstash-web proxy \
  listen=tcp:0.0.0.0:"${PORT}" \
  connect=tcp:127.0.0.1:3000 2>/dev/null || true

CONTAINER_IP=$($CLI exec "$NAME" -- hostname -I | awk '{print $1}')
echo ""
echo "=== Done ==="
echo "HermitStash is running at:"
echo "  Container: http://${CONTAINER_IP}:3000"
echo "  Host:      http://localhost:${PORT}"
echo ""
echo "Complete the setup wizard at the URL above."
echo ""
echo "Container management:"
echo "  $CLI exec $NAME -- bash              # shell into container"
echo "  $CLI stop $NAME                      # stop container"
echo "  $CLI exec $NAME -- docker logs hermitstash  # view logs"
