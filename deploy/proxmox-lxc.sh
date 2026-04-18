#!/usr/bin/env bash
# HermitStash — Proxmox LXC deployment script
#
# Run on the Proxmox host:
#   bash proxmox-lxc.sh
#
# Creates a Debian 12 LXC container with Docker and HermitStash.
# Supports both privileged (simple) and unprivileged (secure) modes.

set -euo pipefail

# ---- Configuration (edit these) ----
CTID="${CTID:-200}"
HOSTNAME="${HOSTNAME:-hermitstash}"
STORAGE="${STORAGE:-local-lvm}"
TEMPLATE="${TEMPLATE:-local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst}"
MEMORY="${MEMORY:-1024}"
SWAP="${SWAP:-512}"
DISK="${DISK:-16}"
CORES="${CORES:-2}"
BRIDGE="${BRIDGE:-vmbr0}"
IP="${IP:-dhcp}"
PASSWORD="${PASSWORD:-changeme}"

echo "=== HermitStash LXC Installer ==="
echo ""
echo "Container ID: $CTID"
echo "Hostname:     $HOSTNAME"
echo "Memory:       ${MEMORY}MB"
echo "Disk:         ${DISK}GB"
echo "Network:      $BRIDGE ($IP)"
echo ""

# ---- Download template if missing ----
TMPL_FILE=$(echo "$TEMPLATE" | cut -d: -f2)
if [ ! -f "/var/lib/vz/$TMPL_FILE" ]; then
  echo "Downloading Debian 12 template..."
  pveam update
  pveam download local debian-12-standard_12.7-1_amd64.tar.zst
fi

# ---- Create container ----
echo "Creating LXC container $CTID..."
pct create "$CTID" "$TEMPLATE" \
  --hostname "$HOSTNAME" \
  --memory "$MEMORY" \
  --swap "$SWAP" \
  --cores "$CORES" \
  --rootfs "${STORAGE}:${DISK}" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=${IP}" \
  --password "$PASSWORD" \
  --unprivileged 1 \
  --features nesting=1,keyctl=1 \
  --ostype debian \
  --start 0

# Enable /dev/shm with 256MB for the in-memory database
echo "lxc.mount.entry: tmpfs dev/shm tmpfs defaults,size=256M 0 0" >> "/etc/pve/lxc/${CTID}.conf"

# ---- Start and configure ----
echo "Starting container..."
pct start "$CTID"
sleep 5

echo "Installing Docker and HermitStash..."
pct exec "$CTID" -- bash -c '
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
    ghcr.io/dotcoocoo/hermitstash:latest

  # Wait for health
  echo "Waiting for HermitStash to start..."
  for i in $(seq 1 30); do
    if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
      echo "HermitStash is running on port 3000"
      break
    fi
    sleep 1
  done
'

CONTAINER_IP=$(pct exec "$CTID" -- hostname -I | awk '{print $1}')
echo ""
echo "=== Done ==="
echo "HermitStash is running at: http://${CONTAINER_IP}:3000"
echo "Complete the setup wizard to configure your instance."
echo ""
echo "Container management:"
echo "  pct enter $CTID              # shell into container"
echo "  pct stop $CTID               # stop container"
echo "  docker logs hermitstash      # view logs (inside container)"
