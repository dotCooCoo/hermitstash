#!/bin/sh
# docker-entrypoint.sh — fix volume ownership, remap UID/GID, drop to hermit

# ── PUID / PGID remapping ──────────────────────────────────────────
# Default 99:100 (Unraid nobody:users). Override for Linux: PUID=1000 PGID=1000
if [ "$(id -u)" = "0" ]; then
  PUID="${PUID:-99}"
  PGID="${PGID:-100}"
  CUR_UID="$(id -u hermit)"
  CUR_GID="$(id -g hermit)"

  if [ "$PGID" != "$CUR_GID" ]; then
    groupmod -o -g "$PGID" hermit
  fi
  if [ "$PUID" != "$CUR_UID" ]; then
    usermod -o -u "$PUID" hermit
  fi
fi

# ── Timezone ───────────────────────────────────────────────────────
# Set container timezone from TZ env var (e.g. TZ=America/New_York).
# Warn loudly on invalid values — silent fallback to UTC was a footgun
# for operators who typo'd a zone name and didn't notice their backups
# were running at the wrong time.
if [ -n "$TZ" ]; then
  if [ -f "/usr/share/zoneinfo/$TZ" ]; then
    ln -sf "/usr/share/zoneinfo/$TZ" /etc/localtime
    echo "$TZ" > /etc/timezone
  else
    echo ""
    echo "  WARNING: TZ='$TZ' is not a valid IANA timezone name."
    echo "  Container will use UTC. Valid examples: America/New_York, Europe/London, Asia/Tokyo."
    echo ""
  fi
fi

# ── UMASK ──────────────────────────────────────────────────────────
# Set default file permission mask (e.g. UMASK=002 → 775/664)
if [ -n "$UMASK" ]; then
  umask "$UMASK"
fi

# ── Volume permissions ─────────────────────────────────────────────
# Docker/Coolify volumes mount as root — fix ownership at runtime.
# NOTE: chmod MUST come before chown. Our runtime cap set is
# CHOWN + SETUID + SETGID + DAC_OVERRIDE (no FOWNER), which means root
# CAN chown a file it owns but CAN'T chmod a file it no longer owns.
# If we chowned first, the subsequent chmod on the now-hermit-owned
# dir would fail with "Operation not permitted".
for dir in /app/data /app/uploads /app/public/img/custom; do
  if [ -d "$dir" ] && [ "$(id -u)" = "0" ]; then
    chmod 700 "$dir"
    chown -R hermit:hermit "$dir"
  fi
done

# ── /dev/shm size check ───────────────────────────────────────────
# Default Docker shm is 64MB — the app needs at least 128MB for safe operation
if [ -d "/dev/shm" ] && [ "${HERMITSTASH_TMPDIR:-/dev/shm}" = "/dev/shm" ]; then
  SHM_KB=$(df /dev/shm 2>/dev/null | awk 'NR==2 {print $2}')
  if [ -n "$SHM_KB" ] && [ "$SHM_KB" -lt 131072 ] 2>/dev/null; then
    echo ""
    echo "  WARNING: /dev/shm is only $((SHM_KB / 1024))MB."
    echo "  HermitStash needs at least 128MB for the in-memory database."
    echo "  Add --shm-size=256m to your docker run command, or"
    echo "  shm_size: 256m in your docker-compose.yml."
    echo ""
  fi
fi

# ── Tailscale sidecar (fully opt-in, boot-time install) ────────────
# NOTHING about Tailscale is baked into the image. Only when TAILSCALE_ENABLED=true
# does the container install tailscaled + tailscale at boot (via apk — Wolfi apk
# packages are signature-verified against the Wolfi signing key, so no unverified
# binary is fetched) and bring the node up in userspace-networking mode (no
# /dev/net/tun, no NET_ADMIN — fits cap_drop: ALL). If it is never enabled, none
# of this runs and nothing is installed. Every step is non-fatal: a failure logs
# and the app still starts, just without the tailnet front.
#
# Requires root at entry (apk + tailscaled). The hardened compose runs
# `user: 1000:1000`, which starts non-root — so a Tailscale-enabled deployment must
# start as root and let this entrypoint drop to hermit (via su-exec below) AFTER
# the sidecar is up. When enabled-but-non-root we warn and skip rather than fail.
if [ "$TAILSCALE_ENABLED" = "true" ]; then
  if [ "$(id -u)" != "0" ]; then
    echo "[tailscale] WARNING: TAILSCALE_ENABLED=true but the container is not running as root."
    echo "[tailscale] The sidecar needs root to install + start tailscaled. Remove 'user: 1000:1000'"
    echo "[tailscale] (the entrypoint still drops to the hermit user for the app). Skipping Tailscale."
  else
    if ! command -v tailscaled >/dev/null 2>&1; then
      echo "[tailscale] installing sidecar via apk (signature-verified Wolfi package)…"
      if ! apk add --no-cache tailscale >/dev/null 2>&1; then
        echo "[tailscale] ERROR: install failed — starting the app WITHOUT Tailscale."
        TAILSCALE_ENABLED="skip"
      fi
    fi
  fi
fi

if [ "$TAILSCALE_ENABLED" = "true" ] && command -v tailscaled >/dev/null 2>&1; then
  TS_SOCKET="${TAILSCALE_SOCKET:-/run/tailscale/tailscaled.sock}"
  TS_STATE="${TAILSCALE_STATE_DIR:-/app/data/tailscale}"
  mkdir -p "$(dirname "$TS_SOCKET")" "$TS_STATE" 2>/dev/null || true
  echo "[tailscale] starting tailscaled (userspace networking)…"
  tailscaled \
    --tun=userspace-networking \
    --socket="$TS_SOCKET" \
    --statedir="$TS_STATE" &
  # Wait (≤6s) for the control socket before configuring.
  ts_i=0
  while [ ! -S "$TS_SOCKET" ] && [ "$ts_i" -lt 30 ]; do sleep 0.2; ts_i=$((ts_i + 1)); done
  if [ -S "$TS_SOCKET" ]; then
    if [ -n "$TAILSCALE_AUTHKEY" ]; then
      # Ephemeral, tagged node. Extra flags via TAILSCALE_UP_ARGS (e.g. exit-node).
      # shellcheck disable=SC2086
      tailscale --socket="$TS_SOCKET" up \
        --authkey="$TAILSCALE_AUTHKEY" \
        --hostname="${TAILSCALE_HOSTNAME:-hermitstash}" \
        --advertise-tags="${TAILSCALE_TAGS:-tag:hermitstash}" \
        ${TAILSCALE_UP_ARGS:-} || echo "[tailscale] WARNING: 'tailscale up' failed"
    else
      echo "[tailscale] WARNING: TAILSCALE_AUTHKEY not set — the node cannot authenticate."
    fi
    # Front the app over the tailnet. serve = tailnet-only (injects the identity
    # headers HermitStash's Sign-in-with-Tailscale reads); funnel = public internet
    # (NO identity — visitors fall back to the other sign-in methods). The app binds
    # loopback, so only this in-container proxy can present identity. The serve CLI
    # surface varies by tailscale version — override the whole invocation with
    # TAILSCALE_SERVE_ARGS if the default doesn't match your version.
    TS_APP_PORT="${PORT:-3000}"
    ts_target="http://127.0.0.1:${TS_APP_PORT}"
    case "${TAILSCALE_SERVE_MODE:-serve}" in
      serve)
        # shellcheck disable=SC2086
        tailscale --socket="$TS_SOCKET" serve ${TAILSCALE_SERVE_ARGS:---bg $ts_target} \
          || echo "[tailscale] WARNING: 'tailscale serve' failed — configure it manually or set TAILSCALE_SERVE_ARGS."
        ;;
      funnel)
        # shellcheck disable=SC2086
        tailscale --socket="$TS_SOCKET" funnel ${TAILSCALE_SERVE_ARGS:---bg $ts_target} \
          || echo "[tailscale] WARNING: 'tailscale funnel' failed — configure it manually or set TAILSCALE_SERVE_ARGS."
        ;;
      off)
        echo "[tailscale] serve mode 'off' — node is up, no proxy configured (bind the app to the tailnet yourself)."
        ;;
      *)
        echo "[tailscale] WARNING: unknown TAILSCALE_SERVE_MODE='${TAILSCALE_SERVE_MODE}' (expected serve|funnel|off)."
        ;;
    esac
  else
    echo "[tailscale] WARNING: tailscaled socket did not appear — starting the app without the tailnet front."
  fi
fi

# ── Start ──────────────────────────────────────────────────────────
# Drop to hermit user if running as root.
# su-exec (installed via apk in Dockerfile) does direct exec — node
# becomes the PID, SIGTERM reaches it natively for graceful shutdown.
# We previously used setpriv from util-linux, but wolfi's BusyBox ships
# its own setpriv applet that doesn't support --reuid/--regid and takes
# PATH priority over the real util-linux binary. su-exec is purpose-built
# for this, ~10KB, and standard in the Alpine/wolfi ecosystem.
if [ "$(id -u)" = "0" ]; then
  exec su-exec hermit:hermit node server.js
else
  exec node server.js
fi
