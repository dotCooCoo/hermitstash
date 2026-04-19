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
# Docker/Coolify volumes mount as root — fix ownership at runtime
for dir in /app/data /app/uploads /app/public/img/custom; do
  if [ -d "$dir" ] && [ "$(id -u)" = "0" ]; then
    chown -R hermit:hermit "$dir"
    chmod 700 "$dir"
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

# ── Start ──────────────────────────────────────────────────────────
# Drop to hermit user if running as root.
# setpriv (util-linux, pre-installed) does direct exec — node becomes the PID,
# SIGTERM reaches it natively for graceful shutdown.
if [ "$(id -u)" = "0" ]; then
  exec setpriv --reuid=hermit --regid=hermit --init-groups -- node server.js
else
  exec node server.js
fi
