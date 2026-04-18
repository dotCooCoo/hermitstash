#!/bin/sh
# Ensure persistent volume directories are writable
# Docker/Coolify volumes mount as root — fix ownership at runtime
for dir in /app/data /app/uploads /app/public/img/custom; do
  if [ -d "$dir" ]; then
    # Only chown if we're root (won't fail if already running as hermit)
    if [ "$(id -u)" = "0" ]; then
      chown -R hermit:hermit "$dir"
      chmod 700 "$dir"
    fi
  fi
done

# Warn if /dev/shm is too small for the decrypted database
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

# Drop to hermit user if running as root
if [ "$(id -u)" = "0" ]; then
  exec gosu hermit node server.js
else
  exec node server.js
fi
