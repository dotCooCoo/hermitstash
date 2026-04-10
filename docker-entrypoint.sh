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

# Drop to hermit user if running as root
if [ "$(id -u)" = "0" ]; then
  exec gosu hermit node server.js
else
  exec node server.js
fi
