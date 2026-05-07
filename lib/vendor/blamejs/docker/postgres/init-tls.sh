#!/bin/sh
# Postgres pre-start hook — runs on EVERY container start (via the
# entrypoint override in docker-compose.test.yml), not just initdb.
# Copies certs from the read-only mount into a postgres-user-owned
# location with the strict 0600 perms the server demands.

set -eu

mkdir -p /var/lib/postgresql/certs
cp /certs/postgres.crt /var/lib/postgresql/certs/server.crt
cp /certs/postgres.key /var/lib/postgresql/certs/server.key
cp /certs/ca.crt       /var/lib/postgresql/certs/root.crt
chown -R postgres:postgres /var/lib/postgresql/certs
chmod 600 /var/lib/postgresql/certs/server.key
chmod 644 /var/lib/postgresql/certs/server.crt /var/lib/postgresql/certs/root.crt

echo "[postgres-init-tls] certs ready at /var/lib/postgresql/certs/"
