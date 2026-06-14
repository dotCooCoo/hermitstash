#!/bin/sh
# Postgres hot-standby replica. On first boot (empty data dir) base-back-up
# from the primary with -R (writes standby.signal + primary_conninfo);
# thereafter just start and stream. Serves TLS with the same test-CA leaf as
# the primary so the framework's read-replica client verifies it against the
# CA with no rejectUnauthorized:false.

set -eu

# Certs into a postgres-owned location with the strict perms the server wants
# (same shape as the primary's init-tls.sh).
mkdir -p /var/lib/postgresql/certs
cp /certs/postgres.crt /var/lib/postgresql/certs/server.crt
cp /certs/postgres.key /var/lib/postgresql/certs/server.key
cp /certs/ca.crt       /var/lib/postgresql/certs/root.crt
chown -R postgres:postgres /var/lib/postgresql/certs
chmod 600 /var/lib/postgresql/certs/server.key
chmod 644 /var/lib/postgresql/certs/server.crt /var/lib/postgresql/certs/root.crt

PGDATA="${PGDATA:-/var/lib/postgresql/18/docker}"

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "[replica] empty data dir — waiting for primary, then base-backing up..."
  mkdir -p "$PGDATA"
  until pg_isready -h postgres -p 5432 -U blamejs >/dev/null 2>&1; do
    echo "[replica] primary not ready yet..."
    sleep 2
  done
  # Replication is trust-authed from the bridge subnet (initdb hook), so no
  # password is needed. -R writes standby.signal + primary_conninfo; -Xs
  # streams WAL during the backup so the standby is consistent on start.
  pg_basebackup -h postgres -p 5432 -U blamejs -D "$PGDATA" -Fp -Xs -R -P
  chown -R postgres:postgres "$PGDATA"
  chmod 700 "$PGDATA"
  echo "[replica] base backup complete — starting as hot standby."
fi

exec docker-entrypoint.sh postgres -c config_file=/etc/postgresql/postgresql.conf
