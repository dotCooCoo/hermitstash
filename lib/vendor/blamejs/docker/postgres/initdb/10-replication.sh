#!/bin/sh
# Primary-side initdb hook. Allows streaming replication and client
# connections from the docker bridge subnets so the standby can base-back-up
# and stream, and so integration tests reach the server over the compose
# network. Appended during initdb; the real server starts afterward and reads
# the full file (no reload needed). Test-only: the network is loopback-isolated
# (host ports bound to 127.0.0.1 / ::1), so trust is acceptable for the fixture.
cat >> "$PGDATA/pg_hba.conf" <<'EOF'

# --- blamejs test stack: replication + bridge-network access ---
host replication all 172.30.0.0/16        trust
host replication all fd00:dead:beef::/48  trust
host all         all 172.30.0.0/16        trust
host all         all fd00:dead:beef::/48  trust
EOF
