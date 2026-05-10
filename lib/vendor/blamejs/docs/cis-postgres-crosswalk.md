# CIS Postgres Benchmark — blamejs cross-walk

This document maps **CIS PostgreSQL Benchmarks (v14 / v15 / v16)** to the
framework primitives that satisfy each control. Operators wire the
result into compliance evidence packages alongside the framework's
audit chain.

The crosswalk lists **the framework's posture** (how the primitive
default discharges the control out of the box), **operator action**
(what the operator must additionally configure on the Postgres host),
and **citation** (the CIS section number).

## 1. Installation and Patches

| CIS § | Control | Framework posture | Operator action |
| ----- | ------- | ----------------- | --------------- |
| 1.1 | Ensure packages are obtained from authorized repositories | n/a | OS-layer; track upstream PostgreSQL security advisories. |
| 1.2 | Ensure systemd Service Files Are Enabled | n/a | OS-layer; `systemctl enable postgresql` outside the framework. |
| 1.3 | Ensure Data Cluster Initialized Successfully | n/a | Operator-managed `initdb`. |

## 2. Directory and File Permissions

| CIS § | Control | Framework posture | Operator action |
| ----- | ------- | ----------------- | --------------- |
| 2.1 | Ensure the file permissions mask is correct | n/a | OS-layer; data dir 0700. |
| 2.2 | Ensure the PostgreSQL pg_wheel group membership is correct | n/a | OS-layer. |

## 3. Logging Monitoring and Auditing

| CIS § | Control | Framework posture | Operator action |
| ----- | ------- | ----------------- | --------------- |
| 3.1.2 | Ensure the log destinations are set correctly | `b.audit.safeEmit` writes every framework-emitted event into the audit chain | Forward Postgres CSV logs to the same SIEM the framework's audit chain ships to. |
| 3.1.3 | Ensure the logging collector is enabled | n/a | `logging_collector = on` in `postgresql.conf`. |
| 3.1.4-22 | log_destination / log_filename / log_rotation_* / log_min_messages / log_connections / log_disconnections / log_error_verbosity / log_statement / log_timezone | n/a (framework reads via b.externalDb pool) | Operator-supplied `postgresql.conf`. The framework's `b.compliance.set("hipaa")` posture emits a `compliance.posture.tz_warning` when `process.env.TZ` isn't UTC — mirror at the Postgres layer with `log_timezone = 'UTC'`. |
| 3.2 | Ensure the PostgreSQL Audit Extension (pgaudit) Is Enabled | Composes — framework audit chain captures every write the framework emits; pgaudit captures the Postgres-level statements the framework doesn't see. | Install + enable `pgaudit` extension; configure `pgaudit.log = 'all'`. |

## 4. User Access and Authorization

| CIS § | Control | Framework posture | Operator action |
| ----- | ------- | ----------------- | --------------- |
| 4.1 | Ensure sudo Is Configured Correctly | n/a | OS-layer. |
| 4.2 | Ensure Excessive Administrative Privileges Are Revoked | `b.db.declareRowPolicy` emits ROW LEVEL SECURITY migrations | Operator runs the migration; principle-of-least-privilege at the role level. |
| 4.3 | Ensure Excessive Function Privileges Are Revoked | n/a | `REVOKE EXECUTE ON FUNCTION ...` per role. |
| 4.4 | Ensure Excessive DML Privileges Are Revoked from PUBLIC | `b.db.declareView` + `declareRowPolicy` emit GRANT/REVOKE migrations | Run the framework migration; the framework refuses to write directly under PUBLIC roles. |
| 4.5 | Ensure Row Level Security (RLS) Is Configured Correctly | `b.db.declareRowPolicy` is the framework's RLS primitive | Use it for every multi-tenant table. |
| 4.6 | Ensure the set_user Extension Is Installed | n/a | Operator-installed extension. |

## 5. Connection and Login

| CIS § | Control | Framework posture | Operator action |
| ----- | ------- | ----------------- | --------------- |
| 5.1 | Ensure login via "local" UNIX domain socket Is Configured Correctly | n/a | `pg_hba.conf` — `local all all peer`. |
| 5.2 | Ensure login via "host" TCP/IP Socket Is Configured Correctly | Framework defaults to `TLSv1.3` minimum on every TLS socket via `tls.DEFAULT_MIN_VERSION` set at index.js entry | `pg_hba.conf` — `hostssl ... cert clientcert=verify-full`; framework sets the floor, operator pins the role. |
| 5.3 | Ensure Passwords are Stored in Encrypted Format | `b.auth.password` uses Argon2id (RFC 9106) | Postgres-side: `password_encryption = 'scram-sha-256'`. |
| 5.4 | Ensure max_connections Is Set Correctly | `b.externalDb` connection-pool config | `max_connections` matches pool size + headroom. |

## 6. PostgreSQL Settings

| CIS § | Control | Framework posture | Operator action |
| ----- | ------- | ----------------- | --------------- |
| 6.1 | Understanding attack vectors and runtime parameters | n/a | Operator-managed. |
| 6.2 | Ensure 'backend' runtime parameters are configured correctly | `b.externalDb` pool sets `application_name` per connection | `statement_timeout = 60000`, `idle_in_transaction_session_timeout = 60000`. |
| 6.7 | Ensure FIPS 140-2 OpenSSL Cryptography is Used | Framework uses Node's nodeCrypto bound to OpenSSL on Linux | Operator builds Postgres against FIPS-validated OpenSSL. |
| 6.8 | Ensure SSL Is Configured Correctly | TLS 1.3 framework-wide; `b.network.tls.ocsp` + `b.network.tls.ct` for outbound | `ssl = on`, `ssl_min_protocol_version = 'TLSv1.3'`. |
| 6.9 | Ensure pgcrypto Is Installed | Framework uses XChaCha20-Poly1305 + SHA3-512 + ML-KEM-1024 in-process | Operator installs pgcrypto only if needed for column-level Postgres-side crypto. |

## 7. Replication

| CIS § | Control | Framework posture | Operator action |
| ----- | ------- | ----------------- | --------------- |
| 7.1 | Ensure a replication-only user is created | `b.cluster.create({ externalDbBackend })` uses operator-supplied pool — framework doesn't create roles itself | Create `replication_user` role; framework's cluster module reads under that role. |
| 7.2 | Ensure logical replication is configured | `b.outbox.create({ envelope: "debezium" })` provides change-event emission compatible with logical-replication consumers | Enable `wal_level = logical`. |
| 7.3 | Ensure base backups are configured and functional | `b.backup.scheduleTest({ cron, restoreTo, verify, posture })` runs periodic restore-and-verify drills (HIPAA §164.308(a)(7)(ii)(D)) | Wire `pg_basebackup` for the Postgres-layer side. |
| 7.4 | Ensure WAL archiving is configured and functional | n/a | `archive_mode = on`, `archive_command = '...'`. |
| 7.5 | Ensure streaming replication parameters are configured correctly | n/a | `max_wal_senders`, `wal_keep_size`. |

## 8. Special Configuration Considerations

| CIS § | Control | Framework posture | Operator action |
| ----- | ------- | ----------------- | --------------- |
| 8.1 | Ensure PostgreSQL subdirectory locations are outside the data cluster | n/a | Operator-managed paths. |
| 8.2 | Ensure the backup and restore tool, 'pgBackRest', is installed and configured | `b.backup` + `b.restoreBundle` provide framework-level encrypted bundles with ML-DSA-87 signed manifest (`b.backupBundle.verifyManifestSignature`) | Operators with petabyte-scale data combine pgBackRest with framework backup for layer-2 belt-and-suspenders. |
| 8.3 | Ensure miscellaneous configuration settings are correct | n/a | Operator-managed. |

## Framework primitives that close the gap

- **`b.tenantQuota.create`** — per-tenant DB storage caps (CIS 4.5
  composes; ISO 27001 A.8.1.5)
- **`b.tenantQuota.budget`** — per-tenant query budget
- **`b.tenantQuota.instrumentQuery`** — emits `db.tenant.crossover`
  on RLS-bypass
- **`b.db.exportCsv`** — RFC 4180 strict export with SHA3-512 manifest
  + ML-DSA-87 signature
- **`b.db.getTableMetadata({ format: "json-schema-2020-12" })`** — JSON
  Schema 2020-12 representation of every table (sealed/derived
  annotations preserved)
- **`b.audit.export({ format: "cadf" })`** — CADF (ISO/IEC 19395:2017)
  envelope export for federated SIEM
- **`b.drRunbook.emit({ posture: "hipaa", ... })`** — disaster-recovery
  runbook generator composing b.budr + b.cluster + b.backup
- **`b.backupBundle.verifyManifestSignature`** — ML-DSA-87 signature
  verification on restore
