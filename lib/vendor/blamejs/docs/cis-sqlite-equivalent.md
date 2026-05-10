# SQLite CIS-equivalent — blamejs hardening crosswalk

CIS does NOT publish a SQLite Benchmark — SQLite is library-shaped,
embedded into the framework process rather than running as a service,
so the per-host audit/role/replication controls a Postgres benchmark
covers don't apply. Operators under HIPAA / PCI-DSS / SOC 2 / FedRAMP
still need an evidence package showing the framework's SQLite layer
meets the equivalent control intent.

This document synthesises a CIS-equivalent crosswalk from:

- **NIST SP 800-53 Rev. 5** AC / AU / CM / SC / SI control families
- **CIS PostgreSQL Benchmark v16** (the closest published baseline)
- **The framework's defaults** (which apply uniformly across SQLite
  + Postgres deployments)

For every adapted control, the framework's posture is the operator's
evidence — the framework primitive name + the audit-emission events it
produces.

## File-system & process isolation

| Control intent | NIST 800-53 | Framework posture |
| -------------- | ----------- | ----------------- |
| DB file readable only by owning process | AC-3 | `b.db.init({ atRest: "encrypted" })` writes db.enc with mode 0600 (atomicFile.writeSync). Plaintext DB lives in tmpfs (`/dev/shm/blamejs-*` on Linux) — wiped on every clean shutdown via `removePlaintextFiles`. |
| Encryption-at-rest with PQC primitives | SC-28 | Default mode = `encrypted`. XChaCha20-Poly1305 + Argon2id (RFC 9106). Operator-supplied passphrase via `BLAMEJS_VAULT_PASSPHRASE_*` env. |
| Backup encryption mandatory under regulated postures | SC-28(1) | `b.compliance.set("hipaa")` / `pci-dss` causes `b.backup.create` to refuse `encrypt: false` (F-BUDR-4). |
| Backup integrity protection | SC-12 | Manifest is signed with the audit-sign keypair (ML-DSA-87 / SLH-DSA-SHAKE-256f). `b.backupBundle.verifyManifestSignature` rejects tampered bundles. |
| Periodic backup test | CP-9(1) | `b.backup.scheduleTest({ cron, restoreTo, verify, posture })` emits `backup.test.passed` / `.failed` audit rows (HIPAA §164.308(a)(7)(ii)(D)). |

## Audit & accountability

| Control intent | NIST 800-53 | Framework posture |
| -------------- | ----------- | ----------------- |
| Append-only audit log | AU-9(2) | `audit_log` BEFORE-DELETE trigger refuses writes; chained with SHA3-512 prevHash/rowHash. Every row carries a `monotonicCounter` indexed `unique`. |
| Audit-log signed checkpoint | AU-10 | `b.audit.checkpoint` emits ML-DSA-87 / SLH-DSA-SHAKE-256f signed `audit_checkpoints` rows. The audit-tip sidecar (`<dataDir>/audit.tip`) detects rollback at boot. |
| Time-source synchronisation | AU-8(1) | `b.db.init` runs `b.ntpCheck.bootCheck` against operator-supplied NTP servers; warning / fatal thresholds via `BLAMEJS_NTP_DRIFT_*`. |
| Audit export for federated SIEM | AU-6(3) | `b.audit.export({ format: "cadf" })` emits CADF (ISO/IEC 19395) envelope mapping every audit field. |
| Tamper-evident integrity check | SI-7 | `b.db.integrityCheck` runs `PRAGMA integrity_check` on demand; `b.db.integrityMonitor({ intervalMs })` schedules periodic verification with audit emission. |

## Access control

| Control intent | NIST 800-53 | Framework posture |
| -------------- | ----------- | ----------------- |
| Per-tenant data isolation | AC-3 | `b.tenantQuota.create` / `b.tenantQuota.budget` / `b.tenantQuota.instrumentQuery` provide storage caps + query budget + crossover detection. SOC 2 CC6.1 + ISO 27001 A.8.1.5. |
| Role-context for every query | AC-6 | `b.dbRoleContext` binds an actor → audit emission row pair on every query the framework executes. |
| WORM (write-once-read-many) for regulatory tables | AU-9(1) | `b.db.declareWorm({ table })` installs SQLite trigger refusing UPDATE/DELETE; required under postures `sec-17a-4`, `finra-4511`, `fda-21cfr11`. |
| Dual-control on sensitive operations | AC-3(7) | `b.dualControl.consume` gates `b.db.eraseHard` on declared tables. |
| Step-up auth on PHI/PCI columns | IA-2(11) | `b.breakGlass` wraps column-policy / row-enforcement step-up auth (PHI / PCI columns require fresh second-factor grant + reason). |

## Configuration management

| Control intent | NIST 800-53 | Framework posture |
| -------------- | ----------- | ----------------- |
| Configuration drift detection | CM-2 | `b.configDrift` snapshots framework config + emits `config.drift.detected` events on change. |
| Schema migrations under change control | CM-3 | `b.migrations.create` installs `_blamejs_migrations` tracking; every DDL emits `db.ddl.executed` audit rows (D-M1). |
| DDL audit | AU-12 | DDL_RE-classified statements emit per-statement audit rows automatically. |
| Reflective schema metadata | CM-8 | `b.db.getTableMetadata({ format: "json-schema-2020-12" })` emits a JSON Schema 2020-12 representation of every table for inventory tooling. |

## Data export & evidence

| Control intent | NIST 800-53 | Framework posture |
| -------------- | ----------- | ----------------- |
| RFC 4180 strict CSV export | AU-7 | `b.db.exportCsv({ table, where, signWith })` — RFC 4180 strict + UTF-8 BOM optional + ISO-8601 timestamp casts + SHA3-512 manifest + ML-DSA-87 signature. |
| Subject-access export (GDPR Art. 15) | n/a | `b.subject.export(subjectId)` walks every registered subject table with auto-unseal. |
| Audit-slice export with chain proof | AU-6 | `b.auditTools.exportSlice({ from, to, action, passphrase })` — encrypted bundle + chain proof. |

## Disaster recovery

| Control intent | NIST 800-53 | Framework posture |
| -------------- | ----------- | ----------------- |
| Documented DR plan | CP-2 | `b.drRunbook.emit({ outDir, posture, services, rtoMs, rpoMs })` generates posture-appropriate Markdown runbook composing b.budr + b.cluster + b.backup. |
| Recovery-time / recovery-point objectives | CP-2(8) | DR runbook captures per-service RTO/RPO. |
| Tested backup restoration | CP-9(1) | `b.backup.scheduleTest` (above). |

## Crypto

| Control intent | NIST 800-53 | Framework posture |
| -------------- | ----------- | ----------------- |
| Approved cryptographic algorithms | SC-13 | XChaCha20-Poly1305 (RFC 8439), SHA3-512, SHAKE256, HKDF-SHA3-512, ML-KEM-1024, ML-DSA-87, SLH-DSA-SHAKE-256f, Argon2id. No AES-GCM / SHA-256 / P-256 defaults. |
| Cryptographic key protection | SC-28(1) | Vault keys sealed under operator passphrase; audit-signing key sealed under a SEPARATE passphrase. Both via Argon2id wrap. |
| Cryptographic module verification | CM-6 | The framework refuses to load older audit-sign keys without an `algorithm` field. |
| Quantum-safe defaults | SC-12 | PQC-first throughout. `b.pqcGate` rejects classical-only handshakes when the operator opts in. |

## Network

| Control intent | NIST 800-53 | Framework posture |
| -------------- | ----------- | ----------------- |
| TLS 1.3 minimum | SC-8 | `tls.DEFAULT_MIN_VERSION = "TLSv1.3"` set at index.js entry; sticky for the entire process. |
| OCSP stapling | SC-12 | `b.network.tls.ocsp` for outbound; required under HIPAA/PCI-DSS/DORA postures. |
| Certificate Transparency SCT verification | SC-12 | `b.network.tls.ct` for outbound. |
| DoH for DNS | SC-20 | `b.network.dns.doh` is the framework default for outbound DNS. |
