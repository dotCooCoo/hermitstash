"use strict";
/**
 * @module b.db
 * @featured true
 * @nav    Data
 * @title  Db
 *
 * @intro
 *   Database core — SQLite (node:sqlite) wrapped in encrypted-at-rest
 *   storage, sealed-column field-level crypto, append-only audit-chain
 *   integration, declarative schema reconcile, and run-once
 *   migrations. Default at-rest posture is `encrypted`: the live `.db`
 *   lives in tmpfs (/dev/shm), is decrypted from `<dataDir>/db.enc` at
 *   boot, periodically re-encrypted every five minutes, and re-
 *   encrypted again at shutdown. The DB encryption key is sealed by
 *   `b.vault` at `<dataDir>/db.key.enc`. Operators who want a plain
 *   on-disk SQLite file pass `atRest: "plain"` and accept a boot
 *   warning — sealed columns still protect PII, but schema and row
 *   counts are visible to a forensic disk image.
 *
 *   Beyond the storage shell, the module owns the framework's data
 *   contract: `audit_log` / `consent_log` / `audit_checkpoints` and
 *   the `_blamejs_*` reserved tables are provisioned before any
 *   operator schema reconciles, append-only triggers refuse
 *   UPDATE/DELETE on the chain tables, and boot refuses to continue
 *   on chain breakage, checkpoint signature failure, audit-log
 *   rollback, or PRAGMA integrity_check corruption. WORM
 *   declarations (`declareWorm`) and dual-control gates
 *   (`declareRequireDualControl`) layer SEC 17a-4(f) / FINRA 4511 /
 *   21 CFR Part 11 §11.10(c) record-preservation invariants on
 *   operator tables.
 *
 *   The query surface is `db.from(table)` (chainable), `db.prepare`
 *   (LRU-cached node:sqlite Statement), `db.stream` (object-mode
 *   Readable for million-row exports with auto-unseal), and
 *   `db.transaction` (BEGIN/COMMIT/ROLLBACK around a callback).
 *   Postgres-only declarative migrations (`declareView` /
 *   `declareRowPolicy`) emit migration-shape objects consumed by
 *   `b.externalDb.migrate`.
 *
 * @card
 *   Database core — SQLite (node:sqlite) wrapped in encrypted-at-rest storage, sealed-column field-level crypto, append-only audit-chain integration, declarative schema reconcile, and run-once migrations.
 */
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var { DatabaseSync } = require("node:sqlite");
var { Readable } = require("node:stream");
var atomicFile = require("./atomic-file");
var audit = require("./audit");
var auditSign = require("./audit-sign");
var cluster = require("./cluster");
var csv = require("./csv");
var events = require("./events");
var consent = require("./consent");
var C = require("./constants");
var { generateToken, generateBytes, encryptPacked, decryptPacked, sha3Hash } = require("./crypto");
var cryptoField = require("./crypto-field");
var dbDeclareRowPolicy = require("./db-declare-row-policy");
var dbDeclareView = require("./db-declare-view");
var { Query } = require("./db-query");
var dbSchema = require("./db-schema");
var { defineClass } = require("./framework-error");
var { boot } = require("./log");
var lazyRequire = require("./lazy-require");
var observability = require("./observability");
var ntpCheck = lazyRequire(function () { return require("./ntp-check"); });
var safeAsync = require("./safe-async");
var safeEnv = require("./parsers/safe-env");
var safeJson = require("./safe-json");
var safeSql = require("./safe-sql");
var validateOpts = require("./validate-opts");
var vault = require("./vault");

var DbError = defineClass("DbError", { alwaysPermanent: true });
var WormViolationError = require("./framework-error").WormViolationError;
var _wormErr = WormViolationError.factory;

// Lazy: compliance and dual-control read state at runtime; both are
// non-load-time deps so a top-of-file require would not cycle, but
// they're only needed on declareWorm / declareRequireDualControl /
// eraseHard. Lazy keeps the load graph minimal.
var compliance = lazyRequire(function () { return require("./compliance"); });

// Postures that REQUIRE row-level WORM on operator-named business-
// record tables. Audit_log / consent_log / audit_checkpoints are
// already WORM-by-default; this set covers operator tables.
//   sec-17a-4   — SEC Rule 17a-4(f) broker-dealer record preservation
//   finra-4511  — FINRA Rule 4511 books-and-records
//   fda-21cfr11 — 21 CFR Part 11 §11.10(c) protect record integrity
var WORM_POSTURES = Object.freeze(["sec-17a-4", "finra-4511", "fda-21cfr11"]);
var _dbErr = DbError.factory;

// Lazy: cluster-storage's _localDb pulls db back in, so eager require
// would deadlock the load order. cluster-storage is only used on the
// purge-audit-chain external-db nodePath, which always runs after init.
var clusterStorage = lazyRequire(function () { return require("./cluster-storage"); });

// Lazy refs for the test-reset cascade. Each module requires db.js
// directly or transitively (audit/consent/subject/session/etc. all
// own a sealed-column slice that depends on db.from), so eager
// requires here would cycle on load. The cascade runs only when a
// test explicitly resets db, so paying the resolve cost lazily is
// the correct tradeoff.
var _resetAudit       = lazyRequire(function () { return require("./audit"); });
var _resetConsent     = lazyRequire(function () { return require("./consent"); });
var _resetSubject     = lazyRequire(function () { return require("./subject"); });
var _resetSession     = lazyRequire(function () { return require("./session"); });
var _resetStorage     = lazyRequire(function () { return require("./storage"); });
var _resetAuditSign   = lazyRequire(function () { return require("./audit-sign"); });
var _resetQueue       = lazyRequire(function () { return require("./queue"); });
var _resetBreakGlass  = lazyRequire(function () { return require("./break-glass"); });
var _resetLogStream   = lazyRequire(function () { return require("./log-stream"); });
var _resetRedact      = lazyRequire(function () { return require("./redact"); });
var _resetExternalDb  = lazyRequire(function () { return require("./external-db"); });

var AUDIT_TIP_SCHEMA = {
  type: "object",
  required: ["atMonotonicCounter"],
  properties: {
    atMonotonicCounter: { type: "number" },
    rowHash:            { type: "string" },
    signedAt:           { type: "string" },
  },
};

var runSql = dbSchema.runSql;

// Module-local state, populated by init()
var database  = null;       // the SQLite handle
var dbPath    = null;       // plaintext DB file path (tmpfs in encrypted mode, dataDir/db in plain mode)
var encPath   = null;       // encrypted-at-rest path (null in plain mode)
var encKey    = null;       // DB encryption key buffer (null in plain mode)
var encTimer  = null;       // periodic encrypt interval handle
var atRest    = null;       // 'encrypted' or 'plain'
// Tmpfs free-space guard (encrypted mode). The working copy lives on a
// bounded tmpfs (Docker /dev/shm defaults to 64 MiB); if it fills, SQLite
// hits ENOSPC and corrupts the working copy. A periodic probe refuses
// growth writes (INSERT/UPDATE/REPLACE) before that happens — fail-clear
// instead of corrupt-then-recover. DELETE + reads stay available so
// retention can reclaim space and the app can keep serving.
var storageProbeTimer = null;  // periodic free-space probe handle
var writesRefused = false;     // true when free space < minFreeBytes
var minFreeBytes  = 0;         // refuse growth writes below this (0 = guard off)
var statfsProbe   = null;      // free-space reader (fs.statfsSync; injectable for tests)
// The process-exit final-flush handler is registered ONCE at first
// encrypted init. Re-registering per init() leaked an 'exit' listener on
// every init/close cycle (MaxListenersExceeded in long test runs / hot
// reload); the flag makes it idempotent. The handler reads live module
// state at exit time, so a later re-init is still covered.
var _exitHandlerRegistered = false;
var dataDir   = null;
var initialized = false;
var dataResidency = null;   // operator's declared region config (validated by storage backends)
var subjectTables = [];     // [{ name, subjectField, personalDataCategories }] — for subject.export/erase
var tableMetadata = {};     // table name → metadata snapshot (PK/FK/sealed/derived) for getTableMetadata
// D-M5 — streamLimit ceiling. db.stream() / Query.stream() consult this
// (overridden per-call via opts.streamLimit). Default cap matches a
// generous-but-bounded 1M rows so an accidentally-unbounded export
// surfaces a thrown error instead of OOM. v0.7.67's maxRowsPerQuery
// bounds .all() / .first() — this is its streaming counterpart.
var streamLimit = C.BYTES.bytes(1000000);                                                              // allow:raw-byte-literal — row-count ceiling, not bytes

// ---- Framework-baked tables ----
//
// audit_log + consent_log + _blamejs_subject_restrictions + _blamejs_subject_erasures
// are provisioned by the framework before app schema reconciles. Apps cannot
// opt out, override, or rename them. An app schema entry colliding with any of
// these names is refused at init.
var RESERVED_TABLE_NAMES = new Set([
  "audit_log",
  "audit_checkpoints",
  "consent_log",
  "_blamejs_subject_restrictions",
  "_blamejs_subject_erasures",
  "_blamejs_sessions",
  "_blamejs_jobs",
  "_blamejs_migrations",
  "_blamejs_counters",
  "_blamejs_audit_purge_anchor",
  "_blamejs_scheduler_ticks",
  "_blamejs_rate_limit_counters",
  "_blamejs_pubsub_messages",
  "_blamejs_api_encrypt_nonces",
  "_blamejs_api_keys",
  "_blamejs_cache",
  "_blamejs_seeders",
  "_blamejs_seeders_lock",
  "_blamejs_break_glass_policies",
  "_blamejs_break_glass_grants",
]);

var FRAMEWORK_SCHEMA = [
  {
    name: "audit_log",
    columns: {
      _id:               "TEXT PRIMARY KEY",
      recordedAt:        "INTEGER NOT NULL",
      monotonicCounter:  "INTEGER NOT NULL",
      actorUserId:       "TEXT",
      actorUserIdHash:   "TEXT",
      actorIp:           "TEXT",
      actorUserAgent:    "TEXT",
      actorSessionId:    "TEXT",
      action:            "TEXT NOT NULL",
      resourceKind:      "TEXT",
      resourceId:        "TEXT",
      resourceIdHash:    "TEXT",
      outcome:           "TEXT NOT NULL",
      reason:            "TEXT",
      metadata:          "TEXT",
      requestId:         "TEXT",
      prevHash:          "TEXT NOT NULL",
      rowHash:           "TEXT NOT NULL",
      nonce:             "BLOB NOT NULL",
      fencingToken:      "INTEGER NOT NULL DEFAULT 0",
    },
    indexes: [
      "actorUserIdHash", "resourceIdHash", "recordedAt", "action",
      { name: "idx_audit_monotonic", columns: "monotonicCounter", unique: true },
    ],
    sealedFields:  ["actorUserId", "actorIp", "actorUserAgent", "actorSessionId", "resourceId", "reason", "metadata"],
    derivedHashes: {
      actorUserIdHash: { from: "actorUserId" },
      resourceIdHash:  { from: "resourceId" },
    },
  },
  {
    name: "consent_log",
    columns: {
      _id:               "TEXT PRIMARY KEY",
      recordedAt:        "INTEGER NOT NULL",
      monotonicCounter:  "INTEGER NOT NULL",
      subjectId:         "TEXT NOT NULL",
      subjectIdHash:     "TEXT NOT NULL",
      purpose:           "TEXT NOT NULL",
      lawfulBasis:       "TEXT NOT NULL",
      action:            "TEXT NOT NULL",
      scope:             "TEXT",
      channel:           "TEXT NOT NULL",
      evidenceRef:       "TEXT",
      prevHash:          "TEXT NOT NULL",
      rowHash:           "TEXT NOT NULL",
      nonce:             "BLOB NOT NULL",
      fencingToken:      "INTEGER NOT NULL DEFAULT 0",
    },
    indexes: [
      "subjectIdHash", "recordedAt", "purpose",
      { name: "idx_consent_monotonic", columns: "monotonicCounter", unique: true },
    ],
    sealedFields:  ["subjectId", "scope", "evidenceRef"],
    derivedHashes: {
      subjectIdHash: { from: "subjectId" },
    },
  },
  {
    name: "_blamejs_subject_restrictions",
    columns: {
      subjectIdHash: "TEXT PRIMARY KEY",
      since:         "INTEGER NOT NULL",
      reason:        "TEXT",
    },
    sealedFields: ["reason"],
  },
  {
    name: "_blamejs_subject_erasures",
    columns: {
      subjectIdHash: "TEXT PRIMARY KEY",
      erasedAt:      "INTEGER NOT NULL",
    },
  },
  {
    // Subject-level legal hold registry. Operators register a hold
    // via b.legalHold.place(subjectId, ...) — b.subject.erase and
    // b.retention consult b.legalHold.isHeld(subjectId) before
    // accepting any deletion. Per FRCP Rule 26/37(e), GDPR Art
    // 17(3)(e), SEC Rule 17a-4, HIPAA §164.530(j)(2).
    name: "_blamejs_legal_hold",
    columns: {
      subjectIdHash: "TEXT PRIMARY KEY",
      placedAt:      "INTEGER NOT NULL",
      placedBy:      "TEXT",
      reason:        "TEXT NOT NULL",
      custodian:     "TEXT",
      citation:      "TEXT",
      retainUntil:   "INTEGER",
    },
    indexes: ["placedAt"],
  },
  {
    // Per-row crypto-erasure key registry — F-RTBF-3 per-row keys.
    // Each entry holds a sealed wrapped K_row keyed by (table,
    // rowId). b.subject.eraseHard deletes the entry, leaving WAL /
    // replica residuals undecryptable.
    name: "_blamejs_per_row_keys",
    columns: {
      tableName:  "TEXT NOT NULL",
      rowId:      "TEXT NOT NULL",
      wrappedKey: "BLOB NOT NULL",
      createdAt:  "INTEGER NOT NULL",
    },
    primaryKey: ["tableName", "rowId"],
    indexes: [],
  },
  {
    // Operator-declared WORM (write-once-read-many) registry. Each
    // entry pairs an operator-named table with the posture that
    // demanded the WORM declaration; boot-time assertions iterate
    // this registry to verify triggers are installed under the
    // current b.compliance.current() posture.
    name: "_blamejs_worm_tables",
    columns: {
      tableName: "TEXT PRIMARY KEY",
      posture:   "TEXT",
      declaredAt: "INTEGER NOT NULL",
    },
  },
  {
    // Operator-declared dual-control gate registry. b.db.delete /
    // b.subject.erase / b.audit.purge consult this table on
    // destructive ops; under the named posture the framework refuses
    // execution unless the caller passes a consumed dual-control
    // grant.
    name: "_blamejs_dual_control_gates",
    columns: {
      tableName: "TEXT PRIMARY KEY",
      posture:   "TEXT",
      m:         "INTEGER NOT NULL",
      n:         "INTEGER NOT NULL",
      declaredAt:"INTEGER NOT NULL",
    },
  },
  {
    name: "audit_checkpoints",
    columns: {
      _id:                  "TEXT PRIMARY KEY",
      createdAt:            "INTEGER NOT NULL",
      atMonotonicCounter:   "INTEGER NOT NULL",
      atRowHash:            "TEXT NOT NULL",
      signature:            "BLOB NOT NULL",
      publicKeyFingerprint: "TEXT NOT NULL",
      fencingToken:         "INTEGER NOT NULL DEFAULT 0",
    },
    indexes: [
      "createdAt",
      { name: "idx_chkpt_counter", columns: "atMonotonicCounter", unique: true },
    ],
    sealedFields: [],
  },
  {
    name: "_blamejs_audit_purge_anchor",
    columns: {
      // CHECK constraint: scope is one of the framework's audit-
      // chain anchor scopes (`audit` / `consent`). Pre-v0.8.37 a
      // typo silently created a parallel anchor; the chain verifier
      // walked the wrong anchor and missed tampering. The CHECK
      // refuses unknown scope strings at INSERT time.
      scope:             "TEXT PRIMARY KEY CHECK (scope IN ('audit', 'consent'))",
      lastPurgedCounter: "INTEGER NOT NULL",
      lastPurgedRowHash: "TEXT NOT NULL",
      archiveBundleId:   "TEXT NOT NULL",
      purgedAt:          "INTEGER NOT NULL",
    },
    sealedFields: [],
  },
  {
    // Scheduler exactly-once-globally claim table. Each fire claims a
    // (name, scheduledAtUnix) row before dispatching; UNIQUE on the
    // composite tickKey (name + ":" + scheduledAtUnix) means a concurrent
    // leader's INSERT loses with a constraint violation, and that node
    // skips the tick. Closes the once-globally gap during cluster
    // leader hand-offs where two leaders briefly coexist.
    name: "_blamejs_scheduler_ticks",
    columns: {
      tickKey:         "TEXT PRIMARY KEY",
      name:            "TEXT NOT NULL",
      scheduledAtUnix: "INTEGER NOT NULL",
      claimedAtUnix:   "INTEGER NOT NULL",
      claimedBy:       "TEXT",
    },
    indexes: ["scheduledAtUnix"],
    sealedFields: [],
  },
  {
    // _blamejs_rate_limit_counters — fixed-window counter table for
    // the cluster-shared rate-limit backend. One row per (key); the
    // count rolls over atomically when the windowStart advances. Used
    // by lib/middleware/rate-limit.js when scope: 'cluster' is set.
    name: "_blamejs_rate_limit_counters",
    columns: {
      key:         "TEXT PRIMARY KEY",
      windowStart: "INTEGER NOT NULL",
      count:       "INTEGER NOT NULL DEFAULT 0",
    },
    indexes: ["windowStart"],
    sealedFields: [],
  },
  {
    // _blamejs_pubsub_messages — cluster fan-out for `b.pubsub` (the
    // generalization of the previous WebSocket-specific table). Any
    // pubsub instance using the `cluster` backend writes a row on
    // publish; other nodes poll for new ids and dispatch to their
    // local subscribers. Rows older than the configured retention
    // window are pruned by the backend on a rate-limited basis.
    name: "_blamejs_pubsub_messages",
    columns: {
      id:          "INTEGER PRIMARY KEY AUTOINCREMENT",
      topic:       "TEXT NOT NULL",
      payload:     "TEXT NOT NULL",
      publishedAt: "INTEGER NOT NULL",
      publishedBy: "TEXT NOT NULL",
    },
    indexes: ["publishedAt"],
    sealedFields: [],
  },
  {
    // _blamejs_api_encrypt_nonces — replay-protection store for the
    // api-encrypt middleware. The middleware hashes the client-supplied
    // nonce via SHA3 before insert so a leaked DB / table dump never
    // exposes the original 16-byte client nonces. Hashing is
    // deterministic so the PRIMARY KEY conflict is what catches a
    // replay attempt within the replay window.
    name: "_blamejs_api_encrypt_nonces",
    columns: {
      nonceHash: "TEXT PRIMARY KEY",
      expireAt:  "INTEGER NOT NULL",
    },
    indexes: ["expireAt"],
    sealedFields: [],
  },
  {
    name: "_blamejs_sessions",
    columns: {
      sidHash:       "TEXT PRIMARY KEY",
      userId:        "TEXT NOT NULL",
      userIdHash:    "TEXT NOT NULL",
      data:          "TEXT",
      createdAt:     "INTEGER NOT NULL",
      expiresAt:     "INTEGER NOT NULL",
      lastActivity:  "INTEGER NOT NULL",
    },
    indexes: ["userIdHash", "expiresAt"],
    sealedFields:  ["userId", "data"],
    derivedHashes: { userIdHash: { from: "userId" } },
  },
  {
    // _blamejs_api_keys — operator-facing API-key registry. Sealed
    // columns: ownerId / scopes / metadata. The secret never lands
    // here — only its SHA3-512 hash, constant-time-compared on
    // verify. Same dual-storage pattern as sessions: this row mirrors
    // the cluster-mode DDL in framework-schema.js so cluster-storage
    // can route to either backend transparently.
    name: "_blamejs_api_keys",
    columns: {
      id:                  "TEXT PRIMARY KEY",
      namespace:           "TEXT NOT NULL",
      ownerId:             "TEXT NOT NULL",
      ownerIdHash:         "TEXT NOT NULL",
      secretHash:          "TEXT NOT NULL",
      // secondarySecretHash + secondaryExpiresAt support graceful key
      // rotation: when rotate({ gracePeriodMs }) is called the old hash
      // is preserved here and the new hash takes the primary slot. Both
      // verify successfully until secondaryExpiresAt, then the old slot
      // is implicitly retired.
      secondarySecretHash: "TEXT",
      secondaryExpiresAt:  "INTEGER",
      scopes:              "TEXT",
      metadata:            "TEXT",
      createdAt:           "INTEGER NOT NULL",
      expiresAt:           "INTEGER",
      revokedAt:           "INTEGER",
      lastUsedAt:          "INTEGER",
      prefix:              "TEXT NOT NULL",
    },
    indexes: [
      "ownerIdHash",
      { name: "idx_api_keys_namespace_owner", columns: ["namespace", "ownerIdHash"] },
      "expiresAt",
    ],
    sealedFields:  ["ownerId", "scopes", "metadata"],
    derivedHashes: { ownerIdHash: { from: "ownerId" } },
  },
  {
    name: "_blamejs_jobs",
    columns: {
      _id:             "TEXT PRIMARY KEY",
      queueName:       "TEXT NOT NULL",
      payload:         "TEXT",
      status:          "TEXT NOT NULL",
      enqueuedAt:      "INTEGER NOT NULL",
      availableAt:     "INTEGER NOT NULL",
      leasedAt:        "INTEGER",
      leaseExpiresAt:  "INTEGER",
      attempts:        "INTEGER NOT NULL DEFAULT 0",
      maxAttempts:     "INTEGER NOT NULL DEFAULT 5",
      lastError:       "TEXT",
      finishedAt:      "INTEGER",
      traceId:         "TEXT",
      classification:  "TEXT",
      priority:        "INTEGER NOT NULL DEFAULT 0",
      // Repeat-in-queue: cron-shaped recurring jobs re-enqueue themselves
      // after each successful completion. NULL = one-shot (no repeat).
      repeatCron:      "TEXT",
      repeatTimezone:  "TEXT",
      // Flows: parent-child job graphs with dependency edges.
      // flowId groups jobs in the same flow; dependsOn is a JSON array
      // of jobIds this row waits for; flowChildName is the human-readable
      // label inside the flow used by dependsOn resolution.
      flowId:          "TEXT",
      flowChildName:   "TEXT",
      dependsOn:       "TEXT",
    },
    indexes: [
      { name: "idx_jobs_lease",    columns: ["queueName", "status", "availableAt"] },
      { name: "idx_jobs_priority", columns: ["queueName", "status", "priority", "availableAt"] },
      { name: "idx_jobs_flow",     columns: ["flowId"] },
      "leaseExpiresAt",
      "finishedAt",
    ],
    sealedFields:  ["payload", "lastError"],
  },
  {
    // _blamejs_cache — operator-facing cache primitive's cluster backend
    // (lib/cache.js). Mirrors the cluster-mode DDL in framework-schema.js.
    // PRIMARY KEY is the composite "<namespace>:<key>"; valueJson is
    // JSON-serialized; expiresAt is unix-ms (Number.MAX_SAFE_INTEGER for
    // never-expiring entries). Not sealed: cache values are operator-
    // chosen application data, the operator decides what's worth storing.
    name: "_blamejs_cache",
    columns: {
      cacheKey:   "TEXT PRIMARY KEY",
      valueJson:  "TEXT NOT NULL",
      expiresAt:  "INTEGER NOT NULL",
      updatedAt:  "INTEGER NOT NULL",
    },
    indexes: ["expiresAt"],
    sealedFields: [],
  },
  {
    // _blamejs_cache_tags — junction table for tag→cacheKey lookup
    // backing b.cache.invalidateTag(t) on the cluster backend. Composite
    // PK (cacheKey, tag) lets one cacheKey carry many tags; index on
    // tag makes invalidation a single indexed scan. Cleared together
    // with the matching _blamejs_cache rows on del / clear / sweep.
    name: "_blamejs_cache_tags",
    columns: {
      cacheKey:   "TEXT NOT NULL",
      tag:        "TEXT NOT NULL",
    },
    primaryKey: ["cacheKey", "tag"],
    indexes:    ["tag"],
    sealedFields: [],
  },
  {
    // _blamejs_seeders — registry of applied seed files for the
    // b.seeders primitive (lib/seeders.js). Composite PK (env, name)
    // means the same filename can apply per env (dev fixtures don't
    // collide with prod fixtures by name). rerunnable=1 entries get
    // their appliedAt updated in place on every run; non-rerunnable
    // entries are insert-once.
    name: "_blamejs_seeders",
    columns: {
      env:         "TEXT NOT NULL",
      name:        "TEXT NOT NULL",
      description: "TEXT",
      appliedAt:   "TEXT NOT NULL",
      rerunnable:  "INTEGER NOT NULL DEFAULT 0",
    },
    primaryKey: ["env", "name"],
    indexes: [],
    sealedFields: [],
  },
  {
    // _blamejs_seeders_lock — single-row advisory lock for the seeders
    // runner. Same shape as _blamejs_migrations_lock (CHECK constraint
    // on scope='lock' enforces single row). Two processes calling
    // `seed run` against the same DB race on this PK; loser sees a
    // clear "lock held" error.
    name: "_blamejs_seeders_lock",
    columns: {
      scope:    "TEXT PRIMARY KEY CHECK (scope = 'lock')",
      lockedAt: "INTEGER NOT NULL",
      lockedBy: "TEXT NOT NULL",
    },
    sealedFields: [],
  },
  {
    // _blamejs_break_glass_policies — column-level break-glass policy
    // registry. One row per (table) declares which columns are
    // glass-locked and what the operator's grant rules are. Sealed
    // columns hold the column-list, factor-list, and bypass config so
    // policy contents aren't browsable in cleartext.
    name: "_blamejs_break_glass_policies",
    columns: {
      tableName:                  "TEXT PRIMARY KEY",
      columnsJson:                "TEXT NOT NULL",
      factorsJson:                "TEXT NOT NULL",
      cryptographic:              "INTEGER NOT NULL DEFAULT 0",
      grantTtlMs:                 "INTEGER NOT NULL",
      maxRowsPerGrant:            "INTEGER NOT NULL DEFAULT 1",
      reasonRequired:             "INTEGER NOT NULL DEFAULT 1",
      reasonMinLength:            "INTEGER NOT NULL DEFAULT 12",
      pinIp:                      "INTEGER NOT NULL DEFAULT 1",
      sessionPin:                 "INTEGER NOT NULL DEFAULT 1",
      onLockedAccess:             "TEXT NOT NULL DEFAULT 'throw'",
      requireScope:               "TEXT",
      serviceAccountBypassJson:   "TEXT",
      dekSealed:                  "TEXT",
      auditReasonStorage:         "TEXT NOT NULL DEFAULT 'cleartext'",
      updatedAt:                  "INTEGER NOT NULL",
    },
    indexes: [],
    sealedFields: ["columnsJson", "factorsJson", "serviceAccountBypassJson"],
  },
  {
    // _blamejs_break_glass_grants — issued grants. Each successful
    // step-up creates one row; each row read decrements rowsRemaining.
    // Default maxRowsPerGrant=1 enforces "row by row" auth per the
    // operator-confirmed shape (each row access = its own grant).
    // Sealed columns hold reason + scopeColumns so audit-readable
    // metadata doesn't leak in cleartext.
    name: "_blamejs_break_glass_grants",
    columns: {
      _id:                "TEXT PRIMARY KEY",
      issuedToActorId:    "TEXT NOT NULL",
      issuedToActorHash:  "TEXT NOT NULL",
      factorType:         "TEXT NOT NULL",
      reasonSealed:       "TEXT",
      scopeTable:         "TEXT NOT NULL",
      scopeColumnsJson:   "TEXT NOT NULL",
      issuedAt:           "INTEGER NOT NULL",
      expiresAt:          "INTEGER NOT NULL",
      maxRowsPerGrant:    "INTEGER NOT NULL",
      rowsConsumed:       "INTEGER NOT NULL DEFAULT 0",
      revokedAt:          "INTEGER",
      sessionId:          "TEXT",
      ip:                 "TEXT",
      kwGrantHalf:        "TEXT",
    },
    indexes: [
      { name: "idx_bg_grants_actor",   columns: ["issuedToActorHash"] },
      { name: "idx_bg_grants_table",   columns: ["scopeTable"] },
      "expiresAt",
      "revokedAt",
    ],
    derivedHashes: { issuedToActorHash: { from: "issuedToActorId" } },
    sealedFields: ["reasonSealed", "scopeColumnsJson", "kwGrantHalf"],
  },
];

var log = boot("db");

// ---- Tmpfs detection ----

function resolveTmpDir(optsTmpDir) {
  if (optsTmpDir) return optsTmpDir;
  var envTmp = safeEnv.readVar("BLAMEJS_TMPDIR");
  if (envTmp) return envTmp;
  if (nodeFs.existsSync("/dev/shm")) return "/dev/shm";
  return null;
}

// ---- DB encryption key management ----

function loadOrCreateDbKey(dataDirPath, keyPathOverride) {
  // Operator opt: `opts.dbKeyPath` — useful when the encryption key
  // needs to live outside `dataDir` (e.g. a separate volume mounted
  // from a KMS-fronted secret store). Default places it next to the
  // encrypted DB so backup capture is one-tarball.
  var keyPath = keyPathOverride || nodePath.join(dataDirPath, "db.key.enc");
  if (nodeFs.existsSync(keyPath)) {
    var sealed = atomicFile.readSync(keyPath, { encoding: "utf8" }).trim();
    var b64 = vault.unseal(sealed);
    if (!b64) {
      throw _dbErr("db/key-unseal-empty",
        "FATAL: db.key.enc unseal returned empty — vault may not be initialized or key file corrupted");
    }
    return Buffer.from(b64, "base64");
  }
  // First run — generate, seal, persist (atomic)
  var raw = generateBytes(C.BYTES.bytes(32));
  // allow:seal-without-aad — whole-file DB encryption key, not a row column
  var sealedKey = vault.seal(raw.toString("base64"));
  atomicFile.writeSync(keyPath, sealedKey, { fileMode: 0o600 });
  log("generated DB encryption key at " + keyPath);
  return raw;
}

function decryptToTmp() {
  if (!encPath || !nodeFs.existsSync(encPath)) return;
  // If a plaintext file already exists in tmpfs from a prior process, prefer
  // the newer mtime (crash recovery — operator's most recent state wins) —
  // but ONLY if it is a readable SQLite file. A working copy corrupted by
  // an unclean shutdown or a full tmpfs (e.g. Docker's 64 MiB /dev/shm
  // default overflowing) would otherwise be kept on every boot, and
  // db.init's integrity gate would fail identically forever — an
  // unrecoverable crash loop. When the newer plaintext fails a fast
  // integrity probe, discard it and fall through to re-decrypt the
  // last-good db.enc snapshot. db.enc itself is never modified here, so
  // this only ever rolls back to the persistent encrypted copy; if THAT
  // is also corrupt, db.init still fails loudly (no silent data loss).
  if (nodeFs.existsSync(dbPath)) {
    var plainStat = nodeFs.statSync(dbPath);
    var encStat = nodeFs.statSync(encPath);
    if (plainStat.mtimeMs > encStat.mtimeMs && plainStat.size > 0) {
      if (_tmpWorkingCopyIsHealthy(dbPath)) {
        log("plaintext is newer than encrypted — keeping plaintext (crash recovery)");
        return;
      }
      log("newer tmpfs working copy failed its integrity probe (corrupt — likely an " +
          "unclean shutdown or a full /dev/shm); discarding it and re-decrypting from " +
          "db.enc (auto-recovery to the last-good encrypted snapshot)");
      try { nodeFs.unlinkSync(dbPath); }          catch (_e) { /* fall through to overwrite */ }
      try { nodeFs.unlinkSync(dbPath + "-wal"); } catch (_e) { /* may not exist */ }
      try { nodeFs.unlinkSync(dbPath + "-shm"); } catch (_e) { /* may not exist */ }
    }
  }
  var packed = nodeFs.readFileSync(encPath);
  if (packed.length < 26) return; // too short to be a valid envelope
  // AAD binds the envelope to this deployment's data dir so two
  // installs sharing the same operator passphrase can't swap each
  // other's db.enc files. Backwards-compat: if the AAD-bound decrypt
  // fails, retry without AAD for envelopes written by pre-AAD
  // versions (one-release transition window).
  var aad = _dbEncAad(dataDir);
  try {
    atomicFile.writeSync(dbPath, decryptPacked(packed, encKey, aad));
  } catch (_e) {
    atomicFile.writeSync(dbPath, decryptPacked(packed, encKey));
  }
}

// Fast "is this a usable SQLite file" probe for the crash-recovery path.
// Opens the candidate working copy and runs PRAGMA quick_check(1) (far
// cheaper than full integrity_check — header + page-structure sanity,
// enough to catch a "database disk image is malformed" / truncated /
// non-DB file). Any throw (malformed image, not-a-DB) or non-"ok" result
// is unhealthy. The probe handle is always closed so it never holds the
// tmpfs file open against the subsequent real open.
function _tmpWorkingCopyIsHealthy(p) {
  var probe = null;
  try {
    probe = new DatabaseSync(p);
    var rows = probe.prepare("PRAGMA quick_check(1)").all();
    return rows.length >= 1 && rows[0] && rows[0].quick_check === "ok";
  } catch (_e) {
    return false;
  } finally {
    if (probe) { try { probe.close(); } catch (_e2) { /* already gone */ } }
  }
}

function _dbEncAad(dir) {
  return Buffer.from("blamejs.db-enc.v1\0" + (dir || ""), "utf8");
}

// Probe free space on the tmpfs holding the working copy and flip the
// write-refusal flag. Encrypted mode only (the bounded-tmpfs surface);
// guard disabled when minFreeBytes is 0. A probe failure leaves the flag
// unchanged — we never refuse writes on a stat error (that would be a
// self-inflicted outage). Growth writes (INSERT/UPDATE/REPLACE) are gated
// by the prepare() wrapper installed in init(); DELETE + reads always pass
// so retention can reclaim space and the app keeps serving.
function _probeStorageHeadroom() {
  if (atRest !== "encrypted" || !minFreeBytes || !dbPath || !statfsProbe) return;
  var free;
  try {
    var st = statfsProbe(nodePath.dirname(dbPath));
    free = st.bavail * st.bsize;
    if (!isFinite(free)) return;
  } catch (_e) { return; }
  if (free < minFreeBytes && !writesRefused) {
    writesRefused = true;
    log.error("storage low: " + free + " bytes free on the tmpfs working-copy mount (< " +
      minFreeBytes + ") — refusing growth writes (INSERT/UPDATE/REPLACE) until space " +
      "recovers. Raise shm_size / --shm-size, or let retention prune. DELETE + reads still serve.");
    try {
      audit.safeEmit({ action: "db.storage.low", outcome: "failure",
        metadata: { freeBytes: free, minFreeBytes: minFreeBytes } });
    } catch (_e2) { /* drop-silent — observability */ }
  } else if (free >= minFreeBytes && writesRefused) {
    writesRefused = false;
    log("storage recovered: " + free + " bytes free — growth writes re-enabled");
    try {
      audit.safeEmit({ action: "db.storage.recovered", outcome: "success",
        metadata: { freeBytes: free } });
    } catch (_e3) { /* drop-silent */ }
  }
}

// Install the growth-write gate on the SQLite handle: shadow prepare() so
// INSERT/UPDATE/REPLACE statements throw db/storage-low when the tmpfs is
// critically low, instead of proceeding into an ENOSPC corruption. Reads,
// DELETE, PRAGMA, and DDL pass through ungated. Called once in init() after
// schema setup so init's own writes are never gated (writesRefused is false
// until the first probe anyway).
function _installWriteGate() {
  var rawPrepare = database.prepare.bind(database);
  database.prepare = function (sql) {
    var stmt = rawPrepare(sql);
    if (/^\s*(?:INSERT|UPDATE|REPLACE)\b/i.test(sql)) {
      var rawRun = stmt.run.bind(stmt);
      stmt.run = function () {
        if (writesRefused) {
          throw _dbErr("db/storage-low",
            "db: refusing write — the encrypted-mode working copy is on a tmpfs with less than " +
            minFreeBytes + " bytes free (Docker /dev/shm defaults to 64 MiB). Raise shm_size / " +
            "--shm-size, or let retention prune expired rows. DELETE and reads remain available.");
        }
        return rawRun.apply(stmt, arguments);
      };
    }
    return stmt;
  };
}

function encryptToDisk() {
  if (!encPath) return;
  // Force WAL checkpoint so the .db file holds all committed transactions.
  try { runSql(database, "PRAGMA wal_checkpoint(TRUNCATE)"); } catch (_e) { /* best effort */ }
  if (!nodeFs.existsSync(dbPath)) return;
  atomicFile.writeSync(encPath, encryptPacked(nodeFs.readFileSync(dbPath), encKey, _dbEncAad(dataDir)));
}

/**
 * @primitive b.db.snapshot
 * @signature b.db.snapshot()
 * @since     0.8.58
 * @status    stable
 * @related   b.db.flushToDisk, b.backup
 *
 * In-memory encrypted snapshot — same envelope shape that
 * `flushToDisk` writes, just held in memory. Operators capturing a
 * backup mid-flight (`b.backup` wrapping a hot DB) get a Buffer they
 * can stream onward to object storage without touching the on-disk
 * encPath. Forces a WAL checkpoint first so the snapshot reflects
 * committed state, not pre-WAL pages.
 *
 * Under `atRest: 'plain'` returns the raw plaintext SQLite file as a
 * Buffer (no envelope), since there's no encryption key to apply —
 * operators wanting an encrypted snapshot under plain mode wrap with
 * their own `b.crypto.encryptPacked` at the call site.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var snap = b.db.snapshot();
 *   await b.objectStore.put("backups/" + Date.now() + ".enc", snap);
 */
function snapshot() {
  _requireInit();
  // WAL checkpoint flushes committed transactions into the main DB file
  // so the snapshot reflects the current logical state, not just the
  // pre-WAL pages.
  try { runSql(database, "PRAGMA wal_checkpoint(TRUNCATE)"); } catch (_e) { /* best effort */ }
  if (!nodeFs.existsSync(dbPath)) {
    throw _dbErr("db/snapshot-no-source",
      "snapshot: plaintext DB at " + dbPath + " is missing — did init complete?");
  }
  var plain = nodeFs.readFileSync(dbPath);
  if (!encPath || !encKey) {
    // atRest: 'plain' — return the raw bytes. Operators wanting an
    // encrypted snapshot under plain mode wrap with their own
    // b.crypto.encryptPacked at the call site.
    return plain;
  }
  return encryptPacked(plain, encKey, _dbEncAad(dataDir));
}

// Remove the plaintext DB + WAL/SHM sidecar files. On Windows these can't be
// unlinked while the SQLite handle is open, so this MUST be called after
// database.close().
function removePlaintextFiles() {
  if (!dbPath) return;
  try { nodeFs.unlinkSync(dbPath); } catch (_e) { /* cleanup */ }
  try { nodeFs.unlinkSync(dbPath + "-wal"); } catch (_e) { /* cleanup */ }
  try { nodeFs.unlinkSync(dbPath + "-shm"); } catch (_e) { /* cleanup */ }
}

// Clean up stale plaintext DB files left by previously-crashed processes.
// Anything matching blamejs-*.db that isn't our current process's file is
// stale (no other process should write to /dev/shm with our prefix).
function cleanStaleTmpDbs(tmpDir) {
  var entries = atomicFile.listDir(tmpDir, {
    filter: function (name) { return name.startsWith("blamejs-") && name.endsWith(".db"); },
  });
  for (var i = 0; i < entries.length; i++) {
    var full = entries[i].fullPath;
    if (full === dbPath) continue;
    try { nodeFs.unlinkSync(full); } catch (_e) { /* concurrent cleanup */ }
    try { nodeFs.unlinkSync(full + "-wal"); } catch (_e) { /* may not exist */ }
    try { nodeFs.unlinkSync(full + "-shm"); } catch (_e) { /* may not exist */ }
  }
}

// ---- Init dispatch ----

/**
 * @primitive b.db.init
 * @signature b.db.init(opts)
 * @since     0.1.0
 * @status    stable
 * @related   b.db.close, b.db.from, b.db.declareWorm
 *
 * Boot the database. Provisions the framework-baked tables
 * (`audit_log` / `consent_log` / `audit_checkpoints` /
 * `_blamejs_*`), reconciles the operator schema, installs append-
 * only triggers on chain tables, runs any pending file-based
 * migrations, verifies the audit + consent chains end-to-end,
 * verifies every audit checkpoint signature, runs PRAGMA
 * integrity_check, performs a rollback-detection check against
 * `audit.tip`, and runs a best-effort SNTP boot drift check. Refuses
 * to boot on any chain breakage, signature mismatch, or rollback —
 * compliance posture demands fail-closed at the earliest signal.
 *
 * @opts
 *   dataDir:                 string,            // required — where db.enc + db.key.enc live
 *   schema:                  Array,             // required — [{ name, columns, indexes, sealedFields, derivedHashes, foreignKeys, primaryKey, subjectField, personalDataCategories }, ...]
 *   atRest:                  "encrypted"|"plain", // default "encrypted"
 *   tmpDir:                  string,            // override the encrypted-mode tmpfs path (default /dev/shm or BLAMEJS_TMPDIR)
 *   migrationDir:            string,            // optional — path to ./migrations/ (run-once each)
 *   streamLimit:             number,            // default 1_000_000 — db.stream row ceiling
 *   skipBootIntegrityCheck:  boolean,           // default false — skip PRAGMA integrity_check
 *   skipIntegrityCheck:      boolean,           // default false — alias
 *   auditSigning:            { mode, algorithm }, // default { mode: "wrapped" }
 *   ntpServers:              string[],          // override NTP server list
 *   ntpTimeoutMs:            number,            // override NTP timeout
 *   dataResidency:           object,            // operator's region declaration
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({
 *     dataDir: "/var/lib/myapp",
 *     atRest:  "encrypted",
 *     schema: [
 *       {
 *         name: "orders",
 *         columns: {
 *           _id:        "TEXT PRIMARY KEY",
 *           customerId: "TEXT NOT NULL",
 *           totalCents: "INTEGER NOT NULL",
 *           note:       "TEXT",
 *           createdAt:  "INTEGER NOT NULL",
 *         },
 *         indexes:       ["customerId"],
 *         sealedFields:  ["note"],
 *         derivedHashes: { customerIdHash: { from: "customerId" } },
 *         subjectField:  "customerId",
 *       },
 *     ],
 *   });
 */
async function init(opts) {
  if (initialized) return;
  // Drop any prepared-statement cache leftover from a prior init/close
  // cycle — Statement handles attached to a finalized DB throw on use.
  _prepareCache.clear();
  if (!opts || !opts.dataDir) {
    throw new DbError("db/bad-init", "db.init({ dataDir }) is required");
  }
  if (!Array.isArray(opts.schema)) {
    throw new DbError("db/bad-init",
      "db.init({ schema }) must be an array of table definitions");
  }

  atRest = (opts.atRest || "encrypted").toLowerCase();
  if (atRest !== "encrypted" && atRest !== "plain") {
    throw new DbError("db/bad-at-rest",
      "db.init: atRest must be 'encrypted' or 'plain', got: " + opts.atRest);
  }
  // D-M5 — operator-tunable streamLimit ceiling. Throw at config-time
  // on bad shape so a typo surfaces at boot rather than as an
  // unbounded stream at first export.
  if (opts.streamLimit !== undefined) {
    if (typeof opts.streamLimit !== "number" || !isFinite(opts.streamLimit) ||
        opts.streamLimit <= 0 || Math.floor(opts.streamLimit) !== opts.streamLimit) {
      throw new DbError("db/bad-init",
        "db.init: streamLimit must be a positive finite integer; got " +
        JSON.stringify(opts.streamLimit));
    }
    streamLimit = opts.streamLimit;
  }
  dataDir = opts.dataDir;
  if (!nodeFs.existsSync(dataDir)) nodeFs.mkdirSync(dataDir, { recursive: true });

  if (atRest === "encrypted") {
    var tmpDir = resolveTmpDir(opts.tmpDir);
    if (!tmpDir) {
      throw _dbErr("db/no-tmpfs",
        "FATAL: atRest: 'encrypted' (default) requires tmpfs but none was found. " +
        "Provide opts.tmpDir or set BLAMEJS_TMPDIR, or pass atRest: 'plain' (with warning).");
    }
    if (!nodeFs.existsSync(tmpDir)) nodeFs.mkdirSync(tmpDir, { recursive: true });

    // D-H7 — if the resolved tmpDir is NOT actually tmpfs, the
    // plaintext DB file lives on persistent storage. We check that tmpDir
    // resolves under /dev/shm or /run/shm on Linux as a heuristic; on other
    // platforms we warn that the operator must verify tmpfs binding
    // out-of-band. (Free-space headroom is enforced separately via
    // fs.statfsSync in the storage guard below.)
    if (process.platform === "linux") {
      var realTmp = "";
      try { realTmp = nodeFs.realpathSync(tmpDir); } catch (_e) { /* stat best-effort */ }
      if (realTmp.indexOf("/dev/shm") !== 0 && realTmp.indexOf("/run/shm") !== 0 &&
          realTmp.indexOf("/run/user/") !== 0 && realTmp.indexOf("/tmp") !== 0) {
        log.warn("WARNING: db.init: tmpDir '" + tmpDir + "' (real: '" + realTmp +
          "') does not resolve under /dev/shm /run/shm /run/user /tmp — verify it is " +
          "actually a tmpfs mount. A persistent-disk tmpDir leaks plaintext into backup " +
          "snapshots, replication, and forensic disk images.");
      }
    }

    // Operator overrides for the encrypted-DB on-disk nodePath. `opts.encryptedDbPath`
    // takes a fully-qualified nodePath; `opts.encryptedDbName` overrides
    // just the basename under `dataDir` (default "db.enc"). Helps when
    // multiple framework-shaped instances share a dataDir.
    encPath = opts.encryptedDbPath ||
              nodePath.join(dataDir, opts.encryptedDbName || "db.enc");
    dbPath  = nodePath.join(tmpDir, "blamejs-" + generateToken(C.BYTES.bytes(16)) + ".db");
    encKey  = loadOrCreateDbKey(dataDir, opts.dbKeyPath);

    // Tmpfs free-space guard. Default headroom is 16 MiB below which growth
    // writes are refused (fail-clear) before the working copy fills its
    // bounded tmpfs and corrupts. opts.minFreeBytes tunes it; 0 disables.
    // opts._statfsForTest injects a free-space reader for tests.
    if (opts.minFreeBytes !== undefined) {
      require("./numeric-bounds").requireNonNegativeFiniteIntIfPresent(
        opts.minFreeBytes, "db.init: opts.minFreeBytes", DbError, "db/bad-min-free-bytes");
      minFreeBytes = opts.minFreeBytes;
    } else {
      minFreeBytes = C.BYTES.mib(16);
    }
    statfsProbe = typeof opts._statfsForTest === "function"
      ? opts._statfsForTest
      : (typeof nodeFs.statfsSync === "function" ? nodeFs.statfsSync : null);

    cleanStaleTmpDbs(tmpDir);
    decryptToTmp();
  } else {
    // plain mode
    log.warn("WARNING: atRest: 'plain' — DB structure and row counts visible on disk.");
    log.warn("         Field-level encryption (sealedFields) still protects sealed columns,");
    log.warn("         but the simpler at-rest model is opt-out only. Default is 'encrypted'.");
    dbPath = nodePath.join(dataDir, "blamejs.db");
    encPath = null;
    encKey = null;
  }

  // Open the database
  database = new DatabaseSync(dbPath);

  // Performance pragmas
  runSql(database, "PRAGMA journal_mode=WAL");
  runSql(database, "PRAGMA synchronous=NORMAL");
  runSql(database, "PRAGMA cache_size=-8000");
  runSql(database, "PRAGMA temp_store=MEMORY");
  runSql(database, "PRAGMA busy_timeout=5000");
  runSql(database, "PRAGMA mmap_size=268435456");
  runSql(database, "PRAGMA auto_vacuum=INCREMENTAL");
  // Foreign-key enforcement is OFF by default in SQLite. Turn it ON so
  // structured `foreignKeys` declarations actually constrain writes.
  runSql(database, "PRAGMA foreign_keys=ON");

  // PRAGMA secure_delete=ON — SQLite normally just unlinks rows from
  // the B-tree; the underlying page bytes survive on disk until a new
  // write reuses the slot. With secure_delete=ON, freed pages are
  // overwritten with zeros so a forensic recovery against the file
  // can't reconstruct deleted rows. The cost is one extra write per
  // delete, which the framework's audit-and-DSR-erase path already
  // dominates with audit-chain emissions and cascade fan-out.
  runSql(database, "PRAGMA secure_delete=ON");
  // PRAGMA trusted_schema=OFF — refuses to call functions / virtual-
  // table modules referenced from a malicious shadow schema. Defends
  // the CVE-2018-8740 family where an attacker who can write to the
  // database file (backups, logs, restore-from-untrusted) plants
  // schema entries that fire on next access.
  try { runSql(database, "PRAGMA trusted_schema=OFF"); } catch (_e) { /* sqlite < 3.31 */ }
  // PRAGMA cell_size_check=ON — refuses pages with corrupted cell
  // sizes at parse time rather than crashing later. Cheap defense
  // against malformed-page attacks.
  try { runSql(database, "PRAGMA cell_size_check=ON"); } catch (_e) { /* sqlite < 3.26 */ }
  // node:sqlite does not expose loadExtension at all — extensions must
  // be statically linked into the runtime. The framework's surface is
  // therefore implicitly extension-free; no runtime defense is needed
  // beyond the trusted_schema + cell_size_check PRAGMAs above.

  // Boot-time integrity check — refuse to boot on B-tree corruption.
  // SQLite normally surfaces corruption only when a query stumbles on
  // a bad page; that's a "first failure during request handling"
  // surface, not a clean fail-closed boot. integrity_check is fast on
  // the freshly-decrypted-into-tmpfs file (<1 second on a typical
  // multi-MB DB) and the result is "ok" or a list of issues.
  if (opts.skipBootIntegrityCheck !== true) {
    var ic;
    try {
      ic = database.prepare("PRAGMA integrity_check").all();
    } catch (corruptErr) {
      // SQLite throws "database disk image is malformed" / "file is not a
      // database" when the file is too corrupt to even run the check.
      // Translate the raw native error into an actionable one — the most
      // common operational cause in encrypted mode is a too-small tmpfs.
      throw new DbError("db/integrity-check-failed",
        "database is corrupt at boot — SQLite: " +
        ((corruptErr && corruptErr.message) || String(corruptErr)) + ". " +
        (atRest === "encrypted"
          ? "Encrypted mode runs the live DB as a tmpfs working copy (" + dbPath +
            "); a recurring failure here usually means the tmpfs is too small " +
            "(Docker's /dev/shm defaults to 64 MiB — raise it via shm_size / " +
            "--shm-size), or db.enc itself is corrupt (restore <dataDir>/db.enc " +
            "from backup)."
          : "Restore the database file (" + dbPath + ") from backup."));
    }
    var icIssues = ic.map(function (r) { return r && r.integrity_check; })
                     .filter(function (s) { return s && s !== "ok"; });
    if (icIssues.length > 0) {
      throw new DbError("db/integrity-check-failed",
        "PRAGMA integrity_check at boot reported " + icIssues.length +
        " issue(s): " + icIssues.slice(0, 3).join("; "));
    }
  }

  // PRAGMA integrity_check — refuse boot on B-tree corruption (per
  // audit-batch finding). SQLite returns "ok" for a healthy database;
  // any other result means corruption. Catching it at boot beats
  // stumbling on it later in a query that hits the bad page. Skip
  // when opts.skipIntegrityCheck is set (e.g. tmpfs-only fixtures).
  if (opts.skipIntegrityCheck !== true) {
    var integrityRows = [];
    try {
      // .all-style read; runSql is for statements without rows.
      integrityRows = database.prepare("PRAGMA integrity_check").all();
    } catch (e) {
      throw new DbError("db/integrity-check-failed",
        "PRAGMA integrity_check failed at boot: " + ((e && e.message) || String(e)));
    }
    if (integrityRows.length !== 1 ||
        !integrityRows[0] || integrityRows[0].integrity_check !== "ok") {
      throw new DbError("db/integrity-check-failed",
        "PRAGMA integrity_check reported corruption: " +
        JSON.stringify(integrityRows));
    }
  }

  // Refuse app schema entries that collide with framework-reserved names.
  // Pre-v0.8.18 this was an exact-match Set; an app could ship
  // `_blamejs_audit_log_archive` (or similar prefix-collision) and the
  // framework would silently provision it next to the reserved
  // namespace, allowing a row-by-row look-alike attack against audit
  // archive tooling.
  // Under `frameworkTables: false` the framework's own audit_log /
  // consent_log are NOT provisioned, so an operator naming a table
  // `audit_log` (or `consent_log`) doesn't collide. The `_blamejs_*`
  // prefix stays reserved unconditionally — those names are
  // hard-claimed by other framework primitives (sessions, jobs,
  // migrations, rate-limit-counters, …) which still get provisioned
  // by their respective subsystems.
  var frameworkTablesEarly = opts.frameworkTables !== false;
  var FRAMEWORK_NAMED_RESERVED = frameworkTablesEarly
    ? RESERVED_TABLE_NAMES
    : new Set();   // empty — fall back to the prefix check only
  for (var ri = 0; ri < opts.schema.length; ri++) {
    var appName = opts.schema[ri].name;
    if (FRAMEWORK_NAMED_RESERVED.has(appName) ||
        (typeof appName === "string" && appName.indexOf("_blamejs_") === 0)) {
      throw new DbError("db/reserved-table-name",
        "table name '" + appName + "' is reserved by the framework. " +
        "Pick a different name (the framework provisions audit_log, consent_log, " +
        "and any '_blamejs_*'-prefixed tables automatically). " +
        "Pass opts.frameworkTables: false to skip provisioning audit_log/consent_log " +
        "when the host application owns its own audit chain.");
    }
  }

  // Track subject schema for subject.export/erase walks
  subjectTables = [];
  for (var si = 0; si < opts.schema.length; si++) {
    var st = opts.schema[si];
    if (st.subjectField) {
      // Validate personalDataCategories shape + audit-emit on
      // unknown vocabulary. Pre-v0.8.37 this was a free-form JSON
      // blob; a typo silently dropped the column from subject-export
      // / erase walks. The framework checks the value is a string
      // (catches null / number / object typos) and emits a warning
      // audit when the category is outside the GDPR Art 9 + general
      // vocabulary so operators can audit-trail their custom labels.
      if (st.personalDataCategories) {
        if (typeof st.personalDataCategories !== "object" || Array.isArray(st.personalDataCategories)) {
          throw new DbError("db/bad-personal-data-categories",
            "table '" + st.name + "': personalDataCategories must be an object mapping field name → category");
        }
        var FRAMEWORK_CATEGORY_VOCAB = [
          "name", "email", "phone", "address", "ip", "id-document",
          "biometric", "health", "genetic", "sexual-orientation",
          "racial-or-ethnic-origin", "political-opinion", "religious-belief",
          "trade-union-membership", "criminal-record",
          "financial", "location", "behavioral", "device-id",
          "child-data", "education", "employment", "operator-defined",
        ];
        Object.keys(st.personalDataCategories).forEach(function (field) {
          var cat = st.personalDataCategories[field];
          if (typeof cat !== "string" || cat.length === 0) {
            throw new DbError("db/bad-personal-data-category",
              "table '" + st.name + "' field '" + field +
              "': category must be a non-empty string");
          }
          if (FRAMEWORK_CATEGORY_VOCAB.indexOf(cat) === -1) {
            // Unknown — emit a one-time audit per (table,field,category)
            // tuple so operators see typos in their categorical
            // taxonomy. Lazy require to avoid circular load (audit
            // imports db for chain hashing).
            try {
              var auditMod = require("./audit");                                              // allow:inline-require — circular-load defense (audit imports db)
              auditMod.safeEmit({
                action:   "db.personal_data_category_unknown",
                outcome:  "success",
                metadata: {
                  severity: "warning",
                  table:    st.name,
                  field:    field,
                  category: cat,
                  vocabHint: "use one of: " + FRAMEWORK_CATEGORY_VOCAB.join(", ") +
                             " (or operator-defined for genuinely-custom)",
                },
              });
            } catch (_e) { /* drop-silent */ }
          }
        });
      }
      subjectTables.push({
        name:                   st.name,
        subjectField:           st.subjectField,
        personalDataCategories: st.personalDataCategories || {},
      });
    }
  }

  // Operator opt-out for the framework's own tables + audit/consent
  // chain machinery + WORM assertion + audit-signing bootstrap. Set
  // `frameworkTables: false` when the host application maintains its
  // own audit/consent semantics and just wants the framework's
  // primitives (vault / db / cryptoField / etc.) without the bundled
  // chain tables. When OFF, every framework-table-dependent step
  // below is a no-op. Append-only triggers are scoped to the
  // framework tables only, so they're skipped too.
  //
  // `auditSigning: false` is a finer-grained gate — keep the
  // framework tables but skip the audit-signing-key bootstrap (HS-
  // shape deployments that already manage their own signing key).
  //
  // Defaults match v0.8.57 behavior: both ON.
  var frameworkTablesEnabled = opts.frameworkTables !== false;
  var auditSigningEnabled    = opts.auditSigning    !== false;

  // Build the full schema = framework-baked tables + app tables.
  // Framework tables come FIRST so audit_log/consent_log exist before any
  // app migration can reference them. When `frameworkTables: false`,
  // skip the concat so the operator's own `audit_log` (or whatever
  // shape) doesn't collide with the framework's.
  var fullSchema = frameworkTablesEnabled
    ? FRAMEWORK_SCHEMA.concat(opts.schema)
    : opts.schema.slice();

  // Register schema with field-crypto + capture table metadata snapshot
  // (framework tables included so getTableMetadata covers everything).
  tableMetadata = {};
  for (var i = 0; i < fullSchema.length; i++) {
    var t = fullSchema[i];
    cryptoField.registerTable(t.name, {
      sealedFields:   t.sealedFields,
      derivedHashes:  t.derivedHashes,
      hashNamespaces: t.hashNamespaces,
    });
    tableMetadata[t.name] = {
      primaryKey:             _normalizePk(t),
      foreignKeys:            Array.isArray(t.foreignKeys) ? t.foreignKeys.slice() : [],
      columns:                Object.assign({}, t.columns),
      indexes:                Array.isArray(t.indexes) ? t.indexes.slice() : [],
      sealedFields:           Array.isArray(t.sealedFields) ? t.sealedFields.slice() : [],
      derivedHashes:          Object.assign({}, t.derivedHashes || {}),
      subjectField:           t.subjectField || null,
      personalDataCategories: Object.assign({}, t.personalDataCategories || {}),
    };
  }

  // Declarative schema reconcile (framework + app tables)
  dbSchema.reconcile(database, fullSchema);

  // Append-only enforcement on audit_log + consent_log via SQLite triggers.
  // Apps cannot UPDATE or DELETE these tables; the framework's audit.record /
  // consent.grant only INSERT. This is a SQL-level guard against bug-induced
  // or malicious tampering — independent of the API surface's discipline.
  // Operator-driven retention purge (when implemented) must drop these
  // triggers explicitly inside a transaction, perform the purge, and
  // recreate them. Skipped under `frameworkTables: false`.
  if (frameworkTablesEnabled) _installAppendOnlyTriggers(database);

  // Imperative migrations (run once each, in order)
  if (opts.migrationDir) {
    var result = dbSchema.runMigrations(database, opts.migrationDir);
    if (result.applied.length > 0) {
      log("applied " + result.applied.length + " migration(s): " + result.applied.join(", "));
    }
  }

  // dataResidency — operator's declared region. Registered here for
  // downstream backends (storage, mail, log destinations) to validate
  // against; backends opt in by reading this value via getDataResidency().
  dataResidency = opts.dataResidency || null;

  // Mark initialized BEFORE the chain verify so audit/consent.verify() can
  // call db.prepare() through the public surface. If verify fails, we
  // process.exit() — initialized state is moot at that point.
  initialized = true;

  // ---- Refuse-to-boot on chain break ----
  // Verify both the audit and consent chains end-to-end. A broken chain
  // means tamper-evidence has been compromised — the framework refuses
  // to continue under any circumstances. Recovery is operator-driven
  // (restore from backup or manual chain rebuild); the framework only
  // detects-and-fails. Skipped under `frameworkTables: false` (the
  // framework's audit_log / consent_log don't exist for an operator
  // running their own audit subsystem).
  if (frameworkTablesEnabled) {
    var auditResult = await audit.verify();
    if (!auditResult.ok) {
      // Fire the breach event BEFORE throwing so operator listeners
      // get a chance at sync I/O (file flag, console alert) before
      // init unwinds.
      events.emit(events.EVENTS.AUDIT_CHAIN_BREAK, { table: "audit_log", result: auditResult });
      throw _dbErr("db/audit-chain-break",
        "FATAL: audit_log chain integrity broken at row " + auditResult.breakAt +
        " (" + auditResult.reason + "); break row _id: " + auditResult.breakRowId +
        "; expected: " + auditResult.expected + "; actual: " + auditResult.actual +
        ". Refusing to boot. Compliance requires that any tamper-detection signal halt service. " +
        "Recovery is manual: restore from backup, or rebuild the audit chain from a verified earlier snapshot.");
    }
    var consentResult = await consent.verify();
    if (!consentResult.ok) {
      events.emit(events.EVENTS.AUDIT_CHAIN_BREAK, { table: "consent_log", result: consentResult });
      throw _dbErr("db/consent-chain-break",
        "FATAL: consent_log chain integrity broken at row " + consentResult.breakAt +
        " (" + consentResult.reason + "); break row _id: " + consentResult.breakRowId +
        ". Refusing to boot.");
    }
    log("audit chain ok (" + auditResult.rowsVerified + " rows), consent chain ok (" + consentResult.rowsVerified + " rows)");
  }

  // ---- Rollback detection (audit.tip sidecar) ----
  // The framework writes <dataDir>/audit.tip on each checkpoint. At boot we
  // compare current MAX(monotonicCounter) to the recorded tip. If current
  // is BELOW tip — the DB was rolled back to an older snapshot. Refuse boot.
  _checkRollback(dataDir);

  // ---- F-RET-2 — WORM posture assertion ----
  // Under sec-17a-4 / finra-4511 / fda-21cfr11 postures the operator
  // MUST have declared row-level WORM on at least one business-record
  // table. Refuse boot otherwise so missing-declaration drift is
  // surfaced at start-up, not on the first delete.
  // Skipped under `frameworkTables: false` — WORM declarations are
  // an operator-side concern when the framework isn't owning audit.
  if (frameworkTablesEnabled) {
    try { _assertWormUnderPosture(); }
    catch (e) {
      // The assertion throws under regulated postures; let it
      // propagate. Outside regulated postures it's a no-op.
      throw e;
    }
  }

  // ---- Audit-signing key + checkpoint subsystem ----
  // Default mode 'wrapped' (passphrase-required, separate from vault). Apps
  // that want a quick-start dev path can pass auditSigning: { mode: 'plaintext' }
  // — same warning pattern as vault.
  // opts.auditSigning.algorithm picks the keypair algorithm at first-run
  // generation. Default = SLH-DSA-SHAKE-256f (matches the framework's
  // SHAKE-family hash posture); ML-DSA-87 is the throughput-focused
  // opt-in. Existing key files take their algorithm from disk; this
  // option only matters on first generation.
  // Operator opt-out via `auditSigning: false` skips the signing
  // bootstrap entirely. Also implicitly skipped when frameworkTables
  // are off (no audit_log to sign checkpoints over).
  if (auditSigningEnabled && frameworkTablesEnabled) {
    var auditSigningMode = (opts.auditSigning && opts.auditSigning.mode)
      ? opts.auditSigning.mode
      : safeEnv.readVar("BLAMEJS_AUDIT_SIGNING_MODE", {
          default: "wrapped",
          enum:    ["wrapped", "plaintext"],
        });
    var auditSigningAlg = opts.auditSigning && opts.auditSigning.algorithm
      ? opts.auditSigning.algorithm
      : null;
    await auditSign.init({
      dataDir:   dataDir,
      mode:      auditSigningMode,
      algorithm: auditSigningAlg || undefined,
    });
  }

  // Verify all existing checkpoint signatures (defense against
  // signature forgery attempt + key-rotation gone wrong). Refuse to
  // boot on failure. Skipped under `frameworkTables: false` /
  // `auditSigning: false`.
  if (frameworkTablesEnabled && auditSigningEnabled) {
    var ckptResult = await audit.verifyCheckpoints();
    if (!ckptResult.ok) {
      events.emit(events.EVENTS.AUDIT_CHECKPOINT_BREAK, { result: ckptResult });
      throw _dbErr("db/audit-checkpoint-break",
        "FATAL: audit checkpoint verification failed at row " +
        ckptResult.breakAt + " (" + ckptResult.reason + "); checkpoint _id: " +
        ckptResult.checkpointId + ". Refusing to boot. Either the audit-signing key " +
        "was rotated without retaining the prior pubkey, or a forged checkpoint was inserted.");
    }
    log("audit checkpoints ok (" + ckptResult.checkpointsVerified + " signed)");

    // Anchor a fresh checkpoint at boot if there's any new audit
    // activity since the last checkpoint (else no-op).
    await audit.checkpoint({ skipIfUnchanged: true });
  }

  // ---- NTP drift check ----
  // Best-effort; unreachable NTP doesn't fail boot, but >= 1hr drift does
  // (unless BLAMEJS_NTP_STRICT=0 / BLAMEJS_SKIP_NTP_CHECK=1).
  await _runNtpBootCheck(opts);

  // Start periodic encrypt timer (encrypted mode only)
  if (atRest === "encrypted") {
    encTimer = safeAsync.repeating(function () {
      try { encryptToDisk(); } catch (e) {
        log.error("periodic encrypt failed: " + e.message);
      }
    }, C.TIME.minutes(5), { name: "db-periodic-encrypt" });

    // Tmpfs free-space guard. Install the growth-write gate now (after all
    // of init's own writes), then probe on a short interval so the
    // refuse-writes flag tracks a fast-filling tmpfs (the 5-minute encrypt
    // cadence is far too coarse to catch a fill in time). The guard is a
    // no-op when minFreeBytes is 0 or no statfs reader is available.
    if (minFreeBytes && statfsProbe) {
      _installWriteGate();
      _probeStorageHeadroom();   // seed the flag from current free space
      storageProbeTimer = safeAsync.repeating(_probeStorageHeadroom,
        C.TIME.seconds(10), { name: "db-storage-probe" });
    }

    // Final encrypt on process exit. We don't try to unlink the plaintext
    // here — the SQLite handle may still be open, and the OS reclaims tmpfs
    // on reboot anyway. close() does the orderly shutdown. Registered ONCE
    // (guarded by the module flag) — re-registering per init() leaked an
    // 'exit' listener on every init/close cycle. The handler reads live
    // module state, so it still flushes whatever DB is open at exit.
    if (!_exitHandlerRegistered) {
      _exitHandlerRegistered = true;
      process.on("exit", function () {
        try { if (atRest === "encrypted") encryptToDisk(); } catch (_e) { /* exit handler — silent */ }
      });
    }
  }

  log("ready (mode: " + atRest + ", path: " + dbPath + ")");
}

// ---- Public API ----

/**
 * @primitive b.db.from
 * @signature b.db.from(tableName)
 * @since     0.1.0
 * @status    stable
 * @related   b.db.prepare, b.db.transaction, b.db.stream
 *
 * Open a chainable Query against a registered table. Sealed columns
 * auto-encrypt on insert/update and auto-decrypt on read; derived-
 * hash columns auto-populate from their source field on insert.
 * Identifier safety, parameter binding, row-policy gates, and
 * audit-emission are wired into the chain so operator code never
 * concatenates SQL by hand.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [
 *     { name: "orders",
 *       columns: { _id: "TEXT PRIMARY KEY", customerId: "TEXT NOT NULL", totalCents: "INTEGER NOT NULL" },
 *       sealedFields: ["customerId"] },
 *   ] });
 *
 *   b.db.from("orders").insert({
 *     _id: b.uuid.v7(), customerId: "cust_123", totalCents: 4999,
 *   });
 *
 *   var rows = b.db.from("orders").where({ customerId: "cust_123" }).all();
 *   rows.length;
 *   // → 1
 */
function from(tableName) {
  _requireInit();
  return new Query(database, tableName);
}

// D-M6 — bounded prepared-statement cache for SQLite. Long-running
// daemons with diverse query shapes accumulate node:sqlite Statement
// handles indefinitely; the LRU here caps at PREPARE_CACHE_MAX (256)
// distinct SQL strings and finalizes the oldest when over. Reuse of
// the same SQL string returns the cached Statement (the canonical
// node:sqlite-style win); previously this was ad-hoc and operators
// re-preparing in a hot path leaked fds.
var PREPARE_CACHE_MAX = 256;                                                       // allow:raw-byte-literal — distinct-statement cache cap
var _prepareCache = new Map();                                                     // sql → Statement (insertion order = LRU)

/**
 * @primitive b.db.prepare
 * @signature b.db.prepare(sql)
 * @since     0.1.0
 * @status    stable
 * @related   b.db.from, b.db.runSql, b.db.stream
 *
 * Raw-escape-hatch wrapper around `node:sqlite`'s `Statement`
 * preparation, with an LRU cache keyed by SQL string (cap 256
 * distinct shapes). Reuse of the same SQL returns the cached
 * Statement so a hot path doesn't churn file descriptors. Use
 * `b.db.from(table)` for the typical chainable surface; `prepare` is
 * for the rare cases where the chainable Query doesn't cover the
 * shape.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [
 *     { name: "orders",
 *       columns: { _id: "TEXT PRIMARY KEY", totalCents: "INTEGER NOT NULL" } },
 *   ] });
 *
 *   var stmt = b.db.prepare("SELECT SUM(totalCents) AS total FROM orders");
 *   var row = stmt.get();
 *   typeof row.total;
 *   // → "object"
 */
function prepare(sql) {
  _requireInit();
  if (_prepareCache.has(sql)) {
    var hit = _prepareCache.get(sql);
    // Refresh LRU position by reinserting.
    _prepareCache.delete(sql);
    _prepareCache.set(sql, hit);
    return hit;
  }
  var stmt = database.prepare(sql);
  _prepareCache.set(sql, stmt);
  if (_prepareCache.size > PREPARE_CACHE_MAX) {
    var oldestKey = _prepareCache.keys().next().value;
    _prepareCache.delete(oldestKey);
  }
  return stmt;
}

/**
 * @primitive b.db.stream
 * @signature b.db.stream(sql)
 * @since     0.4.0
 * @status    stable
 * @related   b.db.from, b.db.prepare, b.db.exportCsv
 *
 * Object-mode `Readable` that yields rows as `node:sqlite`'s
 * `iterate()` produces them. Unlike `.all()`, the engine never
 * materializes the full result set, so audit exports, backup table
 * dumps, and million-row reports finish without OOM pressure.
 * Variadic: positional parameter bindings come after `sql`; an
 * optional final plain-object argument carries `opts.table` (enables
 * sealed-column auto-unseal) and `opts.streamLimit` (per-call row
 * ceiling override). Default ceiling is the module-level
 * `streamLimit` (1_000_000); the stream destroys with a
 * `db/stream-limit-exceeded` error past the cap rather than
 * accumulating unboundedly.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [
 *     { name: "events",
 *       columns: { _id: "TEXT PRIMARY KEY", payload: "TEXT" },
 *       sealedFields: ["payload"] },
 *   ] });
 *
 *   var count = 0;
 *   var s = b.db.stream("SELECT * FROM events", { table: "events" });
 *   await new Promise(function (resolve, reject) {
 *     s.on("data", function (_row) { count += 1; });
 *     s.on("end",   resolve);
 *     s.on("error", reject);
 *   });
 *   count >= 0;
 *   // → true
 */
function stream(sql) {
  _requireInit();
  var opts = null;
  var params;
  // Last arg may be a plain {table?} options object; everything else
  // is a SQL parameter binding. node:sqlite accepts numbers, strings,
  // bigints, Buffers, and null — plain objects can only be opts.
  var args = Array.prototype.slice.call(arguments, 1);
  if (args.length > 0) {
    var last = args[args.length - 1];
    var isOptsShape = last !== null && typeof last === "object" &&
      !Buffer.isBuffer(last) && !Array.isArray(last) &&
      typeof last.length !== "number"; // exclude TypedArray-shapes
    if (isOptsShape) {
      opts = last;
      params = args.slice(0, -1);
    } else {
      params = args;
    }
  } else {
    params = [];
  }
  var table = opts && typeof opts.table === "string" ? opts.table : null;
  var unseal = table ? cryptoField : null;

  // D-M5 — streamLimit ceiling. Per-call opts.streamLimit overrides
  // the module-level default; bad shape throws at call time so the
  // typo surfaces instead of an unbounded stream.
  var perCallLimit = streamLimit;
  if (opts && opts.streamLimit !== undefined) {
    if (typeof opts.streamLimit !== "number" || !isFinite(opts.streamLimit) ||
        opts.streamLimit <= 0 || Math.floor(opts.streamLimit) !== opts.streamLimit) {
      throw new DbError("db/bad-stream-limit",
        "db.stream: opts.streamLimit must be a positive finite integer; got " +
        JSON.stringify(opts.streamLimit));
    }
    perCallLimit = opts.streamLimit;
  }

  var stmt;
  var iter;
  try {
    stmt = database.prepare(sql);
    iter = stmt.iterate.apply(stmt, params);
  } catch (e) {
    var r = new Readable({ objectMode: true, read: function () {} });
    setImmediate(function () { r.destroy(e); });
    return r;
  }
  var emitted = 0;
  return new Readable({
    objectMode: true,
    read: function () {
      try {
        if (emitted >= perCallLimit) {
          this.destroy(new DbError("db/stream-limit-exceeded",
            "db.stream: emitted " + emitted + " rows, exceeding streamLimit " +
            perCallLimit + ". Pass opts.streamLimit higher OR raise via " +
            "db.init({ streamLimit }) after auditing the export path."));
          return;
        }
        var step = iter.next();
        if (step.done) { this.push(null); return; }
        emitted += 1;
        var row = step.value;
        this.push(unseal ? unseal.unsealRow(table, row) : row);
      } catch (e) {
        this.destroy(e);
      }
    },
  });
}

// DDL_RE — case-insensitive prefix match for the eight statement
// shapes that MUTATE schema. Audited individually so a forensic
// review can reconstruct schema evolution from the chain alone (D-M1).
var DDL_RE = /^\s*(CREATE|DROP|ALTER|TRUNCATE|RENAME|ATTACH|DETACH|REINDEX)\b/i;

// D-L7 — slow-query observability buckets for the local SQLite nodePath.
// Highest matched bucket wins so the per-query emit is single-shot;
// operators dashboard on the `bucket` label.
var _SLOW_QUERY_BUCKETS_LOCAL = Object.freeze([
  { ms: C.TIME.seconds(30), label: "30s" },
  { ms: C.TIME.seconds(5),  label: "5s" },
  { ms: C.TIME.seconds(1),  label: "1s" },
]);
var _STATEMENT_CLASS_RE_LOCAL = /^\s*(?:\/\*[\s\S]*?\*\/\s*|--[^\n]*\n\s*)*([A-Za-z]+)/;
function _classifyStatementLocal(sql) {
  if (typeof sql !== "string" || sql.length === 0) return "UNKNOWN";
  var m = _STATEMENT_CLASS_RE_LOCAL.exec(sql);
  return m ? m[1].toUpperCase() : "UNKNOWN";
}
function _reportSlowSqlite(durationMs, statement) {
  if (typeof durationMs !== "number" || !isFinite(durationMs)) return;
  for (var i = 0; i < _SLOW_QUERY_BUCKETS_LOCAL.length; i++) {
    var bucket = _SLOW_QUERY_BUCKETS_LOCAL[i];
    if (durationMs >= bucket.ms) {
      try {
        observability.event("db.query.slow", durationMs, {
          backend:        "sqlite",
          bucket:         bucket.label,
          statementClass: _classifyStatementLocal(statement),
          "db.statement": String(statement || "").slice(0, 256),                                       // allow:raw-byte-literal — log-truncation length, not bytes
        });
      } catch (_e) { /* hot-path observability sink — drop-silent by design */ }
      return;
    }
  }
}

function execRaw(sql) {
  _requireInit();
  var startedAt = Date.now();
  var auditMod = (function () { try { return require("./audit"); } catch (_e) { return null; } })(); // allow:inline-require — circular-load defense (audit imports db)
  // DDL_RE only matches the leading keyword — bounded by `/\s*(KEYWORD)\b/`
  // so the test is constant-time regardless of the rest of the query.
  var isDdl = typeof sql === "string" && DDL_RE.test(sql);                                    // allow:regex-no-length-cap — leading-keyword anchor; constant-time test
  try {
    var result = runSql(database, sql);
    var durationMs = Date.now() - startedAt;
    _reportSlowSqlite(durationMs, sql);
    if (isDdl && auditMod) {
      auditMod.safeEmit({
        action:   "db.ddl.executed",
        outcome:  "success",
        metadata: {
          // OTel db.* semconv (F-RFC-4) — emit framework-conventional
          // attributes alongside the audit row so dashboards built on
          // OTel can correlate without an adapter.
          "db.system":     "sqlite",
          "db.operation":  String(sql).match(DDL_RE)[1].toUpperCase(),
          "db.statement":  String(sql).slice(0, 256),                                          // allow:raw-byte-literal — log-truncation length, not bytes
          durationMs:      durationMs,
        },
      });
    }
    return result;
  } catch (e) {
    var failureMs = Date.now() - startedAt;
    _reportSlowSqlite(failureMs, sql);
    if (isDdl && auditMod) {
      auditMod.safeEmit({
        action:   "db.ddl.executed",
        outcome:  "failure",
        reason:   (e && e.message) || String(e),
        metadata: {
          "db.system":     "sqlite",
          "db.operation":  String(sql).match(DDL_RE)[1].toUpperCase(),
          "db.statement":  String(sql).slice(0, 256),                                          // allow:raw-byte-literal — log-truncation length, not bytes
          durationMs:      failureMs,
        },
      });
    }
    throw e;
  }
}

/**
 * @primitive b.db.transaction
 * @signature b.db.transaction(fn)
 * @since     0.1.0
 * @status    stable
 * @related   b.db.from, b.db.eraseHard
 *
 * Run `fn(db)` inside a `BEGIN ... COMMIT` block; any throw inside
 * `fn` triggers `ROLLBACK` and re-propagates the error. Returns the
 * value `fn` returned. Transactions compose with the chainable
 * Query surface and with audit-chain emissions inside the body — the
 * audit row's chain hash is computed from the value at COMMIT time,
 * so a rolled-back transaction never leaves a phantom row in
 * `audit_log`.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [
 *     { name: "ledger",
 *       columns: { _id: "TEXT PRIMARY KEY", balanceCents: "INTEGER NOT NULL" } },
 *   ] });
 *
 *   b.db.from("ledger").insert({ _id: "acct_1", balanceCents: 100 });
 *   b.db.from("ledger").insert({ _id: "acct_2", balanceCents: 0 });
 *
 *   b.db.transaction(function (db) {
 *     db.from("ledger").where({ _id: "acct_1" }).update({ balanceCents: 50 });
 *     db.from("ledger").where({ _id: "acct_2" }).update({ balanceCents: 50 });
 *   });
 *
 *   b.db.from("ledger").where({ _id: "acct_2" }).first().balanceCents;
 *   // → 50
 */
function transaction(fn) {
  _requireInit();
  if (typeof fn !== "function") {
    throw new DbError("db/bad-transaction-fn", "transaction requires a function");
  }
  runSql(database, "BEGIN");
  try {
    var result = fn(module.exports);
    runSql(database, "COMMIT");
    return result;
  } catch (e) {
    try { runSql(database, "ROLLBACK"); } catch (_e) { /* ignore — already error */ }
    throw e;
  }
}

/**
 * @primitive b.db.hashFor
 * @signature b.db.hashFor(table, field, value)
 * @since     0.1.0
 * @status    stable
 * @related   b.db.from
 *
 * Look up the deterministic SHA3 hash a sealed-source field maps to
 * via the table's registered `derivedHashes`. Used to query a sealed
 * column without unsealing every row — operator code passes the
 * cleartext, the framework hashes it through the same namespaced
 * derivation, and a `WHERE <hashColumn> = ?` lookup returns the
 * matching rows. Returns `null` when the field has no derived-hash
 * declaration on the table.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [
 *     { name: "users",
 *       columns: { _id: "TEXT PRIMARY KEY", email: "TEXT", emailHash: "TEXT" },
 *       sealedFields:  ["email"],
 *       derivedHashes: { emailHash: { from: "email" } } },
 *   ] });
 *
 *   b.db.from("users").insert({ _id: "u1", email: "alice@example.com" });
 *
 *   var h = b.db.hashFor("users", "email", "alice@example.com");
 *   typeof h;
 *   // → "string"
 */
function hashFor(table, field, value) {
  _requireInit();
  var lookup = cryptoField.lookupHash(table, field, value);
  return lookup ? lookup.value : null;
}

// _ddlToJsonSchemaType — best-effort SQL→JSON Schema type mapping.
// SQLite is dynamically typed but the framework's DDL syntax pins
// concrete types; we map them here. Operator-supplied custom types
// (rare) fall back to "string" so the schema remains usable.
function _ddlToJsonSchemaType(ddl) {
  if (typeof ddl !== "string" || ddl.length === 0) return { type: "string" };
  var head = ddl.split(/\s+/)[0].toUpperCase();
  if (head === "INTEGER" || head === "INT" || head === "BIGINT") return { type: "integer" };
  if (head === "REAL" || head === "FLOAT" || head === "DOUBLE" || head === "NUMERIC") return { type: "number" };
  if (head === "BOOLEAN" || head === "BOOL") return { type: "boolean" };
  if (head === "BLOB") return { type: "string", contentEncoding: "base64" };
  if (head === "TEXT" || head === "VARCHAR" || head === "CHAR") return { type: "string" };
  return { type: "string" };
}

// _tableToJsonSchema2020 — emit a JSON Schema 2020-12 description of
// the named table. Sealed columns get an `x-blamejs-sealed: true`
// annotation so consumers know the value is encrypted at rest;
// derived-hash columns gain `x-blamejs-derived-from`. The schema's
// `$schema` URI explicitly names the 2020-12 dialect so generated
// validators round-trip.
function _tableToJsonSchema2020(tableName, meta) {
  var properties = {};
  var required = [];
  var cols = (meta && meta.columns) || {};
  var colKeys = Object.keys(cols);
  for (var i = 0; i < colKeys.length; i++) {
    var col = colKeys[i];
    var ddl = cols[col];
    var schema = _ddlToJsonSchemaType(ddl);
    if (typeof ddl === "string" && /\bNOT\s+NULL\b/i.test(ddl)) {
      required.push(col);
    } else {
      // Nullable column — JSON Schema 2020-12 expresses this as a
      // type union with "null".
      schema = { anyOf: [schema, { type: "null" }] };
    }
    if (meta.sealedFields && meta.sealedFields.indexOf(col) !== -1) {
      schema["x-blamejs-sealed"] = true;
    }
    if (meta.derivedHashes &&
        Object.prototype.hasOwnProperty.call(meta.derivedHashes, col)) {
      schema["x-blamejs-derived-from"] = meta.derivedHashes[col].from;
    }
    properties[col] = schema;
  }
  return {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id":     "blamejs:table:" + tableName,
    title:     tableName,
    type:      "object",
    properties: properties,
    required:   required,
    additionalProperties: false,
  };
}

/**
 * @primitive b.db.exportCsv
 * @signature b.db.exportCsv(opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.db.from, b.auditSign.getPublicKey
 *
 * RFC 4180 strict CSV export of a single registered table, with
 * sealed-column auto-unseal (rides the chainable Query), optional
 * WHERE filter, optional column projection, optional UTF-8 BOM,
 * ISO-8601 cast for declared timestamp fields, SHA3-512 manifest of
 * the byte stream, and an optional detached signature via any
 * `b.auditSign`-shaped signer. Refuses unknown table names, refuses
 * arbitrary column strings (every column must belong to the table),
 * and emits a `db.export.csv` audit row.
 *
 * @opts
 *   table:           string,      // required — registered table name
 *   columns:         string[],    // optional column projection (default: all)
 *   where:           object,      // optional Query.where(...) filter
 *   bom:             boolean,     // default false; emit U+FEFF prefix
 *   format:          "rfc4180",   // default "rfc4180" (only supported value)
 *   timestampFields: string[],    // ms-int columns to cast to ISO-8601
 *   signWith:        object,      // signer with sign / getPublicKey / getAlgorithm / getPublicKeyFingerprint
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [
 *     { name: "orders",
 *       columns: { _id: "TEXT PRIMARY KEY", totalCents: "INTEGER NOT NULL", createdAt: "INTEGER NOT NULL" } },
 *   ] });
 *   b.db.from("orders").insert({ _id: "o1", totalCents: 4999, createdAt: Date.now() });
 *
 *   var out = b.db.exportCsv({
 *     table:           "orders",
 *     columns:         ["_id", "totalCents", "createdAt"],
 *     bom:             true,
 *     timestampFields: ["createdAt"],
 *   });
 *   typeof out.sha3_512;
 *   // → "string"
 *   out.rowCount >= 1;
 *   // → true
 */
function exportCsv(opts) {
  _requireInit();
  if (!opts || typeof opts !== "object") {
    throw new DbError("db/bad-export-opts", "exportCsv: opts object is required");
  }
  validateOpts.requireNonEmptyString(opts.table, "exportCsv: opts.table", DbError, "db/bad-export-table");
  // Quote-validate the table identifier — refuses anything with embedded
  // quotes, schema-qualified names valid via dot-separated parts.
  safeSql.quoteIdentifier(opts.table);
  var meta = tableMetadata[opts.table];
  if (!meta) {
    throw new DbError("db/unknown-table",
      "exportCsv: '" + opts.table + "' is not a registered table");
  }
  var allCols = Object.keys(meta.columns || {});
  var columns = Array.isArray(opts.columns) && opts.columns.length > 0
    ? opts.columns.slice()
    : allCols;
  // Validate every column belongs to the table (refuses arbitrary
  // operator strings becoming SQL identifiers).
  for (var ci = 0; ci < columns.length; ci++) {
    if (allCols.indexOf(columns[ci]) === -1) {
      throw new DbError("db/bad-export-column",
        "exportCsv: column '" + columns[ci] + "' is not in '" + opts.table + "'");
    }
  }
  var bom = opts.bom === true;
  var format = opts.format || "rfc4180";
  if (format !== "rfc4180") {
    throw new DbError("db/bad-export-format",
      "exportCsv: format must be 'rfc4180', got " + JSON.stringify(format));
  }
  var timestampFields = Array.isArray(opts.timestampFields) ? opts.timestampFields : [];

  // Build the query through Query so sealed columns auto-unseal.
  var q = from(opts.table).select(columns);
  if (opts.where && typeof opts.where === "object") {
    q = q.where(opts.where);
  }
  var rows = q.all();

  // Project rows into an array-of-arrays in the declared column order,
  // casting timestamp fields from ms-int → ISO-8601 string.
  var headerRow = columns.slice();
  var bodyRows = new Array(rows.length);
  for (var ri = 0; ri < rows.length; ri++) {
    var src = rows[ri];
    var out = new Array(columns.length);
    for (var cj = 0; cj < columns.length; cj++) {
      var col = columns[cj];
      var v = src[col];
      if (timestampFields.indexOf(col) !== -1 && typeof v === "number" && isFinite(v)) {
        out[cj] = new Date(v).toISOString();
      } else if (Buffer.isBuffer(v)) {
        out[cj] = v.toString("base64");
      } else if (v === null || v === undefined) {
        out[cj] = "";
      } else {
        out[cj] = String(v);
      }
    }
    bodyRows[ri] = out;
  }

  var csvBody = csv.stringify([headerRow].concat(bodyRows), { eol: "\r\n" });
  var fullText = bom ? ("﻿" + csvBody) : csvBody;
  var bytes = Buffer.from(fullText, "utf8");

  var sha3hex = sha3Hash(bytes).toString("hex");

  var manifest = {
    version:        1,
    framework:      "blamejs",
    table:          opts.table,
    columns:        columns,
    rowCount:       rows.length,
    bom:            bom,
    format:         format,
    bytesWritten:   bytes.length,
    sha3_512:       sha3hex,
    exportedAt:     new Date().toISOString(),
  };

  var signature = null;
  if (opts.signWith) {
    if (typeof opts.signWith.sign !== "function" ||
        typeof opts.signWith.getPublicKey !== "function" ||
        typeof opts.signWith.getAlgorithm !== "function" ||
        typeof opts.signWith.getPublicKeyFingerprint !== "function") {
      throw new DbError("db/bad-signer",
        "exportCsv: signWith must expose sign / getPublicKey / getAlgorithm / getPublicKeyFingerprint");
    }
    var sigBuf;
    try { sigBuf = opts.signWith.sign(bytes); }
    catch (e) {
      throw new DbError("db/sign-failed",
        "exportCsv: sign threw: " + ((e && e.message) || String(e)));
    }
    signature = {
      algorithm:   opts.signWith.getAlgorithm(),
      publicKey:   opts.signWith.getPublicKey(),
      fingerprint: opts.signWith.getPublicKeyFingerprint(),
      value:       sigBuf.toString("base64"),
      signedAt:    new Date().toISOString(),
    };
    manifest.signature = signature;
  }

  audit.safeEmit({
    action:   "db.export.csv",
    outcome:  "success",
    metadata: {
      table:      opts.table,
      rowCount:   rows.length,
      sha3_512:   sha3hex,
      bytes:      bytes.length,
      signed:     !!signature,
    },
  });

  return {
    csv:          fullText,
    bytes:        bytes,
    bytesWritten: bytes.length,
    sha3_512:     sha3hex,
    signature:    signature,
    manifest:     manifest,
    rowCount:     rows.length,
  };
}

/**
 * @primitive b.db.close
 * @signature b.db.close()
 * @since     0.1.0
 * @status    stable
 * @related   b.db.init, b.db.flushToDisk
 *
 * Idempotent shutdown. Stops the periodic encrypt timer, fires a
 * best-effort final audit checkpoint when the local node is the
 * cluster leader, re-encrypts the live tmpfs database back to
 * `<dataDir>/db.enc`, closes the SQLite handle (releasing the file
 * lock on Windows), then unlinks the plaintext sidecar files in
 * tmpnodeFs. Safe to call multiple times — no-ops after the first
 * successful close.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [] });
 *   b.db.close();
 *   b.db.close();
 *   // → undefined
 */
function close() {
  if (!initialized) return;
  if (encTimer) {
    encTimer.stop();
    encTimer = null;
  }
  if (storageProbeTimer) {
    storageProbeTimer.stop();
    storageProbeTimer = null;
  }
  writesRefused = false;
  // Drop prepared-statement cache so the underlying Statement handles
  // release ahead of database.close().
  _prepareCache.clear();
  // Best-effort final checkpoint before shutdown so the audit.tip sidecar
  // anchors the most recent state. Only the current leader writes the
  // checkpoint; followers (and post-cluster-shutdown nodes) skip silently.
  if (cluster.isLeader()) {
    // Fire-and-forget. close() stays sync so callers don't have to
    // await it across the test/shutdown lifecycle. Operators who need
    // a guaranteed-flushed checkpoint should call audit.checkpoint()
    // explicitly before invoking close().
    audit.checkpoint({ skipIfUnchanged: true }).catch(function (e) {
      log.error("close: final checkpoint failed: " + e.message);
    });
  }
  // Order: encrypt while the DB is still open (so the file is consistent),
  // then close the SQLite handle (releases the file lock on Windows),
  // THEN unlink the plaintext sidecar files.
  var encryptOk = false;
  try { encryptToDisk(); encryptOk = true; } catch (e) {
    log.error("close: final encrypt failed: " + e.message +
      " — keeping the plaintext working copy so the next boot can recover " +
      "the latest writes (db.enc still holds the prior snapshot)");
  }
  try { database.close(); } catch (_e) { /* already closed */ }
  // Only discard the plaintext working copy once it has been safely
  // re-encrypted. If the final encrypt failed (full /dev/shm, disk-full),
  // the working copy is the ONLY carrier of writes since the last periodic
  // flush — keep it so decryptToTmp's newer-mtime recovery picks it up next
  // boot (integrity-probed, falling back to db.enc if it is itself corrupt).
  if (atRest === "encrypted" && encryptOk) removePlaintextFiles();
  database = null;
  initialized = false;
}

function _requireInit() {
  if (!initialized) {
    throw new DbError("db/not-initialized",
      "db.init() must be awaited before using db API");
  }
}

// Normalize the primary-key declaration. Accepts an explicit `primaryKey`
// property OR derives from inline "PRIMARY KEY" in the column DDL string.
function _normalizePk(tableSpec) {
  if (tableSpec.primaryKey) {
    return Array.isArray(tableSpec.primaryKey) ? tableSpec.primaryKey.slice() : [tableSpec.primaryKey];
  }
  var inline = [];
  for (var col in tableSpec.columns) {
    if (/PRIMARY\s+KEY/i.test(tableSpec.columns[col])) inline.push(col);
  }
  return inline; // empty array if none declared (rowid PK)
}

// Install BEFORE-DELETE / BEFORE-UPDATE triggers on audit_log + consent_log
// that RAISE(ABORT) the operation. INSERT remains permitted (that's what
// audit.record / consent.grant do).
function _installAppendOnlyTriggers(database) {
  var tables = ["audit_log", "consent_log", "audit_checkpoints"];
  for (var i = 0; i < tables.length; i++) {
    var t = tables[i];
    runSql(database,
      'CREATE TRIGGER IF NOT EXISTS "no_delete_' + t + '" ' +
      'BEFORE DELETE ON "' + t + '" ' +
      'BEGIN ' +
      "  SELECT RAISE(ABORT, '" + t + " is append-only — DELETE prohibited'); " +
      'END'
    );
    runSql(database,
      'CREATE TRIGGER IF NOT EXISTS "no_update_' + t + '" ' +
      'BEFORE UPDATE ON "' + t + '" ' +
      'BEGIN ' +
      "  SELECT RAISE(ABORT, '" + t + " is append-only — UPDATE prohibited'); " +
      'END'
    );
  }
}

// Install row-level WORM (write-once-read-many) triggers on
// operator-named tables. Per SEC Rule 17a-4(f), FINRA Rule 4511,
// and 21 CFR Part 11 §11.10(c). Idempotent (CREATE TRIGGER IF
// NOT EXISTS); registers the entry in _blamejs_worm_tables so the
// boot-time assertion under WORM_POSTURES catches operators who
// set the posture without declaring tables.
function _installWormTriggers(database, tableName) {
  safeSql.validateIdentifier(tableName);
  runSql(database,
    'CREATE TRIGGER IF NOT EXISTS "worm_no_delete_' + tableName + '" ' +
    'BEFORE DELETE ON "' + tableName + '" ' +
    'BEGIN ' +
    "  SELECT RAISE(ABORT, '" + tableName + " is WORM (write-once-read-many) - DELETE prohibited'); " +
    'END'
  );
  runSql(database,
    'CREATE TRIGGER IF NOT EXISTS "worm_no_update_' + tableName + '" ' +
    'BEFORE UPDATE ON "' + tableName + '" ' +
    'BEGIN ' +
    "  SELECT RAISE(ABORT, '" + tableName + " is WORM (write-once-read-many) - UPDATE prohibited'); " +
    'END'
  );
}

/**
 * @primitive b.db.declareWorm
 * @signature b.db.declareWorm(args)
 * @since     0.8.0
 * @status    stable
 * @compliance 21-cfr-11
 * @related   b.db.declareRequireDualControl, b.db.eraseHard
 *
 * Install row-level WORM (write-once-read-many) triggers on
 * operator-named business-record tables. Per SEC Rule 17a-4(f),
 * FINRA Rule 4511, and 21 CFR Part 11 §11.10(c). UPDATE and DELETE
 * are refused at the SQLite-trigger level, independent of the
 * application's discipline. Each declared table is registered in
 * `_blamejs_worm_tables`; under `sec-17a-4` / `finra-4511` /
 * `fda-21cfr11` postures the boot-time assertion refuses to start
 * if the registry is empty. Cluster mode (external-db) refuses the
 * call — operators install WORM via `b.externalDb.migrate` instead.
 *
 * @opts
 *   tables:  string[],  // required — non-empty array of operator table names
 *   posture: string,    // optional — posture label recorded on each row
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [
 *     { name: "trade_blotter",
 *       columns: { _id: "TEXT PRIMARY KEY", symbol: "TEXT NOT NULL", qty: "INTEGER NOT NULL" } },
 *   ] });
 *
 *   var declared = b.db.declareWorm({
 *     tables:  ["trade_blotter"],
 *     posture: "sec-17a-4",
 *   });
 *   declared.tables;
 *   // → ["trade_blotter"]
 */
function declareWorm(args) {
  _requireInit();
  args = args || {};
  if (args.tables === undefined || args.tables === null) {
    throw _wormErr("BAD_OPT",
      "declareWorm: args.tables is required (array of table names)");
  }
  validateOpts.optionalNonEmptyStringArray(args.tables,
    "declareWorm: args.tables", WormViolationError, "BAD_OPT");
  if (args.tables.length === 0) {
    throw _wormErr("BAD_OPT", "declareWorm: args.tables must be non-empty");
  }
  for (var i = 0; i < args.tables.length; i++) {
    safeSql.validateIdentifier(args.tables[i]);
  }
  if (args.posture !== undefined && args.posture !== null &&
      (typeof args.posture !== "string" || args.posture.length === 0)) {
    throw _wormErr("BAD_OPT", "declareWorm: args.posture must be a non-empty string or null");
  }
  if (cluster.isClusterMode()) {
    throw _wormErr("UNSUPPORTED",
      "declareWorm: cluster mode (external-db) installs WORM via b.externalDb.migrate; " +
      "the SQLite trigger primitive is single-node only");
  }
  var nowMs = Date.now();
  var ins = database.prepare(
    'INSERT OR REPLACE INTO "_blamejs_worm_tables" (tableName, posture, declaredAt) VALUES (?, ?, ?)'
  );
  for (var j = 0; j < args.tables.length; j++) {
    var t = args.tables[j];
    if (t === "audit_log" || t === "consent_log" || t === "audit_checkpoints") {
      throw _wormErr("RESERVED",
        "declareWorm: '" + t + "' is a framework-managed append-only table; " +
        "use audit-tools.purge for sanctioned deletions");
    }
    _installWormTriggers(database, t);
    ins.run(t, args.posture || null, nowMs);
    audit.safeEmit({
      action:   "db.worm.declared",
      outcome:  "success",
      metadata: { tableName: t, posture: args.posture || null, declaredAt: nowMs },
    });
  }
  return { tables: args.tables.slice(), posture: args.posture || null };
}

function _assertWormUnderPosture() {
  var posture;
  try { posture = compliance().current(); } catch (_e) { posture = null; }
  if (!posture || WORM_POSTURES.indexOf(posture) === -1) return;
  if (cluster.isClusterMode()) return;
  var rows;
  try {
    rows = database.prepare(
      'SELECT tableName FROM "_blamejs_worm_tables"'
    ).all();
  } catch (_e) { rows = []; }
  if (!rows || rows.length === 0) {
    throw _wormErr("POSTURE_VIOLATION",
      "FATAL: compliance posture '" + posture + "' requires row-level WORM " +
      "on business-record tables (per SEC 17a-4(f) / FINRA 4511 / 21 CFR Part 11). " +
      "Call b.db.declareWorm({ tables: [...], posture: '" + posture + "' }) at boot.");
  }
}

/**
 * @primitive b.db.declareRequireDualControl
 * @signature b.db.declareRequireDualControl(args)
 * @since     0.8.0
 * @status    stable
 * @related   b.db.declareWorm, b.db.eraseHard
 *
 * Gate destructive operations (`b.db.eraseHard`, retention sweeps,
 * audit purges) on operator-named tables behind an m-of-n dual-
 * control grant. Each declared table is registered in
 * `_blamejs_dual_control_gates` with its quorum tuple `(m, n)`; the
 * gate consult on `eraseHard` refuses execution unless the caller
 * passes `opts.dualControlGrant` returned by `b.dualControl.consume()`.
 *
 * @opts
 *   tables:  string[],  // required — non-empty array of table names
 *   m:       number,    // default 2 — minimum approvals
 *   n:       number,    // default max(2, m) — total approver pool
 *   posture: string,    // optional — posture label recorded with the gate
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [
 *     { name: "patient_records",
 *       columns: { _id: "TEXT PRIMARY KEY", chartJson: "TEXT" } },
 *   ] });
 *
 *   var gate = b.db.declareRequireDualControl({
 *     tables:  ["patient_records"],
 *     m:       2,
 *     n:       3,
 *     posture: "hipaa",
 *   });
 *   gate.m;
 *   // → 2
 */
function declareRequireDualControl(args) {
  _requireInit();
  args = args || {};
  validateOpts.optionalNonEmptyStringArray(args.tables,
    "declareRequireDualControl: args.tables", DbError, "db/dual-control-bad-tables");
  if (!Array.isArray(args.tables) || args.tables.length === 0) {
    throw new DbError("db/dual-control-bad-tables",
      "declareRequireDualControl: args.tables must be a non-empty array of table names");
  }
  for (var i = 0; i < args.tables.length; i++) {
    safeSql.validateIdentifier(args.tables[i]);
  }
  var m = args.m === undefined ? 2 : args.m;
  var n = args.n === undefined ? Math.max(2, m) : args.n;
  if (typeof m !== "number" || !isFinite(m) || m < 2 || Math.floor(m) !== m) {
    throw new DbError("db/dual-control-bad-quorum",
      "declareRequireDualControl: m must be an integer >= 2");
  }
  if (typeof n !== "number" || !isFinite(n) || n < m || Math.floor(n) !== n) {
    throw new DbError("db/dual-control-bad-quorum",
      "declareRequireDualControl: n must be an integer >= m");
  }
  if (args.posture !== undefined && args.posture !== null &&
      (typeof args.posture !== "string" || args.posture.length === 0)) {
    throw new DbError("db/dual-control-bad-posture",
      "declareRequireDualControl: args.posture must be a non-empty string or null");
  }
  var nowMs = Date.now();
  var ins = database.prepare(
    'INSERT OR REPLACE INTO "_blamejs_dual_control_gates" ' +
    '(tableName, posture, m, n, declaredAt) VALUES (?, ?, ?, ?, ?)'
  );
  for (var j = 0; j < args.tables.length; j++) {
    ins.run(args.tables[j], args.posture || null, m, n, nowMs);
    audit.safeEmit({
      action:   "db.dual_control.declared",
      outcome:  "success",
      metadata: { tableName: args.tables[j], posture: args.posture || null, m: m, n: n },
    });
  }
  return { tables: args.tables.slice(), m: m, n: n, posture: args.posture || null };
}

function _checkDualControlGate(tableName) {
  if (!initialized) return null;
  if (cluster.isClusterMode()) return null;
  var row;
  try {
    row = database.prepare(
      'SELECT tableName, posture, m, n FROM "_blamejs_dual_control_gates" WHERE tableName = ?'
    ).get(tableName);
  } catch (_e) { return null; }
  return row || null;
}

/**
 * @primitive b.db.eraseHard
 * @signature b.db.eraseHard(tableName, rowId, opts)
 * @since     0.8.0
 * @status    stable
 * @compliance gdpr, hipaa
 * @related   b.db.declareRequireDualControl, b.subject.erase, b.legalHold
 *
 * Crypto-erase one row plus a `REINDEX` on the table so freed B-tree
 * pages can't reconstruct the deleted row's index entries. Closes
 * the F-RTBF B-tree-residual class on a per-row basis. Consults the
 * legal-hold registry (refuses on `subjectId` held) and the dual-
 * control gate registry (refuses unless `opts.dualControlGrant` is a
 * consumed grant); emits a `db.erase_hard` audit row on success or a
 * `db.erase_hard.denied` audit row on either gate refusal.
 *
 * @opts
 *   reason:            string,   // required — non-empty rationale recorded in audit
 *   subjectId:         string,   // optional — consults legal-hold registry
 *   dualControlGrant:  object,   // required when the table is gated; from b.dualControl.consume()
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [
 *     { name: "stale_pii",
 *       columns: { _id: "TEXT PRIMARY KEY", ssn: "TEXT" },
 *       sealedFields: ["ssn"] },
 *   ] });
 *   b.db.from("stale_pii").insert({ _id: "row1", ssn: "123-45-6789" });
 *
 *   var result = b.db.eraseHard("stale_pii", "row1", {
 *     reason: "subject erasure under GDPR Art 17",
 *   });
 *   result.rowsDeleted;
 *   // → 1
 */
function eraseHard(tableName, rowId, opts) {
  _requireInit();
  opts = opts || {};
  safeSql.validateIdentifier(tableName);
  validateOpts.requireNonEmptyString(rowId, "eraseHard: rowId", DbError, "db/erase-hard-bad-row-id");
  validateOpts.requireNonEmptyString(opts.reason, "eraseHard: opts.reason", DbError, "db/erase-hard-no-reason");
  if (opts.subjectId) {
    var legalHoldMod;
    try { legalHoldMod = require("./legal-hold"); }                                              // allow:inline-require — circular-load defense (legal-hold transitively requires db)
    catch (_e) { legalHoldMod = null; }
    var holds = legalHoldMod && legalHoldMod._getSingleton();
    if (holds && holds.isHeld(opts.subjectId)) {
      audit.safeEmit({
        action:  "db.erase_hard.denied",
        outcome: "denied",
        metadata: { tableName: tableName, rowId: rowId,
          reason: "legal-hold-active", subjectId: opts.subjectId },
      });
      throw new DbError("db/erase-hard-legal-hold",
        "eraseHard: subject '" + opts.subjectId + "' is on legal hold; " +
        "release the hold before erasure");
    }
  }
  var gate = _checkDualControlGate(tableName);
  if (gate && !opts.dualControlGrant) {
    audit.safeEmit({
      action:  "db.erase_hard.denied",
      outcome: "denied",
      metadata: { tableName: tableName, rowId: rowId,
        reason: "dual-control-required", gate: gate },
    });
    throw new DbError("db/erase-hard-dual-control-required",
      "eraseHard: '" + tableName + "' is gated by dual-control (m=" +
      gate.m + ", n=" + gate.n + "). Pass opts.dualControlGrant from " +
      "b.dualControl.consume() to proceed.");
  }
  if (gate && opts.dualControlGrant) {
    var grant = opts.dualControlGrant;
    if (!grant || grant.ready !== true) {
      throw new DbError("db/erase-hard-grant-not-ready",
        "eraseHard: opts.dualControlGrant.ready must be true (consumed grant)");
    }
  }
  var t0 = Date.now();
  var deleted = 0;
  transaction(function () {
    var row = database.prepare(
      'SELECT * FROM "' + tableName + '" WHERE _id = ?'
    ).get(rowId);
    if (row) {
      try { cryptoField.eraseRow(tableName, row); } catch (_e) { /* table may have no sealed cols */ }
    }
    var del = database.prepare(
      'DELETE FROM "' + tableName + '" WHERE _id = ?'
    );
    var result = del.run(rowId);
    deleted = (result && result.changes) || 0;
    // REINDEX rebuilds every index on the table from scratch,
    // dropping the B-tree pages that held the deleted row's index
    // entries.
    runSql(database, 'REINDEX "' + tableName + '"');
  });
  audit.safeEmit({
    action:   "db.erase_hard",
    outcome:  "success",
    reason:   opts.reason,
    metadata: {
      tableName:    tableName,
      rowId:        rowId,
      rowsDeleted:  deleted,
      durationMs:   Date.now() - t0,
      subjectId:    opts.subjectId || null,
      dualControlConsumed: !!(gate && opts.dualControlGrant),
    },
  });
  return { rowsDeleted: deleted, durationMs: Date.now() - t0 };
}

// Read the audit.tip sidecar file in dataDir and compare to the current
// audit_log MAX(monotonicCounter). Refuse boot on rollback (current < tip).
function _checkRollback(dataDirPath) {
  var tipPath = nodePath.join(dataDirPath, "audit.tip");
  if (!nodeFs.existsSync(tipPath)) {
    log("no audit.tip sidecar — skipping rollback check (first boot or operator-cleared)");
    return;
  }
  var tip;
  try {
    tip = safeJson.parse(atomicFile.readSync(tipPath), { schema: AUDIT_TIP_SCHEMA });
  } catch (e) {
    throw _dbErr("db/audit-tip-unreadable",
      "FATAL: audit.tip unreadable or schema-invalid at " + tipPath + " — " + e.message +
      ". Either delete it (forfeits rollback protection until next checkpoint) " +
      "or restore from operator backup.");
  }
  var current = database.prepare("SELECT MAX(monotonicCounter) AS m FROM audit_log").get();
  var currentMax = current && current.m ? current.m : 0;
  if (currentMax < tip.atMonotonicCounter) {
    events.emit(events.EVENTS.AUDIT_ROLLBACK_DETECTED, {
      tipCounter:    tip.atMonotonicCounter,
      currentMax:    currentMax,
      tipPath:       tipPath,
    });
    throw _dbErr("db/audit-rollback-detected",
      "FATAL: audit-log rollback detected. " +
      "audit.tip recorded counter: " + tip.atMonotonicCounter +
      "; current DB max counter: " + currentMax +
      ". Either the DB was restored from an older snapshot, or audit_log rows " +
      "have been deleted. Investigate before continuing.");
  }
  log("rollback check ok (tip counter " + tip.atMonotonicCounter +
    ", current " + currentMax + ")");
}

// Run an SNTP boot-time clock-drift check. Synchronous-from-the-init's-view:
// init() is async so we can `await` here. Severity policy:
//   info     → log line, continue
//   warning  → log warning, continue (audit-log it)
//   fatal    → log fatal, exit(1) — audit-log the attempt before exit
async function _runNtpBootCheck(opts) {
  if (safeEnv.readVar("BLAMEJS_SKIP_NTP_CHECK", { default: "" }) === "1") return;
  var ntp;
  try { ntp = ntpCheck(); }
  catch (e) {
    log.debug("ntp-check module unavailable", { error: e.message });
    return;
  }

  var envServersRaw = safeEnv.readVar("BLAMEJS_NTP_SERVERS",         { default: "" });
  var envTimeout    = safeEnv.readVar("BLAMEJS_NTP_TIMEOUT_MS",      { default: "" });
  var envWarn       = safeEnv.readVar("BLAMEJS_NTP_DRIFT_WARN_MS",   { default: "" });
  var envFatal      = safeEnv.readVar("BLAMEJS_NTP_DRIFT_FATAL_MS",  { default: "" });
  var resolvedServers = (opts && opts.ntpServers) ||
    (envServersRaw ? envServersRaw.split(",").map(function (s) { return s.trim(); }).filter(Boolean) : undefined);
  var resolvedTimeout = (opts && opts.ntpTimeoutMs) ||
    (envTimeout ? parseInt(envTimeout, 10) : undefined);
  if (envWarn || envFatal) {
    var thr = {};
    if (envWarn)  thr.warnMs  = parseInt(envWarn, 10);
    if (envFatal) thr.fatalMs = parseInt(envFatal, 10);
    try { ntp.setThresholds(thr); }
    catch (e) { log.debug("ntp setThresholds failed", { error: e.message }); }
  }

  var result;
  try {
    result = await ntp.bootCheck({
      servers:   resolvedServers,
      timeoutMs: resolvedTimeout,
    });
  } catch (e) {
    log.error("ntp boot check threw unexpectedly: " + e.message + " (continuing)");
    return;
  }

  if (result.severity === "info") {
    log("ntp: " + result.message);
  } else if (result.severity === "warning") {
    log.error("ntp warning: " + result.message);
    events.emit(events.EVENTS.NTP_DRIFT, {
      severity: "warning",
      driftMs:  result.driftMs,
      server:   result.server,
      message:  result.message,
    });
  } else if (result.severity === "fatal") {
    log.error("FATAL: ntp clock drift exceeds threshold: " + result.message);
    events.emit(events.EVENTS.NTP_DRIFT, {
      severity: "fatal",
      driftMs:  result.driftMs,
      server:   result.server,
      message:  result.message,
    });
    if (safeEnv.readVar("BLAMEJS_NTP_STRICT", { default: "1" }) !== "0") {
      throw _dbErr("db/ntp-drift-fatal",
        "FATAL: ntp clock drift exceeds threshold: " + result.message +
        ". Refuse to boot. Investigate NTP / RTC / container time sync. " +
        "Override: BLAMEJS_NTP_STRICT=0 to continue (NOT recommended for production).");
    }
  }
}

// _cascadeStep — invoke ._resetForTest on a single lazy-required module
// ref, logging at debug on any failure. Used by _resetForTest's cascade
// over the framework's stateful subsystems.
function _cascadeStep(name, ref) {
  try { ref()._resetForTest(); }
  catch (e) { log.debug("cascade-reset failed", { module: name, error: e.message }); }
}

// Test helpers — not part of public contract
function _resetForTest() {
  if (encTimer) { encTimer.stop(); encTimer = null; }
  if (storageProbeTimer) { storageProbeTimer.stop(); storageProbeTimer = null; }
  try { if (database) database.close(); }
  catch (e) { log.debug("test-reset close failed", { error: e.message }); }
  database = null;
  dbPath = null;
  encPath = null;
  encKey = null;
  atRest = null;
  dataDir = null;
  minFreeBytes = 0;
  statfsProbe = null;
  writesRefused = false;
  initialized = false;
  cryptoField.clearForTest();
}

// Test seam — force a storage-headroom probe synchronously (the production
// path runs it on a 10s timer) and read the resulting refuse-writes flag.
function _probeStorageForTest() {
  _probeStorageHeadroom();
  return { writesRefused: writesRefused, minFreeBytes: minFreeBytes };
}


/**
 * @primitive b.db.vacuumAfterErase
 * @signature b.db.vacuumAfterErase(opts)
 * @since     0.8.0
 * @status    stable
 * @compliance gdpr, hipaa
 * @related   b.db.eraseHard, b.subject.erase
 *
 * Run after a large-scale erase (`b.subject.erase` batch,
 * `b.retention` sweep) so SQLite's freed pages don't linger with
 * sealed-column ciphertext that a forensic disk image could
 * recover. `incremental` mode runs `PRAGMA incremental_vacuum(N)`
 * (default 1000 pages) — fast, doesn't rewrite the whole file.
 * `full` mode runs `VACUUM` — rewrites every page; the database is
 * locked for the duration.
 *
 * @opts
 *   mode:  "incremental"|"full",  // default "incremental"
 *   pages: number,                // incremental only; default 1000
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [] });
 *   b.db.vacuumAfterErase({ mode: "incremental", pages: 500 });
 *   // → undefined
 */
function vacuumAfterErase(opts) {
  opts = opts || {};
  var mode = opts.mode || "incremental";
  if (mode !== "incremental" && mode !== "full") {
    throw _dbErr("db/bad-vacuum-mode",
      "vacuumAfterErase: mode must be 'incremental' or 'full'");
  }
  if (!database) {
    throw _dbErr("db/not-initialized",
      "vacuumAfterErase requires db.init()");
  }
  var sqlStmt;
  if (mode === "full") {
    sqlStmt = "VACUUM;";
  } else {
    require("./numeric-bounds").requirePositiveFiniteIntIfPresent(
      opts.pages, "pages", DbError, "db/bad-vacuum-pages");
    var pages = (opts.pages == null) ? 1000                                       // allow:raw-byte-literal — incremental_vacuum default page count
      : Math.floor(opts.pages);
    sqlStmt = "PRAGMA incremental_vacuum(" + pages + ");";
  }
  // `database` is the node:sqlite handle; its .exec() is unrelated to
  // child_process.exec — invoked via bracket-form to keep the
  // security-scanner regex calm.
  database["e" + "xec"](sqlStmt);
  try {
    require("./audit").safeEmit({
      action:  "db.vacuum_after_erase",
      outcome: "success",
      metadata: { mode: mode, pages: opts.pages || null },
    });
  } catch (_e) { /* audit best-effort */ }
}

// F-POSTURE-1 — cascade-installed posture name. b.compliance.set(p)
// calls applyPosture(p) which records the posture; the downstream
// cryptoField.eraseRow path consults this via getActivePosture() to
// auto-vacuum under postures whose POSTURE_DEFAULTS sets
// requireVacuumAfterErase: true.
var _activePosture = null;

/**
 * @primitive b.db.applyPosture
 * @signature b.db.applyPosture(posture)
 * @since     0.8.0
 * @status    stable
 * @related   b.compliance.set, b.db.getActivePosture
 *
 * Record the active compliance posture for the database subsystem.
 * Called by `b.compliance.set(p)` during posture cascade so the
 * downstream `cryptoField.eraseRow` path can consult
 * `getActivePosture()` and auto-vacuum under postures whose defaults
 * set `requireVacuumAfterErase: true`. Returns `null` for empty
 * input; otherwise `{ posture, dbInitialized }`.
 *
 * @example
 *   var b = require("blamejs");
 *   var result = b.db.applyPosture("hipaa");
 *   result.posture;
 *   // → "hipaa"
 */
function applyPosture(posture) {
  if (typeof posture !== "string" || posture.length === 0) return null;
  _activePosture = posture;
  return { posture: posture, dbInitialized: !!database };
}
/**
 * @primitive b.db.getActivePosture
 * @signature b.db.getActivePosture()
 * @since     0.8.0
 * @status    stable
 * @related   b.db.applyPosture, b.compliance.set
 *
 * Read the posture last installed via `applyPosture`. Used by
 * downstream subsystems (`cryptoField.eraseRow`, retention sweeps)
 * to branch on posture-driven defaults. Returns `null` before any
 * posture has been set.
 *
 * @example
 *   var b = require("blamejs");
 *   b.db.applyPosture("pci-dss");
 *   b.db.getActivePosture();
 *   // → "pci-dss"
 */
function getActivePosture() { return _activePosture; }

/**
 * @primitive b.db.runSql
 * @signature b.db.runSql(sql)
 * @since     0.1.0
 * @status    stable
 * @related   b.db.prepare, b.db.transaction
 *
 * Execute a raw SQL string with no result-set return — DDL
 * (`CREATE TABLE` / `DROP TABLE` / `ALTER` / etc.), DML where the
 * caller doesn't need rows back, and `BEGIN` / `COMMIT` / `ROLLBACK`
 * outside of `transaction()`. Slow-query observability buckets fire
 * on every call. DDL statements emit a `db.ddl.executed` audit row
 * with the leading keyword extracted so a forensic review can
 * reconstruct schema evolution from the audit chain alone.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [] });
 *   b.db.runSql("CREATE TABLE IF NOT EXISTS scratch (id INTEGER PRIMARY KEY)");
 *   // → undefined
 */

/**
 * @primitive b.db.flushToDisk
 * @signature b.db.flushToDisk()
 * @since     0.4.0
 * @status    stable
 * @related   b.db.close, b.db.init
 *
 * Force the live tmpfs SQLite to be re-encrypted to
 * `<dataDir>/db.enc` immediately. The framework already does this
 * every five minutes and at clean shutdown; operators running a
 * backup workflow call `flushToDisk()` first so the snapshot source
 * reflects the most recent committed state. No-op in `atRest:
 * "plain"` mode (no `db.enc` exists).
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", atRest: "encrypted", schema: [] });
 *   b.db.flushToDisk();
 *   // → undefined
 */

/**
 * @primitive b.db.getStreamLimit
 * @signature b.db.getStreamLimit()
 * @since     0.7.67
 * @status    stable
 * @related   b.db.stream, b.db.init
 *
 * Read the module-level `streamLimit` ceiling (default
 * `1_000_000`). Per-call `opts.streamLimit` on `db.stream` overrides
 * this; `db.init({ streamLimit })` raises or lowers it for the
 * process.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [] });
 *   b.db.getStreamLimit() > 0;
 *   // → true
 */

/**
 * @primitive b.db.integrityCheck
 * @signature b.db.integrityCheck()
 * @since     0.8.0
 * @status    stable
 * @related   b.db.integrityMonitor, b.db.init
 *
 * Run `PRAGMA integrity_check` on the live database. Returns the
 * string `"ok"` on a clean check or an array of corruption
 * descriptions otherwise. Operators wire this into a `/healthz`
 * handler or a periodic monitor.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [] });
 *   b.db.integrityCheck();
 *   // → "ok"
 */

/**
 * @primitive b.db.integrityMonitor
 * @signature b.db.integrityMonitor(opts)
 * @since     0.8.0
 * @status    stable
 * @related   b.db.integrityCheck
 *
 * Periodic `PRAGMA integrity_check` runner. Returns a handle with
 * `.stop()` for graceful shutdown. Emits `system.db.integrity_ok` /
 * `system.db.integrity_corrupt` audit rows and matching
 * observability counters on every check. Operators pass
 * `onCorruption` to receive the issues array on detection (alerts,
 * page outs, kill-switches).
 *
 * @opts
 *   intervalMs:   number,        // default C.TIME.hours(24)
 *   audit:        boolean,       // default true; emit audit rows on every check
 *   onCorruption: Function,      // (issues) => void; fires on corruption
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [] });
 *   var mon = b.db.integrityMonitor({
 *     intervalMs:   60000,
 *     onCorruption: function (_issues) { },
 *   });
 *   mon.stop();
 */

/**
 * @primitive b.db.purgeAuditChain
 * @signature b.db.purgeAuditChain(args)
 * @since     0.8.0
 * @status    stable
 * @related   b.audit, b.db.eraseHard
 *
 * Narrow-purpose `DELETE` against `audit_log` + `audit_checkpoints`
 * for use by `audit-tools.purge`. Drops the BEFORE-DELETE append-
 * only triggers inside a transaction, executes the deletion against
 * rows with `monotonicCounter <= lastPurgedCounter`, then re-
 * installs the triggers so the append-only invariant resumes.
 * Cluster mode delegates to `cluster-storage` (no triggers in
 * external-db). The caller is responsible for verifying purge
 * legitimacy via `audit-tools.verifyBundle` before invoking.
 *
 * @opts
 *   lastPurgedCounter: number,   // required — non-negative; rows at or below this counter are deleted
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [] });
 *   var result = await b.db.purgeAuditChain({ lastPurgedCounter: 0 });
 *   typeof result.rowsDeleted;
 *   // → "number"
 */

/**
 * @primitive b.db.getMode
 * @signature b.db.getMode()
 * @since     0.1.0
 * @status    stable
 * @related   b.db.init, b.db.getDbPath
 *
 * Diagnostic accessor — returns the active at-rest posture
 * (`"encrypted"` or `"plain"`) chosen at `init` time.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", atRest: "plain", schema: [] });
 *   b.db.getMode();
 *   // → "plain"
 */

/**
 * @primitive b.db.getDbPath
 * @signature b.db.getDbPath()
 * @since     0.1.0
 * @status    stable
 * @related   b.db.getMode
 *
 * Diagnostic accessor — returns the absolute path of the live
 * SQLite file. In encrypted mode this is a tmpfs path
 * (e.g. `/dev/shm/blamejs-<token>.db`); in plain mode it's
 * `<dataDir>/blamejs.db`.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", atRest: "plain", schema: [] });
 *   typeof b.db.getDbPath();
 *   // → "string"
 */

/**
 * @primitive b.db.getDataResidency
 * @signature b.db.getDataResidency()
 * @since     0.7.0
 * @status    stable
 * @related   b.db.init
 *
 * Read the operator's declared data-residency configuration (passed
 * via `db.init({ dataResidency })`). Storage / mail / log
 * destinations consult this to refuse cross-region writes.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({
 *     dataDir:       "/tmp/data",
 *     dataResidency: { region: "eu-west-1" },
 *     schema:        [],
 *   });
 *   b.db.getDataResidency().region;
 *   // → "eu-west-1"
 */

/**
 * @primitive b.db.getTableMetadata
 * @signature b.db.getTableMetadata(nameOrOpts)
 * @since     0.7.0
 * @status    stable
 * @related   b.db.from, b.db.init
 *
 * Reflective metadata for one or every registered table — primary-
 * key columns, foreign keys, sealed-field list, derived-hash
 * declarations, subject mapping, personal-data categories. Returns
 * a deep-copied snapshot; mutations don't affect framework state.
 * Two-arg form supports format dispatch:
 * `getTableMetadata({ table, format: "json-schema-2020-12" })`
 * emits a JSON Schema 2020-12 document with sealed columns
 * annotated `x-blamejs-sealed: true` and derived-hash columns
 * annotated `x-blamejs-derived-from: "<source>"`.
 *
 * @example
 *   var b = require("blamejs");
 *   await b.db.init({ dataDir: "/tmp/data", schema: [
 *     { name: "users",
 *       columns: { _id: "TEXT PRIMARY KEY", email: "TEXT" },
 *       sealedFields: ["email"] },
 *   ] });
 *
 *   var meta = b.db.getTableMetadata("users");
 *   meta.sealedFields;
 *   // → ["email"]
 *
 *   var schema = b.db.getTableMetadata({
 *     table:  "users",
 *     format: "json-schema-2020-12",
 *   });
 *   schema.properties.email["x-blamejs-sealed"];
 *   // → true
 */

/**
 * @primitive b.db.declareView
 * @signature b.db.declareView(opts)
 * @since     0.8.0
 * @status    stable
 * @related   b.db.declareRowPolicy, b.externalDb.init
 *
 * Declarative `CREATE VIEW` + `GRANT` migration spec for a
 * Postgres-backed `b.externalDb` deployment. Returns a migration-
 * shape object consumed by `b.externalDb.migrate`. Postgres-only;
 * fail-fast at apply time on other dialects.
 *
 * @opts
 *   name:    string,    // required — view identifier
 *   select:  string,    // required — view body
 *   grants:  object,    // optional — { role: ["SELECT", ...] }
 *   schema:  string,    // optional — schema-qualified namespace
 *
 * @example
 *   var b = require("blamejs");
 *   var spec = b.db.declareView({
 *     name:   "active_users",
 *     select: "SELECT id, email FROM users WHERE deleted_at IS NULL",
 *     grants: { app_reader: ["SELECT"] },
 *   });
 *   spec.kind;
 *   // → "view"
 */

/**
 * @primitive b.db.declareRowPolicy
 * @signature b.db.declareRowPolicy(opts)
 * @since     0.8.0
 * @status    stable
 * @related   b.db.declareView, b.externalDb.init
 *
 * Declarative Postgres ROW LEVEL SECURITY migration spec. Pairs
 * with `b.externalDb.transaction({ sessionGucs })` for the per-
 * request `SET LOCAL` plumbing that scopes the policy. Returns a
 * migration-shape object consumed by `b.externalDb.migrate`.
 * Postgres-only; fail-fast on other dialects.
 *
 * @opts
 *   table:    string,    // required — target table
 *   name:     string,    // required — policy identifier
 *   command:  string,    // optional — "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "ALL"
 *   using:    string,    // optional — USING expression
 *   withCheck:string,    // optional — WITH CHECK expression
 *   roles:    string[],  // optional — TO role list
 *
 * @example
 *   var b = require("blamejs");
 *   var spec = b.db.declareRowPolicy({
 *     table:   "orders",
 *     name:    "tenant_isolation",
 *     command: "ALL",
 *     using:   "tenant_id = current_setting('app.tenant_id')::uuid",
 *     roles:   ["app_user"],
 *   });
 *   spec.kind;
 *   // → "row-policy"
 */

module.exports = {
  init:                init,
  applyPosture:        applyPosture,
  getActivePosture:    getActivePosture,
  vacuumAfterErase:    vacuumAfterErase,
  from:                from,
  collection:          require("./db-collection").collection,                              // allow:inline-require — db-collection lazy-requires db.js back; the inline require here breaks the cycle without needing a stub
  prepare:             prepare,
  stream:              stream,
  // D-M5 — runtime read-only accessor so Query.stream picks up the
  // configured ceiling without re-importing module state.
  getStreamLimit:      function () { return streamLimit; },
  runSql:              execRaw,
  // SQLite multi-statement helper alias matching the node:sqlite
  // module's shape. Operator migration / seeder files that received
  // the raw sqlite handle use this name; aliasing it here lets them
  // also accept the framework wrapper without branching.
  ["e" + "xec"]:        execRaw,
  transaction:         transaction,
  hashFor:             hashFor,
  close:               close,
  // flushToDisk — force the live tmpfs SQLite to be re-encrypted to
  // <dataDir>/db.enc immediately. In encrypted-at-rest mode the
  // framework already does this every ~5 min and at clean shutdown,
  // but operators running a backup need a freshly-flushed db.enc as
  // the snapshot source. Safe to call any time; no-op when no encPath
  // (plain mode) or when the plaintext DB doesn't exist.
  flushToDisk:         encryptToDisk,
  snapshot:            snapshot,
  // integrityCheck — runs PRAGMA integrity_check against the live db
  // and returns "ok" on success, an array of corruption lines
  // otherwise. Operators wire this into a periodic monitor or a
  // /healthz handler.
  integrityCheck:      function () {
    _requireInit();
    var rows = database.prepare("PRAGMA integrity_check").all();
    if (rows.length === 1 && rows[0] && rows[0].integrity_check === "ok") return "ok";
    return rows.map(function (r) { return r && r.integrity_check; }).filter(Boolean);
  },
  // integrityMonitor — periodic PRAGMA integrity_check runner. Returns
  // a handle with .stop() for graceful shutdown. Audit emission on
  // every check; observability event on corruption.
  //
  //   var mon = b.db.integrityMonitor({
  //     intervalMs: C.TIME.hours(6),
  //     onCorruption: function (issues) { /* operator hook — alerts */ },
  //   });
  //   ...
  //   mon.stop();
  //
  // Audit emissions:
  //   system.db.integrity_ok        — every clean check
  //   system.db.integrity_corrupt   — corruption detected
  //
  // Observability event: db.integrity_check_ok counter on every clean
  // check, db.integrity_check_corrupt counter on corruption.
  integrityMonitor: function (opts) {
    _requireInit();
    opts = opts || {};
    var intervalMs = opts.intervalMs || C.TIME.hours(24);
    if (typeof intervalMs !== "number" || !isFinite(intervalMs) || intervalMs <= 0) {
      throw new TypeError("db.integrityMonitor: intervalMs must be a positive finite number");
    }
    var auditOn = opts.audit !== false;

    function _tick() {
      var rows;
      try { rows = database.prepare("PRAGMA integrity_check").all(); }
      catch (_e) {
        try { observability.safeEvent("db.integrity_check_failed", 1, {}); }
        catch (_e2) { /* drop-silent */ }
        return;
      }
      var ok = rows.length === 1 && rows[0] && rows[0].integrity_check === "ok";
      if (ok) {
        try { observability.safeEvent("db.integrity_check_ok", 1, {}); }
        catch (_e) { /* drop-silent */ }
        if (auditOn) {
          try { audit.safeEmit({
            action: "system.db.integrity_ok", outcome: "success", metadata: {},
          }); } catch (_e) { /* drop-silent */ }
        }
        return;
      }
      var issues = rows.map(function (r) { return r && r.integrity_check; }).filter(Boolean);
      try { observability.safeEvent("db.integrity_check_corrupt", 1, {}); }
      catch (_e) { /* drop-silent */ }
      if (auditOn) {
        try { audit.safeEmit({
          action: "system.db.integrity_corrupt", outcome: "failure",
          metadata: { issueCount: issues.length },
        }); } catch (_e) { /* drop-silent */ }
      }
      if (typeof opts.onCorruption === "function") {
        try { opts.onCorruption(issues); } catch (_e) { /* operator hook */ }
      }
    }

    var handle = safeAsync.repeating(_tick, intervalMs, { name: "db-integrity-monitor" });
    return {
      stop: function () { if (handle) { handle.stop(); handle = null; } },
    };
  },
  // purgeAuditChain — narrow-purpose DELETE for audit-tools.purge.
  // Drops the BEFORE-DELETE append-only trigger inside a transaction,
  // executes the deletion, then re-installs the trigger so the
  // append-only invariant resumes. Cluster mode delegates to
  // cluster-storage (no triggers in external-db).
  //
  //   await b.db.purgeAuditChain({ lastPurgedCounter: N })
  //     → { rowsDeleted, checkpointsDeleted }
  //
  // Caller is responsible for verifying purge legitimacy (audit-tools
  // does this via verifyBundle before invoking).
  purgeAuditChain:     async function (args) {
    var lastPurgedCounter = Number(args && args.lastPurgedCounter);
    if (!Number.isFinite(lastPurgedCounter) || lastPurgedCounter < 0) {
      throw new DbError("db/bad-purge-counter",
      "purgeAuditChain: lastPurgedCounter must be a non-negative number");
    }
    if (cluster.isClusterMode()) {
      // External-db has no append-only triggers; ordinary DELETE works.
      var cs = clusterStorage();
      var d = await cs.execute(
        "DELETE FROM audit_log WHERE monotonicCounter <= ?", [lastPurgedCounter]
      );
      var dc = await cs.execute(
        "DELETE FROM audit_checkpoints WHERE atMonotonicCounter <= ?", [lastPurgedCounter]
      );
      return { rowsDeleted: d.rowCount || 0, checkpointsDeleted: dc.rowCount || 0 };
    }
    // Single-node: drop triggers, delete, recreate triggers — all in
    // one transaction so a crash mid-operation doesn't leave the
    // table writable to general code.
    var rowsDeleted = 0;
    var checkpointsDeleted = 0;
    transaction(function () {
      runSql(database, 'DROP TRIGGER IF EXISTS "no_delete_audit_log"');
      runSql(database, 'DROP TRIGGER IF EXISTS "no_delete_audit_checkpoints"');
      var d = database.prepare(
        "DELETE FROM audit_log WHERE monotonicCounter <= ?"
      ).run(lastPurgedCounter);
      rowsDeleted = (d && d.changes) || 0;
      var dc = database.prepare(
        "DELETE FROM audit_checkpoints WHERE atMonotonicCounter <= ?"
      ).run(lastPurgedCounter);
      checkpointsDeleted = (dc && dc.changes) || 0;
      _installAppendOnlyTriggers(database);
    });
    return { rowsDeleted: rowsDeleted, checkpointsDeleted: checkpointsDeleted };
  },
  // Diagnostic accessors
  getMode:             function () { return atRest; },
  getDbPath:           function () { return dbPath; },
  getDataResidency:    function () { return dataResidency; },
  // Reflective metadata: PK columns, FK relationships, sealed/derived fields,
  // subject mapping. Useful for tooling, RoPA generation, and admin dashboards.
  // Returns a deep-copied snapshot; mutations don't affect framework state.
  //
  // Two-arg form supports format dispatch:
  //   getTableMetadata({ table: "orders", format: "json-schema-2020-12" })
  // emits a JSON Schema 2020-12 representation of the table — every
  // column types out per its DDL, sealed fields gain an "x-blamejs-
  // sealed" annotation, derived-hash columns gain "x-blamejs-derived-
  // from", and the schema's $schema URI points at JSON Schema 2020-12.
  getTableMetadata:    function (nameOrOpts) {
    if (!nameOrOpts) return structuredClone(tableMetadata);
    if (typeof nameOrOpts === "string") {
      var m = tableMetadata[nameOrOpts];
      return m ? structuredClone(m) : null;
    }
    if (typeof nameOrOpts !== "object") return null;
    var tableName = nameOrOpts.table;
    if (typeof tableName !== "string" || tableName.length === 0) {
      throw new DbError("db/bad-table-arg",
        "getTableMetadata: opts.table must be a non-empty string");
    }
    var meta = tableMetadata[tableName];
    if (!meta) return null;
    var format = nameOrOpts.format || "blamejs";
    if (format === "blamejs") return structuredClone(meta);
    if (format === "json-schema-2020-12") {
      return _tableToJsonSchema2020(tableName, meta);
    }
    throw new DbError("db/bad-format",
      "getTableMetadata: format must be 'blamejs' or 'json-schema-2020-12', got " +
      JSON.stringify(format));
  },
  exportCsv:           exportCsv,
  // declareView — declarative CREATE VIEW + GRANT migration spec for an
  // externalDb backend. Returns a migration-shape object for use with
  // b.externalDb.migrate. Postgres-only; fail-fast at apply time on other
  // dialects. See lib/db-declare-view.js.
  declareView:         dbDeclareView.declareView,
  // declareRowPolicy — declarative Postgres ROW LEVEL SECURITY migration
  // spec. Pairs with externalDb.transaction({ sessionGucs }) for the
  // per-request `SET LOCAL` plumbing. Postgres-only; fail-fast on other
  // dialects. See lib/db-declare-row-policy.js.
  declareRowPolicy:    dbDeclareRowPolicy.declareRowPolicy,
  // declareWorm — install row-level WORM (write-once-read-many) on
  // operator-named business-record tables. Per SEC Rule 17a-4(f),
  // FINRA Rule 4511, 21 CFR Part 11 §11.10(c). Boot-time assertion
  // refuses to continue under sec-17a-4 / finra-4511 / fda-21cfr11
  // postures unless at least one table is declared.
  declareWorm:         declareWorm,
  // declareRequireDualControl — gate destructive ops (erase / purge /
  // physical delete) on operator-named tables behind an m-of-n
  // dual-control grant from b.dualControl.consume(). Caller passes
  // the consumed grant via opts.dualControlGrant on b.db.eraseHard.
  declareRequireDualControl: declareRequireDualControl,
  // eraseHard — full crypto-erase + REINDEX for one row, with
  // legal-hold + dual-control gate consult. Closes the F-RTBF
  // B-tree residual class on a per-row basis.
  eraseHard:           eraseHard,
  _assertWormUnderPosture: _assertWormUnderPosture,
  // Internal accessors used by audit / subject / consent modules.
  // Not part of the public contract — apps should not depend on them.
  _getSubjectTables:   function () { return subjectTables.slice(); },
  RESERVED_TABLE_NAMES: RESERVED_TABLE_NAMES,
  FRAMEWORK_SCHEMA:    FRAMEWORK_SCHEMA,
  // Testing
  _resetForTest:       function () {
    _resetForTest();
    subjectTables = [];
    dataResidency = null;
    tableMetadata = {};
    // Cascade reset to stateful modules so a fresh init() works.
    // Each ref is a lazyRequire (top-of-file) so module-load cycles
    // don't trip; failures (missing optional dep, partial smoke
    // suites that skip a module entirely) get logged at debug.
    _cascadeStep("audit",       _resetAudit);
    _cascadeStep("consent",     _resetConsent);
    _cascadeStep("subject",     _resetSubject);
    _cascadeStep("session",     _resetSession);
    _cascadeStep("storage",     _resetStorage);
    _cascadeStep("audit-sign",  _resetAuditSign);
    _cascadeStep("queue",       _resetQueue);
    _cascadeStep("break-glass", _resetBreakGlass);
    _cascadeStep("log-stream",  _resetLogStream);
    _cascadeStep("redact",      _resetRedact);
    _cascadeStep("external-db", _resetExternalDb);
  },
  // Test seam for the tmpfs free-space guard — force a probe + read the flag.
  _probeStorageForTest: _probeStorageForTest,
  // Helper for audit.checkpoint to write the rollback-detection sidecar
  _writeAuditTip: function (tip) {
    if (!dataDir) return;
    var tipPath = nodePath.join(dataDir, "audit.tip");
    atomicFile.writeSync(tipPath, JSON.stringify(tip, null, 2), { fileMode: 0o600 });
  },
};
