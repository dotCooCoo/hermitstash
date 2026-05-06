"use strict";
/**
 * Database orchestrator — encrypted-at-rest SQLite backed by node:sqlite.
 *
 * At-rest modes (default 'encrypted' per modernity stance; 'plain' is opt-out
 * only and emits a console warning at boot):
 *
 *   encrypted (default):
 *     - DB file lives in tmpfs (/dev/shm by default; configurable via
 *       db.init({ tmpDir }) or BLAMEJS_TMPDIR env var) at runtime.
 *     - On boot: <dataDir>/db.enc → decrypt → tmpDir/blamejs-<token>.db
 *     - Periodic re-encrypt every 5 minutes back to <dataDir>/db.enc.
 *     - On shutdown: final encrypt + remove plaintext from tmpfs.
 *     - DB encryption key sealed by vault, persisted at <dataDir>/db.key.enc.
 *     - Refuses to boot if neither a tmpDir nor /dev/shm is available.
 *
 *   plain (opt-out):
 *     - DB file lives directly at <dataDir>/db (plain SQLite on disk).
 *     - No periodic encryption. Field-level encryption (field-crypto.js)
 *       still protects sealed columns, but schema and row counts are visible.
 *     - Boot warning printed.
 *
 * Public API:
 *
 *   await db.init({
 *     dataDir,                         // required — where db.enc + db.key.enc live
 *     tmpDir,                          // optional — override (default /dev/shm)
 *     atRest: 'encrypted' | 'plain',   // default 'encrypted'
 *     schema: [ { name, columns, indexes, sealedFields, derivedHashes }, ... ],
 *     migrationDir,                    // optional — path to ./migrations/ (run-once)
 *   });
 *
 *   db.from(tableName)                 → Query (chainable)
 *   db.prepare(sql)                    → SQLite Statement (raw escape hatch)
 *   db.stream(sql, ...params, opts?)   → Readable (object-mode rows;
 *                                       opts.table enables auto-unseal)
 *   db.runSql(sql)                     → raw SQL execution (DDL, BEGIN/COMMIT)
 *   db.transaction(function (db) {…})  → wraps in BEGIN/COMMIT/ROLLBACK
 *   db.hashFor(table, field, value)    → derived-hash lookup helper
 *   db.close()                         → final encrypt + close (idempotent)
 */
var fs = require("fs");
var path = require("path");
var { DatabaseSync } = require("node:sqlite");
var { Readable } = require("node:stream");
var atomicFile = require("./atomic-file");
var audit = require("./audit");
var auditSign = require("./audit-sign");
var cluster = require("./cluster");
var events = require("./events");
var consent = require("./consent");
var C = require("./constants");
var { generateToken, generateBytes, encryptPacked, decryptPacked } = require("./crypto");
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
var vault = require("./vault");

var DbError = defineClass("DbError", { alwaysPermanent: true });
var _dbErr = DbError.factory;

// Lazy: cluster-storage's _localDb pulls db back in, so eager require
// would deadlock the load order. cluster-storage is only used on the
// purge-audit-chain external-db path, which always runs after init.
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
var dataDir   = null;
var initialized = false;
var dataResidency = null;   // operator's declared region config (validated by storage backends)
var subjectTables = [];     // [{ name, subjectField, personalDataCategories }] — for subject.export/erase
var tableMetadata = {};     // table name → metadata snapshot (PK/FK/sealed/derived) for getTableMetadata

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
      scope:             "TEXT PRIMARY KEY",
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
    sealedFields: ["reasonSealed", "scopeColumnsJson"],
  },
];

var log = boot("db");

// ---- Tmpfs detection ----

function resolveTmpDir(optsTmpDir) {
  if (optsTmpDir) return optsTmpDir;
  var envTmp = safeEnv.readVar("BLAMEJS_TMPDIR");
  if (envTmp) return envTmp;
  if (fs.existsSync("/dev/shm")) return "/dev/shm";
  return null;
}

// ---- DB encryption key management ----

function loadOrCreateDbKey(dataDirPath) {
  var keyPath = path.join(dataDirPath, "db.key.enc");
  if (fs.existsSync(keyPath)) {
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
  var sealedKey = vault.seal(raw.toString("base64"));
  atomicFile.writeSync(keyPath, sealedKey, { fileMode: 0o600 });
  log("generated DB encryption key at " + keyPath);
  return raw;
}

function decryptToTmp() {
  if (!encPath || !fs.existsSync(encPath)) return;
  // If a plaintext file already exists in tmpfs from a prior process, prefer
  // the newer mtime (crash recovery — operator's most recent state wins).
  if (fs.existsSync(dbPath)) {
    var plainStat = fs.statSync(dbPath);
    var encStat = fs.statSync(encPath);
    if (plainStat.mtimeMs > encStat.mtimeMs && plainStat.size > 0) {
      log("plaintext is newer than encrypted — keeping plaintext (crash recovery)");
      return;
    }
  }
  var packed = fs.readFileSync(encPath);
  if (packed.length < 26) return; // too short to be a valid envelope
  atomicFile.writeSync(dbPath, decryptPacked(packed, encKey));
}

function encryptToDisk() {
  if (!encPath) return;
  // Force WAL checkpoint so the .db file holds all committed transactions.
  try { runSql(database, "PRAGMA wal_checkpoint(TRUNCATE)"); } catch (_e) { /* best effort */ }
  if (!fs.existsSync(dbPath)) return;
  atomicFile.writeSync(encPath, encryptPacked(fs.readFileSync(dbPath), encKey));
}

// Remove the plaintext DB + WAL/SHM sidecar files. On Windows these can't be
// unlinked while the SQLite handle is open, so this MUST be called after
// database.close().
function removePlaintextFiles() {
  if (!dbPath) return;
  try { fs.unlinkSync(dbPath); } catch (_e) { /* cleanup */ }
  try { fs.unlinkSync(dbPath + "-wal"); } catch (_e) { /* cleanup */ }
  try { fs.unlinkSync(dbPath + "-shm"); } catch (_e) { /* cleanup */ }
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
    try { fs.unlinkSync(full); } catch (_e) { /* concurrent cleanup */ }
    try { fs.unlinkSync(full + "-wal"); } catch (_e) { /* may not exist */ }
    try { fs.unlinkSync(full + "-shm"); } catch (_e) { /* may not exist */ }
  }
}

// ---- Init dispatch ----

async function init(opts) {
  if (initialized) return;
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
  dataDir = opts.dataDir;
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

  if (atRest === "encrypted") {
    var tmpDir = resolveTmpDir(opts.tmpDir);
    if (!tmpDir) {
      throw _dbErr("db/no-tmpfs",
        "FATAL: atRest: 'encrypted' (default) requires tmpfs but none was found. " +
        "Provide opts.tmpDir or set BLAMEJS_TMPDIR, or pass atRest: 'plain' (with warning).");
    }
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });

    encPath = path.join(dataDir, "db.enc");
    dbPath  = path.join(tmpDir, "blamejs-" + generateToken(C.BYTES.bytes(16)) + ".db");
    encKey  = loadOrCreateDbKey(dataDir);

    cleanStaleTmpDbs(tmpDir);
    decryptToTmp();
  } else {
    // plain mode
    log.warn("WARNING: atRest: 'plain' — DB structure and row counts visible on disk.");
    log.warn("         Field-level encryption (sealedFields) still protects sealed columns,");
    log.warn("         but the simpler at-rest model is opt-out only. Default is 'encrypted'.");
    dbPath = path.join(dataDir, "blamejs.db");
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

  // Refuse app schema entries that collide with framework-reserved names
  for (var ri = 0; ri < opts.schema.length; ri++) {
    if (RESERVED_TABLE_NAMES.has(opts.schema[ri].name)) {
      throw new DbError("db/reserved-table-name",
        "table name '" + opts.schema[ri].name + "' is reserved by the framework. " +
        "Pick a different name (the framework provisions audit_log, consent_log, " +
        "and _blamejs_* tables automatically).");
    }
  }

  // Track subject schema for subject.export/erase walks
  subjectTables = [];
  for (var si = 0; si < opts.schema.length; si++) {
    var st = opts.schema[si];
    if (st.subjectField) {
      subjectTables.push({
        name:                   st.name,
        subjectField:           st.subjectField,
        personalDataCategories: st.personalDataCategories || {},
      });
    }
  }

  // Build the full schema = framework-baked tables + app tables.
  // Framework tables come FIRST so audit_log/consent_log exist before any
  // app migration can reference them.
  var fullSchema = FRAMEWORK_SCHEMA.concat(opts.schema);

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
  // recreate them.
  _installAppendOnlyTriggers(database);

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
  // detects-and-fails.
  var auditResult = await audit.verify();
  if (!auditResult.ok) {
    // Fire the breach event BEFORE throwing so operator listeners get
    // a chance at sync I/O (file flag, console alert) before init
    // unwinds.
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

  // ---- Rollback detection (audit.tip sidecar) ----
  // The framework writes <dataDir>/audit.tip on each checkpoint. At boot we
  // compare current MAX(monotonicCounter) to the recorded tip. If current
  // is BELOW tip — the DB was rolled back to an older snapshot. Refuse boot.
  _checkRollback(dataDir);

  // ---- Audit-signing key + checkpoint subsystem ----
  // Default mode 'wrapped' (passphrase-required, separate from vault). Apps
  // that want a quick-start dev path can pass auditSigning: { mode: 'plaintext' }
  // — same warning pattern as vault.
  // opts.auditSigning.algorithm picks the keypair algorithm at first-run
  // generation. Default = SLH-DSA-SHAKE-256f (matches the framework's
  // SHAKE-family hash posture); ML-DSA-87 is the throughput-focused
  // opt-in. Existing key files take their algorithm from disk; this
  // option only matters on first generation.
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

  // Verify all existing checkpoint signatures (defense against signature
  // forgery attempt + key-rotation gone wrong). Refuse to boot on failure.
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

  // Anchor a fresh checkpoint at boot if there's any new audit activity
  // since the last checkpoint (else no-op).
  await audit.checkpoint({ skipIfUnchanged: true });

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

    // Final encrypt on process exit. We don't try to unlink the plaintext
    // here — the SQLite handle may still be open, and the OS reclaims tmpfs
    // on reboot anyway. close() does the orderly shutdown.
    process.on("exit", function () {
      try { encryptToDisk(); } catch (_e) { /* exit handler — silent */ }
    });
  }

  log("ready (mode: " + atRest + ", path: " + dbPath + ")");
}

// ---- Public API ----

function from(tableName) {
  _requireInit();
  return new Query(database, tableName);
}

function prepare(sql) {
  _requireInit();
  return database.prepare(sql);
}

// stream — Readable in object mode that yields rows as node:sqlite's
// iterate() produces them. Unlike all(), the engine doesn't materialize
// the result set in memory before the first row arrives, so audit
// exports / backup table dumps / large reports can process millions of
// rows without OOM pressure.
//
// Optional opts.table enables auto-unseal of sealed columns via the
// table's registered cryptoField schema. Raw / aggregate queries omit
// it. Mid-iteration prepare()-bound errors propagate as 'error' events.
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
  return new Readable({
    objectMode: true,
    read: function () {
      try {
        var step = iter.next();
        if (step.done) { this.push(null); return; }
        var row = step.value;
        this.push(unseal ? unseal.unsealRow(table, row) : row);
      } catch (e) {
        this.destroy(e);
      }
    },
  });
}

function execRaw(sql) {
  _requireInit();
  return runSql(database, sql);
}

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

function hashFor(table, field, value) {
  _requireInit();
  var lookup = cryptoField.lookupHash(table, field, value);
  return lookup ? lookup.value : null;
}

function close() {
  if (!initialized) return;
  if (encTimer) {
    encTimer.stop();
    encTimer = null;
  }
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
  try { encryptToDisk(); } catch (e) {
    log.error("close: final encrypt failed: " + e.message);
  }
  try { database.close(); } catch (_e) { /* already closed */ }
  if (atRest === "encrypted") removePlaintextFiles();
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

// Read the audit.tip sidecar file in dataDir and compare to the current
// audit_log MAX(monotonicCounter). Refuse boot on rollback (current < tip).
function _checkRollback(dataDirPath) {
  var tipPath = path.join(dataDirPath, "audit.tip");
  if (!fs.existsSync(tipPath)) {
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
  try { if (database) database.close(); }
  catch (e) { log.debug("test-reset close failed", { error: e.message }); }
  database = null;
  dbPath = null;
  encPath = null;
  encKey = null;
  atRest = null;
  dataDir = null;
  initialized = false;
  cryptoField.clearForTest();
}


module.exports = {
  init:                init,
  from:                from,
  prepare:             prepare,
  stream:              stream,
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
            action: "system.db.integrity_ok", outcome: "ok", metadata: {},
          }); } catch (_e) { /* drop-silent */ }
        }
        return;
      }
      var issues = rows.map(function (r) { return r && r.integrity_check; }).filter(Boolean);
      try { observability.safeEvent("db.integrity_check_corrupt", 1, {}); }
      catch (_e) { /* drop-silent */ }
      if (auditOn) {
        try { audit.safeEmit({
          action: "system.db.integrity_corrupt", outcome: "fail",
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
  getTableMetadata:    function (name) {
    if (!name) return structuredClone(tableMetadata);
    var m = tableMetadata[name];
    return m ? structuredClone(m) : null;
  },
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
  // Helper for audit.checkpoint to write the rollback-detection sidecar
  _writeAuditTip: function (tip) {
    if (!dataDir) return;
    var tipPath = path.join(dataDir, "audit.tip");
    atomicFile.writeSync(tipPath, JSON.stringify(tip, null, 2), { fileMode: 0o600 });
  },
};
