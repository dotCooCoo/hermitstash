// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var nodeUrl = require("node:url");
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
var { Query, _isRawWriteToResidencyTable, _assertRawWriteResidency, _stripLeadingSqlComments } = require("./db-query");
var dbSchema = require("./db-schema");
var { defineClass } = require("./framework-error");
var frameworkFiles = require("./framework-files");
var frameworkSchema = require("./framework-schema");
var safeMountInfo = require("./safe-mount-info");
var { boot } = require("./log");
var lazyRequire = require("./lazy-require");
var observability = require("./observability");
var ntpCheck = lazyRequire(function () { return require("./ntp-check"); });
var safeAsync = require("./safe-async");
var safeEnv = require("./parsers/safe-env");
var safeJson = require("./safe-json");
var safeSql = require("./safe-sql");
var sql = require("./sql");
var validateOpts = require("./validate-opts");
var pidProbe = require("./pid-probe");
var vault = require("./vault");
var vaultAad = require("./vault-aad");

var _SQL_OPTS = { dialect: "sqlite", quoteName: true };

var DbError = defineClass("DbError", { alwaysPermanent: true });

var OWNER_SUFFIX = ".owner";
var workingCopyClaimed = false;
var WormViolationError = require("./framework-error").WormViolationError;
var _wormErr = WormViolationError.factory;

// Lazy: compliance and dual-control read state at runtime; both are
// non-load-time deps so a top-of-file require would not cycle, but
// they're only needed on declareWorm / declareRequireDualControl /
// eraseHard. Lazy keeps the load graph minimal.
var compliance = lazyRequire(function () { return require("./compliance"); });

var WORM_POSTURES = Object.freeze(["sec-17a-4", "finra-4511", "fda-21cfr11"]);
var _dbErr = DbError.factory;

// Lazy: cluster-storage's _localDb pulls db back in, so eager require
// would deadlock the load order. cluster-storage is only used on the
// purge-audit-chain external-db nodePath, which always runs after init.
var clusterStorage = lazyRequire(function () { return require("./cluster-storage"); });
// audit-tools requires db.js back (for the purge DELETE), so this one is lazy
// to break the cycle rather than by preference — see the top-of-file rule.
var auditTools = lazyRequire(function () { return require("./audit-tools"); });

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

var database  = null;
var dbPath    = null;
var encPath   = null;
var encKey    = null;
var encTimer  = null;
var atRest    = null;
var storageProbeTimer = null;
var writesRefused = false;
var minFreeBytes  = 0;
var statfsProbe   = null;
var _exitHandlerRegistered = false;
var readOnly  = false;
var immutableOpen = false;
var dataDir   = null;
var initialized = false;
var _dbGenerationCounter = 0;
function dbGeneration() { return _dbGenerationCounter; }
var dataResidency = null;
var subjectTables = [];
var tableMetadata = {};
var streamLimit = C.BYTES.bytes(1000000);
var columnGateMode = "reject";

// literal names ARE the contract. allow:hand-rolled-sql markers below.
var RESERVED_TABLE_NAMES = new Set([
  "audit_log",
  "audit_checkpoints",
  "consent_log",
  "_blamejs_subject_restrictions",   // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_subject_erasures",       // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_sessions",               // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_session_valid_from",     // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_jobs",                   // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_migrations",             // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_counters",               // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_audit_purge_anchor",     // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_scheduler_ticks",        // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_rate_limit_counters",    // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_pubsub_messages",        // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_api_encrypt_nonces",     // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_api_keys",               // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_cache",                  // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_seeders",                // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_seeders_lock",           // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_break_glass_policies",   // allow:hand-rolled-sql — canonical reserved local table-name declaration
  "_blamejs_break_glass_grants",     // allow:hand-rolled-sql — canonical reserved local table-name declaration
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
    name: "_blamejs_subject_restrictions",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
    columns: {
      subjectIdHash: "TEXT PRIMARY KEY",
      since:         "INTEGER NOT NULL",
      reason:        "TEXT",
    },
    sealedFields: ["reason"],
  },
  {
    name: "_blamejs_subject_erasures",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
    columns: {
      subjectIdHash: "TEXT PRIMARY KEY",
      erasedAt:      "INTEGER NOT NULL",
    },
  },
  {
    name: "_blamejs_legal_hold",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
    columns: {
      subjectIdHash: "TEXT PRIMARY KEY",
      placedAt:      "INTEGER NOT NULL",
      placedBy:      "TEXT",
      reason:        "TEXT NOT NULL",
      custodian:     "TEXT",
      citation:      "TEXT",
      retainUntil:   "INTEGER",
    },
    sealedFields: ["reason", "placedBy", "custodian", "citation"],
    indexes: ["placedAt"],
  },
  {
    name: "_blamejs_per_row_keys",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
    columns: {
      _id:        "TEXT",
      tableName:  "TEXT NOT NULL",
      rowId:      "TEXT NOT NULL",
      wrappedKey: "BLOB NOT NULL",
      createdAt:  "INTEGER NOT NULL",
    },
    primaryKey: ["tableName", "rowId"],
    indexes: [],
    sealedFields:  ["wrappedKey"],
    aad:           true,
    rowIdField:    "rowId",
    schemaVersion: "1",
  },
  {
    name: "_blamejs_worm_tables",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
    columns: {
      tableName: "TEXT PRIMARY KEY",
      posture:   "TEXT",
      declaredAt: "INTEGER NOT NULL",
    },
  },
  {
    name: "_blamejs_dual_control_gates",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
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
    name: "_blamejs_audit_purge_anchor",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
    columns: {
      scope:             "TEXT PRIMARY KEY CHECK (scope IN ('audit', 'consent'))",
      lastPurgedCounter: "INTEGER NOT NULL",
      lastPurgedRowHash: "TEXT NOT NULL",
      archiveBundleId:   "TEXT NOT NULL",
      purgedAt:          "INTEGER NOT NULL",
      firstPurgedCounter:   "INTEGER NOT NULL DEFAULT 0",
      archiveRowsDigest:    "TEXT",
      archiveCheckpointDigest: "TEXT",
      archiveManifestDigest: "TEXT",
      signature:            "BLOB",
      publicKeyFingerprint: "TEXT",
      fencingToken:         "INTEGER NOT NULL DEFAULT 0",
    },
    sealedFields: [],
  },
  {
    name: "_blamejs_scheduler_ticks",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
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
    name: "_blamejs_rate_limit_counters",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
    columns: {
      key:         "TEXT PRIMARY KEY",
      windowStart: "INTEGER NOT NULL",
      count:       "INTEGER NOT NULL DEFAULT 0",
    },
    indexes: ["windowStart"],
    sealedFields: [],
  },
  {
    name: "_blamejs_pubsub_messages",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
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
    name: "_blamejs_api_encrypt_nonces",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
    columns: {
      nonceHash: "TEXT PRIMARY KEY",
      expireAt:  "INTEGER NOT NULL",
    },
    indexes: ["expireAt"],
    sealedFields: [],
  },
  {
    name: "_blamejs_sessions",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
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
    name: "_blamejs_session_valid_from",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
    columns: {
      subjectHash:    "TEXT PRIMARY KEY",
      validFromEpoch: "INTEGER NOT NULL",
      updatedAt:      "INTEGER NOT NULL",
    },
    indexes: [],
    sealedFields: [],
  },
  {
    name: "_blamejs_api_keys",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
    columns: {
      id:                  "TEXT PRIMARY KEY",
      namespace:           "TEXT NOT NULL",
      ownerId:             "TEXT NOT NULL",
      ownerIdHash:         "TEXT NOT NULL",
      secretHash:          "TEXT NOT NULL",
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
    aad:           true,
    rowIdField:    "id",
  },
  {
    name: "_blamejs_jobs",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
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
      repeatCron:      "TEXT",
      repeatTimezone:  "TEXT",
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
    name: "_blamejs_cache",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
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
    name: "_blamejs_cache_tags",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
    columns: {
      cacheKey:   "TEXT NOT NULL",
      tag:        "TEXT NOT NULL",
    },
    primaryKey: ["cacheKey", "tag"],
    indexes:    ["tag"],
    sealedFields: [],
  },
  {
    name: "_blamejs_seeders",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
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
    name: "_blamejs_seeders_lock",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
    columns: {
      scope:    "TEXT PRIMARY KEY CHECK (scope = 'lock')",
      lockedAt: "INTEGER NOT NULL",
      lockedBy: "TEXT NOT NULL",
    },
    sealedFields: [],
  },
  {
    name: "_blamejs_break_glass_policies",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
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
    name: "_blamejs_break_glass_grants",   // allow:hand-rolled-sql — canonical local-schema table-name declaration
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

function _resolveTmpDirFrom(optsTmpDir, platform, exists) {
  if (optsTmpDir) return optsTmpDir;
  var envTmp = safeEnv.readVar("BLAMEJS_TMPDIR");
  if (envTmp) return envTmp;
  if (platform !== "linux") return null;
  if (exists("/dev/shm")) return "/dev/shm";
  return null;
}

function resolveTmpDir(optsTmpDir) {
  return _resolveTmpDirFrom(optsTmpDir, process.platform, nodeFs.existsSync);
}

function _tmpDirResidencyIssue(tmpDir, platform, realpath, readMountInfo) {
  if (platform !== "linux") {
    return {
      determined: false,
      message: "db.init: tmpDir '" + tmpDir + "' cannot be shown to be an in-memory " +
        "mount on " + platform + " — the tmpfs heuristic compares against /dev/shm " +
        "/run/shm /run/user /tmp, which are Linux mounts. If it is disk-backed, the " +
        "decrypted working copy reaches backup snapshots, replication, and forensic " +
        "disk images; verify the mount is in-memory out-of-band, or pass " +
        "atRest: 'plain' if encryption-at-rest is not required.",
    };
  }
  var realTmp = "";
  try { realTmp = realpath(tmpDir); } catch (_e) { /* stat best-effort */ }

  var entries = null;
  try { entries = safeMountInfo.parse(readMountInfo()); }
  catch (_e) { entries = null; }
  if (!entries || entries.length === 0) {
    return {
      determined: false,
      message: "db.init: tmpDir '" + tmpDir + "' (real: '" + realTmp + "') could not be " +
        "classified — the mount table was unreadable, so whether this path is in memory " +
        "is unknown. If it is disk-backed, the decrypted working copy reaches backup " +
        "snapshots, replication, and forensic disk images; verify the mount out-of-band, " +
        "or pass atRest: 'plain' if encryption-at-rest is not required.",
    };
  }
  var mount = safeMountInfo.bestMatch(entries, realTmp);
  var fstype = mount && mount.fstype ? String(mount.fstype) : "";
  if (fstype === "tmpfs" || fstype === "ramfs") return null;
  return {
    determined: true,
    message: "db.init: tmpDir '" + tmpDir + "' (real: '" + realTmp + "') is on " +
      (fstype ? "a '" + fstype + "' filesystem" : "no identifiable mount") +
      (mount && mount.mountPoint ? " mounted at '" + mount.mountPoint + "'" : "") +
      ", not tmpfs or ramfs — it is not an in-memory mount. A persistent-disk " +
      "tmpDir leaks the decrypted working copy into backup snapshots, replication, " +
      "and forensic disk images.",
  };
}

function _dbKeyAad(dataDirPath, keyPath) {
  return vaultAad.buildContextAad({
    purpose: "blamejs/db-encryption-key/v1",
    dataDir: nodePath.resolve(dataDirPath),
    keyPath: nodePath.resolve(keyPath),
  });
}

function loadOrCreateDbKey(dataDirPath, keyPathOverride) {
  var keyPath = keyPathOverride || nodePath.join(dataDirPath, frameworkFiles.fileName("dbKeyEnc"));
  var aad = _dbKeyAad(dataDirPath, keyPath);
  if (nodeFs.existsSync(keyPath)) {
    var sealed = atomicFile.readSync(keyPath, { encoding: "utf8", maxBytes: C.BYTES.kib(64) }).trim();
    var b64;
    if (vaultAad.isAadSealed(sealed)) {
      b64 = vaultAad.unseal(sealed, aad);
    } else {
      b64 = vault.unseal(sealed);
      if (b64 && !readOnly) {
        atomicFile.writeSync(keyPath, vaultAad.seal(b64, aad), { fileMode: 0o600 });
        log("re-sealed DB encryption key with deployment-path binding at " + keyPath);
      }
    }
    if (!b64) {
      throw _dbErr("db/key-unseal-empty",
        "FATAL: db.key.enc unseal returned empty — vault may not be initialized or key file corrupted");
    }
    return Buffer.from(b64, "base64");
  }
  if (readOnly) {
    throw _dbErr("db/read-only-no-key",
      "readOnly: no encryption key at " + keyPath + " — a read-only open reads an " +
      "existing encrypted volume and will not create one");
  }
  var raw = generateBytes(C.BYTES.bytes(32));
  var sealedKey = vaultAad.seal(raw.toString("base64"), aad);
  atomicFile.writeSync(keyPath, sealedKey, { fileMode: 0o600 });
  log("generated DB encryption key at " + keyPath);
  return raw;
}

function decryptToTmp() {
  if (!encPath || !nodeFs.existsSync(encPath)) return;
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
  var packed = atomicFile.fdSafeReadSync(encPath, { maxBytes: C.BYTES.gib(2) });
  if (packed.length < 1 + C.BYTES.bytes(24) + C.BYTES.bytes(16)) {
    throw _dbErr("db/enc-truncated",
      "FATAL: db.enc exists but is only " + packed.length + " byte(s) — too short to be " +
      "a valid encrypted snapshot; refusing to start a fresh database over a corrupt durable " +
      "copy (restore db.enc from backup, or remove it to intentionally start empty)");
  }
  var aad = _dbEncAad(dataDir);
  try {
    atomicFile.writeSync(dbPath, decryptPacked(packed, encKey, aad));
  } catch (_e) {
    atomicFile.writeSync(dbPath, decryptPacked(packed, encKey));
  }
}

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

function _isGrowthWrite(sql) {
  if (typeof sql !== "string") return false;
  var s = _stripLeadingSqlComments(sql);
  if (/^\s*(?:INSERT|UPDATE|REPLACE)\b/i.test(s)) return true;
  if (/^\s*(?:WITH|EXPLAIN)\b/i.test(s) &&
      /\b(?:(?:INSERT|REPLACE|MERGE)\s+(?:OR\s+[A-Za-z]+\s+)?INTO|UPDATE\s+[\w".`]+\s+SET)\b/i.test(s)) return true;
  return false;
}

function _installWriteGate() {
  var rawPrepare = database.prepare.bind(database);
  database.prepare = function (sql) {
    var stmt = rawPrepare(sql);
    if (_isGrowthWrite(sql)) {
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

function _walNotDrainedFrom(forPath, canCheckpoint, stat, checkpoint) {
  var walStat = null;
  try { walStat = stat(forPath + "-wal"); }
  catch (e) {
    if (e && e.code === "ENOENT") return null;
    return "the write-ahead log '" + forPath + "-wal' could not be read (" +
      ((e && e.code) || "unknown error") + "), so whether the database file holds " +
      "every committed transaction cannot be established";
  }
  if (walStat.size === 0) return null;

  if (!canCheckpoint) {
    return "'" + forPath + "-wal' holds " + walStat.size + " byte(s) and this handle " +
      "cannot checkpoint, so whether those frames are already in the database file " +
      "cannot be established without writing";
  }

  var row = null;
  try { row = checkpoint(); }
  catch (e) {
    return "the checkpoint that folds the write-ahead log into the database file " +
      "failed (" + ((e && e.message) || String(e)) + ")";
  }
  if (!row) return null;
  if (Number(row.busy) !== 0) {
    return "the checkpoint could not run to completion because the database was busy, " +
      "so '" + forPath + "-wal' may hold transactions the database file does not";
  }
  var frames = Number(row.log) || 0;
  var moved  = Number(row.checkpointed) || 0;
  if (frames > moved) {
    return "the checkpoint left " + (frames - moved) + " of " + frames + " frame(s) in '" +
      forPath + "-wal', so the database file does not carry every committed transaction";
  }
  return null;
}

function _walNotDrained(forPath, canCheckpoint) {
  return _walNotDrainedFrom(forPath, canCheckpoint, nodeFs.statSync, function () {
    return database.prepare("PRAGMA wal_checkpoint(TRUNCATE)").all()[0];
  });
}

function encryptToDisk() {
  if (!encPath) return;
  if (readOnly) return;
  if (!database) return;
  if (!nodeFs.existsSync(dbPath)) {
    throw new DbError("db/working-copy-missing",
      "db flush: the encrypted-mode working copy " + dbPath + " no longer exists, so " +
      "nothing can be written to " + encPath + ". Writes made since the last successful " +
      "flush are still in this process's open file and are NOT on disk. Another process " +
      "sharing this tmpDir most likely removed it; give each process its own tmpDir, or " +
      "run one process per volume.");
  }
  var unflushedWal = _walNotDrained(dbPath, true);
  if (unflushedWal) {
    throw new DbError("db/flush-pending-wal",
      "db flush: " + unflushedWal + ". Writing the working copy to " + encPath +
      " would store a volume that opens cleanly while missing the most recent " +
      "writes; retry once the writer is idle.");
  }
  atomicFile.writeSync(encPath, encryptPacked(atomicFile.fdSafeReadSync(dbPath, { maxBytes: C.BYTES.gib(2) }), encKey, _dbEncAad(dataDir)));
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
 *   // requires: write access to the backup directory below
 *   var b = require("@blamejs/core");
 *   var snap = b.db.snapshot();
 *   var store = b.objectStore.buildBackend({ protocol: "local", rootDir: "/srv/backups" });
 *   await store.put("backups/" + Date.now() + ".enc", snap);
 */
function snapshot() {
  _requireInit();
  var pendingWal = _walNotDrained(dbPath, !readOnly);
  if (pendingWal) {
    throw _dbErr("db/snapshot-pending-wal",
      "snapshot: " + pendingWal + ", so a copy of the database file would be missing " +
      "the most recent rows while still opening cleanly." +
      (readOnly
        ? " Take the snapshot from a handle that can write, or checkpoint the volume " +
          "before opening it readOnly."
        : " Retry once the writer is idle."));
  }
  if (!nodeFs.existsSync(dbPath)) {
    throw _dbErr("db/snapshot-no-source",
      "snapshot: plaintext DB at " + dbPath + " is missing — did init complete?");
  }
  var plain = atomicFile.fdSafeReadSync(dbPath, { maxBytes: C.BYTES.gib(2) });
  if (!encPath || !encKey) {
    return plain;
  }
  return encryptPacked(plain, encKey, _dbEncAad(dataDir));
}

function removePlaintextFiles() {
  if (!dbPath) return;
  workingCopyClaimed = false;
  if (database) {
    try { database.close(); } catch (_e) { /* already closed */ }
    database = null;
  }
  try { nodeFs.unlinkSync(dbPath); } catch (_e) { /* cleanup */ }
  try { nodeFs.unlinkSync(dbPath + "-wal"); } catch (_e) { /* cleanup */ }
  try { nodeFs.unlinkSync(dbPath + "-shm"); } catch (_e) { /* cleanup */ }
  try { nodeFs.unlinkSync(dbPath + OWNER_SUFFIX); } catch (_e) { /* cleanup */ }
}

var _opaqueNamespace = null;
function _namespaceFrom(platform, readlink) {
  if (platform !== "linux") return "host";
  try { return String(readlink("/proc/self/ns/pid")); }
  catch (_e) { /* decided below — /proc is unmounted or restricted */ }
  if (!_opaqueNamespace) _opaqueNamespace = "unreadable-ns:" + generateToken(16);
  return _opaqueNamespace;
}

function _ownerNamespace() {
  return _namespaceFrom(process.platform, nodeFs.readlinkSync);
}

function _anchorCheckpoint() {
  if (readOnly) return Promise.resolve(null);
  return audit.checkpoint({ skipIfUnchanged: true });
}

function _tmpDbOwnerAlive(workingCopyPath) {
  var raw;
  try {
    raw = atomicFile.fdSafeReadSync(workingCopyPath + OWNER_SUFFIX, {
      maxBytes: C.BYTES.kib(1), refuseSymlink: true, encoding: "utf8",
    });
  } catch (_e) { return null; }
  var parts = String(raw).trim().split(" ");
  if (parts.length !== 2) return null;
  if (parts[0] !== _ownerNamespace()) return null;
  var pid = parseInt(parts[1], 10);
  if (!isFinite(pid) || pid <= 0) return null;
  return pidProbe.isLivePid(pid);
}

function cleanStaleTmpDbs(tmpDir) {
  var bases = Object.create(null);
  atomicFile.listDir(tmpDir, {
    filter: function (name) {
      return name.startsWith("blamejs-") &&
        (name.endsWith(".db") || name.endsWith(".db" + OWNER_SUFFIX));
    },
  }).forEach(function (entry) {
    var full = entry.fullPath;
    var base = full.endsWith(OWNER_SUFFIX)
      ? full.slice(0, full.length - OWNER_SUFFIX.length) : full;
    bases[base] = true;
  });
  var entries = Object.keys(bases).sort().map(function (base) {   // allow:bare-canonicalize-walk
    return { fullPath: base };
  });
  for (var i = 0; i < entries.length; i++) {
    var full = entries[i].fullPath;
    if (full === dbPath) continue;
    if (!nodeFs.existsSync(full)) {
      if (_tmpDbOwnerAlive(full) === true) {
        log("leaving ownership record for " + full + " (owner still running, working copy not yet created)");
        continue;
      }
      try { nodeFs.unlinkSync(full + OWNER_SUFFIX); } catch (_e) { /* concurrent cleanup */ }
      continue;
    }
    var alive = _tmpDbOwnerAlive(full);
    if (alive !== false) {
      log("leaving working copy " + full +
          (alive === null ? " (owner unknown)" : " (owner still running)"));
      continue;
    }
    try { nodeFs.unlinkSync(full); } catch (_e) { /* concurrent cleanup */ }
    try { nodeFs.unlinkSync(full + "-wal"); } catch (_e) { /* may not exist */ }
    try { nodeFs.unlinkSync(full + "-shm"); } catch (_e) { /* may not exist */ }
    try { nodeFs.unlinkSync(full + OWNER_SUFFIX); } catch (_e) { /* may not exist */ }
  }
}

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
 *   immutable:               boolean,           // default false — requires `readOnly` and `atRest: "plain"`. Declares that NOTHING writes this volume while it is open, so SQLite reads it without creating the `-wal` / `-shm` pair it otherwise needs for a WAL-mode database. That pair is what makes a plain read-only open fail on a read-only mount. Only the operator can make this claim: if a writer is in fact active, the reader's view is undefined rather than merely stale, which is why it is never inferred.
 *   readOnly:                boolean,           // default false — open without ever writing back. Under `atRest: "encrypted"` two processes sharing one volume each decrypt their own working copy, so whichever flushes last overwrites the other's writes; a reader takes no part in that. SQLite refuses writes too, so a stray one fails where it is issued.
 *   tmpDir:                  string,            // the encrypted-mode tmpfs path. Defaults to `BLAMEJS_TMPDIR`, then to `/dev/shm` on Linux only — off Linux nothing is inferred and encrypted mode refuses with `db/no-tmpfs` until one of the two names a mount.
 *   allowNonTmpfsTmpDir:     boolean,           // default false — on Linux, where the mount table can be compared against, encrypted mode THROWS when tmpDir resolves outside the recognized tmpfs mounts (plaintext-on-disk leak); pass true to downgrade that to a warning when the mount is verified in-memory out-of-band. Off Linux the mount cannot be classified, so an operator-named path is always taken with a warning and this option changes nothing.
 *   migrationDir:            string,            // optional — path to ./migrations/ (run-once each)
 *   streamLimit:             number,            // default 1_000_000 — db.stream row ceiling
 *   columnGate:              "reject"|"warn"|"off", // default "reject" — refuse queries on columns not declared in the table schema
 *   skipBootIntegrityCheck:  boolean,           // default false — skip PRAGMA integrity_check
 *   skipIntegrityCheck:      boolean,           // default false — alias
 *   auditSigning:            { mode, algorithm }, // default { mode: "wrapped" }
 *   acceptUnsignedPurgeAnchor: boolean,        // default: false — one boot only; signs an anchor left unsigned by an earlier version, then does nothing. Refused with `readOnly` — it writes
 *   acceptRotatedPurgeAnchorKey: boolean,      // default: false — one boot only; re-signs, under the live key, an anchor still naming a key that was rotated out. For a rotation interrupted before `b.auditTools.signExistingPurgeAnchor()` ran. The existing signature must verify under the rotated key first, so a tampered anchor is refused rather than laundered. Refused with `readOnly` — it writes
 *   purgeAnchorPublicKey:    string,           // PEM. The key a purge anchor must be signed under, for a deployment running `auditSigning: false`: no key is loaded there, and the volume's own public-key history is unsealed, so nothing on disk can say which key was AUTHORIZED. Supply one and the anchor is verified against it — a trust root the operator chose, bound to the fingerprint the anchor names. Without it the anchor reports as unchecked rather than verified
 *   resolvePurgeArchive:     function,         // (archiveBundleId, { firstCounter, lastCounter, lastRowHash }) => truthy if that archive can still be produced; boot refuses a purge boundary whose archive has gone missing. Several slices can share the checkpoint that covers them, and so share the identifier — match the range too, or a surviving sibling answers for the one that went missing
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
async function _initReleasingClaimOnFailure(opts) {
  try {
    return await init(opts);
  } catch (e) {
    if (initialized) {
      try { _shutdown(false); } catch (_e) { /* the caller's error is the refusal, not this */ }
    } else if (workingCopyClaimed) {
      try { removePlaintextFiles(); } catch (_e) { /* best effort on a failing path */ }
    }
    throw e;
  }
}

async function init(opts) {
  if (initialized) return;
  workingCopyClaimed = false;
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
  validateOpts.optionalBoolean(opts.readOnly, "db.init: readOnly",
    DbError, "db/bad-read-only");
  readOnly = opts.readOnly === true;
  validateOpts.optionalBoolean(opts.immutable, "db.init: immutable",
    DbError, "db/bad-immutable");
  immutableOpen = opts.immutable === true;
  if (readOnly && opts.acceptUnsignedPurgeAnchor === true) {
    throw new DbError("db/bad-accept-unsigned-purge-anchor",
      "db.init: acceptUnsignedPurgeAnchor signs the existing anchor in place, " +
      "which a readOnly open cannot do. Run the repair once on a writable open, " +
      "then read the volume.");
  }
  var pinnedAnchorResolver = null;
  if (opts.purgeAnchorPublicKey !== undefined && opts.purgeAnchorPublicKey !== null) {
    validateOpts.requireNonEmptyString(opts.purgeAnchorPublicKey,
      "db.init: purgeAnchorPublicKey", DbError, "db/bad-purge-anchor-public-key");
    try {
      pinnedAnchorResolver = auditSign.pinnedKeyResolver(opts.purgeAnchorPublicKey);
    } catch (e) {
      throw new DbError("db/bad-purge-anchor-public-key",
        "db.init: purgeAnchorPublicKey is not a readable PEM public key: " +
        ((e && e.message) || String(e)));
    }
  }
  if (readOnly && opts.acceptRotatedPurgeAnchorKey === true) {
    throw new DbError("db/bad-accept-rotated-purge-anchor-key",
      "db.init: acceptRotatedPurgeAnchorKey re-signs the existing anchor in " +
      "place, which a readOnly open cannot do. Run the repair once on a " +
      "writable open, then read the volume.");
  }
  validateOpts.definedFunction(opts.resolvePurgeArchive, "db.init: resolvePurgeArchive",
    DbError, "db/bad-resolve-purge-archive");
  if (immutableOpen && !readOnly) {
    throw new DbError("db/bad-immutable",
      "db.init: immutable requires readOnly: true — it declares the volume will " +
      "not change, which says nothing about a handle that may write to it");
  }
  if (immutableOpen && atRest !== "plain") {
    throw new DbError("db/bad-immutable",
      "db.init: immutable applies to atRest: 'plain', where the volume is the " +
      "file opened. Under 'encrypted' the handle opens a working copy this " +
      "process just decrypted, so there is nothing for the operator to declare");
  }
  if (opts.streamLimit !== undefined) {
    require("./numeric-bounds").requirePositiveFiniteIntIfPresent(opts.streamLimit,
      "db.init: streamLimit", DbError, "db/bad-init");
    streamLimit = opts.streamLimit;
  }
  if (opts.columnGate !== undefined &&
      opts.columnGate !== "reject" && opts.columnGate !== "warn" && opts.columnGate !== "off") {
    throw new DbError("db/bad-init",
      "db.init: columnGate must be 'reject' (default), 'warn', or 'off'; got " +
      JSON.stringify(opts.columnGate));
  }
  columnGateMode = opts.columnGate || "reject";
  if (opts.tablePrefix !== undefined) {
    frameworkSchema.setTablePrefix(opts.tablePrefix);
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

    var residencyIssue = _tmpDirResidencyIssue(tmpDir, process.platform, nodeFs.realpathSync,
      function () { return nodeFs.readFileSync(safeMountInfo.DEFAULT_PATH, "utf8"); });
    if (residencyIssue) {
      if (residencyIssue.determined && opts.allowNonTmpfsTmpDir !== true) {
        throw _dbErr("db/tmpdir-not-tmpfs", "FATAL: " + residencyIssue.message +
          " Mount a tmpfs at the path (or set BLAMEJS_TMPDIR / opts.tmpDir to one), " +
          "or pass opts.allowNonTmpfsTmpDir: true to accept the disk-residency tradeoff, " +
          "or pass atRest: 'plain' if encryption-at-rest is not required.");
      }
      log.warn("WARNING: " + residencyIssue.message +
        (residencyIssue.determined
          ? " (allowNonTmpfsTmpDir:true — verify the mount is in-memory out-of-band.)"
          : ""));
    }

    encPath = opts.encryptedDbPath ||
              nodePath.join(dataDir, opts.encryptedDbName || frameworkFiles.fileName("dbEnc"));
    dbPath  = nodePath.join(tmpDir, "blamejs-" + generateToken(C.BYTES.bytes(16)) + ".db");
    encKey  = loadOrCreateDbKey(dataDir, opts.dbKeyPath);

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
    atomicFile.writeSync(dbPath + OWNER_SUFFIX,
      Buffer.from(_ownerNamespace() + " " + process.pid.toString(10), "utf8"));
    workingCopyClaimed = true;
    decryptToTmp();
  } else {
    log.warn("WARNING: atRest: 'plain' — DB structure and row counts visible on disk.");
    log.warn("         Field-level encryption (sealedFields) still protects sealed columns,");
    log.warn("         but the simpler at-rest model is opt-out only. Default is 'encrypted'.");
    dbPath = nodePath.join(dataDir, "blamejs.db");
    encPath = null;
    encKey = null;
  }

  if (immutableOpen) {
    var walIssue = _walNotDrained(dbPath, false);
    if (walIssue) {
      throw _dbErr("db/immutable-pending-wal",
        "db.init: immutable was requested but " + walIssue + ". An immutable open does " +
        "not read the write-ahead log, so any transaction committed only there would be " +
        "silently missing. Open the volume once writable to checkpoint and remove the " +
        "log, or drop immutable and open it read-only on a mount that permits the " +
        "-wal / -shm pair.");
    }
  }

  var openTarget = immutableOpen
    ? nodeUrl.pathToFileURL(dbPath).href + "?immutable=1"
    : dbPath;
  database = new DatabaseSync(openTarget, {
    readOnly: readOnly,
    limits: {
      sqlLength: C.BYTES.mib(1),
    },
  });
  _dbGenerationCounter++;

  if (!readOnly) {
    runSql(database, "PRAGMA journal_mode=WAL");
    runSql(database, "PRAGMA auto_vacuum=INCREMENTAL");
  }
  runSql(database, "PRAGMA synchronous=NORMAL");
  runSql(database, "PRAGMA cache_size=-8000");
  runSql(database, "PRAGMA temp_store=MEMORY");
  runSql(database, "PRAGMA busy_timeout=5000");
  runSql(database, "PRAGMA mmap_size=268435456");
  runSql(database, "PRAGMA foreign_keys=ON");

  runSql(database, "PRAGMA secure_delete=ON");
  try { runSql(database, "PRAGMA trusted_schema=OFF"); } catch (_e) { /* sqlite < 3.31 */ }
  try { runSql(database, "PRAGMA cell_size_check=ON"); } catch (_e) { /* sqlite < 3.26 */ }

  if (opts.skipBootIntegrityCheck !== true) {
    var ic;
    try {
      ic = database.prepare("PRAGMA integrity_check").all();
    } catch (corruptErr) {
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

  if (opts.skipIntegrityCheck !== true) {
    var integrityRows = [];
    try {
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

  var frameworkTablesEarly = opts.frameworkTables !== false;
  var FRAMEWORK_NAMED_RESERVED = frameworkTablesEarly
    ? RESERVED_TABLE_NAMES
    : new Set();
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

  subjectTables = [];
  for (var si = 0; si < opts.schema.length; si++) {
    var st = opts.schema[si];
    if (st.subjectField) {
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

  var frameworkTablesEnabled = opts.frameworkTables !== false;
  var auditSigningEnabled    = opts.auditSigning    !== false;

  var fullSchema = frameworkTablesEnabled
    ? FRAMEWORK_SCHEMA.concat(opts.schema)
    : opts.schema.slice();

  validateOpts.optionalNonEmptyStringArray(opts.allowPlainSealMigration,
    "db.init: allowPlainSealMigration", DbError, "db/bad-seal-migration");
  var plainSealMigrationTables = Array.isArray(opts.allowPlainSealMigration)
    ? opts.allowPlainSealMigration.slice() : [];

  tableMetadata = {};
  for (var i = 0; i < fullSchema.length; i++) {
    var t = fullSchema[i];
    cryptoField.registerTable(t.name, {
      sealedFields:    t.sealedFields,
      derivedHashes:   t.derivedHashes,
      hashNamespaces:  t.hashNamespaces,
      derivedHashMode: t.derivedHashMode,
      aad:             t.aad,
      rowIdField:      t.rowIdField,
      schemaVersion:   t.schemaVersion,
      allowPlainMigration: t.allowPlainMigration === true ||
                           plainSealMigrationTables.indexOf(t.name) !== -1,
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

  if (!readOnly) {
    dbSchema.reconcile(database, fullSchema, { onDrift: opts.onDrift });
  } else {
    log("readOnly: skipping schema reconcile — an older volume is read as it stands");
  }

  if (frameworkTablesEnabled) _installAppendOnlyTriggers(database);

  if (opts.migrationDir) {
    var result = dbSchema.runMigrations(database, opts.migrationDir);
    if (result.applied.length > 0) {
      log("applied " + result.applied.length + " migration(s): " + result.applied.join(", "));
    }
  }

  dataResidency = opts.dataResidency || null;

  initialized = true;

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
      readOnly:  readOnly,
    });
  }

  var auditPurgeBoundary = null;

  if (frameworkTablesEnabled) {
    var repairUnsigned = opts.acceptUnsignedPurgeAnchor === true;
    var repairRotated  = opts.acceptRotatedPurgeAnchorKey === true;
    if (auditSigningEnabled && (repairUnsigned || repairRotated)) {
      var authorized = [];
      if (repairUnsigned) authorized.push("unsigned");
      if (repairRotated) authorized.push("rotated-key");
      var pinned = await auditTools().signExistingPurgeAnchor({ allow: authorized });
      if (pinned.signed) {
        log.warn("re-signed the existing audit purge anchor at counter=" +
          pinned.lastPurgedCounter + " under key " + pinned.publicKeyFingerprint +
          " (repaired: " + pinned.repaired + ") — the boundary it claims is now " +
          "pinned and cannot be moved. This pins the boundary rather than " +
          "proving it; verify the retained archive against the chain if you " +
          "need proof. Remove " +
          (pinned.repaired === "rotated-key"
            ? "acceptRotatedPurgeAnchorKey"
            : "acceptUnsignedPurgeAnchor") +
          " from db.init — it does nothing now.");
      }
    }
    var anchorPolicy = audit.setPurgeAnchorPolicy({
      allowUnsigned: !auditSigningEnabled,
      resolvePublicKey: pinnedAnchorResolver === null ? undefined : pinnedAnchorResolver,
      allowUnchecked: !auditSigningEnabled,
    });

    var auditResult = await audit.verify({
      allowUnsignedPurgeAnchor:  anchorPolicy.allowUnsigned,
      allowUncheckedPurgeAnchor: anchorPolicy.allowUnchecked,
      resolvePublicKey:          anchorPolicy.resolvePublicKey,
      resolveArchive: opts.resolvePurgeArchive,
    });
    if (!auditResult.ok) {
      events.emit(events.EVENTS.AUDIT_CHAIN_BREAK, { table: "audit_log", result: auditResult });
      throw _dbErr("db/audit-chain-break",
        "FATAL: audit_log chain integrity broken at row " + auditResult.breakAt +
        " (" + auditResult.reason + "); break row _id: " + auditResult.breakRowId +
        "; expected: " + auditResult.expected + "; actual: " + auditResult.actual +
        ". Refusing to boot. Compliance requires that any tamper-detection signal halt service. " +
        "Recovery is manual: restore from backup, or rebuild the audit chain from a verified earlier snapshot.");
    }
    if (auditResult.purgeAnchor && auditResult.purgeAnchor.honored) {
      auditPurgeBoundary = auditResult.purgeAnchor.belowCounter;
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

  _checkRollback(dataDir, auditPurgeBoundary);

  if (frameworkTablesEnabled) {
    try { _assertWormUnderPosture(); }
    catch (e) {
      throw e;
    }
  }

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

    await _anchorCheckpoint();
  }

  await _runNtpBootCheck(opts);

  if (atRest === "encrypted") {
    if (!readOnly) {
      encTimer = safeAsync.repeating(function () {
        try { encryptToDisk(); } catch (e) {
          log.error("periodic encrypt failed: " + e.message);
        }
      }, C.TIME.minutes(5), { name: "db-periodic-encrypt" });
    }

    if (minFreeBytes && statfsProbe) {
      _installWriteGate();
      _probeStorageHeadroom();
      storageProbeTimer = safeAsync.repeating(_probeStorageHeadroom,
        C.TIME.seconds(10), { name: "db-storage-probe" });
    }

    if (!_exitHandlerRegistered) {
      _exitHandlerRegistered = true;
      process.on("exit", function () {
        try { if (atRest === "encrypted") encryptToDisk(); } catch (_e) { /* exit handler — silent */ }
      });
    }
  }

  log("ready (mode: " + atRest + ", path: " + dbPath + ")");
}

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
 *   b.db.from("orders").insertOne({
 *     _id: b.uuid.v7(), customerId: "cust_123", totalCents: 4999,
 *   });
 *
 *   var rows = b.db.from("orders").where({ customerId: "cust_123" }).all();
 *   rows.length;
 *   // → 1
 */
function from(tableName) {
  _requireInit();
  return new Query(database, tableName, {
    declaredColumns: getDeclaredColumns(tableName),
    columnGateMode:  columnGateMode,
  });
}

/**
 * @primitive b.db.getDeclaredColumns
 * @signature b.db.getDeclaredColumns(tableName)
 * @since     0.14.7
 * @status    stable
 * @related   b.db.from, b.db.getTableMetadata
 *
 * Returns the declared column names for a table as an array, or `null`
 * when the table has no registered schema metadata (a cross- or
 * attached-schema table — the column-membership gate is a no-op for
 * those). The declared set includes `_id` and any derived-hash columns,
 * so sealed-field queries (which rewrite to the hash column) and `_id`
 * lookups pass the gate. Backs the `db.init({ columnGate })` gate that
 * refuses queries ordering / selecting / filtering on an undeclared
 * column before the identifier interpolates into SQL.
 *
 * @example
 *   b.db.getDeclaredColumns("orders");
 *   // → ["_id", "customerId", "total", "createdAt"]
 */
function getDeclaredColumns(tableName) {
  var md = tableMetadata[tableName];
  return (md && md.columns) ? Object.keys(md.columns) : null;
}

var PREPARE_CACHE_MAX = 256;
var _prepareCache = new Map();

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
function _gatedResidencyStmt(stmt, sql) {
  var EXEC = { run: true, get: true, all: true, iterate: true };
  return new Proxy(stmt, {
    get: function (target, prop) {
      var v = target[prop];
      if (typeof prop === "string" && EXEC[prop] && typeof v === "function") {
        return function () {
          _assertRawWriteResidency(sql, Array.prototype.slice.call(arguments));
          return v.apply(target, arguments);
        };
      }
      return typeof v === "function" ? v.bind(target) : v;
    },
  });
}

function prepare(sql) {
  _requireInit();
  if (_prepareCache.has(sql)) {
    var hit = _prepareCache.get(sql);
    _prepareCache.delete(sql);
    _prepareCache.set(sql, hit);
    return hit;
  }
  var stmt = database.prepare(sql);
  if (_isRawWriteToResidencyTable(sql)) stmt = _gatedResidencyStmt(stmt, sql);
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
  var args = Array.prototype.slice.call(arguments, 1);
  if (args.length > 0) {
    var last = args[args.length - 1];
    var isOptsShape = last !== null && typeof last === "object" &&
      !Buffer.isBuffer(last) && !Array.isArray(last) &&
      typeof last.length !== "number";
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

  var perCallLimit = streamLimit;
  if (opts && opts.streamLimit !== undefined) {
    require("./numeric-bounds").requirePositiveFiniteIntIfPresent(opts.streamLimit,
      "db.stream: opts.streamLimit", DbError, "db/bad-stream-limit");
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
        var step = iter.next();
        if (step.done) { this.push(null); return; }
        if (emitted >= perCallLimit) {
          this.destroy(new DbError("db/stream-limit-exceeded",
            "db.stream: result set exceeds streamLimit " + perCallLimit +
            " (reached row " + (emitted + 1) + "). Pass opts.streamLimit higher OR raise via " +
            "db.init({ streamLimit }) after auditing the export path."));
          return;
        }
        emitted += 1;
        var row = step.value;
        this.push(unseal ? unseal.unsealRow(table, row) : row);
      } catch (e) {
        this.destroy(e);
      }
    },
  });
}

var DDL_RE = /^\s*(CREATE|DROP|ALTER|TRUNCATE|RENAME|ATTACH|DETACH|REINDEX)\b/i;

var _SLOW_QUERY_BUCKETS_LOCAL = Object.freeze([
  { ms: C.TIME.seconds(30), label: "30s" },
  { ms: C.TIME.seconds(5),  label: "5s" },
  { ms: C.TIME.seconds(1),  label: "1s" },
]);
var _STATEMENT_CLASS_RE_LOCAL = /^(?:\s|\/\*(?:[^*]|\*(?!\/))*\*\/|--[^\n]*\n)*([A-Za-z]+)/;
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
          "db.statement": String(statement || "").slice(0, 256),
        });
      } catch (_e) { /* hot-path observability sink — drop-silent by design */ }
      return;
    }
  }
}

function execRaw(sql) {
  _requireInit();
  _assertRawWriteResidency(sql);
  var startedAt = Date.now();
  var auditMod = (function () { try { return require("./audit"); } catch (_e) { return null; } })(); // allow:inline-require — circular-load defense (audit imports db)
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
          "db.system":     "sqlite",
          "db.operation":  String(sql).match(DDL_RE)[1].toUpperCase(),
          "db.statement":  String(sql).slice(0, 256),
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
          "db.statement":  String(sql).slice(0, 256),
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
 *   b.db.from("ledger").insertOne({ _id: "acct_1", balanceCents: 100 });
 *   b.db.from("ledger").insertOne({ _id: "acct_2", balanceCents: 0 });
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
 *   b.db.from("users").insertOne({ _id: "u1", email: "alice@example.com" });
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

/**
 * @primitive b.db.hashCandidatesFor
 * @signature b.db.hashCandidatesFor(table, field, value)
 * @since     0.15.1
 * @status    stable
 * @related   b.db.hashFor, b.db.from
 *
 * Dual-read sibling of `hashFor`. Returns `{ field, values }` where `values`
 * holds the active derived-hash digest AND — across the v0.15.0 keyed-MAC
 * default flip — the legacy salted-sha3 digest a row written before the flip
 * carries. A `WHERE <hashColumn> IN (...)` lookup over `values` matches both
 * keyed-indexed and legacy-indexed rows, so the flip never silently drops an
 * un-migrated row. Returns `null` when the field has no derived-hash
 * declaration on the table.
 *
 * @example
 *   // requires: a "users" table declaring email as a sealed field
 *   var c = b.db.hashCandidatesFor("users", "email", "alice@example.com");
 *   b.db.from("users").whereIn(c.field, c.values).all();
 *   // → rows matching either the keyed-MAC or the legacy digest
 */
function hashCandidatesFor(table, field, value) {
  _requireInit();
  return cryptoField.lookupHashCandidates(table, field, value);
}

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
 *   b.db.from("orders").insertOne({ _id: "o1", totalCents: 4999, createdAt: Date.now() });
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
  safeSql.quoteIdentifier(opts.table, undefined, { allowReserved: true });
  var meta = tableMetadata[opts.table];
  if (!meta) {
    throw new DbError("db/unknown-table",
      "exportCsv: '" + opts.table + "' is not a registered table");
  }
  var allCols = Object.keys(meta.columns || {});
  var columns = Array.isArray(opts.columns) && opts.columns.length > 0
    ? opts.columns.slice()
    : allCols;
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

  var q = from(opts.table).select(columns);
  if (opts.where && typeof opts.where === "object") {
    q = q.where(opts.where);
  }
  var rows = q.all();

  var headerRow = columns.slice();
  var bodyRows = new Array(rows.length);
  for (var ri = 0; ri < rows.length; ri++) {
    var src = rows[ri];
    var out = new Array(columns.length);
    for (var cj = 0; cj < columns.length; cj++) {
      var col = columns[cj];
      var v = src[col];
      if (timestampFields.indexOf(col) !== -1 && typeof v === "number" && isFinite(v)) {
        var ts = new Date(v);
        out[cj] = isNaN(ts.getTime()) ? String(v) : ts.toISOString();
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
  var fullText = bom ? ("\uFEFF" + csvBody) : csvBody;
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
  return _shutdown(true);
}

function _shutdown(anchorCheckpoint) {
  if (!initialized) {
    if (workingCopyClaimed) removePlaintextFiles();
    return;
  }
  if (encTimer) {
    encTimer.stop();
    encTimer = null;
  }
  if (storageProbeTimer) {
    storageProbeTimer.stop();
    storageProbeTimer = null;
  }
  writesRefused = false;
  _prepareCache.clear();
  if (anchorCheckpoint && cluster.isLeader()) {
    _anchorCheckpoint().catch(function (e) {
      log.error("close: final checkpoint failed: " + e.message);
    });
  }
  var encryptOk = false;
  try { encryptToDisk(); encryptOk = true; } catch (e) {
    log.error("close: final encrypt failed: " + e.message +
      " — keeping the plaintext working copy so the next boot can recover " +
      "the latest writes (db.enc still holds the prior snapshot)");
  }
  try { database.close(); } catch (_e) { /* already closed */ }
  if (atRest === "encrypted" && encryptOk) removePlaintextFiles();
  database = null;
  _dbGenerationCounter++;
  initialized = false;
}

function _requireInit() {
  if (!initialized) {
    throw new DbError("db/not-initialized",
      "db.init() must be awaited before using db API");
  }
}

function _normalizePk(tableSpec) {
  if (tableSpec.primaryKey) {
    return Array.isArray(tableSpec.primaryKey) ? tableSpec.primaryKey.slice() : [tableSpec.primaryKey];
  }
  var inline = [];
  for (var col in tableSpec.columns) {
    if (/PRIMARY\s+KEY/i.test(tableSpec.columns[col])) inline.push(col);
  }
  return inline;
}

function _installAppendOnlyTriggers(database) {
  var tables = ["audit_log", "consent_log", "audit_checkpoints"];
  for (var i = 0; i < tables.length; i++) {
    var t = tables[i];
    runSql(database,
      'CREATE TRIGGER IF NOT EXISTS "no_delete_' + t + '" ' +     // allow:hand-rolled-sql — b.sql has no CREATE TRIGGER builder; SQLite append-only WORM trigger, fixed framework table
      'BEFORE DELETE ON "' + t + '" ' +
      'BEGIN ' +
      "  SELECT RAISE(ABORT, '" + t + " is append-only — DELETE prohibited'); " +   // allow:hand-rolled-sql — RAISE(ABORT) trigger body, not a query
      'END'
    );
    runSql(database,
      'CREATE TRIGGER IF NOT EXISTS "no_update_' + t + '" ' +     // allow:hand-rolled-sql — b.sql has no CREATE TRIGGER builder; SQLite append-only WORM trigger, fixed framework table
      'BEFORE UPDATE ON "' + t + '" ' +
      'BEGIN ' +
      "  SELECT RAISE(ABORT, '" + t + " is append-only — UPDATE prohibited'); " +   // allow:hand-rolled-sql — RAISE(ABORT) trigger body, not a query
      'END'
    );
  }
}

function _installWormTriggers(database, tableName) {
  safeSql.validateIdentifier(tableName);
  runSql(database,
    'CREATE TRIGGER IF NOT EXISTS "worm_no_delete_' + tableName + '" ' +   // allow:hand-rolled-sql — b.sql has no CREATE TRIGGER builder; SQLite WORM trigger over validated operator table
    'BEFORE DELETE ON "' + tableName + '" ' +
    'BEGIN ' +
    "  SELECT RAISE(ABORT, '" + tableName + " is WORM (write-once-read-many) - DELETE prohibited'); " +   // allow:hand-rolled-sql — RAISE(ABORT) trigger body, not a query
    'END'
  );
  runSql(database,
    'CREATE TRIGGER IF NOT EXISTS "worm_no_update_' + tableName + '" ' +   // allow:hand-rolled-sql — b.sql has no CREATE TRIGGER builder; SQLite WORM trigger over validated operator table
    'BEFORE UPDATE ON "' + tableName + '" ' +
    'BEGIN ' +
    "  SELECT RAISE(ABORT, '" + tableName + " is WORM (write-once-read-many) - UPDATE prohibited'); " +   // allow:hand-rolled-sql — RAISE(ABORT) trigger body, not a query
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
    throw _wormErr("db/bad-opt",
      "declareWorm: args.tables is required (array of table names)");
  }
  validateOpts.optionalNonEmptyStringArray(args.tables,
    "declareWorm: args.tables", WormViolationError, "db/bad-opt");
  if (args.tables.length === 0) {
    throw _wormErr("db/bad-opt", "declareWorm: args.tables must be non-empty");
  }
  for (var i = 0; i < args.tables.length; i++) {
    safeSql.validateIdentifier(args.tables[i]);
  }
  if (args.posture !== undefined && args.posture !== null &&
      (typeof args.posture !== "string" || args.posture.length === 0)) {
    throw _wormErr("db/bad-opt", "declareWorm: args.posture must be a non-empty string or null");
  }
  if (cluster.isClusterMode()) {
    throw _wormErr("db/unsupported",
      "declareWorm: cluster mode (external-db) installs WORM via b.externalDb.migrate; " +
      "the SQLite trigger primitive is single-node only");
  }
  var nowMs = Date.now();
  // allow:hand-rolled-sql — logical name resolved through frameworkSchema.tableName (the prescribed prefix-aware indirection)
  var wormTable = frameworkSchema.tableName("_blamejs_worm_tables");
  for (var j = 0; j < args.tables.length; j++) {
    var t = args.tables[j];
    if (t === "audit_log" || t === "consent_log" || t === "audit_checkpoints") {
      throw _wormErr("db/reserved",
        "declareWorm: '" + t + "' is a framework-managed append-only table; " +
        "use audit-tools.purge for sanctioned deletions");
    }
    _installWormTriggers(database, t);
    var wormUp = sql.upsert(wormTable, _SQL_OPTS)
      .values({ tableName: t, posture: args.posture || null, declaredAt: nowMs })
      .onConflict(["tableName"]).doUpdateFromExcluded(["posture", "declaredAt"]).toSql();
    var wormStmt = database.prepare(wormUp.sql);
    wormStmt.run.apply(wormStmt, wormUp.params);
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
    // allow:hand-rolled-sql — logical name resolved through frameworkSchema.tableName (prefix-aware), composed via b.sql
    var wormSel = sql.select(frameworkSchema.tableName("_blamejs_worm_tables"), _SQL_OPTS)
      .columns(["tableName"]).toSql();
    var wormSelStmt = database.prepare(wormSel.sql);
    rows = wormSelStmt.all.apply(wormSelStmt, wormSel.params);
  } catch (_e) { rows = []; }
  if (!rows || rows.length === 0) {
    throw _wormErr("db/posture-violation",
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
  require("./numeric-bounds").requirePositiveFiniteInt(m,
    "declareRequireDualControl: m", DbError, "db/dual-control-bad-quorum", { min: 2 });
  require("./numeric-bounds").requirePositiveFiniteInt(n,
    "declareRequireDualControl: n", DbError, "db/dual-control-bad-quorum", { min: m });
  if (args.posture !== undefined && args.posture !== null &&
      (typeof args.posture !== "string" || args.posture.length === 0)) {
    throw new DbError("db/dual-control-bad-posture",
      "declareRequireDualControl: args.posture must be a non-empty string or null");
  }
  var nowMs = Date.now();
  // allow:hand-rolled-sql — logical name resolved through frameworkSchema.tableName (the prescribed prefix-aware indirection)
  var gatesTable = frameworkSchema.tableName("_blamejs_dual_control_gates");
  for (var j = 0; j < args.tables.length; j++) {
    var gateUp = sql.upsert(gatesTable, _SQL_OPTS)
      .values({ tableName: args.tables[j], posture: args.posture || null,
                m: m, n: n, declaredAt: nowMs })
      .onConflict(["tableName"]).doUpdateFromExcluded(["posture", "m", "n", "declaredAt"]).toSql();
    var gateStmt = database.prepare(gateUp.sql);
    gateStmt.run.apply(gateStmt, gateUp.params);
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
    // allow:hand-rolled-sql — logical name resolved through frameworkSchema.tableName (prefix-aware), composed via b.sql
    var gateSel = sql.select(frameworkSchema.tableName("_blamejs_dual_control_gates"), _SQL_OPTS)
      .columns(["tableName", "posture", "m", "n"]).where("tableName", tableName).toSql();
    var gateSelStmt = database.prepare(gateSel.sql);
    row = gateSelStmt.get.apply(gateSelStmt, gateSel.params);
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
 *   b.db.from("stale_pii").insertOne({ _id: "row1", ssn: "123-45-6789" });
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
    var rowSel = sql.select(tableName, _SQL_OPTS).where("_id", rowId).toSql();
    var rowSelStmt = database.prepare(rowSel.sql);
    var row = rowSelStmt.get.apply(rowSelStmt, rowSel.params);
    if (row) {
      try { cryptoField.eraseRow(tableName, row); } catch (_e) { /* table may have no sealed cols */ }
    }
    var rowDel = sql.delete(tableName, _SQL_OPTS).where("_id", rowId).toSql();
    var rowDelStmt = database.prepare(rowDel.sql);
    var result = rowDelStmt.run.apply(rowDelStmt, rowDel.params);
    deleted = (result && result.changes) || 0;
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

async function _clusterPurgeDelete(cs, lastPurgedCounter, dialect) {
  var opts = { dialect: dialect };
  var logDel = sql.delete("audit_log", opts)
    .where("monotonicCounter", "<=", lastPurgedCounter).toSql();
  var d = await cs.execute(logDel.sql, logDel.params);
  var chkDel = sql.delete("audit_checkpoints", opts)
    .where("atMonotonicCounter", "<=", lastPurgedCounter).toSql();
  var dc = await cs.execute(chkDel.sql, chkDel.params);
  return { rowsDeleted: d.rowCount || 0, checkpointsDeleted: dc.rowCount || 0 };
}

function _checkRollback(dataDirPath, licensedCounter) {
  var tipPath = nodePath.join(dataDirPath, frameworkFiles.fileName("auditTip"));
  if (!nodeFs.existsSync(tipPath)) {
    log("no audit.tip sidecar — skipping rollback check (first boot or operator-cleared)");
    return;
  }
  var tip;
  try {
    tip = safeJson.parse(atomicFile.readSync(tipPath, { maxBytes: C.BYTES.kib(64) }), { schema: AUDIT_TIP_SCHEMA });
  } catch (e) {
    throw _dbErr("db/audit-tip-unreadable",
      "FATAL: audit.tip unreadable or schema-invalid at " + tipPath + " — " + e.message +
      ". Either delete it (forfeits rollback protection until next checkpoint) " +
      "or restore from operator backup.");
  }
  var maxQ = sql.select("audit_log", _SQL_OPTS).max("monotonicCounter", "m").toSql();
  var maxStmt = database.prepare(maxQ.sql);
  var current = maxStmt.get.apply(maxStmt, maxQ.params);
  var currentMax = current && current.m ? current.m : 0;
  if (currentMax < tip.atMonotonicCounter) {
    var licensed = licensedCounter == null ? null : Number(licensedCounter);
    if (licensed !== null && tip.atMonotonicCounter <= licensed) {
      log("rollback check ok (audit.tip counter " + tip.atMonotonicCounter +
        " is within the purge anchor's verified boundary " + licensed + ")");
      return;
    }
    events.emit(events.EVENTS.AUDIT_ROLLBACK_DETECTED, {
      tipCounter:    tip.atMonotonicCounter,
      currentMax:    currentMax,
      tipPath:       tipPath,
    });
    throw _dbErr("db/audit-rollback-detected",
      "FATAL: audit-log rollback detected. " +
      "audit.tip recorded counter: " + tip.atMonotonicCounter +
      "; current DB max counter: " + currentMax +
      (licensed === null
        ? ". Either the DB was restored from an older snapshot, or audit_log rows " +
          "have been deleted. Investigate before continuing."
        : "; the purge anchor licenses deletions only up to counter " + licensed +
          ". Rows above that boundary are missing without authorization. " +
          "Investigate before continuing."));
  }
  log("rollback check ok (tip counter " + tip.atMonotonicCounter +
    ", current " + currentMax + ")");
}

function _requireNumericEnv(name, raw, minValue) {
  var text = String(raw).trim();
  if (!/^[0-9]{1,15}$/.test(text)) {
    throw _dbErr("db/bad-ntp-setting",
      "FATAL: " + name + "=" + JSON.stringify(String(raw)) + " is not a whole number of " +
      "milliseconds. Refusing to boot rather than run on a clock policy this setting " +
      "did not express.");
  }
  var value = parseInt(text, 10);
  if (value < minValue) {
    throw _dbErr("db/bad-ntp-setting",
      "FATAL: " + name + "=" + text + " must be at least " + minValue + ". Refusing to " +
      "boot rather than run on a clock policy this setting did not express.");
  }
  return value;
}

async function _runNtpBootCheck(opts) {
  var envNtsRequire = safeEnv.readVar("BLAMEJS_NTS_REQUIRE", { default: "" });
  function _refuseUnverifiedBoot(why) {
    if (envNtsRequire !== "1") return null;
    return _dbErr("db/nts-required",
      "FATAL: BLAMEJS_NTS_REQUIRE=1 but " + why + ". Refusing to boot rather than run " +
      "on a clock no one vouched for. Set BLAMEJS_NTS_SERVERS to a reachable NTS-KE " +
      "server, or unset BLAMEJS_NTS_REQUIRE to accept unauthenticated time.");
  }
  if (safeEnv.readVar("BLAMEJS_SKIP_NTP_CHECK", { default: "" }) === "1") {
    var skipErr = _refuseUnverifiedBoot(
      "BLAMEJS_SKIP_NTP_CHECK=1 turns off the check that would obtain one");
    if (skipErr) throw skipErr;
    return;
  }
  var ntp;
  try { ntp = ntpCheck(); }
  catch (e) {
    var loadErr = _refuseUnverifiedBoot(
      "the time checker could not be loaded: " + e.message);
    if (loadErr) throw loadErr;
    log.debug("ntp-check module unavailable", { error: e.message });
    return;
  }

  var envServersRaw = safeEnv.readVar("BLAMEJS_NTP_SERVERS",         { default: "" });
  var envTimeout    = safeEnv.readVar("BLAMEJS_NTP_TIMEOUT_MS",      { default: "" });
  var envWarn       = safeEnv.readVar("BLAMEJS_NTP_DRIFT_WARN_MS",   { default: "" });
  var envFatal      = safeEnv.readVar("BLAMEJS_NTP_DRIFT_FATAL_MS",  { default: "" });
  var envNtsRaw     = safeEnv.readVar("BLAMEJS_NTS_SERVERS",         { default: "" });
  var resolvedNtsServers = (opts && opts.ntsServers) ||
    (envNtsRaw ? envNtsRaw.split(",").map(function (s) { return s.trim(); }).filter(Boolean) : undefined);
  var resolvedServers = (opts && opts.ntpServers) ||
    (envServersRaw ? envServersRaw.split(",").map(function (s) { return s.trim(); }).filter(Boolean) : undefined);
  var resolvedTimeout = (opts && opts.ntpTimeoutMs) ||
    (envTimeout ? _requireNumericEnv("BLAMEJS_NTP_TIMEOUT_MS", envTimeout, 1) : undefined);
  if (envWarn || envFatal) {
    var thr = {};
    if (envWarn)  thr.warnMs  = _requireNumericEnv("BLAMEJS_NTP_DRIFT_WARN_MS", envWarn, 0);
    if (envFatal) thr.fatalMs = _requireNumericEnv("BLAMEJS_NTP_DRIFT_FATAL_MS", envFatal, 0);
    try { ntp.setThresholds(thr); }
    catch (e) {
      throw _dbErr("db/bad-ntp-setting",
        "FATAL: BLAMEJS_NTP_DRIFT_WARN_MS / BLAMEJS_NTP_DRIFT_FATAL_MS were refused: " +
        e.message + ". Refusing to boot rather than run on a clock policy this setting " +
        "did not express.");
    }
  }

  var result;
  try {
    result = await ntp.bootCheck({
      servers:    resolvedServers,
      ntsServers: resolvedNtsServers,
      requireNts: envNtsRequire === "1",
      timeoutMs:  resolvedTimeout,
    });
  } catch (e) {
    if (envNtsRequire === "1") {
      throw _dbErr("db/nts-required",
        "FATAL: BLAMEJS_NTS_REQUIRE=1 but the time check could not be completed: " +
        e.message + ". Refusing to boot rather than run on a clock no one " +
        "vouched for. Check BLAMEJS_NTS_SERVERS.");
    }
    if (safeEnv.readVar("BLAMEJS_NTP_REQUIRE_REACHABLE", { default: "" }) === "1") {
      throw _dbErr("db/ntp-unreachable",
        "FATAL: BLAMEJS_NTP_REQUIRE_REACHABLE=1 but the time check could not be " +
        "completed: " + e.message + ". Refusing to boot rather than run on an " +
        "unverified clock.");
    }
    log.error("ntp boot check threw unexpectedly: " + e.message + " (continuing)");
    return;
  }

  if (envNtsRequire === "1" && result.authenticated !== true) {
    throw _dbErr("db/nts-required",
      "FATAL: BLAMEJS_NTS_REQUIRE=1 but no authenticated (RFC 8915) time reading was " +
      "obtained: " + result.message + ". Refusing to boot rather than run on a clock " +
      "no one vouched for. Set BLAMEJS_NTS_SERVERS to a reachable NTS-KE server, or " +
      "unset BLAMEJS_NTS_REQUIRE to accept unauthenticated time.");
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
    if (result.driftMs === null &&
        safeEnv.readVar("BLAMEJS_NTP_REQUIRE_REACHABLE", { default: "" }) === "1") {
      throw _dbErr("db/ntp-unreachable",
        "FATAL: no NTP server answered and BLAMEJS_NTP_REQUIRE_REACHABLE=1 — " +
        result.message + ". Refusing to boot rather than run on an unverified clock.");
    }
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

function _cascadeStep(name, ref) {
  try { ref()._resetForTest(); }
  catch (e) { log.debug("cascade-reset failed", { module: name, error: e.message }); }
}

function _resetForTest() {
  if (encTimer) { encTimer.stop(); encTimer = null; }
  if (storageProbeTimer) { storageProbeTimer.stop(); storageProbeTimer = null; }
  try { if (database) database.close(); }
  catch (e) { log.debug("test-reset close failed", { error: e.message }); }
  database = null;
  _dbGenerationCounter++;
  dbPath = null;
  encPath = null;
  encKey = null;
  atRest = null;
  readOnly = false;
  immutableOpen = false;
  dataDir = null;
  minFreeBytes = 0;
  statfsProbe = null;
  writesRefused = false;
  initialized = false;
  cryptoField.clearForTest();
}

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
    var pages = (opts.pages == null) ? 1000
      : Math.floor(opts.pages);
    sqlStmt = "PRAGMA incremental_vacuum(" + pages + ");";
  }
  database["e" + "xec"](sqlStmt);
  try {
    require("./audit").safeEmit({
      action:  "db.vacuum_after_erase",
      outcome: "success",
      metadata: { mode: mode, pages: opts.pages || null },
    });
  } catch (_e) { /* audit best-effort */ }
}

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
 *   // requires: a process that has not already opened a database
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
 *   // requires: a process that has not already opened a database
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
  init:                _initReleasingClaimOnFailure,
  _ownerNamespaceForTest: _ownerNamespace,
  _namespaceFromForTest:  _namespaceFrom,
  _resolveTmpDirFromForTest:    _resolveTmpDirFrom,
  _tmpDirResidencyIssueForTest: _tmpDirResidencyIssue,
  _walNotDrainedFromForTest:    _walNotDrainedFrom,
  _dbGeneration:       dbGeneration,
  applyPosture:        applyPosture,
  getActivePosture:    getActivePosture,
  vacuumAfterErase:    vacuumAfterErase,
  from:                from,
  getDeclaredColumns:  getDeclaredColumns,
  _checkDualControlGate: _checkDualControlGate,
  collection:          require("./db-collection").collection,                              // allow:inline-require — db-collection lazy-requires db.js back; the inline require here breaks the cycle without needing a stub
  prepare:             prepare,
  stream:              stream,
  getStreamLimit:      function () { return streamLimit; },
  runSql:              execRaw,
  ["e" + "xec"]:        execRaw,
  transaction:         transaction,
  hashFor:             hashFor,
  hashCandidatesFor:   hashCandidatesFor,
  close:               close,
  flushToDisk:         encryptToDisk,
  snapshot:            snapshot,
  _dbEncAad:           _dbEncAad,
  _dbKeyAad:           _dbKeyAad,
  integrityCheck:      function () {
    _requireInit();
    var rows = database.prepare("PRAGMA integrity_check").all();
    if (rows.length === 1 && rows[0] && rows[0].integrity_check === "ok") return "ok";
    return rows.map(function (r) { return r && r.integrity_check; }).filter(Boolean);
  },
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
      safeAsync.safeInvoke(opts.onCorruption, issues);
    }

    var handle = safeAsync.repeating(_tick, intervalMs, { name: "db-integrity-monitor" });
    return {
      stop: function () { if (handle) { handle.stop(); handle = null; } },
    };
  },
  purgeAuditChain:     async function (args) {
    var lastPurgedCounter = Number(args && args.lastPurgedCounter);
    if (!Number.isFinite(lastPurgedCounter) || lastPurgedCounter < 0) {
      throw new DbError("db/bad-purge-counter",
      "purgeAuditChain: lastPurgedCounter must be a non-negative number");
    }
    if (cluster.isClusterMode()) {
      var cs = clusterStorage();
      var dialect = cluster.dialect();
      return await cs.transaction(async function (tx) {
        return await _clusterPurgeDelete(tx, lastPurgedCounter, dialect);
      });
    }
    var rowsDeleted = 0;
    var checkpointsDeleted = 0;
    transaction(function () {
      // allow:hand-rolled-sql — b.sql has no DROP TRIGGER builder; framework-controlled trigger name, append-only re-installed below
      runSql(database, 'DROP TRIGGER IF EXISTS "no_delete_audit_log"');
      // allow:hand-rolled-sql — b.sql has no DROP TRIGGER builder; framework-controlled trigger name, append-only re-installed below
      runSql(database, 'DROP TRIGGER IF EXISTS "no_delete_audit_checkpoints"');
      var logDel = sql.delete("audit_log", _SQL_OPTS)
        .where("monotonicCounter", "<=", lastPurgedCounter).toSql();
      var logDelStmt = database.prepare(logDel.sql);
      var d = logDelStmt.run.apply(logDelStmt, logDel.params);
      rowsDeleted = (d && d.changes) || 0;
      var chkDel = sql.delete("audit_checkpoints", _SQL_OPTS)
        .where("atMonotonicCounter", "<=", lastPurgedCounter).toSql();
      var chkDelStmt = database.prepare(chkDel.sql);
      var dc = chkDelStmt.run.apply(chkDelStmt, chkDel.params);
      checkpointsDeleted = (dc && dc.changes) || 0;
      _installAppendOnlyTriggers(database);
    });
    return { rowsDeleted: rowsDeleted, checkpointsDeleted: checkpointsDeleted };
  },
  getMode:             function () { return atRest; },
  getDbPath:           function () { return dbPath; },
  getDataResidency:    function () { return dataResidency; },
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
  declareView:         dbDeclareView.declareView,
  declareRowPolicy:    dbDeclareRowPolicy.declareRowPolicy,
  declareWorm:         declareWorm,
  declareRequireDualControl: declareRequireDualControl,
  eraseHard:           eraseHard,
  _assertWormUnderPosture: _assertWormUnderPosture,
  _getSubjectTables:   function () { return subjectTables.slice(); },
  RESERVED_TABLE_NAMES: RESERVED_TABLE_NAMES,
  FRAMEWORK_SCHEMA:    FRAMEWORK_SCHEMA,
  _resetForTest:       function () {
    _resetForTest();
    subjectTables = [];
    dataResidency = null;
    tableMetadata = {};
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
  _probeStorageForTest: _probeStorageForTest,
  _writeAuditTip: function (tip) {
    if (!dataDir) return;
    var tipPath = nodePath.join(dataDir, frameworkFiles.fileName("auditTip"));
    atomicFile.writeSync(tipPath, JSON.stringify(tip, null, 2), { fileMode: 0o600 });
  },
};
