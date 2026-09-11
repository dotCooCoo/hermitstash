// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var nodePath = require("node:path");
var moduleLoader = require("./module-loader");
var atomicFile = require("./atomic-file");
var canonicalJson = require("./canonical-json");
var { sha3Hash } = require("./crypto");
var lazyRequire = require("./lazy-require");
var migrationFiles = require("./migration-files");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var auditSign = lazyRequire(function () { return require("./audit-sign"); });

var ExternalDbMigrateError = defineClass("ExternalDbMigrateError", { alwaysPermanent: true });

// Lazy require — external-db imports back into this module via its
// public `migrate` namespace; load-order would cycle without lazy. The
// same cycle (external-db -> external-db-migrate -> cluster-storage ->
// cluster -> cluster-provider-db -> external-db) means clusterStorage +
// frameworkSchema must be lazy here too, and the table-name constants
// resolved on first use rather than at module load (frameworkSchema's
// tableName export is not yet bound while this module evaluates).
var externalDb = lazyRequire(function () { return require("./external-db"); });
var clusterStorage = lazyRequire(function () { return require("./cluster-storage"); });
var frameworkSchema = lazyRequire(function () { return require("./framework-schema"); });
var sql = lazyRequire(function () { return require("./sql"); });

function _trackingTable() { return frameworkSchema().tableName("_blamejs_externaldb_migrations"); }        // allow:hand-rolled-sql — single canonical logical-name reference
function _lockTable()     { return frameworkSchema().tableName("_blamejs_externaldb_migrations_lock"); }   // allow:hand-rolled-sql — single canonical logical-name reference
function _historyTable()  { return frameworkSchema().tableName("_blamejs_schema_version_history"); }       // allow:hand-rolled-sql — single canonical logical-name reference

function _backendDialect(backendName) {
  var listed;
  try { listed = externalDb().listBackends(); }
  catch (_e) { return "postgres"; }
  for (var i = 0; i < listed.length; i++) {
    if (listed[i].name === backendName) {
      return (listed[i].dialect || "postgres").toLowerCase();
    }
  }
  return "postgres";
}

function _bind(builder, dialect) {
  var built = builder.toSql();
  return { sql: clusterStorage().placeholderize(built.sql, dialect), params: built.params };
}

var FRAMEWORK_METADATA_OPTS = Object.freeze({ rowResidencyTag: "unrestricted" });

var HISTORY_SIGNATURE_FORMAT = "blamejs-schema-history-v1";

function _historyPayload(row) {
  var payload =
    HISTORY_SIGNATURE_FORMAT + "\n" +
    canonicalJson.stringify({
      version:                 row.version,
      ranAt:                   row.ranAt,
      ranBy:                   row.ranBy,
      schemaIntrospectionHash: row.schemaIntrospectionHash,
    });
  return Buffer.from(payload, "utf8");
}

async function _defaultSchemaIntrospect(xdb, dialect) {
  var q = _bind(sql().select(_trackingTable(), { dialect: dialect })
    .columns(["name", "appliedAt"])
    .orderBy("appliedAt", "asc").orderBy("name", "asc"), dialect);
  var res = await xdb.query(q.sql, q.params);
  var rows = (res && res.rows) || [];
  return sha3Hash(Buffer.from(canonicalJson.stringify(rows), "utf8"));
}

var FILE_NAME_MAX = 255;

function _isMigrationFile(name) {
  return typeof name === "string" &&
         name.length > 0 &&
         name.length <= FILE_NAME_MAX &&
         migrationFiles.MIGRATION_FILE_RE.test(name);
}

function _err(code, message) {
  return new ExternalDbMigrateError(code, message);
}

var _BOOT_TOKEN = require("node:crypto").randomBytes(8).toString("hex");

function _lockHolderId() {
  return String(process.pid) + "@" +
    (require("node:os").hostname() || "unknown") + "@" + _BOOT_TOKEN;
}

async function _ensureTrackingTable(xdb, dialect) {
  await xdb.query(sql().createTable(_trackingTable(), [
    { name: "name",        type: "VARCHAR(255)", primaryKey: true },
    { name: "description", type: "TEXT" },
    { name: "appliedAt",   type: "TEXT", notNull: true },
  ], { dialect: dialect }).sql, []);
}

async function _ensureHistoryTable(xdb, dialect) {
  await xdb.query(sql().createTable(_historyTable(), [
    { name: "version",                 type: "VARCHAR(255)", notNull: true },
    { name: "ranAt",                   type: "VARCHAR(64)", notNull: true },
    { name: "ranBy",                   type: "TEXT", notNull: true },
    { name: "schemaIntrospectionHash", type: "TEXT", notNull: true },
    { name: "signature",               type: "TEXT" },
    { name: "publicKeyFingerprint",    type: "TEXT" },
  ], { dialect: dialect, primaryKey: ["version", "ranAt"] }).sql, []);
}

async function _writeHistoryRow(xdb, row, dialect) {
  var q = _bind(sql().insert(_historyTable(), { dialect: dialect }).values({
    version:                 row.version,
    ranAt:                   row.ranAt,
    ranBy:                   row.ranBy,
    schemaIntrospectionHash: row.schemaIntrospectionHash,
    signature:               row.signature,
    publicKeyFingerprint:    row.publicKeyFingerprint,
  }), dialect);
  await xdb.query(q.sql, q.params, FRAMEWORK_METADATA_OPTS);
}

async function _ensureLockTable(xdb, dialect) {
  await xdb.query(sql().createTable(_lockTable(), [
    { name: "scope",    type: "VARCHAR(64)", primaryKey: true },
    { name: "lockedAt", type: "INTEGER", notNull: true },
    { name: "lockedBy", type: "TEXT", notNull: true,
      constraints: ", CHECK (scope = 'lock')" },                                    // allow:hand-rolled-sql — static DDL CHECK literal
  ], { dialect: dialect }).sql, []);
}

async function _acquireLock(xdb, opts, dialect) {
  await _ensureLockTable(xdb, dialect);
  var holder = _lockHolderId();
  var nowMs = Date.now();
  var staleAfterMs = 0;
  if (opts) {
    numericBounds.requireNonNegativeFiniteIntIfPresent(opts.staleAfterMs,
      "externalDb.migrate.acquireLock: staleAfterMs",
      ExternalDbMigrateError, "externaldb-migrate/bad-opt");
    if (opts.staleAfterMs !== undefined) staleAfterMs = opts.staleAfterMs;
  }
  function _insertLock() {
    return _bind(sql().upsert(_lockTable(), { dialect: dialect })
      .values({ scope: "lock", lockedAt: nowMs, lockedBy: holder })
      .onConflict(["scope"]).doNothing(), dialect);
  }
  var insRes;
  try {
    var ins = _insertLock();
    insRes = await xdb.query(ins.sql, ins.params, FRAMEWORK_METADATA_OPTS);
  } catch (e0) {
    throw _err("externaldb-migrate/lock-busy",
      "could not acquire migration lock: " + ((e0 && e0.message) || String(e0)));
  }
  if (insRes && insRes.rowCount >= 1) {
    return { holder: holder, takeoverFrom: null, takeoverAgeMs: 0 };
  }
  {
    var selExisting = _bind(sql().select(_lockTable(), { dialect: dialect })
      .columns(["lockedAt", "lockedBy"]).where("scope", "lock"), dialect);
    var existingRes;
    try {
      existingRes = await xdb.query(selExisting.sql, selExisting.params);
    } catch (_inspectErr) {
      throw _err("externaldb-migrate/lock-held",
        "migration lock is held — another process is running migrations " +
        "(the lock row could not be inspected). Wait for it to finish, or " +
        "pass staleAfterMs to force-replace stale locks.");
    }
    var existing = existingRes && existingRes.rows && existingRes.rows[0];
    if (!existing) {
      try {
        var insRetry = _insertLock();
        var retryRes = await xdb.query(insRetry.sql, insRetry.params, FRAMEWORK_METADATA_OPTS);
        if (retryRes && retryRes.rowCount >= 1) {
          return { holder: holder, takeoverFrom: null, takeoverAgeMs: 0 };
        }
        throw _err("externaldb-migrate/lock-held",
          "migration lock is held — another process re-acquired it during " +
          "the acquire race. Wait for it to finish, or pass staleAfterMs to " +
          "force-replace stale locks.");
      } catch (e2) {
        if (e2 && e2.isExternalDbMigrateError) throw e2;
        throw _err("externaldb-migrate/lock-busy",
          "could not acquire migration lock: " + ((e2 && e2.message) || String(e2)));
      }
    }
    var ageMs = nowMs - Number(existing.lockedat || existing.lockedAt);
    if (staleAfterMs > 0 && ageMs > staleAfterMs) {
      var prevHolder = existing.lockedby || existing.lockedBy;
      var delStale = _bind(sql().delete(_lockTable(), { dialect: dialect })
        .where("scope", "lock")
        .where("lockedAt", Number(existing.lockedat || existing.lockedAt)), dialect);
      await xdb.query(delStale.sql, delStale.params, FRAMEWORK_METADATA_OPTS);
      var insTakeover = _insertLock();
      var takeoverRes = await xdb.query(insTakeover.sql, insTakeover.params, FRAMEWORK_METADATA_OPTS);
      if (!takeoverRes || takeoverRes.rowCount < 1) {
        throw _err("externaldb-migrate/lock-held",
          "migration lock was re-acquired by another process during the " +
          "stale-lock takeover. Wait for it to finish, or retry.");
      }
      return { holder: holder, takeoverFrom: prevHolder, takeoverAgeMs: ageMs };
    }
    throw _err("externaldb-migrate/lock-held",
      "migration lock is held by " + (existing.lockedby || existing.lockedBy) +
      " (acquired " + ageMs + "ms ago). Another process is running migrations" +
      " — wait for it to finish, or pass staleAfterMs to force-replace stale locks.");
  }
}

async function _releaseLock(xdb, holder, dialect) {
  try {
    var del = _bind(sql().delete(_lockTable(), { dialect: dialect })
      .where("scope", "lock").where("lockedBy", holder), dialect);
    await xdb.query(del.sql, del.params, FRAMEWORK_METADATA_OPTS);
  } catch (_e) {
    // best-effort release; operator can DELETE manually.
  }
}

function _list(dir) {
  return atomicFile.listDir(dir, {
    filter: _isMigrationFile,
  }).map(function (e) { return e.name; }).sort();
}

function _loadMigration(file, dir) {
  var mod = moduleLoader.requireFresh(nodePath.join(dir, file), function (e) {
    return _err("externaldb-migrate/load-failed",
      "migration '" + file + "' failed to load: " + ((e && e.message) || String(e)));
  });
  if (!mod || typeof mod.up !== "function") {
    throw _err("externaldb-migrate/missing-up",
      "migration '" + file + "' must export an `up(xdb, ctx)` function");
  }
  return mod;
}

// ---- Audit emit (drop-silent) ----

function _emit(audit, action, outcome, info, reason) {
  if (!audit) return;
  try {
    audit.safeEmit({
      action:   action,
      outcome:  outcome,
      metadata: info || {},
      reason:   reason || null,
    });
  } catch (_e) { /* drop-silent — audit emit failure must not crash the migration */ }
}

function _resolveBackendName(opts) {
  if (opts && typeof opts.backend === "string" && opts.backend.length > 0) {
    return opts.backend;
  }
  var listed;
  try { listed = externalDb().listBackends(); }
  catch (_e) {
    throw _err("externaldb-migrate/not-initialized",
      "externalDb is not initialized — call b.externalDb.init({ backends }) first");
  }
  if (!listed || listed.length === 0) {
    throw _err("externaldb-migrate/no-backends",
      "externalDb has no backends configured");
  }
  return listed[0].name;
}

function create(opts) {
  opts = opts || {};
  validateOpts.shape(opts, {
    dir: { rule: "required-string", code: "externaldb-migrate/no-dir",
           label: "externalDb.migrate.create: opts.dir (path to migrations directory)" },
    staleAfterMs: { rule: "optional-non-negative", code: "externaldb-migrate/bad-stale",
                    label: "externalDb.migrate: staleAfterMs" },
    audit: function (value) {
      validateOpts.auditShape(value, "externalDb.migrate", ExternalDbMigrateError, "externaldb-migrate/bad-audit");
    },
    schemaIntrospect: { rule: "optional-function", code: "externaldb-migrate/bad-introspect",
                        label: "externalDb.migrate: schemaIntrospect" },
    backend: { rule: "optional-string", code: "externaldb-migrate/bad-backend",
               label: "externalDb.migrate: backend (externalDb backend name)" },
    ranBy: { rule: "optional-string", code: "externaldb-migrate/bad-ran-by",
             label: "externalDb.migrate: ranBy (schema-history actor)" },
    signHistory: { rule: "optional-boolean", code: "externaldb-migrate/bad-sign-history",
                   label: "externalDb.migrate: signHistory" },
  }, "externalDb.migrate", ExternalDbMigrateError, "externaldb-migrate/bad-opt");
  var dir = opts.dir;
  var audit = opts.audit || null;
  var schemaIntrospect = typeof opts.schemaIntrospect === "function"
    ? opts.schemaIntrospect : _defaultSchemaIntrospect;
  var ranBy = typeof opts.ranBy === "string" && opts.ranBy.length > 0
    ? opts.ranBy : _lockHolderId();
  var signHistory = opts.signHistory !== false;

  function _ctx(backendName) {
    return {
      externalDb:  externalDb(),
      backendName: backendName,
    };
  }

  async function status() {
    var backendName = _resolveBackendName(opts);
    var dialect = _backendDialect(backendName);
    return await externalDb().transaction(async function (xdb) {
      await _ensureTrackingTable(xdb, dialect);
      var q = _bind(sql().select(_trackingTable(), { dialect: dialect })
        .columns(["name", "description", "appliedAt"])
        .orderBy("appliedAt", "asc").orderBy("name", "asc"), dialect);
      var res = await xdb.query(q.sql, q.params);
      var applied = (res && res.rows) || [];
      var appliedNames = new Set(applied.map(function (r) { return r.name; }));
      var files = _list(dir);
      var pending = files.filter(function (f) { return !appliedNames.has(f); });
      return {
        applied:  applied,
        pending:  pending,
        total:    files.length,
        backend:  backendName,
      };
    }, { backend: backendName });
  }

  async function up() {
    var backendName = _resolveBackendName(opts);
    var dialect = _backendDialect(backendName);
    var ctx = _ctx(backendName);

    return await externalDb().transaction(async function (xdb) {
      await _ensureTrackingTable(xdb, dialect);
      await _ensureLockTable(xdb, dialect);
      await _ensureHistoryTable(xdb, dialect);
    }, { backend: backendName }).then(async function () {
      var lockResult = await externalDb().transaction(async function (xdb) {
        return await _acquireLock(xdb, opts, dialect);
      }, { backend: backendName });
      var lockHolder = lockResult.holder;

      _emit(audit, "externaldb.migrate.lock.acquired", "success",
            { holder: lockHolder, backend: backendName }, null);
      if (lockResult.takeoverFrom) {
        _emit(audit, "externaldb.migrate.lock.takeover", "success",
              { holder: lockHolder, takeoverFrom: lockResult.takeoverFrom,
                takeoverAgeMs: lockResult.takeoverAgeMs, backend: backendName }, null);
      }

      try {
        var appliedQ = _bind(sql().select(_trackingTable(), { dialect: dialect })
          .columns(["name"]), dialect);
        var appliedRes = await externalDb().query(appliedQ.sql, appliedQ.params, { backend: backendName });
        var appliedSet = new Set(((appliedRes && appliedRes.rows) || []).map(function (r) { return r.name; }));
        var files = _list(dir);
        var applied = [];
        var skipped = [];

        for (var i = 0; i < files.length; i++) {
          var file = files[i];
          if (appliedSet.has(file)) { skipped.push(file); continue; }
          var mod = _loadMigration(file, dir);
          var t0 = Date.now();
          try {
            await externalDb().transaction(async function (xdb) {
              await mod.up(xdb, ctx);
              var ranAt = new Date().toISOString();
              var insTrack = _bind(sql().insert(_trackingTable(), { dialect: dialect })
                .values({ name: file, description: mod.description || "", appliedAt: ranAt }), dialect);
              await xdb.query(insTrack.sql, insTrack.params, FRAMEWORK_METADATA_OPTS);
              var historyRow = {
                version:                 file,
                ranAt:                   ranAt,
                ranBy:                   ranBy,
                schemaIntrospectionHash: await schemaIntrospect(xdb, dialect),
                signature:               null,
                publicKeyFingerprint:    null,
              };
              if (signHistory) {
                try {
                  var payload = _historyPayload(historyRow);
                  var sigBuf = auditSign().sign(payload);
                  historyRow.signature = sigBuf.toString("base64");
                  historyRow.publicKeyFingerprint = auditSign().getPublicKeyFingerprint();
                } catch (sigErr) {
                  _emit(audit, "migrations.history.sign_failed", "failure",
                    { migration: file, backend: backendName },
                    (sigErr && sigErr.message) || String(sigErr));
                }
              }
              await _writeHistoryRow(xdb, historyRow, dialect);
              _emit(audit, "migrations.history.appended", "success", {
                migration: file,
                schemaIntrospectionHash: historyRow.schemaIntrospectionHash,
                signed: historyRow.signature !== null,
                backend: backendName,
              }, null);
            }, { backend: backendName });
            _emit(audit, "externaldb.migrate.up", "success",
                  { migration: file, durationMs: Date.now() - t0, backend: backendName }, null);
            applied.push(file);
          } catch (e) {
            _emit(audit, "externaldb.migrate.up", "failure",
                  { migration: file, durationMs: Date.now() - t0, backend: backendName },
                  (e && e.message) || String(e));
            throw _err("externaldb-migrate/up-failed",
              "migration '" + file + "' failed to apply: " + ((e && e.message) || String(e)));
          }
        }
        return { applied: applied, skipped: skipped, backend: backendName };
      } finally {
        try {
          await externalDb().transaction(async function (xdb) {
            await _releaseLock(xdb, lockHolder, dialect);
          }, { backend: backendName });
          _emit(audit, "externaldb.migrate.lock.released", "success",
                { holder: lockHolder, backend: backendName }, null);
        } catch (_e) { 
          _emit(audit, "externaldb.migrate.lock.released", "failure",
                { holder: lockHolder, backend: backendName }, "release failed");
        }
      }
    });
  }

  async function down(downOpts) {
    downOpts = downOpts || {};
    var steps = (typeof downOpts.steps === "number" && downOpts.steps > 0)
                  ? Math.floor(downOpts.steps) : 1;
    var backendName = _resolveBackendName(opts);
    var dialect = _backendDialect(backendName);
    var ctx = _ctx(backendName);

    await externalDb().transaction(async function (xdb) {
      await _ensureTrackingTable(xdb, dialect);
      await _ensureLockTable(xdb, dialect);
    }, { backend: backendName });

    var lockResultDown = await externalDb().transaction(async function (xdb) {
      return await _acquireLock(xdb, opts, dialect);
    }, { backend: backendName });
    var lockHolder = lockResultDown.holder;

    _emit(audit, "externaldb.migrate.lock.acquired", "success",
          { holder: lockHolder, backend: backendName }, null);
    if (lockResultDown.takeoverFrom) {
      _emit(audit, "externaldb.migrate.lock.takeover", "success",
            { holder: lockHolder, takeoverFrom: lockResultDown.takeoverFrom,
              takeoverAgeMs: lockResultDown.takeoverAgeMs, backend: backendName }, null);
    }

    try {
      var downQ = _bind(sql().select(_trackingTable(), { dialect: dialect })
        .columns(["name"])
        .orderBy("appliedAt", "desc").orderBy("name", "desc").limit(steps), dialect);
      var appliedRes = await externalDb().query(downQ.sql, downQ.params, { backend: backendName });
      var rows = (appliedRes && appliedRes.rows) || [];
      var reverted = [];
      for (var i = 0; i < rows.length; i++) {
        var file = rows[i].name;
        var mod = _loadMigration(file, dir);
        if (typeof mod.down !== "function") {
          throw _err("externaldb-migrate/no-down",
            "migration '" + file + "' has no down() — write one or restore from backup");
        }
        var t0 = Date.now();
        try {
          await externalDb().transaction(async function (xdb) {
            await mod.down(xdb, ctx);
            var delTrack = _bind(sql().delete(_trackingTable(), { dialect: dialect })
              .where("name", file), dialect);
            await xdb.query(delTrack.sql, delTrack.params);
          }, { backend: backendName });
          _emit(audit, "externaldb.migrate.down", "success",
                { migration: file, durationMs: Date.now() - t0, backend: backendName }, null);
          reverted.push(file);
        } catch (e) {
          _emit(audit, "externaldb.migrate.down", "failure",
                { migration: file, durationMs: Date.now() - t0, backend: backendName },
                (e && e.message) || String(e));
          throw _err("externaldb-migrate/down-failed",
            "migration '" + file + "' failed to roll back: " + ((e && e.message) || String(e)));
        }
      }
      return { reverted: reverted, backend: backendName };
    } finally {
      try {
        await externalDb().transaction(async function (xdb) {
          await _releaseLock(xdb, lockHolder, dialect);
        }, { backend: backendName });
        _emit(audit, "externaldb.migrate.lock.released", "success",
              { holder: lockHolder, backend: backendName }, null);
      } catch (_e) {
        _emit(audit, "externaldb.migrate.lock.released", "failure",
              { holder: lockHolder, backend: backendName }, "release failed");
      }
    }
  }

  async function history(historyOpts) {
    historyOpts = historyOpts || {};
    var backendName = _resolveBackendName(opts);
    var dialect = _backendDialect(backendName);
    return await externalDb().transaction(async function (xdb) {
      await _ensureHistoryTable(xdb, dialect);
      var histQ = _bind(sql().select(_historyTable(), { dialect: dialect })
        .columns(["version", "ranAt", "ranBy", "schemaIntrospectionHash", "signature", "publicKeyFingerprint"])
        .orderBy("ranAt", "asc").orderBy("version", "asc"), dialect);
      var res = await xdb.query(histQ.sql, histQ.params);
      var out = [];
      var rows = (res && res.rows) || [];
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        var verified = false;
        var verifyReason = null;
        if (!row.signature) {
          verifyReason = "row-unsigned";
        } else {
          try {
            var payload = _historyPayload(row);
            var sigBuf = Buffer.from(row.signature, "base64");
            var currentFp = auditSign().getPublicKeyFingerprint();
            if (row.publicKeyFingerprint && row.publicKeyFingerprint !== currentFp) {
              verifyReason = "public-key-fingerprint-mismatch";
            } else {
              verified = !!auditSign().verify(payload, sigBuf);
              if (!verified) verifyReason = "signature-verify-failed";
            }
          } catch (e) {
            verifyReason = "verify-threw: " + ((e && e.message) || String(e));
          }
        }
        out.push({
          version:                 row.version,
          ranAt:                   row.ranAt,
          ranBy:                   row.ranBy,
          schemaIntrospectionHash: row.schemaIntrospectionHash,
          signature:               row.signature,
          publicKeyFingerprint:    row.publicKeyFingerprint,
          verified:                verified,
          verifyReason:            verifyReason,
        });
        if (!verified && row.signature) {
          _emit(audit, "migrations.history.tamper_detected", "denied", {
            version: row.version, ranAt: row.ranAt, reason: verifyReason,
            backend: backendName,
          }, null);
        }
      }
      _emit(audit, "migrations.history.verified", "success", {
        rowsVerified: out.length, backend: backendName,
      }, null);
      return out;
    }, { backend: backendName });
  }

  return {
    up:       up,
    down:     down,
    status:   status,
    history:  history,
  };
}

module.exports = {
  create:                  create,
  ExternalDbMigrateError:  ExternalDbMigrateError,
  HISTORY_SIGNATURE_FORMAT: HISTORY_SIGNATURE_FORMAT,
};

Object.defineProperty(module.exports, "TRACKING_TABLE", {
  enumerable: true, get: function () { return _trackingTable(); },
});
Object.defineProperty(module.exports, "HISTORY_TABLE", {
  enumerable: true, get: function () { return _historyTable(); },
});
