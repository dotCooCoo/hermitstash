// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.externalDb.migrate — versioned migrations for an externalDb backend.
 *
 * Mirrors b.migrations (which targets the framework's local SQLite) but
 * runs against an externalDb backend. Tracking + lock tables live on
 * the externalDb side under `_blamejs_externaldb_migrations` and
 * `_blamejs_externaldb_migrations_lock`. Each migration runs inside
 * `externalDb.transaction(fn)` so a failing migration rolls back
 * cleanly and stops the wave.
 *
 * Migration file format (filename pattern: NNNN-<slug>.js):
 *
 *   module.exports = {
 *     description: "Create users table",
 *     up:   async function (xdb, ctx) { await xdb.query("CREATE TABLE ..."); },
 *     down: async function (xdb, ctx) { await xdb.query("DROP TABLE ..."); },
 *   };
 *
 * `xdb` exposes `.query(sql, params) → { rows, rowCount }`. `ctx` carries
 * `{ externalDb, backendName }` so migrations that need backend-introspection
 * (e.g. `b.db.declareView()`-shaped specs) can call back into the framework.
 *
 * `up` is required; `down` is optional. Calling `down()` on a migration
 * that didn't export `down()` surfaces a clear error.
 *
 *   var migrate = b.externalDb.migrate.create({
 *     dir:      "./migrations-pg",
 *     backend:  "main",         // optional; defaults to default backend
 *     audit:    b.audit,        // optional
 *   });
 *
 *   await migrate.up();         // → { applied: [name], skipped: [name] }
 *   await migrate.down({ steps: 1 });
 *   migrate.status();           // → { applied: [{name, description, appliedAt}], pending: [name], total }
 *
 * Concurrent-apply protection: a single-row advisory lock in
 * `_blamejs_externaldb_migrations_lock` ensures two processes can't apply
 * the same wave concurrently. The losing process gets a clear "lock held
 * by other process" error. Stale locks can be force-replaced via
 * `staleAfterMs`.
 *
 * Audit emissions when wired with `audit: b.audit`:
 *   - externaldb.migrate.up.success      { migration, durationMs }
 *   - externaldb.migrate.up.failure      { migration, durationMs, reason }
 *   - externaldb.migrate.down.success    { migration, durationMs }
 *   - externaldb.migrate.down.failure    { migration, durationMs, reason }
 *   - externaldb.migrate.lock.acquired   { holder }
 *   - externaldb.migrate.lock.released   { holder }
 */
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

// The migration runner's own bookkeeping tables, resolved through
// frameworkSchema so the configurable framework-table prefix is honored
// (these names are not in the LOCAL_TO_EXTERNAL map, so the resolve only
// swaps the leading prefix; default prefix is a no-op). b.sql quotes
// every identifier by construction in the backend's own dialect
// (double-quote on Postgres / SQLite, backtick on MySQL), with the
// placeholder form (`$N` on Postgres, `?` on SQLite / MySQL) selected by
// the resolved backend dialect — see _backendDialect / _bind below.
function _trackingTable() { return frameworkSchema().tableName("_blamejs_externaldb_migrations"); }        // allow:hand-rolled-sql — single canonical logical-name reference
function _lockTable()     { return frameworkSchema().tableName("_blamejs_externaldb_migrations_lock"); }   // allow:hand-rolled-sql — single canonical logical-name reference
function _historyTable()  { return frameworkSchema().tableName("_blamejs_schema_version_history"); }       // allow:hand-rolled-sql — single canonical logical-name reference

// Resolve the SQL dialect of the backend this migration wave targets.
// The runner emits Postgres / SQLite / MySQL — they diverge on identifier
// quoting (double-quote vs backtick), the ON CONFLICT / ON DUPLICATE KEY
// upsert idiom, and placeholder syntax (`$N` vs `?`). Reading the dialect
// off the backend itself (set at b.externalDb.init) is what keeps the
// bookkeeping DDL + tracking statements valid on each. Falls back to
// "postgres" when the backend can't be resolved (uninitialized externalDb
// surfaces a clearer error upstream at _resolveBackendName); the bare
// fallback never reaches a real query.
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

// b.sql emits `?` placeholders; the externalDb driver receives SQL
// verbatim, so translate to the Postgres `$N` form on a Postgres backend
// (placeholderize is a passthrough for SQLite / MySQL, which keep `?`).
// dialect is the resolved backend dialect so the placeholder form matches
// the backend the SQL dispatches to.
function _bind(builder, dialect) {
  var built = builder.toSql();
  return { sql: clusterStorage().placeholderize(built.sql, dialect), params: built.params };
}

// The migration tracking / history / lock tables hold framework
// bookkeeping ("migration X ran at time T"), not region-bound personal
// data, so their writes carry the residency-neutral "unrestricted" tag
// — the per-row residency write gate (b.externalDb.query) refuses DML
// to a residency-tagged backend under a cross-border regulated posture
// unless a compatible rowResidencyTag is supplied. Operator migration
// DML (mod.up) stays subject to the gate; only these internal writes
// are exempt. Passed as the per-statement opts override on the txClient.
var FRAMEWORK_METADATA_OPTS = Object.freeze({ rowResidencyTag: "unrestricted" });

// Bytes that get signed for one history row. Stable forever — changing
// it invalidates every prior signature.
var HISTORY_SIGNATURE_FORMAT = "blamejs-schema-history-v1";

function _historyPayload(row) {
  // Canonical JSON keeps the byte stream deterministic across Node
  // versions / property-insertion order. Order-independent verifiers
  // recompute the same bytes.
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

// Hash the current schema introspection — operators wiring an opts.
// schemaIntrospect that returns deterministic bytes get the strict
// guarantee that a tampered table after-the-fact will not verify. The
// default introspect just returns the migration name list as a JSON
// array, which is enough to detect "someone manually altered the
// migrations table."
async function _defaultSchemaIntrospect(xdb, dialect) {
  var q = _bind(sql().select(_trackingTable(), { dialect: dialect })
    .columns(["name", "appliedAt"])
    .orderBy("appliedAt", "asc").orderBy("name", "asc"), dialect);
  var res = await xdb.query(q.sql, q.params);
  var rows = (res && res.rows) || [];
  return sha3Hash(Buffer.from(canonicalJson.stringify(rows), "utf8"));
}

// Filename grammar lives in lib/migration-files (shared with the local
// migrations.js + seeders.js runners). Length capped before the regex
// test so a hostile directory listing can't drive the engine against
// an unbounded filename string.
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

// Boot-token suffix ensures _lockHolderId() is unique across container
// restarts even if the OS recycles a PID into the same hostname slot —
// without it, a stolen-and-released migration lock could be wrongly
// attributed back to the new boot. The token is process-scoped so
// every replica picks a fresh one at module load.
var _BOOT_TOKEN = require("node:crypto").randomBytes(8).toString("hex");          // boot-id token entropy

function _lockHolderId() {
  return String(process.pid) + "@" +
    (require("node:os").hostname() || "unknown") + "@" + _BOOT_TOKEN;
}

async function _ensureTrackingTable(xdb, dialect) {
  // Tracking table holds the migration history. ISO-8601 timestamp
  // strings keep the framework's tracking table portable across
  // Postgres/SQLite/MySQL without dialect-specific type juggling —
  // operators who want strict TIMESTAMPTZ for their own ad-hoc queries
  // against the table ALTER it post-creation. The `name` PK is a bounded
  // VARCHAR, not TEXT: MySQL refuses an unbounded TEXT/BLOB in a key
  // (ER 1170), and a migration filename is length-capped at FILE_NAME_MAX
  // so 255 covers every valid value. Postgres / SQLite treat VARCHAR(255)
  // identically to TEXT for storage.
  await xdb.query(sql().createTable(_trackingTable(), [
    { name: "name",        type: "VARCHAR(255)", primaryKey: true },
    { name: "description", type: "TEXT" },
    { name: "appliedAt",   type: "TEXT", notNull: true },
  ], { dialect: dialect }).sql, []);
}

async function _ensureHistoryTable(xdb, dialect) {
  // Schema-version history table: append-only record of every migrate.up
  // wave + signature over (version, ranAt, ranBy, schemaIntrospectionHash).
  // Signature uses ML-DSA-87 / SLH-DSA-SHAKE-256f via b.auditSign — an
  // attacker tampering with rows after-the-fact cannot forge a matching
  // signature without the audit-signing private key. version + ranAt form
  // the composite PK, so both are bounded VARCHARs (MySQL refuses an
  // unbounded TEXT/BLOB in a key, ER 1170); version is a filename
  // (length-capped) and ranAt an ISO-8601 string, both within bound.
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
  // The scope CHECK is a static operator-controlled literal, carried as
  // the last column's verbatim constraint (b.sql guards it via
  // allowLiterals). lockedAt holds a ms-epoch value, so the framework INT
  // type (BIGINT on Postgres/MySQL) is required — a 32-bit INTEGER
  // overflows. The scope PK is a bounded VARCHAR (only ever 'lock'): MySQL
  // refuses an unbounded TEXT/BLOB in a key (ER 1170).
  await xdb.query(sql().createTable(_lockTable(), [
    { name: "scope",    type: "VARCHAR(64)", primaryKey: true },
    { name: "lockedAt", type: "INTEGER", notNull: true },
    { name: "lockedBy", type: "TEXT", notNull: true,
      constraints: ", CHECK (scope = 'lock')" },                                    // allow:hand-rolled-sql — static DDL CHECK literal
  ], { dialect: dialect }).sql, []);
}

// ---- Lock acquire / release ----

async function _acquireLock(xdb, opts, dialect) {
  await _ensureLockTable(xdb, dialect);
  var holder = _lockHolderId();
  var nowMs = Date.now();
  // See migrations.acquireLock for the same fix — Infinity was
  // silently identical to 0 (no staleness check) but obscured the typo.
  var staleAfterMs = 0;
  if (opts) {
    numericBounds.requireNonNegativeFiniteIntIfPresent(opts.staleAfterMs,
      "externalDb.migrate.acquireLock: staleAfterMs",
      ExternalDbMigrateError, "externalDb-migrate/bad-opt");
    if (opts.staleAfterMs !== undefined) staleAfterMs = opts.staleAfterMs;
  }
  // Conflict-safe lock acquire. The INSERT runs inside
  // externalDb.transaction(_acquireLock); on Postgres a plain INSERT that
  // hits the PRIMARY KEY conflict raises SQLSTATE 23505 which ABORTS the
  // surrounding transaction (every later statement then fails with 25P02,
  // "current transaction is aborted"), so the holder-naming SELECT could
  // not run and the operator got a raw aborted-transaction error instead of
  // the documented "migration lock is held by <holder>" message. Emitting
  // `INSERT ... ON CONFLICT (scope) DO NOTHING` (Postgres/SQLite) /
  // `INSERT ... ON DUPLICATE KEY UPDATE scope=scope` (MySQL — a no-op)
  // turns the conflict into a 0-row result rather than a transaction-
  // aborting error, so the inspect SELECT below runs cleanly and names the
  // holder. rowCount === 1 means we won the lock; 0 means it is held.
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
    // A genuine driver/connection fault (not a conflict — the conflict is now
    // a 0-row no-op, never a throw). Surface as lock-busy.
    throw _err("externaldb-migrate/lock-busy",
      "could not acquire migration lock: " + ((e0 && e0.message) || String(e0)));
  }
  if (insRes && insRes.rowCount >= 1) {
    return { holder: holder, takeoverFrom: null, takeoverAgeMs: 0 };
  }
  {
    // 0 rows inserted → the lock IS held. Inspect it to name the holder. The
    // conflict was a clean no-op (DO NOTHING), so the transaction is NOT
    // aborted and this SELECT runs.
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
      // Lock row vanished between the no-op insert and the inspect (the
      // holder released concurrently). Retry the acquire once.
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
      // Force-replace the stale lock atomically. Stale-takeover is a
      // SOC2 evidence event — caller emits an audit row.
      var prevHolder = existing.lockedby || existing.lockedBy;
      var delStale = _bind(sql().delete(_lockTable(), { dialect: dialect })
        .where("scope", "lock")
        .where("lockedAt", Number(existing.lockedat || existing.lockedAt)), dialect);
      await xdb.query(delStale.sql, delStale.params, FRAMEWORK_METADATA_OPTS);
      var insTakeover = _insertLock();
      var takeoverRes = await xdb.query(insTakeover.sql, insTakeover.params, FRAMEWORK_METADATA_OPTS);
      if (!takeoverRes || takeoverRes.rowCount < 1) {
        // Another process slipped a fresh lock in between our DELETE and
        // INSERT (the conflict is a DO NOTHING no-op, so 0 rows = lost race).
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

// ---- File loading ----

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

// ---- Backend resolution ----

function _resolveBackendName(opts) {
  if (opts && typeof opts.backend === "string" && opts.backend.length > 0) {
    return opts.backend;
  }
  // Default to the externalDb's defaultBackend; throw clear if not initialized.
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

// ---- Public factory ----

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
      // Acquire the lock OUTSIDE the per-migration transaction so the
      // lock survives across migration boundaries. We use a separate
      // pool acquisition for the lock connection — the migrate runner
      // serializes apply order, so this single-connection lock is
      // sufficient.
      var lockResult = await externalDb().transaction(async function (xdb) {
        return await _acquireLock(xdb, opts, dialect);
      }, { backend: backendName });
      var lockHolder = lockResult.holder;

      _emit(audit, "externaldb.migrate.lock.acquired", "success",
            { holder: lockHolder, backend: backendName }, null);
      // SOC2 evidence — record the stale-takeover separately so a
      // forensic review can reconstruct WHICH process orphaned the
      // lock and WHEN. Pre-v0.8.19 the takeover happened silently.
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
              // Schema-version history with signature. Sign post-INSERT
              // so the introspection hash reflects the row that just
              // landed. Sign-failure is non-fatal for the migration but
              // emits a failure audit so the operator chases it down.
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
        } catch (_e) { /* best-effort release; emit a failure audit */
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

  // history(opts?) — list every schema-version-history row + verify the
  // signature on each. Returns:
  //   [{ version, ranAt, ranBy, schemaIntrospectionHash, signature,
  //      publicKeyFingerprint, verified: bool, verifyReason: string|null }]
  //
  // verify is `true` when the signature decodes + auditSign.verify
  // returns true against the row's payload; `false` with reason
  // otherwise (unsigned row / verify-failed / signing key absent /
  // public-key-fingerprint mismatch).
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

// The resolved table names are exposed as lazy getters: frameworkSchema's
// tableName export is not bound while this module evaluates (the
// external-db require cycle), so resolving at access time gives the
// configurable-prefix-aware concrete name without a load-order trap.
Object.defineProperty(module.exports, "TRACKING_TABLE", {
  enumerable: true, get: function () { return _trackingTable(); },
});
Object.defineProperty(module.exports, "HISTORY_TABLE", {
  enumerable: true, get: function () { return _historyTable(); },
});
