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
var path = require("path");
var atomicFile = require("./atomic-file");
var lazyRequire = require("./lazy-require");
var migrationFiles = require("./migration-files");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var ExternalDbMigrateError = defineClass("ExternalDbMigrateError", { alwaysPermanent: true });

// Lazy require — external-db imports back into this module via its
// public `migrate` namespace; load-order would cycle without lazy.
var externalDbModule = lazyRequire(function () { return require("./external-db"); });

var TRACKING_TABLE = "_blamejs_externaldb_migrations";
var LOCK_TABLE     = "_blamejs_externaldb_migrations_lock";
// Identifiers wrapped in `"..."` per project convention so a reserved-word
// or whitespace-bearing name resolves correctly.
var Q_TRACKING = '"' + TRACKING_TABLE + '"';
var Q_LOCK     = '"' + LOCK_TABLE + '"';

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
var _BOOT_TOKEN = require("node:crypto").randomBytes(8).toString("hex");          // allow:raw-byte-literal — boot-id token entropy

function _lockHolderId() {
  return String(process.pid) + "@" +
    (require("node:os").hostname() || "unknown") + "@" + _BOOT_TOKEN;
}

async function _ensureTrackingTable(xdb) {
  // Tracking table holds the migration history. ISO-8601 timestamp
  // strings (TEXT) keep the framework's tracking table portable across
  // Postgres/SQLite without dialect-specific type juggling — operators
  // who want strict TIMESTAMPTZ for their own ad-hoc queries against
  // the table ALTER it post-creation.
  await xdb.query(
    "CREATE TABLE IF NOT EXISTS " + Q_TRACKING + " (" +
    "  name        TEXT PRIMARY KEY," +
    "  description TEXT," +
    "  appliedAt   TEXT NOT NULL" +
    ")",
    []
  );
}

async function _ensureLockTable(xdb) {
  await xdb.query(
    "CREATE TABLE IF NOT EXISTS " + Q_LOCK + " (" +
    "  scope     TEXT PRIMARY KEY," +
    "  lockedAt  INTEGER NOT NULL," +
    "  lockedBy  TEXT NOT NULL," +
    "  CHECK (scope = 'lock')" +
    ")",
    []
  );
}

// ---- Lock acquire / release ----

async function _acquireLock(xdb, opts) {
  await _ensureLockTable(xdb);
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
  try {
    await xdb.query(
      "INSERT INTO " + Q_LOCK + " (scope, lockedAt, lockedBy) VALUES ('lock', $1, $2)",
      [nowMs, holder]
    );
    return { holder: holder, takeoverFrom: null, takeoverAgeMs: 0 };
  } catch (_e) {
    // PRIMARY KEY conflict → existing lock. Inspect it.
    var existingRes = await xdb.query(
      "SELECT lockedAt, lockedBy FROM " + Q_LOCK + " WHERE scope = 'lock'",
      []
    );
    var existing = existingRes && existingRes.rows && existingRes.rows[0];
    if (!existing) {
      try {
        await xdb.query(
          "INSERT INTO " + Q_LOCK + " (scope, lockedAt, lockedBy) VALUES ('lock', $1, $2)",
          [nowMs, holder]
        );
        return { holder: holder, takeoverFrom: null, takeoverAgeMs: 0 };
      } catch (e2) {
        throw _err("externaldb-migrate/lock-busy",
          "could not acquire migration lock: " + ((e2 && e2.message) || String(e2)));
      }
    }
    var ageMs = nowMs - Number(existing.lockedat || existing.lockedAt);
    if (staleAfterMs > 0 && ageMs > staleAfterMs) {
      // Force-replace the stale lock atomically. Stale-takeover is a
      // SOC2 evidence event — caller emits an audit row.
      var prevHolder = existing.lockedby || existing.lockedBy;
      await xdb.query(
        "DELETE FROM " + Q_LOCK + " WHERE scope = 'lock' AND lockedAt = $1",
        [Number(existing.lockedat || existing.lockedAt)]
      );
      await xdb.query(
        "INSERT INTO " + Q_LOCK + " (scope, lockedAt, lockedBy) VALUES ('lock', $1, $2)",
        [nowMs, holder]
      );
      return { holder: holder, takeoverFrom: prevHolder, takeoverAgeMs: ageMs };
    }
    throw _err("externaldb-migrate/lock-held",
      "migration lock is held by " + (existing.lockedby || existing.lockedBy) +
      " (acquired " + ageMs + "ms ago). Another process is running migrations" +
      " — wait for it to finish, or pass staleAfterMs to force-replace stale locks.");
  }
}

async function _releaseLock(xdb, holder) {
  try {
    await xdb.query(
      "DELETE FROM " + Q_LOCK + " WHERE scope = 'lock' AND lockedBy = $1",
      [holder]
    );
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
  var fullPath = path.join(dir, file);
  // Drop the require cache so a test/dev that edits a file picks up the
  // new content. Matches lib/migrations.js semantics.
  try { delete require.cache[require.resolve(fullPath)]; } catch (_e) { /* not yet cached */ }
  var mod;
  try { mod = require(fullPath); }
  catch (e) {
    throw _err("externaldb-migrate/load-failed",
      "migration '" + file + "' failed to load: " + ((e && e.message) || String(e)));
  }
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
  try { listed = externalDbModule().listBackends(); }
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
  validateOpts(opts, ["dir", "backend", "audit", "staleAfterMs"], "b.externalDb.migrate");
  validateOpts.requireNonEmptyString(opts.dir, "externalDb.migrate.create: opts.dir (path to migrations directory)", ExternalDbMigrateError, "externaldb-migrate/no-dir");
  validateOpts.optionalFiniteNonNegative(opts.staleAfterMs, "externalDb.migrate: staleAfterMs", ExternalDbMigrateError, "externaldb-migrate/bad-stale");
  validateOpts.auditShape(opts.audit, "externalDb.migrate", ExternalDbMigrateError, "externaldb-migrate/bad-audit");
  var dir = opts.dir;
  var audit = opts.audit || null;

  function _ctx(backendName) {
    return {
      externalDb:  externalDbModule(),
      backendName: backendName,
    };
  }

  async function status() {
    var backendName = _resolveBackendName(opts);
    return await externalDbModule().transaction(async function (xdb) {
      await _ensureTrackingTable(xdb);
      var res = await xdb.query(
        "SELECT name, description, appliedAt FROM " + Q_TRACKING +
        " ORDER BY appliedAt ASC, name ASC",
        []
      );
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
    var ctx = _ctx(backendName);

    return await externalDbModule().transaction(async function (xdb) {
      await _ensureTrackingTable(xdb);
      await _ensureLockTable(xdb);
    }, { backend: backendName }).then(async function () {
      // Acquire the lock OUTSIDE the per-migration transaction so the
      // lock survives across migration boundaries. We use a separate
      // pool acquisition for the lock connection — the migrate runner
      // serializes apply order, so this single-connection lock is
      // sufficient.
      var lockResult = await externalDbModule().transaction(async function (xdb) {
        return await _acquireLock(xdb, opts);
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
        var appliedRes = await externalDbModule().query(
          "SELECT name FROM " + Q_TRACKING, [], { backend: backendName }
        );
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
            await externalDbModule().transaction(async function (xdb) {
              await mod.up(xdb, ctx);
              await xdb.query(
                "INSERT INTO " + Q_TRACKING +
                " (name, description, appliedAt) VALUES ($1, $2, $3)",
                [file, mod.description || "", new Date().toISOString()]
              );
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
          await externalDbModule().transaction(async function (xdb) {
            await _releaseLock(xdb, lockHolder);
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
    var ctx = _ctx(backendName);

    await externalDbModule().transaction(async function (xdb) {
      await _ensureTrackingTable(xdb);
      await _ensureLockTable(xdb);
    }, { backend: backendName });

    var lockResultDown = await externalDbModule().transaction(async function (xdb) {
      return await _acquireLock(xdb, opts);
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
      var appliedRes = await externalDbModule().query(
        "SELECT name FROM " + Q_TRACKING + " ORDER BY appliedAt DESC, name DESC LIMIT $1",
        [steps], { backend: backendName }
      );
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
          await externalDbModule().transaction(async function (xdb) {
            await mod.down(xdb, ctx);
            await xdb.query(
              "DELETE FROM " + Q_TRACKING + " WHERE name = $1",
              [file]
            );
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
        await externalDbModule().transaction(async function (xdb) {
          await _releaseLock(xdb, lockHolder);
        }, { backend: backendName });
        _emit(audit, "externaldb.migrate.lock.released", "success",
              { holder: lockHolder, backend: backendName }, null);
      } catch (_e) {
        _emit(audit, "externaldb.migrate.lock.released", "failure",
              { holder: lockHolder, backend: backendName }, "release failed");
      }
    }
  }

  return {
    up:       up,
    down:     down,
    status:   status,
  };
}

module.exports = {
  create:                  create,
  ExternalDbMigrateError:  ExternalDbMigrateError,
  TRACKING_TABLE:          TRACKING_TABLE,
};
