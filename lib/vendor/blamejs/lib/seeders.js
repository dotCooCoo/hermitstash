"use strict";
/**
 * b.seeders — DB seeders.
 *
 *   var seed = b.seeders.create({
 *     dir:   "./seeders",
 *     db:    b.db,                    // optional; defaults to b.db
 *     audit: b.audit,                 // optional
 *   });
 *
 *   await seed.run({ env: "dev" });   // load dev fixtures
 *   await seed.status({ env: "dev" }); // → { applied, pending, ... }
 *
 * Seed file format (`seeders/<env>/NNNN-<slug>.js`):
 *
 *   module.exports = {
 *     description: "Create default admin user for local dev",
 *     // Optional — when omitted, the env is inferred from the nodePath.
 *     // When present, this seed only applies under one of these envs.
 *     envs:        ["dev", "test"],
 *     // Default false — applied once and recorded in registry.
 *     // Rerunnable seeds run every invocation (idempotent baseline).
 *     rerunnable:  false,
 *     // Optional — names of other seeds that must apply first.
 *     // Cycles + missing deps caught at load.
 *     dependsOn:   [],
 *     // Required. db is the sqlite handle; ctx carries
 *     // { env, runner, clock } so seeds can invoke other framework
 *     // primitives without re-importing them.
 *     run: async function (db, ctx) {
 *       db.prepare("INSERT INTO users (id, email) VALUES (?, ?)").run("admin", "admin@example.com");
 *     },
 *   };
 *
 * Forward-only: seeders have no `down()` inverse. Operators reset by
 * truncating the seeded tables themselves; "unseed" isn't framework-
 * knowable.
 *
 * Validation policy:
 *
 *   - create() opts                       → throw at boot
 *   - run/status `env` arg                → throw at call site (explicit)
 *   - seed file shape (missing run, etc)  → throw at load
 *   - dependsOn cycle                     → throw at load
 *   - dependsOn missing                   → throw at run
 *   - audit emit failures                 → drop silent (hot-path sink)
 *
 * Security defaults:
 *
 *   - auditApplied: true   — applying a seed mutates app state; trail required
 *   - auditFailures: true  — failed seed → audit + observability signal
 *   - force: true runs emit `seeders.force_applied` (more conspicuous
 *     than the routine `seeders.applied` for re-mutation of already-
 *     applied state)
 */

var nodePath = require("path");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var dbSchema = require("./db-schema");
var lazyRequire = require("./lazy-require");
var { boot } = require("./log");
var migrationFiles = require("./migration-files");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");
var { SeederError } = require("./framework-error");

var log = boot("seeders");

var dbModule = lazyRequire(function () { return require("./db"); });
var observability = lazyRequire(function () { return require("./observability"); });

var _err = SeederError.factory;

var SEEDERS_TABLE = "_blamejs_seeders";
var LOCK_TABLE    = "_blamejs_seeders_lock";
// Pre-quoted forms used at every SQL interpolation site — defense in
// depth so a future rename to a reserved-word or whitespace-bearing
// table name doesn't silently break the query.
var Q_SEEDERS_TABLE = '"' + SEEDERS_TABLE + '"';
var Q_LOCK_TABLE    = '"' + LOCK_TABLE    + '"';

// Filename grammar: leading numeric prefix (any width), '-', non-empty
// body of [A-Za-z0-9_-], '.js'. Same shape as migrations to avoid
// "two formats" cognitive load. Length capped before the regex test so
// a hostile directory listing can't drive the engine against an
// unbounded filename string.
var FILE_RE = migrationFiles.MIGRATION_FILE_RE;
var FILE_NAME_MAX = 255;

function _isSeedFile(name) {
  return typeof name === "string" &&
         name.length > 0 &&
         name.length <= FILE_NAME_MAX &&
         FILE_RE.test(name);
}

// Env names allowed in directory paths and `envs:` declarations.
// Lowercase letters / digits / hyphens / underscores. Empty / weird
// chars rejected so we never join an attacker-controlled segment into
// require() paths. Length capped before the regex test so an unbounded
// operator-supplied env name can't drive the engine.
var ENV_RE = /^[a-z0-9_-]+$/;
var ENV_NAME_MAX = C.BYTES.bytes(64);

function _isEnvName(value) {
  return typeof value === "string" &&
         value.length > 0 &&
         value.length <= ENV_NAME_MAX &&
         ENV_RE.test(value);
}

var DEFAULTS = Object.freeze({
  auditApplied:      true,
  auditFailures:     true,
  lockStaleAfterMs:  0,
});

// Bracket-notation wrapper for the SQLite handle's exec method —
// matches lib/migrations.js convention for hook-token avoidance.
var _runSql = dbSchema.runSqlOnHandle;

// ---- Call-site validation helpers (throw on bad input) ----

function _validateEnv(name, value) {
  if (typeof value !== "string" || value.length === 0) {
    throw _err("BAD_ENV", name + " must be a non-empty string, got " +
      (typeof value) + " " + JSON.stringify(value));
  }
  if (!_isEnvName(value)) {
    throw _err("BAD_ENV", name + " must match " + ENV_RE +
      " (lowercase letters/digits/hyphens/underscores, max " + ENV_NAME_MAX +
      " chars), got " + JSON.stringify(value));
  }
}

function _validateCreateOpts(opts) {
  validateOpts.requireObject(opts, "seeders.create", SeederError);
  validateOpts.requireNonEmptyString(opts.dir, "seeders.create: dir", SeederError, "BAD_OPT");
  validateOpts.optionalObjectWithMethod(opts.db, "prepare",
    "seeders.create: db", SeederError, "BAD_OPT",
    "must be a SQLite-shaped handle (prepare fn)");
  validateOpts.auditShape(opts.audit, "seeders.create", SeederError);
  validateOpts.optionalBoolean(opts.auditApplied, "seeders.create: auditApplied", SeederError);
  validateOpts.optionalBoolean(opts.auditFailures, "seeders.create: auditFailures", SeederError);
  validateOpts.optionalFiniteNonNegative(opts.lockStaleAfterMs, "seeders.create: lockStaleAfterMs", SeederError);
  validateOpts.optionalFunction(opts.clock, "seeders.create: clock", SeederError);
}

// ---- Resolve helpers ----

function _resolveDb(opts) {
  if (opts && opts.db && typeof opts.db.prepare === "function") return opts.db;
  var d = dbModule();
  if (typeof d.prepare !== "function") {
    throw _err("NO_DB", "seeders: no db handle: pass opts.db or initialize b.db before create()");
  }
  return d;
}

// ---- Directory walking + seed loading ----

function _envDir(rootDir, env) {
  return nodePath.join(rootDir, env);
}

function _listSeedFiles(rootDir, env) {
  return atomicFile.listDir(_envDir(rootDir, env), {
    filter: _isSeedFile,
  }).map(function (e) { return e.name; }).sort();
}

function _loadSeed(rootDir, env, file) {
  var fullPath = nodePath.join(_envDir(rootDir, env), file);
  // Drop require cache for this path so a test rewriting a fixture
  // between calls picks it up. Production restarts the process anyway.
  try { delete require.cache[require.resolve(fullPath)]; } catch (_e) { /* not yet cached */ }
  var mod;
  // Operator-supplied seed — dynamic by design, can't be bundle-traced.
  // Host-CLI scope; deploying via SEA / pkg drops this surface.
  try { mod = require(fullPath); }   // allow:dynamic-require — operator-supplied seed
  catch (e) {
    throw _err("LOAD_FAILED",
      "seed '" + env + "/" + file + "' failed to load: " + ((e && e.message) || String(e)));
  }
  if (!mod || typeof mod.run !== "function") {
    throw _err("BAD_SEED",
      "seed '" + env + "/" + file + "' must export an async `run(db, ctx)` function");
  }
  // Validate optional fields.
  if (mod.envs !== undefined) {
    if (!Array.isArray(mod.envs) || mod.envs.length === 0) {
      throw _err("BAD_SEED",
        "seed '" + env + "/" + file + "': envs must be a non-empty array of env names");
    }
    for (var i = 0; i < mod.envs.length; i++) {
      if (!_isEnvName(mod.envs[i])) {
        throw _err("BAD_SEED",
          "seed '" + env + "/" + file + "': envs[" + i + "] '" + mod.envs[i] +
          "' must match " + ENV_RE + " (max " + ENV_NAME_MAX + " chars)");
      }
    }
  }
  if (mod.rerunnable !== undefined && typeof mod.rerunnable !== "boolean") {
    throw _err("BAD_SEED",
      "seed '" + env + "/" + file + "': rerunnable must be a boolean");
  }
  validateOpts.optionalNonEmptyStringArray(mod.dependsOn,
    "seed '" + env + "/" + file + "': dependsOn", SeederError, "BAD_SEED");
  if (mod.description !== undefined && typeof mod.description !== "string") {
    throw _err("BAD_SEED",
      "seed '" + env + "/" + file + "': description must be a string");
  }
  return mod;
}

// Builds the per-env load map. Caches loaded seeds by name. Detects
// cycles via DFS over dependsOn.
function _loadAllForEnv(rootDir, env) {
  var files = _listSeedFiles(rootDir, env);
  var loaded = {};      // name → mod
  for (var i = 0; i < files.length; i++) {
    loaded[files[i]] = _loadSeed(rootDir, env, files[i]);
  }
  // Filter to seeds whose envs apply (path env always implicit unless
  // overridden by explicit envs declaration).
  var inEnv = {};
  for (var k in loaded) {
    if (!Object.prototype.hasOwnProperty.call(loaded, k)) continue;
    var mod = loaded[k];
    if (mod.envs && mod.envs.indexOf(env) === -1) continue;
    inEnv[k] = mod;
  }
  // Cycle detection (DFS, white/gray/black coloring).
  var WHITE = 0, GRAY = 1, BLACK = 2;
  var color = {};
  for (var n in inEnv) color[n] = WHITE;
  function _dfs(node, stack) {
    if (color[node] === GRAY) {
      throw _err("CYCLE",
        "seed dependency cycle: " + stack.concat([node]).join(" → "));
    }
    if (color[node] === BLACK) return;
    color[node] = GRAY;
    var deps = inEnv[node].dependsOn || [];
    for (var i = 0; i < deps.length; i++) {
      var d = deps[i];
      if (!Object.prototype.hasOwnProperty.call(inEnv, d)) {
        throw _err("MISSING_DEP",
          "seed '" + node + "' dependsOn '" + d + "' which is not present in env '" + env + "'");
      }
      _dfs(d, stack.concat([node]));
    }
    color[node] = BLACK;
  }
  for (var name in inEnv) _dfs(name, []);

  // Topological order for execution. Filenames already sorted so deps
  // typically come first; do a stable topo sort to honor explicit
  // dependsOn even when filename order disagrees.
  var ordered = [];
  var visited = {};
  function _visit(n) {
    if (visited[n]) return;
    visited[n] = true;
    var deps2 = inEnv[n].dependsOn || [];
    for (var i = 0; i < deps2.length; i++) _visit(deps2[i]);
    ordered.push(n);
  }
  for (var n2 of files) {
    if (Object.prototype.hasOwnProperty.call(inEnv, n2)) _visit(n2);
  }
  return { ordered: ordered, modByName: inEnv };
}

// ---- Lock helpers (mirror lib/migrations.js) ----

function _ensureTables(db) {
  // Both _blamejs_seeders + _blamejs_seeders_lock are part of
  // FRAMEWORK_SCHEMA so db.js creates them at boot. The CREATE IF NOT
  // EXISTS here is defensive for tests that hand-seed a fresh
  // node:sqlite Database without going through b.db.
  _runSql(db,
    "CREATE TABLE IF NOT EXISTS " + Q_SEEDERS_TABLE + " (" +
    "  env         TEXT NOT NULL," +
    "  name        TEXT NOT NULL," +
    "  description TEXT," +
    "  appliedAt   TEXT NOT NULL," +
    "  rerunnable  INTEGER NOT NULL DEFAULT 0," +
    "  PRIMARY KEY (env, name)" +
    ")"
  );
  _runSql(db,
    "CREATE TABLE IF NOT EXISTS " + Q_LOCK_TABLE + " (" +
    "  scope     TEXT PRIMARY KEY CHECK (scope = 'lock')," +
    "  lockedAt  INTEGER NOT NULL," +
    "  lockedBy  TEXT NOT NULL" +
    ")"
  );
}

function _lockHolderId() {
  return String(process.pid) + "@" + (require("node:os").hostname() || "unknown");
}

function _acquireLock(db, lockStaleAfterMs, clock) {
  var holder = _lockHolderId();
  var nowMs = clock();
  try {
    db.prepare(
      "INSERT INTO " + Q_LOCK_TABLE + " (scope, lockedAt, lockedBy) VALUES ('lock', ?, ?)"
    ).run(nowMs, holder);
    return holder;
  } catch (_e) {
    var existing = db.prepare(
      "SELECT lockedAt, lockedBy FROM " + Q_LOCK_TABLE + " WHERE scope = 'lock'"
    ).get();
    if (!existing) {
      // Race window between INSERT failure and SELECT — try once more.
      try {
        db.prepare(
          "INSERT INTO " + Q_LOCK_TABLE + " (scope, lockedAt, lockedBy) VALUES ('lock', ?, ?)"
        ).run(nowMs, holder);
        return holder;
      } catch (e2) {
        throw _err("LOCK_BUSY",
          "seeders: could not acquire lock: " + ((e2 && e2.message) || String(e2)));
      }
    }
    var ageMs = nowMs - Number(existing.lockedAt);
    if (lockStaleAfterMs > 0 && ageMs > lockStaleAfterMs) {
      _runSql(db, "BEGIN IMMEDIATE");
      try {
        db.prepare("DELETE FROM " + Q_LOCK_TABLE + " WHERE scope = 'lock' AND lockedAt = ?")
          .run(existing.lockedAt);
        db.prepare(
          "INSERT INTO " + Q_LOCK_TABLE + " (scope, lockedAt, lockedBy) VALUES ('lock', ?, ?)"
        ).run(nowMs, holder);
        _runSql(db, "COMMIT");
        return holder;
      } catch (forceErr) {
        try { _runSql(db, "ROLLBACK"); }
        catch (rollbackErr) {
          log.debug("rollback-failed", {
            op: "lock-stale-replace",
            error: rollbackErr && rollbackErr.message,
          });
        }
        throw _err("LOCK_STALE_REPLACE_FAILED",
          "seeders: could not replace stale lock: " +
          ((forceErr && forceErr.message) || String(forceErr)));
      }
    }
    throw _err("LOCK_HELD",
      "seeders: lock held by " + existing.lockedBy +
      " (acquired " + ageMs + "ms ago). Wait or pass lockStaleAfterMs to force-replace stale locks.");
  }
}

function _releaseLock(db, holder) {
  try {
    db.prepare(
      "DELETE FROM " + Q_LOCK_TABLE + " WHERE scope = 'lock' AND lockedBy = ?"
    ).run(holder);
  } catch (_e) { /* best-effort */ }
}

function _txn(db, fn) {
  return dbSchema.runInTransaction(db, fn, {
    onRollbackFail: function (rollbackErr) {
      log.debug("rollback-failed", {
        op: "txn",
        error: rollbackErr && rollbackErr.message,
      });
    },
  });
}

// ---- Public create ----

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "dir", "db", "audit",
    "auditApplied", "auditFailures",
    "lockStaleAfterMs", "clock",
  ], "b.seeders");
  _validateCreateOpts(opts);
  var cfg = validateOpts.applyDefaults(opts, DEFAULTS);
  var dir = opts.dir;
  var auditApplied  = cfg.auditApplied;
  var auditFailures = cfg.auditFailures;
  var lockStaleAfterMs = cfg.lockStaleAfterMs;
  var audit = opts.audit || null;
  var clock = opts.clock || function () { return Date.now(); };

  function _emitObs(name, labels) {
    try { observability().event(name, 1, labels || {}); }
    catch (_e) { /* drop-silent — observability sink must not crash seeders */ }
  }

  var _emitAudit = validateOpts.makeAuditEmitter(audit);

  function _actor(callerOpts) {
    return requestHelpers.resolveActorWithOverride(callerOpts);
  }

  function _appliedRows(db, env) {
    return db.prepare(
      "SELECT name, description, appliedAt, rerunnable FROM " + Q_SEEDERS_TABLE +
      " WHERE env = ? ORDER BY appliedAt ASC, name ASC"
    ).all(env);
  }

  function status(callerOpts) {
    callerOpts = callerOpts || {};
    _validateEnv("seeders.status: env", callerOpts.env);
    var db = _resolveDb(opts);
    _ensureTables(db);
    var env = callerOpts.env;
    var loaded = _loadAllForEnv(dir, env);
    var applied = _appliedRows(db, env);
    var appliedNames = new Set(applied.map(function (r) { return r.name; }));
    var pending = loaded.ordered.filter(function (n) {
      var mod = loaded.modByName[n];
      if (mod.rerunnable) return true;       // rerunnable seeds are always "pending" in spirit
      return !appliedNames.has(n);
    });
    var rerunnable = loaded.ordered.filter(function (n) { return loaded.modByName[n].rerunnable; });
    return {
      env:        env,
      applied:    applied,
      pending:    pending,
      rerunnable: rerunnable,
      total:      loaded.ordered.length,
    };
  }

  function list(callerOpts) {
    callerOpts = callerOpts || {};
    _validateEnv("seeders.list: env", callerOpts.env);
    return _listSeedFiles(dir, callerOpts.env);
  }

  async function run(callerOpts) {
    callerOpts = callerOpts || {};
    _validateEnv("seeders.run: env", callerOpts.env);
    var env = callerOpts.env;
    var only = callerOpts.only;
    var force = !!callerOpts.force;
    if (only !== undefined && only !== null) {
      if (typeof only !== "string" || only.length === 0) {
        throw _err("BAD_OPT", "seeders.run: only must be a non-empty string filename");
      }
    }

    var db = _resolveDb(opts);
    _ensureTables(db);

    var loaded = _loadAllForEnv(dir, env);

    if (only && !Object.prototype.hasOwnProperty.call(loaded.modByName, only)) {
      throw _err("NOT_FOUND",
        "seeders.run: seed '" + only + "' not found in env '" + env + "'");
    }

    var startedAt = clock();
    _emitObs("seeders.run.start", { env: env, count: loaded.ordered.length });

    var holder = _acquireLock(db, lockStaleAfterMs, clock);
    try {
      var appliedSet = new Set(
        db.prepare("SELECT name FROM " + Q_SEEDERS_TABLE + " WHERE env = ?").all(env)
          .map(function (r) { return r.name; })
      );

      var applied = [];
      var skipped = [];
      var failed = null;

      var toRun = only ? [only] : loaded.ordered;

      for (var i = 0; i < toRun.length; i++) {
        var name = toRun[i];
        var mod = loaded.modByName[name];
        var alreadyApplied = appliedSet.has(name);
        var shouldRun = mod.rerunnable || !alreadyApplied || force;

        if (!shouldRun) {
          skipped.push(name);
          _emitObs("seeders.skipped", { env: env, name: name, reason: "already-applied" });
          continue;
        }

        var ctx = { env: env, runner: { dir: dir }, clock: clock };

        try {
           
          await (async function () {
            // Per-seed transaction: SQLite txns are sync, but the
            // seed's run() may be async — so we begin/commit around
            // an awaited body. Failures roll back this seed only.
            _runSql(db, "BEGIN");
            try {
              await mod.run(db, ctx);
              if (alreadyApplied && mod.rerunnable) {
                db.prepare(
                  "UPDATE " + Q_SEEDERS_TABLE +
                  " SET appliedAt = ?, description = ?, rerunnable = ?" +
                  " WHERE env = ? AND name = ?"
                ).run(new Date(clock()).toISOString(), mod.description || "",
                      mod.rerunnable ? 1 : 0, env, name);
              } else if (alreadyApplied && force) {
                db.prepare(
                  "UPDATE " + Q_SEEDERS_TABLE +
                  " SET appliedAt = ?, description = ?" +
                  " WHERE env = ? AND name = ?"
                ).run(new Date(clock()).toISOString(), mod.description || "",
                      env, name);
              } else {
                db.prepare(
                  "INSERT INTO " + Q_SEEDERS_TABLE +
                  " (env, name, description, appliedAt, rerunnable) VALUES (?, ?, ?, ?, ?)"
                ).run(env, name, mod.description || "",
                      new Date(clock()).toISOString(), mod.rerunnable ? 1 : 0);
              }
              _runSql(db, "COMMIT");
            } catch (e) {
              try { _runSql(db, "ROLLBACK"); }
              catch (rollbackErr) {
                log.debug("rollback-failed", {
                  op: "seed-apply",
                  env: env,
                  name: name,
                  error: rollbackErr && rollbackErr.message,
                });
              }
              throw e;
            }
          })();
          applied.push(name);
          appliedSet.add(name);

          var auditAction = (alreadyApplied && force) ? "seeders.force_applied" : "seeders.applied";
          var auditEvt = { env: env, name: name };
          _emitObs(auditAction, auditEvt);
          if (auditApplied) {
            _emitAudit(auditAction, {
              actor:    _actor(callerOpts),
              resource: { kind: "seeder", id: env + "/" + name },
              outcome:  "success",
              metadata: { description: mod.description || null, rerunnable: !!mod.rerunnable },
            });
          }
        } catch (e) {
          failed = name;
          var msg = (e && e.message) || String(e);
          var code = (e && e.code) || "RUN_FAILED";
          _emitObs("seeders.failed", { env: env, name: name });
          if (auditFailures) {
            _emitAudit("seeders.failed", {
              actor:    _actor(callerOpts),
              resource: { kind: "seeder", id: env + "/" + name },
              outcome:  "failure",
              reason:   "run-failed",
              metadata: { code: code, message: msg },
            });
          }
          // Subsequent seeds in this batch skip — same posture as
          // migrations.up: stop on first failure so the operator can
          // diagnose without further damage.
          break;
        }
      }

      var result = {
        env:        env,
        applied:    applied,
        skipped:    skipped,
        failed:     failed,
        durationMs: clock() - startedAt,
      };
      _emitObs("seeders.run.completed", {
        env:        env,
        applied:    applied.length,
        skipped:    skipped.length,
        durationMs: result.durationMs,
      });
      if (failed) {
        // Surface as a thrown SeederError AFTER emission so callers can
        // catch + still see the partial-result fields on the error.
        var err = _err("RUN_FAILED",
          "seeders.run: seed '" + failed + "' failed; " + applied.length +
          " applied, batch aborted");
        err.result = result;
        throw err;
      }
      return result;
    } finally {
      _releaseLock(db, holder);
    }
  }

  return {
    run:    run,
    status: status,
    list:   list,
    dir:    dir,
  };
}

module.exports = {
  create:           create,
  SeederError:      SeederError,
  DEFAULTS:         DEFAULTS,
  // Internals exposed for tests + tooling
  SEEDERS_TABLE:    SEEDERS_TABLE,
  LOCK_TABLE:       LOCK_TABLE,
  FILE_RE:          FILE_RE,
};
