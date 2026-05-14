"use strict";
/**
 * @module     b.db.fileLifecycle
 * @nav        Data
 * @title      DB file lifecycle
 * @order      215
 * @card       Standalone encrypted-DB-file lifecycle primitive — handles
 *             decrypt-to-tmpfs, periodic re-encrypt flush, in-memory
 *             snapshot, and graceful shutdown without taking ownership
 *             of the SQLite connection or schema. Lets consumers that
 *             keep their own `node:sqlite` handle (downstream
 *             frameworks, the wiki example, anyone with custom
 *             schema/migrations) share one tested implementation.
 *
 * @intro
 *   `b.db` owns the entire data layer — schema reconcile, audit
 *   chain, sealed columns, the works. That's the right tradeoff when
 *   the framework owns the deployment. But operators with their own
 *   schema management, their own migration tool, or a Mongo-style
 *   document model still want the framework's at-rest encryption +
 *   periodic re-flush + WAL-checkpoint snapshot logic without giving
 *   up their own connection.
 *
 *   `b.db.fileLifecycle(opts)` packages just that slice:
 *
 *     1. Decrypt `<dataDir>/db.enc` (or `opts.encryptedDbPath`) to a
 *        random tmpfs file (`/dev/shm/<consumer>-<random>.db`).
 *     2. Surface the plaintext path (`lifecycle.dbPath`) — operators
 *        open their own `new DatabaseSync(dbPath)`.
 *     3. Periodically (every `flushIntervalMs`) re-encrypt the
 *        plaintext file back to `<dataDir>/db.enc`, after running
 *        `PRAGMA wal_checkpoint(TRUNCATE)` against the operator's
 *        connection so committed pages are folded in.
 *     4. Provide `snapshot(db)` for backup callers — same envelope
 *        as the on-disk encPath, returned as a Buffer.
 *     5. Provide `flushAndCleanup(db, opts)` for graceful shutdown —
 *        force-flush, optionally remove the plaintext sidecar.
 *
 *   The DB encryption key is read from / created at `opts.dbKeyPath`
 *   (default `<dataDir>/db.key.enc`). The key file is itself
 *   vault-sealed (operator's `b.vault` instance) — turning the key
 *   into per-row data still doesn't help an attacker without the
 *   vault keypair.
 *
 *   Composes:
 *     - `b.crypto.encryptPacked` / `decryptPacked` — same envelope
 *       `b.db` writes, including the deployment-bound AAD.
 *     - `b.atomicFile` — durable writes that don't leave a partial
 *       db.enc on a crashed flush.
 *     - operator's `b.vault` instance — seals the DB key on first
 *       generation and unseals it at boot.
 *
 *   The framework does NOT touch the SQLite handle — every method
 *   that needs to issue SQL takes the operator's `db` argument
 *   explicitly. This keeps the lifecycle primitive composable with
 *   any sqlite-shaped layer (node:sqlite, better-sqlite3,
 *   bun:sqlite).
 */

var nodeFs   = require("node:fs");
var os   = require("node:os");
var nodePath = require("node:path");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var { generateBytes, generateToken, encryptPacked, decryptPacked } = require("./crypto");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });
var emit = validateOpts.makeNamespacedEmitters("db.fileLifecycle", { audit: audit, observability: observability });

var DbFileLifecycleError = defineClass("DbFileLifecycleError", { alwaysPermanent: true });

var DEFAULT_FLUSH_INTERVAL_MS = C.TIME.minutes(5);
var DB_ENC_KEY_BYTES = 32;                                                                       // allow:raw-byte-literal — 256-bit symmetric key
var TMP_NAME_BYTES   = 16;                                                                       // allow:raw-byte-literal — random suffix

var _emitAudit  = emit.audit;
var _emitMetric = emit.metric;

function _aad(dataDir, label) {
  // Same shape as db.js — bound to the operator's data dir + a
  // consumer-specific label so two consumers under the same dataDir
  // can't swap envelopes.
  return Buffer.from("blamejs.db-file-lifecycle.v1\0" + label + "\0" + (dataDir || ""), "utf8");
}

function _resolveTmpDir(operatorTmpDir, allowDiskFallback) {
  if (operatorTmpDir) return operatorTmpDir;
  // Linux: /dev/shm is the standard tmpfs mount.
  if (process.platform === "linux") {
    try {
      var st = nodeFs.statSync("/dev/shm");
      if (st && st.isDirectory()) return "/dev/shm";
    } catch (_e) { /* fall through */ }
  }
  // Other platforms: only fall back to os.tmpdir() when explicitly
  // permitted — falling back silently lets plaintext leak into
  // backup-included paths on macOS / Windows / non-tmpfs containers.
  if (allowDiskFallback) return os.tmpdir();
  throw new DbFileLifecycleError("db-file-lifecycle/no-tmpfs",
    "fileLifecycle: no tmpfs path resolved. Set opts.tmpDir to a tmpfs mount " +
    "OR set opts.allowDiskFallback: true to accept disk-backed temporary storage.");
}

/**
 * @primitive b.db.fileLifecycle
 * @signature b.db.fileLifecycle(opts)
 * @since     0.8.62
 * @status    stable
 * @related   b.db.snapshot, b.db.flushToDisk, b.crypto.encryptPacked
 *
 * Returns an encrypted-DB-file lifecycle handle. Methods:
 *
 *   - `decryptToTmp()` — decrypt the encrypted DB file to a fresh
 *     tmpfs path and return the path. Idempotent: subsequent calls
 *     return the existing path.
 *   - `dbPath` — the resolved plaintext-tmpfs path (set after
 *     `decryptToTmp()` runs).
 *   - `startFlushTimer(db, opts?)` — start a periodic flush timer
 *     against the operator's SQLite handle. Returns a stop function.
 *   - `flushNow(db)` — force a single re-encrypt flush (WAL
 *     checkpoint + write encPath atomically). Used by backup paths.
 *   - `snapshot(db)` — return the encrypted Buffer (same envelope
 *     as `flushNow` writes), without touching the disk encPath.
 *   - `flushAndCleanup(db, opts)` — shutdown sequence: flushNow,
 *     close the handle, optionally remove the plaintext file +
 *     WAL/SHM sidecars.
 *
 * @opts
 *   {
 *     dataDir:           string,                   // operator's data dir (used as AAD)
 *     tmpDir?:           string,                   // tmpfs path; default /dev/shm on Linux
 *     allowDiskFallback?: boolean,                 // permit os.tmpdir() fallback (warns)
 *     encryptedDbPath?:  string,                   // default <dataDir>/db.enc
 *     encryptedDbName?:  string,                   // basename under dataDir (default "db.enc")
 *     dbKeyPath?:        string,                   // default <dataDir>/db.key.enc
 *     vault:             <b.vault instance>,       // for sealing the DB key
 *     label?:            string,                   // AAD label (default "default")
 *     flushIntervalMs?:  number,                   // default 5 minutes
 *   }
 *
 * @example
 *   var lc = b.db.fileLifecycle({ dataDir: "/var/lib/app", vault: b.vault });
 *   var dbPath = lc.decryptToTmp();
 *   var db = new (require("node:sqlite").DatabaseSync)(dbPath);
 *   var stop = lc.startFlushTimer(db);
 *   // ... operator runs the app ...
 *   process.on("exit", function () { lc.flushAndCleanup(db, { removePlaintext: true }); });
 */
function fileLifecycle(opts) {
  validateOpts.requireObject(opts, "db.fileLifecycle", DbFileLifecycleError);
  validateOpts.requireNonEmptyString(opts.dataDir, "db.fileLifecycle: dataDir",
    DbFileLifecycleError, "db-file-lifecycle/no-data-dir");
  if (!opts.vault || typeof opts.vault.seal !== "function" || typeof opts.vault.unseal !== "function") {
    throw new DbFileLifecycleError("db-file-lifecycle/no-vault",
      "fileLifecycle: opts.vault must expose seal/unseal (use b.vault after b.vault.init resolves)");
  }
  validateOpts.optionalPositiveFinite(opts.flushIntervalMs, "flushIntervalMs",
    DbFileLifecycleError, "db-file-lifecycle/bad-flush-interval");

  var label = opts.label || "default";
  var encName = opts.encryptedDbName || "db.enc";
  var encPath = opts.encryptedDbPath
    ? nodePath.resolve(opts.encryptedDbPath)
    : nodePath.join(opts.dataDir, encName);
  var keyPath = opts.dbKeyPath
    ? nodePath.resolve(opts.dbKeyPath)
    : nodePath.join(opts.dataDir, "db.key.enc");
  var flushIntervalMs = opts.flushIntervalMs || DEFAULT_FLUSH_INTERVAL_MS;
  var tmpDir = _resolveTmpDir(opts.tmpDir, opts.allowDiskFallback === true);
  if (!nodeFs.existsSync(tmpDir)) nodeFs.mkdirSync(tmpDir, { recursive: true });
  if (!nodeFs.existsSync(opts.dataDir)) nodeFs.mkdirSync(opts.dataDir, { recursive: true });

  var dbPath = null;
  var encKey = null;
  var encTimer = null;
  var decrypted = false;

  function _loadOrGenerateKey() {
    if (encKey) return encKey;
    if (nodeFs.existsSync(keyPath)) {
      var sealedKey = nodeFs.readFileSync(keyPath, "utf8");
      var keyB64;
      try { keyB64 = opts.vault.unseal(sealedKey); }
      catch (e) {
        throw new DbFileLifecycleError("db-file-lifecycle/key-unseal-failed",
          "fileLifecycle: cannot unseal " + keyPath + " — vault keypair changed? " +
          "(" + ((e && e.message) || String(e)) + ")");
      }
      encKey = Buffer.from(keyB64, "base64");
      if (encKey.length !== DB_ENC_KEY_BYTES) {
        throw new DbFileLifecycleError("db-file-lifecycle/bad-key-length",
          "fileLifecycle: unsealed key is " + encKey.length + " bytes (expected " + DB_ENC_KEY_BYTES + ")");
      }
      return encKey;
    }
    // First boot — generate, seal, persist.
    encKey = generateBytes(DB_ENC_KEY_BYTES);
    var sealed = opts.vault.seal(encKey.toString("base64"));
    atomicFile.writeSync(keyPath, sealed);
    _emitAudit("key_generated", "success", { label: label });
    return encKey;
  }

  function decryptToTmp() {
    if (decrypted) return dbPath;
    _loadOrGenerateKey();
    dbPath = nodePath.join(tmpDir, "blamejs-fl-" + label + "-" +
      generateToken(TMP_NAME_BYTES) + ".db");
    if (nodeFs.existsSync(encPath)) {
      var packed = nodeFs.readFileSync(encPath);
      if (packed.length < 26) {                                                                  // allow:raw-byte-literal — minimum envelope length
        throw new DbFileLifecycleError("db-file-lifecycle/short-envelope",
          "fileLifecycle: " + encPath + " too short to be a valid envelope (" + packed.length + " bytes)");
      }
      var aad = _aad(opts.dataDir, label);
      try {
        atomicFile.writeSync(dbPath, decryptPacked(packed, encKey, aad));
      } catch (e) {
        throw new DbFileLifecycleError("db-file-lifecycle/decrypt-failed",
          "fileLifecycle: decrypt of " + encPath + " failed: " + ((e && e.message) || String(e)));
      }
    }
    // If encPath doesn't exist, the operator opens a fresh empty DB
    // at dbPath; the first flushNow() will materialize encPath.
    decrypted = true;
    _emitAudit("decrypted", "success", {
      label:    label,
      encPath:  encPath,
      dbPath:   dbPath,
      isEmpty:  !nodeFs.existsSync(encPath),
    });
    _emitMetric("decrypted");
    return dbPath;
  }

  function flushNow(db) {
    if (!decrypted || !dbPath) {
      throw new DbFileLifecycleError("db-file-lifecycle/not-decrypted",
        "fileLifecycle.flushNow: decryptToTmp() must run first");
    }
    if (db && typeof db.prepare === "function") {
      try { db.prepare("PRAGMA wal_checkpoint(TRUNCATE)").run(); }
      catch (_e) { /* best-effort — operators on read-only handles or pre-init still flush */ }
    }
    if (!nodeFs.existsSync(dbPath)) return null;
    var plain = nodeFs.readFileSync(dbPath);
    var packed = encryptPacked(plain, encKey, _aad(opts.dataDir, label));
    atomicFile.writeSync(encPath, packed);
    _emitAudit("flushed", "success", { label: label, bytes: plain.length });
    _emitMetric("flushed");
    return packed;
  }

  function snapshot(db) {
    if (!decrypted || !dbPath) {
      throw new DbFileLifecycleError("db-file-lifecycle/not-decrypted",
        "fileLifecycle.snapshot: decryptToTmp() must run first");
    }
    if (db && typeof db.prepare === "function") {
      try { db.prepare("PRAGMA wal_checkpoint(TRUNCATE)").run(); }
      catch (_e) { /* best-effort */ }
    }
    if (!nodeFs.existsSync(dbPath)) {
      throw new DbFileLifecycleError("db-file-lifecycle/no-source",
        "fileLifecycle.snapshot: " + dbPath + " is missing");
    }
    var plain = nodeFs.readFileSync(dbPath);
    return encryptPacked(plain, encKey, _aad(opts.dataDir, label));
  }

  function startFlushTimer(db, sopts) {
    sopts = sopts || {};
    if (encTimer) {
      throw new DbFileLifecycleError("db-file-lifecycle/timer-already-running",
        "fileLifecycle.startFlushTimer: timer already running — call stop() first");
    }
    var interval = sopts.intervalMs || flushIntervalMs;
    encTimer = setInterval(function () {                                                          // allow:setinterval-unref — .unref() called immediately below; timer doesn't pin the event loop
      try { flushNow(db); }
      catch (e) {
        _emitAudit("flush_failed", "failure", {
          label:  label,
          reason: (e && e.message) || String(e),
        });
      }
    }, interval);
    if (typeof encTimer.unref === "function") encTimer.unref();
    return function stop() {
      if (encTimer) { clearInterval(encTimer); encTimer = null; }
    };
  }

  function flushAndCleanup(db, fopts) {
    fopts = fopts || {};
    if (encTimer) { clearInterval(encTimer); encTimer = null; }
    try { flushNow(db); }
    catch (e) {
      _emitAudit("shutdown_flush_failed", "failure", {
        label: label, reason: (e && e.message) || String(e),
      });
      throw e;
    }
    if (db && typeof db.close === "function") {
      try { db.close(); } catch (_e) { /* best-effort */ }
    }
    if (fopts.removePlaintext === true && dbPath) {
      try { nodeFs.unlinkSync(dbPath); } catch (_e) { /* best-effort */ }
      try { nodeFs.unlinkSync(dbPath + "-wal"); } catch (_e) { /* best-effort */ }
      try { nodeFs.unlinkSync(dbPath + "-shm"); } catch (_e) { /* best-effort */ }
    }
    _emitAudit("shutdown", "success", { label: label });
  }

  return {
    get dbPath()    { return dbPath; },
    get encPath()   { return encPath; },
    get keyPath()   { return keyPath; },
    decryptToTmp:    decryptToTmp,
    flushNow:        flushNow,
    snapshot:        snapshot,
    startFlushTimer: startFlushTimer,
    flushAndCleanup: flushAndCleanup,
  };
}

module.exports = {
  fileLifecycle:        fileLifecycle,
  DbFileLifecycleError: DbFileLifecycleError,
};
